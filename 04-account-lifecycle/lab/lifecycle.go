package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const tokenTTL = time.Hour

// ---- signup + email verification ------------------------------------------

func handleSignup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if err := readJSON(r, &in); err != nil || in.Email == "" || in.Password == "" {
		jsonErr(w, 400, "email and password required")
		return
	}
	ctx := r.Context()

	var userID string
	err := db.QueryRow(ctx,
		`INSERT INTO users (email, display_name) VALUES ($1, $2) RETURNING id`,
		strings.TrimSpace(in.Email), in.DisplayName).Scan(&userID)
	if err != nil {
		// Duplicate live email. Same response as success — Module 0's
		// enumeration lesson applies to signup too. (The real notification
		// happens out-of-band: the existing owner gets an email.)
		sendMail(in.Email, "Someone tried to sign up with your address",
			"A signup was attempted with your email. If this was you, log in instead or reset your password.")
		jsonOut(w, 200, map[string]string{"status": "check your email to verify your account"})
		return
	}

	_, err = db.Exec(ctx,
		`INSERT INTO credentials (user_id, type, password_hash) VALUES ($1, 'password', $2)`,
		userID, hashPassword(in.Password))
	if err != nil {
		jsonErr(w, 500, "internal")
		return
	}

	issueToken(ctx, userID, "verify_email", "", in.Email,
		"Verify your account",
		"Welcome! Confirm your address by opening:\n\n  http://localhost:8080/verify-email?token=%s\n")
	audit(ctx, userID, "signup", "email="+in.Email)
	jsonOut(w, 200, map[string]string{"status": "check your email to verify your account"})
}

// issueToken stores a hashed single-use token and mails the raw one.
func issueToken(ctx context.Context, userID, purpose, newEmail, to, subject, bodyFmt string) {
	raw := randToken()
	_, err := db.Exec(ctx,
		`INSERT INTO verification_tokens (token_hash, user_id, purpose, new_email, expires_at)
		 VALUES ($1, $2, $3, NULLIF($4,''), $5)`,
		hashToken(raw), userID, purpose, newEmail, time.Now().Add(tokenTTL))
	if err == nil {
		sendMail(to, subject, fmt.Sprintf(bodyFmt, raw))
	}
}

// redeemToken atomically marks a token used and returns its row.
func redeemToken(ctx context.Context, raw, purpose string) (userID, newEmail string, err error) {
	var ne *string
	err = db.QueryRow(ctx,
		`UPDATE verification_tokens
		    SET used_at = now()
		  WHERE token_hash = $1 AND purpose = $2
		    AND used_at IS NULL AND expires_at > now()
		 RETURNING user_id, new_email`,
		hashToken(raw), purpose).Scan(&userID, &ne)
	if ne != nil {
		newEmail = *ne
	}
	return
}

func handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	userID, _, err := redeemToken(r.Context(), r.URL.Query().Get("token"), "verify_email")
	if err != nil {
		jsonErr(w, 400, "invalid or expired token")
		return
	}
	db.Exec(r.Context(),
		`UPDATE users SET email_verified = true, status = 'active', updated_at = now()
		  WHERE id = $1 AND status = 'pending_verification'`, userID)
	audit(r.Context(), userID, "email_verified", "")
	jsonOut(w, 200, map[string]string{"status": "verified — you can log in now"})
}

// ---- login / logout --------------------------------------------------------

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Email, Password string }
	if err := readJSON(r, &in); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	ctx := r.Context()

	var userID, status, hash string
	err := db.QueryRow(ctx,
		`SELECT u.id, u.status, c.password_hash
		   FROM users u JOIN credentials c ON c.user_id = u.id AND c.type = 'password'
		  WHERE lower(u.email) = lower($1) AND u.deleted_at IS NULL`,
		in.Email).Scan(&userID, &status, &hash)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !verifyPassword(hash, in.Password) {
		jsonErr(w, 401, "invalid credentials")
		return
	}
	if err != nil {
		jsonErr(w, 500, "internal")
		return
	}

	// The lifecycle gate. Password being right is necessary, not sufficient.
	switch status {
	case "pending_verification":
		jsonErr(w, 403, "verify your email first")
		return
	case "deactivated":
		// Product choice demonstrated here: logging in reactivates.
		db.Exec(ctx, `UPDATE users SET status = 'active', updated_at = now() WHERE id = $1`, userID)
		audit(ctx, userID, "reactivated", "via login")
	case "active":
	default:
		jsonErr(w, 401, "invalid credentials")
		return
	}

	newSession(w, userID)
	audit(ctx, userID, "login", "password")
	jsonOut(w, 200, map[string]string{"status": "logged in"})
}

func handleLogout(w http.ResponseWriter, r *http.Request, userID string) {
	c, _ := r.Cookie("sid")
	sessMu.Lock()
	delete(sess, c.Value)
	sessMu.Unlock()
	jsonOut(w, 200, map[string]string{"status": "logged out"})
}

func handleMe(w http.ResponseWriter, r *http.Request, userID string) {
	var email *string
	var name, status string
	var verified bool
	err := db.QueryRow(r.Context(),
		`SELECT email, display_name, status, email_verified FROM users WHERE id = $1`,
		userID).Scan(&email, &name, &status, &verified)
	if err != nil {
		jsonErr(w, 500, "internal")
		return
	}
	jsonOut(w, 200, map[string]any{
		"id": userID, "email": email, "display_name": name,
		"status": status, "email_verified": verified,
	})
}

// ---- email change ----------------------------------------------------------

func handleEmailChange(w http.ResponseWriter, r *http.Request, userID string) {
	var in struct {
		NewEmail string `json:"new_email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &in); err != nil || in.NewEmail == "" {
		jsonErr(w, 400, "new_email required")
		return
	}
	ctx := r.Context()

	// Changing the email is changing the recovery channel — the keys to the
	// account. It must cost more than holding a session cookie: re-prove the
	// password (step-up; Module 3's re-authentication lesson).
	var hash string
	db.QueryRow(ctx, `SELECT password_hash FROM credentials WHERE user_id = $1 AND type = 'password'`,
		userID).Scan(&hash)
	if !verifyPassword(hash, in.Password) {
		jsonErr(w, 403, "password confirmation required")
		return
	}

	// The new address must prove it exists and is yours: verification token
	// goes to the NEW address; nothing changes until it is clicked.
	issueToken(ctx, userID, "change_email", in.NewEmail, in.NewEmail,
		"Confirm your new email address",
		"Confirm this address for your account:\n\n  http://localhost:8080/email/confirm?token=%s\n")
	audit(ctx, userID, "email_change_requested", "new="+in.NewEmail)
	jsonOut(w, 200, map[string]string{"status": "confirmation sent to new address"})
}

func handleEmailConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, newEmail, err := redeemToken(ctx, r.URL.Query().Get("token"), "change_email")
	if err != nil {
		jsonErr(w, 400, "invalid or expired token")
		return
	}

	var oldEmail string
	if err := db.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, userID).Scan(&oldEmail); err != nil {
		jsonErr(w, 500, "internal")
		return
	}
	_, err = db.Exec(ctx,
		`UPDATE users SET email = $1, email_verified = true, updated_at = now() WHERE id = $2`,
		newEmail, userID)
	if err != nil {
		jsonErr(w, 409, "that address is already in use")
		return
	}

	// Notify the OLD address. If the change was an attacker with a hijacked
	// session, this mail is the victim's only warning — never skip it.
	sendMail(oldEmail, "Your account email was changed",
		"The email on your account was changed to "+newEmail+
			".\nIf this was not you, contact support IMMEDIATELY — reply to this address within 14 days to revert.")
	audit(ctx, userID, "email_changed", oldEmail+" -> "+newEmail)
	jsonOut(w, 200, map[string]string{"status": "email updated"})
}

// ---- deactivate / delete / purge ------------------------------------------

func handleDeactivate(w http.ResponseWriter, r *http.Request, userID string) {
	db.Exec(r.Context(), `UPDATE users SET status = 'deactivated', updated_at = now() WHERE id = $1`, userID)
	revokeSessions(userID)
	audit(r.Context(), userID, "deactivated", "")
	jsonOut(w, 200, map[string]string{"status": "deactivated — log in again to reactivate"})
}

func handleDelete(w http.ResponseWriter, r *http.Request, userID string) {
	var in struct{ Password string }
	readJSON(r, &in)
	var hash string
	db.QueryRow(r.Context(), `SELECT password_hash FROM credentials WHERE user_id = $1 AND type = 'password'`,
		userID).Scan(&hash)
	if !verifyPassword(hash, in.Password) { // deletion is maximally destructive: step-up
		jsonErr(w, 403, "password confirmation required")
		return
	}

	// SOFT delete: mark, revoke access, start the retention clock. The row
	// stays so the user can change their mind and support can investigate.
	db.Exec(r.Context(),
		`UPDATE users SET status = 'soft_deleted', deleted_at = now(), updated_at = now() WHERE id = $1`,
		userID)
	revokeSessions(userID)
	audit(r.Context(), userID, "soft_deleted", "")
	jsonOut(w, 200, map[string]string{"status": "account scheduled for deletion"})
}

// handlePurge plays the retention cron job. ?days=N purges accounts
// soft-deleted more than N days ago (default 30; the demo passes 0).
func handlePurge(w http.ResponseWriter, r *http.Request) {
	days := 30
	fmt.Sscanf(r.URL.Query().Get("days"), "%d", &days)
	ctx := r.Context()

	rows, err := db.Query(ctx,
		`SELECT id FROM users WHERE status = 'soft_deleted' AND deleted_at < now() - make_interval(days => $1)`,
		days)
	if err != nil {
		jsonErr(w, 500, "internal")
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}

	for _, id := range ids {
		purgeUser(ctx, id)
	}
	jsonOut(w, 200, map[string]any{"purged": ids})
}

// purgeUser is the GDPR-erasure step: PII gone, tombstone kept. Deleting the
// users row outright would cascade into every table that references the user
// — and erasure requires removing *personal data*, not breaking referential
// integrity for orders, invoices, or the audit trail.
func purgeUser(ctx context.Context, userID string) {
	db.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1`, userID)
	db.Exec(ctx, `DELETE FROM identities WHERE user_id = $1`, userID)
	db.Exec(ctx, `DELETE FROM verification_tokens WHERE user_id = $1`, userID)
	db.Exec(ctx,
		`UPDATE users SET email = NULL, display_name = '', email_verified = false,
		        status = 'purged', updated_at = now() WHERE id = $1`, userID)
	audit(ctx, userID, "purged", "PII erased")
}

// ---- data access (GDPR art. 15 "right of access", in miniature) ------------

func handleExport(w http.ResponseWriter, r *http.Request, userID string) {
	ctx := r.Context()
	out := map[string]any{}

	var email *string
	var name, status string
	var created time.Time
	db.QueryRow(ctx, `SELECT email, display_name, status, created_at FROM users WHERE id = $1`,
		userID).Scan(&email, &name, &status, &created)
	out["user"] = map[string]any{"id": userID, "email": email, "display_name": name,
		"status": status, "created_at": created}

	ids := []map[string]any{}
	rows, _ := db.Query(ctx, `SELECT provider, subject, email FROM identities WHERE user_id = $1`, userID)
	for rows.Next() {
		var p, s, e string
		rows.Scan(&p, &s, &e)
		ids = append(ids, map[string]any{"provider": p, "subject": s, "email": e})
	}
	out["identities"] = ids

	events := []map[string]any{}
	rows, _ = db.Query(ctx, `SELECT action, detail, at FROM audit_log WHERE user_id = $1 ORDER BY at`, userID)
	for rows.Next() {
		var a, d string
		var at time.Time
		rows.Scan(&a, &d, &at)
		events = append(events, map[string]any{"action": a, "detail": d, "at": at})
	}
	out["audit_log"] = events

	jsonOut(w, 200, out)
}

func handleAudit(w http.ResponseWriter, r *http.Request, userID string) {
	events := []map[string]any{}
	rows, _ := db.Query(r.Context(),
		`SELECT action, detail, at FROM audit_log WHERE user_id = $1 ORDER BY at`, userID)
	for rows.Next() {
		var a, d string
		var at time.Time
		rows.Scan(&a, &d, &at)
		events = append(events, map[string]any{"action": a, "detail": d, "at": at})
	}
	jsonOut(w, 200, events)
}
