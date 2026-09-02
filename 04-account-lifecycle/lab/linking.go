package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// This file is the heart of the module's security lesson: how a federated
// login (Google/SAML) becomes a local account, and how the naive version of
// that is an account-takeover primitive.
//
// This process fakes an IdP so the whole flow is local. The "assertion" is a
// base64 JSON blob with an HMAC — standing in for a signed OIDC id_token. The
// fields that matter are exactly the ones a real id_token carries.

type assertion struct {
	Provider      string `json:"provider"`
	Subject       string `json:"sub"`   // stable per-user IdP id
	Email         string `json:"email"` // may be anything the IdP was told
	EmailVerified bool   `json:"email_verified"`
	Issued        int64  `json:"iat"`
}

// handleFakeIdP mints an assertion. A real IdP would authenticate the user
// first; here the query params ARE the identity, which is the point — it lets
// the lab mint an attacker-controlled assertion to show why `email_verified`
// cannot be trusted for linking.
//
//	GET /fake-idp/authorize?sub=g-victim&email=victim@corp.com&email_verified=true
func handleFakeIdP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a := assertion{
		Provider:      "google",
		Subject:       q.Get("sub"),
		Email:         q.Get("email"),
		EmailVerified: q.Get("email_verified") == "true",
		Issued:        time.Now().Unix(),
	}
	body, _ := json.Marshal(a)
	mac := hmac.New(sha256.New, idpKey)
	mac.Write(body)
	tok := base64.RawURLEncoding.EncodeToString(body) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	jsonOut(w, 200, map[string]string{"assertion": tok})
}

func verifyAssertion(tok string) (*assertion, error) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed assertion")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, idpKey)
	mac.Write(body)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("bad signature")
	}
	var a assertion
	if err := json.Unmarshal(body, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// handleFederatedLogin is "Sign in with Google". Body: {"assertion":"..."}.
//
// The decision tree here is where real products get breached:
//  1. identity already linked (provider+sub match) -> just log in. Always safe.
//  2. brand-new identity, no email match           -> create a fresh user.
//  3. brand-new identity, but email matches a LOCAL account -> the danger zone.
func handleFederatedLogin(w http.ResponseWriter, r *http.Request) {
	var in struct{ Assertion string }
	if err := readJSON(r, &in); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	a, err := verifyAssertion(in.Assertion)
	if err != nil {
		jsonErr(w, 401, "assertion: "+err.Error())
		return
	}
	ctx := r.Context()

	// Case 1: this federated identity is already linked. The join key is
	// (provider, sub) — NEVER the email. This is the only truly safe path.
	var userID string
	err = db.QueryRow(ctx,
		`SELECT user_id FROM identities WHERE provider = $1 AND subject = $2`,
		a.Provider, a.Subject).Scan(&userID)
	if err == nil {
		newSession(w, userID)
		audit(ctx, userID, "login", "federated:"+a.Provider)
		jsonOut(w, 200, map[string]string{"status": "logged in", "path": "existing-identity"})
		return
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		jsonErr(w, 500, "internal")
		return
	}

	// New identity. Is there a local account with the same email?
	var localID, localStatus string
	err = db.QueryRow(ctx,
		`SELECT id, status FROM users WHERE lower(email) = lower($1) AND deleted_at IS NULL`,
		a.Email).Scan(&localID, &localStatus)

	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Case 2: nobody owns this email. Provision a fresh, pre-verified
		// account (the IdP vouched for it) and link the identity.
		if err := db.QueryRow(ctx,
			`INSERT INTO users (email, email_verified, status, display_name)
			 VALUES ($1, $2, 'active', $1) RETURNING id`,
			a.Email, a.EmailVerified).Scan(&userID); err != nil {
			jsonErr(w, 500, "internal")
			return
		}
		linkIdentity(ctx, userID, a)
		newSession(w, userID)
		audit(ctx, userID, "signup", "federated:"+a.Provider)
		jsonOut(w, 201, map[string]string{"status": "account created", "path": "new-user"})

	case err != nil:
		jsonErr(w, 500, "internal")

	default:
		// Case 3: THE DANGER ZONE. A local account already owns this email.
		// Do we attach the new IdP identity to it and log the caller in?
		//
		// UNSAFE (the classic vuln): yes, auto-link on email match. An
		// attacker registers google account with sub=g-attacker and
		// email=victim@corp.com. If the IdP never verified that email — or
		// verified it but we trust the claim blindly — the attacker now owns
		// the victim's local account. "Pre-account-takeover."
		//
		// SAFE: never auto-link. Either require the IdP to assert
		// email_verified AND make the user prove control of the local account
		// (log in with the password first, then link), or just refuse and
		// tell them to link from settings. This lab's SAFE mode refuses.
		if linkMode == "unsafe" {
			linkIdentity(ctx, localID, a)
			newSession(w, localID)
			audit(ctx, localID, "identity_linked", "AUTO by email match (unsafe): "+a.Provider)
			jsonOut(w, 200, map[string]string{
				"status": "logged in", "path": "AUTO-LINKED-BY-EMAIL (this is the vuln)"})
			return
		}
		jsonErr(w, 409,
			"an account with this email already exists — log in with your password, then link "+a.Provider+" from account settings")
	}
}

func linkIdentity(ctx context.Context, userID string, a *assertion) error {
	_, err := db.Exec(ctx,
		`INSERT INTO identities (user_id, provider, subject, email, email_verified)
		 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (provider, subject) DO NOTHING`,
		userID, a.Provider, a.Subject, a.Email, a.EmailVerified)
	return err
}

// handleExplicitLink is the SAFE way to add a federated login: you are already
// authenticated (session) AND you present a fresh assertion from the IdP. The
// local account's ownership is proven by the session, so linking any identity
// to it is fine regardless of the assertion's email.
func handleExplicitLink(w http.ResponseWriter, r *http.Request, userID string) {
	var in struct{ Assertion string }
	if err := readJSON(r, &in); err != nil {
		jsonErr(w, 400, "bad request")
		return
	}
	a, err := verifyAssertion(in.Assertion)
	if err != nil {
		jsonErr(w, 401, "assertion: "+err.Error())
		return
	}
	if err := linkIdentity(r.Context(), userID, a); err != nil {
		jsonErr(w, 409, "that identity is already linked to an account")
		return
	}
	audit(r.Context(), userID, "identity_linked", "explicit (safe): "+a.Provider)
	jsonOut(w, 200, map[string]string{"status": "linked " + a.Provider})
}

func handleListIdentities(w http.ResponseWriter, r *http.Request, userID string) {
	out := []map[string]any{}
	rows, _ := db.Query(r.Context(),
		`SELECT provider, subject, email, email_verified FROM identities WHERE user_id = $1`, userID)
	for rows.Next() {
		var p, s, e string
		var v bool
		rows.Scan(&p, &s, &e, &v)
		out = append(out, map[string]any{"provider": p, "subject": s, "email": e, "email_verified": v})
	}
	jsonOut(w, 200, out)
}

var _ = context.Background
