package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// ---- invitations (the non-SSO path into an org) ----------------------------

func handleInvite(w http.ResponseWriter, r *http.Request, tc tenantContext) {
	var in struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := readJSON(r, &in); err != nil || in.Email == "" {
		jsonErr(w, 400, "email required")
		return
	}
	if in.Role == "" {
		in.Role = "member"
	}
	raw := randToken()
	_, err := db.Exec(r.Context(),
		`INSERT INTO invitations (token_hash, org_id, email, role, expires_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		hashToken(raw), tc.orgID, strings.ToLower(in.Email), in.Role, time.Now().Add(72*time.Hour))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	// In a real app this link is emailed; the demo returns it for scriptability.
	jsonOut(w, 201, map[string]string{"status": "invited", "accept_token": raw})
}

func handleAcceptInvite(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &in); err != nil || in.Token == "" {
		jsonErr(w, 400, "token required")
		return
	}
	ctx := r.Context()

	var orgID, email, role string
	err := db.QueryRow(ctx, `
		UPDATE invitations SET used_at = now()
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		 RETURNING org_id, email, role`,
		hashToken(in.Token)).Scan(&orgID, &email, &role)
	if err != nil {
		jsonErr(w, 400, "invalid or expired invitation")
		return
	}

	userID := upsertUser(ctx, email)
	addMembership(ctx, orgID, userID, role, "invite")
	jsonOut(w, 200, map[string]string{"status": "joined org", "org_id": orgID, "role": role})
}

// ---- SSO: home-realm discovery + JIT provisioning --------------------------

// handleDiscover is home-realm discovery: given an email, which org/IdP owns it?
// The user types their email on a generic login page; the domain routes them to
// the right enterprise SSO, so nobody has to pick their company from a list.
//
//	GET /sso/discover?email=alice@acme.com
func handleDiscover(w http.ResponseWriter, r *http.Request) {
	email := strings.ToLower(r.URL.Query().Get("email"))
	at := strings.LastIndex(email, "@")
	if at < 0 {
		jsonErr(w, 400, "bad email")
		return
	}
	domain := email[at+1:]

	var orgID, idp string
	err := db.QueryRow(r.Context(),
		`SELECT org_id, idp_name FROM sso_connections WHERE domain = $1`, domain).Scan(&orgID, &idp)
	if errors.Is(err, pgx.ErrNoRows) {
		// No SSO for this domain -> fall back to password login (out of scope here).
		jsonOut(w, 200, map[string]any{"sso": false, "method": "password"})
		return
	}
	jsonOut(w, 200, map[string]any{"sso": true, "org_id": orgID, "idp": idp,
		"redirect": "/sso/callback (in reality: the IdP's authorize URL)"})
}

// handleSSOCallback stands in for "the IdP authenticated the user and sent us an
// assertion". JIT provisioning: if the verified user has no membership in the
// org yet and the connection allows it, create one on the fly.
//
// Body: {"email":"alice@acme.com"}  (a real assertion would carry this, signed)
func handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if err := readJSON(r, &in); err != nil || in.Email == "" {
		jsonErr(w, 400, "email required")
		return
	}
	ctx := r.Context()
	email := strings.ToLower(in.Email)
	domain := email[strings.LastIndex(email, "@")+1:]

	var orgID, defRole string
	var jit bool
	err := db.QueryRow(ctx,
		`SELECT org_id, jit_enabled, default_role FROM sso_connections WHERE domain = $1`,
		domain).Scan(&orgID, &jit, &defRole)
	if err != nil {
		jsonErr(w, 403, "no SSO connection for this domain")
		return
	}

	userID := upsertUser(ctx, email)

	// Does the membership exist?
	var active bool
	err = db.QueryRow(ctx, `SELECT active FROM memberships WHERE org_id = $1 AND user_id = $2`,
		orgID, userID).Scan(&active)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if !jit {
			jsonErr(w, 403, "no membership and JIT provisioning is disabled — ask an admin to invite you")
			return
		}
		addMembership(ctx, orgID, userID, defRole, "jit")
		jsonOut(w, 200, map[string]any{"status": "logged in", "provisioned": "jit", "org_id": orgID, "role": defRole})
	case err != nil:
		jsonErr(w, 500, err.Error())
	case !active:
		// The membership was deprovisioned (SCIM). SSO must NOT silently
		// resurrect it — that's the offboarding hole. Refuse.
		jsonErr(w, 403, "your access to this organization was revoked")
	default:
		jsonOut(w, 200, map[string]any{"status": "logged in", "provisioned": "existing", "org_id": orgID})
	}
}

// ---- shared helpers --------------------------------------------------------

func upsertUser(ctx context.Context, email string) string {
	var id string
	db.QueryRow(ctx,
		`INSERT INTO users (email) VALUES ($1)
		 ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
		 RETURNING id`, email).Scan(&id)
	return id
}

func addMembership(ctx context.Context, orgID, userID, role, source string) {
	db.Exec(ctx,
		`INSERT INTO memberships (org_id, user_id, role, source, active)
		 VALUES ($1,$2,$3,$4,true)
		 ON CONFLICT (org_id, user_id) DO UPDATE SET active = true`,
		orgID, userID, role, source)
}
