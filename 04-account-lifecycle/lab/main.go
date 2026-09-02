// Module 4 lab — account lifecycle, data model & identity linking.
//
// One Go service, three backing containers:
//
//	postgres — the users/credentials/identities schema (schema.sql)
//	mailpit  — catches every email the service "sends" (UI on :8025)
//
// Authn plumbing (password hashing, timing, sessions) was Module 0's subject;
// here it is deliberately minimal so the *data model and lifecycle* stay in
// the foreground.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

var (
	db *pgxpool.Pool

	// LINK_MODE controls what a federated login does when no identity row
	// matches but a local account has the same email address:
	//   unsafe — auto-link by email match (the account-takeover demo)
	//   safe   — refuse; require the user to prove the password first
	linkMode = env("LINK_MODE", "unsafe")

	// HMAC key for the fake IdP's "assertions" (this process plays both IdP
	// and RP, so a shared secret stands in for the IdP's signature).
	idpKey = []byte(env("IDP_KEY", "lab-idp-key-not-secret"))
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	dsn := env("DATABASE_URL", "postgres://lab:lab@localhost:5432/lab")

	var err error
	for i := 0; i < 30; i++ { // wait for postgres
		db, err = pgxpool.New(ctx, dsn)
		if err == nil {
			err = db.Ping(ctx)
		}
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}

	mux := http.NewServeMux()
	// Lifecycle
	mux.HandleFunc("POST /signup", handleSignup)
	mux.HandleFunc("GET /verify-email", handleVerifyEmail)
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", requireSession(handleLogout))
	mux.HandleFunc("GET /me", requireSession(handleMe))
	mux.HandleFunc("GET /export", requireSession(handleExport))
	mux.HandleFunc("POST /email/change", requireSession(handleEmailChange))
	mux.HandleFunc("GET /email/confirm", handleEmailConfirm)
	mux.HandleFunc("POST /deactivate", requireSession(handleDeactivate))
	mux.HandleFunc("POST /delete", requireSession(handleDelete))
	mux.HandleFunc("POST /admin/purge", handlePurge)
	mux.HandleFunc("GET /audit", requireSession(handleAudit))
	// Federation / linking
	mux.HandleFunc("GET /fake-idp/authorize", handleFakeIdP)
	mux.HandleFunc("POST /login/google", handleFederatedLogin)
	mux.HandleFunc("POST /identities/link", requireSession(handleExplicitLink))
	mux.HandleFunc("GET /identities", requireSession(handleListIdentities))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("lifecycle lab listening on %s (LINK_MODE=%s)", addr, linkMode)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---- sessions (in-memory; Module 0/3 covered doing this properly) ----------

var (
	sessMu sync.Mutex
	sess   = map[string]string{} // sid -> user id
)

func newSession(w http.ResponseWriter, userID string) {
	sid := randToken()
	sessMu.Lock()
	sess[sid] = userID
	sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// revokeSessions kills every session for a user — deactivation and deletion
// must take effect immediately, not at next cookie expiry.
func revokeSessions(userID string) {
	sessMu.Lock()
	defer sessMu.Unlock()
	for sid, uid := range sess {
		if uid == userID {
			delete(sess, sid)
		}
	}
}

func requireSession(next func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil {
			jsonErr(w, 401, "no session")
			return
		}
		sessMu.Lock()
		uid, ok := sess[c.Value]
		sessMu.Unlock()
		if !ok {
			jsonErr(w, 401, "invalid session")
			return
		}
		next(w, r, uid)
	}
}

// ---- small helpers ---------------------------------------------------------

func randToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	key := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key)
}

func verifyPassword(stored, pw string) bool {
	var salt, key []byte
	for i := 0; i < len(stored); i++ {
		if stored[i] == '$' {
			salt, _ = base64.RawStdEncoding.DecodeString(stored[:i])
			key, _ = base64.RawStdEncoding.DecodeString(stored[i+1:])
			break
		}
	}
	if salt == nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 2, 32)
	return hmac.Equal(got, key)
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func audit(ctx context.Context, userID, action, detail string) {
	_, err := db.Exec(ctx,
		`INSERT INTO audit_log (user_id, action, detail) VALUES ($1, $2, $3)`,
		userID, action, detail)
	if err != nil {
		log.Printf("audit: %v", err)
	}
}
