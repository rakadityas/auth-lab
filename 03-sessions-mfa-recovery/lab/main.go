package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/argon2"
)

// A small account service that demonstrates, together:
//   - refresh token rotation with reuse detection      (refresh.go)
//   - TOTP MFA with recovery codes and replay guard     (mfa.go)
//   - a device/session inventory + "log out everywhere" (this file)
//   - opaque access tokens with introspection            (this file)
//
// The README's ADR compares this opaque+introspection design against a
// short-TTL-JWT+denylist design; the denylist primitive lives in refresh.go.

var (
	rdb     *redis.Client
	refresh *RefreshStore
	mfa     *MFAStore

	accessTTL  = 2 * time.Minute       // deliberately short so you can watch refresh
	refreshTTL = 24 * time.Hour
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	rdb = redis.NewClient(&redis.Options{Addr: env("REDIS_ADDR", "localhost:6379")})
	refresh = NewRefreshStore(rdb, refreshTTL)
	mfa = NewMFAStore(rdb)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /signup", handleSignup)
	mux.HandleFunc("POST /login", handleLogin)              // step 1: password
	mux.HandleFunc("POST /login/mfa", handleLoginMFA)       // step 2: TOTP if enabled
	mux.HandleFunc("POST /token/refresh", handleRefresh)    // rotate refresh -> new access
	mux.HandleFunc("POST /introspect", handleIntrospect)    // resource-server side
	mux.HandleFunc("GET /me", requireAccess(handleMe))
	mux.HandleFunc("POST /mfa/enroll", requireAccess(handleMFAEnroll))
	mux.HandleFunc("POST /mfa/activate", requireAccess(handleMFAActivate))
	mux.HandleFunc("GET /sessions", requireAccess(handleSessions))
	mux.HandleFunc("POST /sessions/logout-all", requireAccess(handleLogoutAll))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("sessions/mfa lab on %s (access TTL %s, refresh TTL %s)", addr, accessTTL, refreshTTL)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// --- users ---

type user struct {
	Email string `json:"email"`
	Hash  string `json:"hash"`
}

func userKey(email string) string { return "u:" + email }

func handleSignup(w http.ResponseWriter, r *http.Request) {
	var c struct{ Email, Password string }
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c)
	if len(c.Password) < 8 || c.Email == "" {
		writeJSON(w, 400, map[string]string{"error": "email and 8+ char password required"})
		return
	}
	salt := make([]byte, 16)
	sha := sha256.Sum256([]byte(c.Email)) // deterministic-ish salt for the demo only
	copy(salt, sha[:16])
	h := argon2.IDKey([]byte(c.Password), salt, 2, 19*1024, 1, 32)
	u := user{Email: c.Email, Hash: hex.EncodeToString(h)}
	blob, _ := json.Marshal(u)
	ok, _ := rdb.SetNX(r.Context(), userKey(c.Email), blob, 0).Result()
	if !ok {
		writeJSON(w, 202, map[string]string{"status": "ok"}) // no enumeration
		return
	}
	writeJSON(w, 202, map[string]string{"status": "ok"})
}

func checkPassword(ctx context.Context, email, password string) bool {
	blob, err := rdb.Get(ctx, userKey(email)).Bytes()
	if err != nil {
		return false
	}
	var u user
	json.Unmarshal(blob, &u)
	salt := make([]byte, 16)
	sha := sha256.Sum256([]byte(email))
	copy(salt, sha[:16])
	h := argon2.IDKey([]byte(password), salt, 2, 19*1024, 1, 32)
	return hex.EncodeToString(h) == u.Hash
}

// --- login: two steps when MFA is on ---

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var c struct{ Email, Password string }
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c)
	if !checkPassword(r.Context(), c.Email, c.Password) {
		writeJSON(w, 401, map[string]string{"error": "invalid email or password"})
		return
	}
	if mfa.Enabled(r.Context(), c.Email) {
		// Issue a short-lived, single-purpose MFA ticket. It is NOT an access
		// token: it can do nothing except complete the second factor. This keeps
		// the "password verified but not yet fully authenticated" state explicit.
		ticket := randID()
		rdb.Set(r.Context(), "mfaticket:"+ticket, c.Email, 5*time.Minute)
		writeJSON(w, 200, map[string]any{"mfa_required": true, "mfa_ticket": ticket})
		return
	}
	issueTokens(w, r, c.Email)
}

func handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	var c struct{ Ticket, Code string }
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c)
	email, err := rdb.Get(r.Context(), "mfaticket:"+c.Ticket).Result()
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid or expired mfa ticket"})
		return
	}
	ok, verr := mfa.Verify(r.Context(), email, c.Code)
	if verr != nil {
		writeJSON(w, 401, map[string]string{"error": verr.Error()})
		return
	}
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "invalid code"})
		return
	}
	rdb.Del(r.Context(), "mfaticket:"+c.Ticket) // single use
	issueTokens(w, r, email)
}

// --- token issuance, access-token store (opaque), session inventory ---

type accessRecord struct {
	User      string    `json:"user"`
	CreatedAt time.Time `json:"created_at"`
	IP        string    `json:"ip"`
	UA        string    `json:"ua"`
}

func accessKey(tok string) string        { return "at:" + hashTok(tok) }
func userSessKey(user string) string     { return "usess:" + user }

func hashTok(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func issueTokens(w http.ResponseWriter, r *http.Request, email string) {
	access := randID() + "." + randID()
	rec := accessRecord{User: email, CreatedAt: time.Now().UTC(), IP: clientIP(r), UA: r.UserAgent()}
	blob, _ := json.Marshal(rec)
	pipe := rdb.TxPipeline()
	pipe.Set(r.Context(), accessKey(access), blob, accessTTL)
	pipe.SAdd(r.Context(), userSessKey(email), hashTok(access))
	pipe.Expire(r.Context(), userSessKey(email), refreshTTL)
	pipe.Exec(r.Context())

	rt, err := refresh.Issue(r.Context(), email)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"access_token":  access,
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
	})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	var c struct {
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c)
	newRT, email, err := refresh.Rotate(r.Context(), c.RefreshToken)
	if errors.Is(err, errRefreshReuse) {
		// The scariest and most important response in the whole lab.
		writeJSON(w, 401, map[string]string{"error": "refresh token reuse detected; all sessions revoked; please log in again"})
		return
	}
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid refresh token"})
		return
	}
	access := randID() + "." + randID()
	rec := accessRecord{User: email, CreatedAt: time.Now().UTC(), IP: clientIP(r), UA: r.UserAgent()}
	blob, _ := json.Marshal(rec)
	rdb.Set(r.Context(), accessKey(access), blob, accessTTL)
	rdb.SAdd(r.Context(), userSessKey(email), hashTok(access))
	writeJSON(w, 200, map[string]any{
		"access_token":  access,
		"refresh_token": newRT, // NOTE: this differs from the one you sent -- rotation
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
	})
}

// handleIntrospect is the resource-server side of the opaque-token design
// (RFC 7662). A JWT design would verify a signature locally instead of calling
// this -- the trade-off the ADR is about.
func handleIntrospect(w http.ResponseWriter, r *http.Request) {
	var c struct {
		Token string `json:"token"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c)
	blob, err := rdb.Get(r.Context(), accessKey(c.Token)).Bytes()
	if err != nil {
		writeJSON(w, 200, map[string]any{"active": false})
		return
	}
	var rec accessRecord
	json.Unmarshal(blob, &rec)
	ttl, _ := rdb.TTL(r.Context(), accessKey(c.Token)).Result()
	writeJSON(w, 200, map[string]any{
		"active":     true,
		"sub":        rec.User,
		"expires_in": int(ttl.Seconds()),
	})
}

func handleMe(w http.ResponseWriter, r *http.Request, rec accessRecord) {
	writeJSON(w, 200, map[string]any{"email": rec.User, "mfa_enabled": mfa.Enabled(r.Context(), rec.User)})
}

// --- MFA endpoints ---

func handleMFAEnroll(w http.ResponseWriter, r *http.Request, rec accessRecord) {
	key, err := mfa.Enroll(r.Context(), rec.User, "AuthLab")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"otpauth_url": key.URL(),
		"secret":      key.Secret(),
		"note":        "add this to an authenticator app, then POST the current 6-digit code to /mfa/activate",
	})
}

func handleMFAActivate(w http.ResponseWriter, r *http.Request, rec accessRecord) {
	var c struct{ Code string }
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c)
	recovery, err := mfa.Activate(r.Context(), rec.User, c.Code)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"status":         "mfa enabled",
		"recovery_codes": recovery,
		"warning":        "these are shown ONCE; store them now",
	})
}

// --- session inventory ---

func handleSessions(w http.ResponseWriter, r *http.Request, rec accessRecord) {
	hashes, _ := rdb.SMembers(r.Context(), userSessKey(rec.User)).Result()
	out := []map[string]any{}
	for _, h := range hashes {
		blob, err := rdb.Get(r.Context(), "at:"+h).Bytes()
		if err != nil {
			rdb.SRem(r.Context(), userSessKey(rec.User), h) // clean expired
			continue
		}
		var s accessRecord
		json.Unmarshal(blob, &s)
		out = append(out, map[string]any{"ip": s.IP, "ua": s.UA, "created_at": s.CreatedAt})
	}
	writeJSON(w, 200, map[string]any{"active_access_tokens": out})
}

func handleLogoutAll(w http.ResponseWriter, r *http.Request, rec accessRecord) {
	hashes, _ := rdb.SMembers(r.Context(), userSessKey(rec.User)).Result()
	pipe := rdb.TxPipeline()
	for _, h := range hashes {
		pipe.Del(r.Context(), "at:"+h)
	}
	pipe.Del(r.Context(), userSessKey(rec.User))
	pipe.Exec(r.Context())
	// A complete implementation also revokes every refresh-token family for the
	// user; wired as an exercise (RefreshStore.RevokeAllForUser).
	refresh.RevokeAllForUser(r.Context(), rec.User)
	writeJSON(w, 200, map[string]any{"revoked_access_tokens": len(hashes)})
}

// --- middleware / helpers ---

func requireAccess(next func(http.ResponseWriter, *http.Request, accessRecord)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeJSON(w, 401, map[string]string{"error": "missing bearer token"})
			return
		}
		blob, err := rdb.Get(r.Context(), accessKey(tok)).Bytes()
		if err != nil {
			// This is the whole point of opaque + store: an expired or revoked
			// token fails IMMEDIATELY, with no revocation window.
			writeJSON(w, 401, map[string]string{"error": "invalid or expired access token"})
			return
		}
		var rec accessRecord
		json.Unmarshal(blob, &rec)
		next(w, r, rec)
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && h[:len(p)] == p {
		return h[len(p):]
	}
	return ""
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func sha256sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
