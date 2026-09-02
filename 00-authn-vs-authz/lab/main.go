package main

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	sessionCookie = "sid"
	csrfCookie    = "csrf"
	// Every credential-taking endpoint spends at least this long, so an attacker
	// cannot tell "no such user" (fast) from "wrong password" (slow hash).
	minResponseTime = 350 * time.Millisecond
)

var (
	store       *Store
	hashAlg     = env("HASH_ALG", "argon2id")
	hibpEnabled = env("HIBP_ENABLED", "false") == "true"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	store = NewStore(env("REDIS_ADDR", "localhost:6379"), 30*time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /signup", handleSignup)
	mux.HandleFunc("POST /login", handleLogin)
	mux.HandleFunc("POST /logout", requireSession(handleLogout))
	mux.HandleFunc("GET /me", requireSession(handleMe))
	mux.HandleFunc("GET /sessions", requireSession(handleListSessions))
	mux.HandleFunc("POST /sessions/revoke-others", requireSession(handleRevokeOthers))
	mux.HandleFunc("POST /password-reset", handlePasswordReset)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("fundamentals lab listening on %s (hash=%s, hibp=%v)", addr, hashAlg, hibpEnabled)
	log.Fatal(http.ListenAndServe(addr, logging(mux)))
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}

// pad makes every call to a credential endpoint take the same wall-clock time.
// Without this, response *content* can be identical while response *timing*
// still enumerates your user base.
func pad(start time.Time) {
	if d := minResponseTime - time.Since(start); d > 0 {
		time.Sleep(d)
	}
}

func handleSignup(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer pad(start)

	var c credentials
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	c.Email = normalizeEmail(c.Email)

	// NIST SP 800-63B: length is the requirement. No composition rules,
	// no forced rotation. 8 chars minimum, 64+ must be accepted.
	if len([]rune(c.Password)) < 8 || len(c.Password) > 1024 || !strings.Contains(c.Email, "@") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "password must be at least 8 characters"})
		return
	}
	if hibpEnabled {
		pwned, err := isPwned(r.Context(), c.Password)
		if err != nil {
			log.Printf("hibp check failed (allowing signup): %v", err)
		} else if pwned {
			// A breached password is the one rejection that is safe to make
			// specific: it says nothing about whether the account exists.
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "this password appears in a known breach corpus, choose another"})
			return
		}
	}

	hash, err := hashPassword(hashAlg, c.Password)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	created, err := store.CreateUser(r.Context(), User{Email: c.Email, PasswordHash: hash, CreatedAt: time.Now().UTC()})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if !created {
		// The address is taken -- but saying so publishes your user list.
		// The real product sends "someone tried to sign up with your address"
		// to the existing owner by email instead.
		log.Printf("signup for existing account %s (response is deliberately identical)", c.Email)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "if this address can be registered, a confirmation email has been sent",
	})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer pad(start)

	var c credentials
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	c.Email = normalizeEmail(c.Email)
	ctx := r.Context()

	// Throttle on the account AND on the source IP. Throttling slows an
	// attacker; a hard lockout would let an attacker deny service to any user
	// they can name.
	okIP, _ := store.Throttle(ctx, "ip:"+clientIP(r), 30, time.Minute)
	okUser, _ := store.Throttle(ctx, "user:"+c.Email, 10, time.Minute)
	if !okIP || !okUser {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again shortly"})
		return
	}

	user, err := store.GetUser(ctx, c.Email)
	if err != nil {
		// Hash anyway against a dummy value so the CPU cost of a miss matches a
		// hit. `pad` covers this too, but defence in depth is free here.
		_, _ = hashPassword(hashAlg, c.Password)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
		return
	}
	ok, err := verifyPassword(c.Password, user.PasswordHash)
	if err != nil || !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
		return
	}

	// Opportunistic upgrade: parameters were raised since this hash was made.
	if needsRehash(user.PasswordHash) {
		if h, err := hashArgon2id(c.Password); err == nil {
			_ = store.UpdatePasswordHash(ctx, c.Email, h)
		}
	}

	// Session fixation defence: a brand new ID is minted at the moment
	// privilege changes. Never reuse a pre-login session identifier.
	sid, err := store.CreateSession(ctx, Session{
		Email:     user.Email,
		CreatedAt: time.Now().UTC(),
		IP:        clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	setSessionCookie(w, sid)
	csrf := setCSRFCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged in", "csrf_token": csrf})
}

func handleMe(w http.ResponseWriter, r *http.Request, sess Session) {
	writeJSON(w, http.StatusOK, map[string]any{
		"email":      sess.Email,
		"session_id": sess.ID[:8] + "...",
		"created_at": sess.CreatedAt,
		"ip":         sess.IP,
	})
}

func handleLogout(w http.ResponseWriter, r *http.Request, sess Session) {
	if !checkCSRF(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_failed"})
		return
	}
	// Server-side destruction is what makes this a real logout. Clearing the
	// cookie alone leaves a working session ID in the attacker's hands.
	_ = store.DeleteSession(r.Context(), sess.ID)
	clearCookie(w, sessionCookie)
	clearCookie(w, csrfCookie)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func handleListSessions(w http.ResponseWriter, r *http.Request, sess Session) {
	list, err := store.ListSessions(r.Context(), sess.Email)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		out = append(out, map[string]any{
			"session_id": s.ID[:8] + "...",
			"current":    s.ID == sess.ID,
			"ip":         s.IP,
			"user_agent": s.UserAgent,
			"created_at": s.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func handleRevokeOthers(w http.ResponseWriter, r *http.Request, sess Session) {
	if !checkCSRF(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_failed"})
		return
	}
	n, err := store.DeleteOtherSessions(r.Context(), sess.Email, sess.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

func handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer pad(start)

	var c credentials
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&c)
	if ok, _ := store.Throttle(r.Context(), "reset:"+normalizeEmail(c.Email), 3, time.Hour); !ok {
		// Even the throttle response must not differ between real and unknown
		// addresses, so return the same 202 body.
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "if that account exists, a reset link has been sent"})
		return
	}
	if _, err := store.GetUser(r.Context(), c.Email); err == nil {
		log.Printf("would send reset email to %s", c.Email)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "if that account exists, a reset link has been sent"})
}

// --- cookies, CSRF, session middleware ---

func setSessionCookie(w http.ResponseWriter, sid string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true, // JavaScript cannot read it -> XSS cannot exfiltrate it
		Secure:   env("COOKIE_SECURE", "false") == "true",
		SameSite: http.SameSiteLaxMode, // blocks cross-site POSTs, the CSRF baseline
		MaxAge:   int((30 * time.Minute).Seconds()),
	})
}

// setCSRFCookie implements the double-submit pattern: the token is readable by
// JS (HttpOnly false, on purpose) and must be echoed in a header. Same-origin
// policy stops a cross-site attacker reading it, so they cannot forge the header.
func setCSRFCookie(w http.ResponseWriter) string {
	b := make([]byte, 32)
	rand.Read(b)
	token := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   env("COOKIE_SECURE", "false") == "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * time.Minute).Seconds()),
	})
	return token
}

func checkCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookie)
	if err != nil {
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	return header != "" && subtle.ConstantTimeCompare([]byte(c.Value), []byte(header)) == 1
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
}

func requireSession(next func(http.ResponseWriter, *http.Request, Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no session"})
			return
		}
		sess, err := store.GetSession(r.Context(), c.Value)
		if err != nil {
			clearCookie(w, sessionCookie)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session expired or revoked"})
			return
		}
		next(w, r, sess)
	}
}

func clientIP(r *http.Request) string {
	// Behind a proxy you must trust a specific hop, not the raw header.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// isPwned queries HaveIBeenPwned's k-anonymity range API: only the first 5 hex
// characters of the SHA-1 leave this process, and the full hash is never sent.
func isPwned(ctx context.Context, password string) (bool, error) {
	sum := sha1.Sum([]byte(password))
	full := strings.ToUpper(fmt.Sprintf("%x", sum))
	prefix, suffix := full[:5], full[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.pwnedpasswords.com/range/"+prefix, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Add-Padding", "true")
	resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(body), "\n") {
		hashSuffix, count, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && hashSuffix == suffix && count != "0" {
			return true, nil
		}
	}
	return false, nil
}
