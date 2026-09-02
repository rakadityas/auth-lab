// Module 6 lab — passkeys / WebAuthn, hands-on with a real browser ceremony.
//
// Module 3 covered passkeys as *concept only*. This one runs the actual
// WebAuthn registration and authentication ceremonies: your browser creates a
// real credential (Touch ID / Windows Hello / a security key / the platform
// authenticator), and this server verifies the cryptographic assertion.
//
// Why this works on plain HTTP: WebAuthn requires a "secure context", and
// `http://localhost` is exempted from the HTTPS requirement precisely so you can
// develop against it. RP ID is therefore "localhost" and the origin is
// "http://localhost:8080".
//
// Storage is in-memory: the subject is the ceremony and what gets verified, not
// persistence (the earlier modules covered durable stores).
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	web   *webauthn.WebAuthn
	users = newUserStore()

	// In a browser flow the challenge/session data must survive between the
	// "begin" and "finish" calls. Keyed by a cookie here.
	sessMu   sync.Mutex
	sessions = map[string]*webauthn.SessionData{}
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var err error
	web, err = webauthn.New(&webauthn.Config{
		// The Relying Party — your service's identity to the authenticator.
		RPDisplayName: "Auth Lab",
		// RPID scopes the credential. It MUST be a registrable-domain suffix of
		// the origin. A credential made for "localhost" will not be offered to
		// any other RP ID — this binding is what stops phishing (see README).
		RPID: env("RP_ID", "localhost"),
		// The exact origin(s) the browser will report. Checked byte-for-byte.
		RPOrigins: []string{env("RP_ORIGIN", "http://localhost:8080")},
	})
	if err != nil {
		log.Fatalf("webauthn config: %v", err)
	}

	mux := http.NewServeMux()
	// The two ceremonies, each a begin/finish pair.
	mux.HandleFunc("POST /register/begin", handleRegisterBegin)
	mux.HandleFunc("POST /register/finish", handleRegisterFinish)
	mux.HandleFunc("POST /login/begin", handleLoginBegin)
	mux.HandleFunc("POST /login/finish", handleLoginFinish)
	mux.HandleFunc("GET /whoami", handleWhoami)
	mux.HandleFunc("POST /logout", handleLogout)

	// The page that actually calls navigator.credentials.*
	mux.Handle("GET /", http.FileServer(http.Dir("static")))

	addr := ":" + env("PORT", "8080")
	log.Printf("passkey lab on http://localhost%s (RPID=%s)", addr, web.Config.RPID)
	log.Fatal(http.ListenAndServe(addr, mux))
}

// ---- session-data stash (challenge state between begin/finish) -------------

func stash(w http.ResponseWriter, name string, sd *webauthn.SessionData) {
	sid := randID()
	sessMu.Lock()
	sessions[name+":"+sid] = sd
	sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "ceremony", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func unstash(r *http.Request, name string) (*webauthn.SessionData, bool) {
	c, err := r.Cookie("ceremony")
	if err != nil {
		return nil, false
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	sd, ok := sessions[name+":"+c.Value]
	delete(sessions, name+":"+c.Value) // challenges are single-use
	return sd, ok
}

// ---- authenticated "who am I" session (post-login) -------------------------

var (
	loginMu   sync.Mutex
	loginSess = map[string]string{} // sid -> username
)

func setLogin(w http.ResponseWriter, username string) {
	sid := randID()
	loginMu.Lock()
	loginSess[sid] = username
	loginMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "auth", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func handleWhoami(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("auth")
	if err != nil {
		jsonOut(w, 200, map[string]any{"authenticated": false})
		return
	}
	loginMu.Lock()
	u, ok := loginSess[c.Value]
	loginMu.Unlock()
	jsonOut(w, 200, map[string]any{"authenticated": ok, "user": u})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("auth"); err == nil {
		loginMu.Lock()
		delete(loginSess, c.Value)
		loginMu.Unlock()
	}
	jsonOut(w, 200, map[string]any{"status": "logged out"})
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	jsonOut(w, code, map[string]string{"error": msg})
}
