// An OpenID Connect Relying Party (RP).
//
// Run two copies (app-a on :9000, app-b on :9001) against one identity provider
// to see SSO and Back-Channel Logout for real.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"authlab/oidclab/internal/oidc"
)

var (
	appName      = env("APP_NAME", "app-a")
	issuer       = env("ISSUER", "http://localhost:8081/realms/authlab")
	clientID     = env("CLIENT_ID", "app-a")
	clientSecret = env("CLIENT_SECRET", "app-a-secret")
	baseURL      = env("BASE_URL", "http://localhost:9000")
	port         = env("PORT", "9000")

	meta   *oidc.Discovery
	keys   *oidc.KeySet
	client = &http.Client{Timeout: 10 * time.Second}
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// localSession is this RP's OWN session. SSO does not mean apps share a session:
// each RP keeps its own, and the IdP keeps a third one. Understanding that three
// sessions exist is the key to understanding why single logout is hard.
type localSession struct {
	Sub        string
	Email      string
	Name       string
	IDTokenSid string // `sid` claim: the IdP's session ID, our join key for logout
	AuthTime   time.Time
	LoginAt    time.Time
	Steps      []string
	RawIDToken string
	Claims     map[string]any
}

var (
	mu       sync.Mutex
	sessions = map[string]*localSession{}
	bySid    = map[string]string{} // IdP sid -> local session id
	logbook  []string
)

func note(f string, a ...any) {
	mu.Lock()
	defer mu.Unlock()
	line := time.Now().Format("15:04:05") + "  " + fmt.Sprintf(f, a...)
	logbook = append(logbook, line)
	if len(logbook) > 40 {
		logbook = logbook[len(logbook)-40:]
	}
	log.Print(line)
}

func main() {
	for i := 0; i < 60; i++ {
		var err error
		if meta, err = oidc.Discover(issuer); err == nil {
			break
		}
		log.Printf("waiting for issuer %s...", issuer)
		time.Sleep(2 * time.Second)
	}
	if meta == nil {
		log.Fatalf("cannot reach issuer %s", issuer)
	}
	keys = oidc.NewKeySet(meta.JwksURI)
	if err := keys.Refresh(); err != nil {
		log.Fatalf("jwks: %v", err)
	}

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/stepup", handleStepUp)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/backchannel-logout", handleBackchannelLogout)

	log.Printf("%s (client_id=%s) on %s", appName, clientID, baseURL)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	sess := current(r)
	var body strings.Builder
	fmt.Fprintf(&body, `<p><b>%s</b> — client_id <code>%s</code> — issuer <code>%s</code></p>`, appName, clientID, issuer)

	if sess == nil {
		body.WriteString(`<p class="out">Not logged in at this RP.</p>
<p><a class="btn" href="/login">Log in</a></p>
<p><i>Tip: if you are already logged in at the other app, this login will complete
without showing a password prompt. That is SSO: one session at the IdP, reused.</i></p>`)
	} else {
		fmt.Fprintf(&body, `<p class="in">Logged in as <b>%s</b> (%s)</p>
<pre>sub:        %s
sid:        %s   <i>(the IdP session — the join key for back-channel logout)</i>
auth_time:  %s   <i>(when the user actually authenticated, not when this RP session began)</i>
RP session: %s</pre>
<p><a class="btn" href="/stepup">Step-up re-authentication</a>
   <a class="btn" href="/logout">RP-initiated logout</a></p>
<h3>ID token verification trace</h3><pre>%s</pre>
<h3>ID token claims</h3><pre>%s</pre>`,
			html.EscapeString(sess.Name), html.EscapeString(sess.Email),
			sess.Sub, sess.IDTokenSid, sess.AuthTime.Format(time.RFC3339), sess.LoginAt.Format(time.RFC3339),
			html.EscapeString(strings.Join(sess.Steps, "\n")),
			html.EscapeString(jsonPretty(sess.Claims)))
	}

	mu.Lock()
	lb := strings.Join(logbook, "\n")
	mu.Unlock()
	fmt.Fprintf(&body, `<h3>Server log</h3><pre>%s</pre>`, html.EscapeString(lb))
	page(w, appName, body.String())
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier := randStr(48)
	state := randStr(16)
	nonce := randStr(16)
	setTemp(w, "pkce", verifier)
	setTemp(w, "state", state)
	setTemp(w, "nonce", nonce)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", baseURL+"/callback")
	// `openid` is what turns an OAuth request into an OIDC request. Without that
	// scope you get no ID token and you are doing authorization, not login.
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge(verifier))
	q.Set("code_challenge_method", "S256")

	for _, extra := range []string{"prompt", "max_age", "acr_values", "login_hint"} {
		if v := r.URL.Query().Get(extra); v != "" {
			q.Set(extra, v)
		}
	}
	note("login: redirecting to authorization endpoint (prompt=%q max_age=%q)", q.Get("prompt"), q.Get("max_age"))
	http.Redirect(w, r, meta.AuthorizationEndpoint+"?"+q.Encode(), http.StatusFound)
}

// handleStepUp forces a fresh authentication for a sensitive action.
// max_age=0 means "the user must authenticate again, right now", regardless of
// an existing SSO session. This is how you gate an email change or a payout.
func handleStepUp(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login?prompt=login&max_age=0", http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		page(w, "Error", "<pre>"+html.EscapeString(e+": "+r.URL.Query().Get("error_description"))+"</pre>")
		return
	}
	if r.URL.Query().Get("state") != getTemp(r, "state") {
		page(w, "State mismatch", "<p>Rejected: the callback state does not match this browser's login attempt.</p>")
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", r.URL.Query().Get("code"))
	form.Set("redirect_uri", baseURL+"/callback")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret) // confidential client
	form.Set("code_verifier", getTemp(r, "pkce"))

	resp, err := client.PostForm(meta.TokenEndpoint, form)
	if err != nil {
		page(w, "Token request failed", "<pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		page(w, "Token error", "<pre>"+html.EscapeString(string(raw))+"</pre>")
		return
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	json.Unmarshal(raw, &tok)
	if tok.IDToken == "" {
		page(w, "No ID token", "<p>The response had no <code>id_token</code>. Did you request the <code>openid</code> scope?</p>")
		return
	}

	opts := &oidc.VerifyOptions{
		Issuer:    issuer,
		Audience:  clientID,
		Nonce:     getTemp(r, "nonce"),
		AllowAlgs: []string{"RS256", "ES256"},
	}
	claims, _, err := oidc.Verify(tok.IDToken, keys, opts)
	if err != nil {
		note("ID TOKEN REJECTED: %v", err)
		page(w, "ID token rejected", "<pre>"+html.EscapeString(err.Error())+"</pre><pre>"+html.EscapeString(strings.Join(opts.Steps, "\n"))+"</pre>")
		return
	}

	sid := randStr(24)
	sess := &localSession{
		Sub: claims.Sub, Email: claims.Email, Name: claims.Name,
		IDTokenSid: claims.Sid,
		AuthTime:   time.Unix(claims.AuthTime, 0),
		LoginAt:    time.Now(),
		Steps:      opts.Steps,
		RawIDToken: tok.IDToken,
		Claims:     claims.Raw,
	}
	mu.Lock()
	sessions[sid] = sess
	if claims.Sid != "" {
		bySid[claims.Sid] = sid
	}
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "rp_session", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 3600})
	note("login OK sub=%s idp_sid=%s (RP session created)", claims.Sub, claims.Sid)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := current(r)
	dropLocal(r)
	http.SetCookie(w, &http.Cookie{Name: "rp_session", Value: "", Path: "/", MaxAge: -1})
	if sess == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// RP-Initiated Logout: hand the ID token back as a hint so the IdP knows
	// which session to end, and it will notify the OTHER RPs via back channel.
	q := url.Values{}
	q.Set("id_token_hint", sess.RawIDToken)
	q.Set("post_logout_redirect_uri", baseURL+"/")
	note("RP-initiated logout: sending user to the IdP end_session_endpoint")
	http.Redirect(w, r, meta.EndSessionEndpoint+"?"+q.Encode(), http.StatusFound)
}

// handleBackchannelLogout receives an OIDC Back-Channel Logout Token: a
// server-to-server POST from the IdP, no browser involved. This is what makes
// single logout actually work when apps live on different domains, because
// front-channel logout (hidden iframes) is broken by third-party cookie blocking.
func handleBackchannelLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	raw := r.PostFormValue("logout_token")
	if raw == "" {
		http.Error(w, "missing logout_token", http.StatusBadRequest)
		return
	}
	opts := &oidc.VerifyOptions{Issuer: issuer, Audience: clientID, AllowAlgs: []string{"RS256", "ES256"}}
	claims, _, err := oidc.Verify(raw, keys, opts)
	if err != nil {
		note("backchannel logout REJECTED: %v", err)
		http.Error(w, "invalid logout token", http.StatusBadRequest)
		return
	}
	// Spec requirements a naive implementation forgets:
	//   - the `events` claim must contain the backchannel-logout event
	//   - a logout token MUST NOT contain a `nonce`
	//   - it must carry `sid` and/or `sub`
	if _, ok := claims.Raw["events"]; !ok {
		http.Error(w, "no events claim", http.StatusBadRequest)
		return
	}
	if claims.Nonce != "" {
		http.Error(w, "logout token must not contain nonce", http.StatusBadRequest)
		return
	}

	mu.Lock()
	killed := 0
	if id, ok := bySid[claims.Sid]; ok {
		delete(sessions, id)
		delete(bySid, claims.Sid)
		killed++
	} else {
		for id, s := range sessions {
			if s.Sub == claims.Sub {
				delete(sessions, id)
				killed++
			}
		}
	}
	mu.Unlock()
	note("BACK-CHANNEL LOGOUT received from IdP (sid=%s sub=%s) -> destroyed %d local session(s)", claims.Sid, claims.Sub, killed)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

// --- helpers ---

func current(r *http.Request) *localSession {
	c, err := r.Cookie("rp_session")
	if err != nil {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	return sessions[c.Value]
}

func dropLocal(r *http.Request) {
	c, err := r.Cookie("rp_session")
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	if s, ok := sessions[c.Value]; ok {
		delete(bySid, s.IDTokenSid)
	}
	delete(sessions, c.Value)
}

func randStr(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func setTemp(w http.ResponseWriter, k, v string) {
	http.SetCookie(w, &http.Cookie{Name: "tmp_" + k, Value: v, Path: "/", HttpOnly: true, MaxAge: 600, SameSite: http.SameSiteLaxMode})
}
func getTemp(r *http.Request, k string) string {
	if c, err := r.Cookie("tmp_" + k); err == nil {
		return c.Value
	}
	return ""
}

func jsonPretty(m map[string]any) string {
	b, _ := json.MarshalIndent(m, "", "  ")
	return string(b)
}

func page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>
<style>body{font:14px/1.6 ui-monospace,Menlo,monospace;max-width:900px;margin:32px auto;padding:0 16px}
pre{background:#f4f4f5;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.btn{display:inline-block;background:#111;color:#fff;padding:6px 12px;border-radius:6px;text-decoration:none;margin-right:8px}
.in{color:#046c4e}.out{color:#9f1239}h1{font-size:20px}h3{font-size:14px;margin-top:22px}</style>
<h1>%s</h1><p><a href="http://localhost:9000/">app-a :9000</a> · <a href="http://localhost:9001/">app-b :9001</a></p>%s`,
		title, title, body)
}
