// A deliberately dependency-free OAuth 2.0 client.
//
// Every byte of the protocol is constructed by hand here. In production you
// would use a library (golang.org/x/oauth2, coreos/go-oidc) -- but you cannot
// debug a library you have never opened, and auth bugs are always in the
// details this file makes visible.
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
	"time"
)

var (
	issuer       = env("ISSUER", "http://localhost:8081/realms/authlab")
	clientID     = env("CLIENT_ID", "demo-web")
	redirectURI  = env("REDIRECT_URI", "http://localhost:9000/callback")
	scope        = env("SCOPE", "openid profile email roles")
	usePKCE      = env("USE_PKCE", "true") == "true"
	listenAddr   = ":" + env("PORT", "9000")
	lastTokenRes string
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// discovery is the .well-known/openid-configuration document. Never hardcode
// endpoint URLs: fetch them from the issuer's metadata (RFC 8414).
type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JwksURI               string   `json:"jwks_uri"`
	EndSessionEndpoint    string   `json:"end_session_endpoint"`
	GrantTypesSupported   []string `json:"grant_types_supported"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
}

var meta discovery

func loadDiscovery() error {
	resp, err := http.Get(strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(&meta)
}

func main() {
	// Keycloak takes a while to boot; retry discovery rather than crash-looping.
	for i := 0; i < 60; i++ {
		if err := loadDiscovery(); err == nil {
			break
		}
		log.Printf("waiting for issuer %s ...", issuer)
		time.Sleep(2 * time.Second)
	}
	if meta.TokenEndpoint == "" {
		log.Fatalf("could not reach issuer discovery document at %s", issuer)
	}
	log.Printf("discovered issuer=%s pkce_methods=%v", meta.Issuer, meta.CodeChallengeMethods)

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/refresh", handleRefresh)
	http.HandleFunc("/logout", handleLogout)

	log.Printf("oauth client on http://localhost%s (client_id=%s pkce=%v)", listenAddr, clientID, usePKCE)
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// s256 produces the PKCE code_challenge from the code_verifier (RFC 7636).
// challenge = BASE64URL(SHA256(ASCII(verifier))), no padding.
func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	page(w, "OAuth 2.0 lab client", fmt.Sprintf(`
<p>Client ID: <code>%s</code> &nbsp; PKCE: <code>%v</code></p>
<p>Issuer: <code>%s</code></p>
<p><a href="/login">Start Authorization Code%s flow</a> &nbsp;|&nbsp;
   <a href="/refresh">Refresh</a> &nbsp;|&nbsp; <a href="/logout">RP-initiated logout</a></p>
<h3>Discovered endpoints</h3>
<pre>authorization_endpoint: %s
token_endpoint:         %s
userinfo_endpoint:      %s
jwks_uri:               %s
end_session_endpoint:   %s
code_challenge_methods: %v</pre>
%s`,
		clientID, usePKCE, meta.Issuer,
		map[bool]string{true: " + PKCE", false: " (NO PKCE - insecure)"}[usePKCE],
		meta.AuthorizationEndpoint, meta.TokenEndpoint, meta.UserinfoEndpoint,
		meta.JwksURI, meta.EndSessionEndpoint, meta.CodeChallengeMethods,
		lastTokenRes))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// state: CSRF protection for the redirect. It ties the callback to THIS
	// browser's login attempt. Without it, an attacker can feed you their code.
	state := randomURLSafe(16)
	// nonce: OIDC replay protection. It is echoed inside the ID token and must
	// be checked there -- state lives in the URL, nonce lives in the token.
	nonce := randomURLSafe(16)

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("nonce", nonce)

	setTemp(w, "oauth_state", state)
	setTemp(w, "oauth_nonce", nonce)

	if usePKCE {
		// The verifier NEVER leaves the client. Only its SHA-256 hash goes out
		// in the authorization request, so an attacker who steals the code from
		// the redirect cannot redeem it.
		verifier := randomURLSafe(48)
		setTemp(w, "pkce_verifier", verifier)
		q.Set("code_challenge", s256(verifier))
		q.Set("code_challenge_method", "S256") // never "plain"
	}

	authURL := meta.AuthorizationEndpoint + "?" + q.Encode()
	log.Printf("STEP 1 -> browser redirected to authorization endpoint:\n%s", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if e := r.URL.Query().Get("error"); e != "" {
		page(w, "Authorization error", fmt.Sprintf("<pre>%s: %s</pre>",
			html.EscapeString(e), html.EscapeString(r.URL.Query().Get("error_description"))))
		return
	}
	code := r.URL.Query().Get("code")
	gotState := r.URL.Query().Get("state")
	wantState := getTemp(r, "oauth_state")

	log.Printf("STEP 2 <- authorization server redirected back with code=%s... state=%s", trunc(code), gotState)

	// Fixed-string comparison is fine for state (it is not a secret being
	// verified against a stored secret of the same lifetime), but bail loudly.
	if wantState == "" || gotState != wantState {
		page(w, "State mismatch", "<p><b>Rejected.</b> The <code>state</code> in the callback does not match the one this browser started with. This is exactly what state is for: it blocks CSRF on the redirect and code-injection from another user's flow.</p>")
		return
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI) // must match byte-for-byte
	form.Set("client_id", clientID)
	if usePKCE {
		form.Set("code_verifier", getTemp(r, "pkce_verifier"))
	}
	// A confidential client would authenticate here instead:
	//   form.Set("client_secret", secret)   // or private_key_jwt / mTLS

	log.Printf("STEP 3 -> POST %s\n  %s", meta.TokenEndpoint, redactForm(form))

	resp, err := http.PostForm(meta.TokenEndpoint, form)
	if err != nil {
		page(w, "Token request failed", "<pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	log.Printf("STEP 4 <- token endpoint responded %d", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		page(w, "Token error", "<pre>"+html.EscapeString(string(body))+"</pre>")
		return
	}

	var tok map[string]any
	json.Unmarshal(body, &tok)
	if rt, ok := tok["refresh_token"].(string); ok {
		setTemp(w, "refresh_token", rt)
	}
	lastTokenRes = renderTokens(tok)

	json, _ := json.MarshalIndent(tok, "", "  ")
	log.Printf("STEP 5 <- raw token endpoint response:\n%s", json)

	page(w, "Tokens", lastTokenRes+`<p><a href="/">back</a></p>`)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	rt := getTemp(r, "refresh_token")
	if rt == "" {
		page(w, "No refresh token", "<p>Log in first.</p>")
		return
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", rt)
	form.Set("client_id", clientID)

	resp, err := http.PostForm(meta.TokenEndpoint, form)
	if err != nil {
		page(w, "Refresh failed", "<pre>"+html.EscapeString(err.Error())+"</pre>")
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var tok map[string]any
	json.Unmarshal(body, &tok)
	// Note whether refresh_token in the response DIFFERS from the one you sent.
	// If it does, the server is doing refresh token rotation (Module 3).
	if nrt, ok := tok["refresh_token"].(string); ok {
		setTemp(w, "refresh_token", nrt)
	}
	page(w, "Refreshed", fmt.Sprintf("<p>Old refresh token: <code>%s</code></p>%s<p><a href=\"/\">back</a></p>",
		trunc(rt), renderTokens(tok)))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// RP-initiated logout (OIDC spec): send the user to the AS to end the SSO
	// session, not merely the local one.
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("post_logout_redirect_uri", "http://localhost:9000/")
	clearTemp(w, "refresh_token")
	http.Redirect(w, r, meta.EndSessionEndpoint+"?"+q.Encode(), http.StatusFound)
}

// --- rendering helpers ---

func renderTokens(tok map[string]any) string {
	var b strings.Builder
	b.WriteString("<h3>Token endpoint response</h3><pre>")
	pretty, _ := json.MarshalIndent(redactTokens(tok), "", "  ")
	b.WriteString(html.EscapeString(string(pretty)))
	b.WriteString("</pre>")
	for _, name := range []string{"access_token", "id_token"} {
		if raw, ok := tok[name].(string); ok {
			b.WriteString(fmt.Sprintf("<h3>%s (decoded, NOT verified)</h3><pre>%s</pre>",
				name, html.EscapeString(decodeJWT(raw))))
		}
	}
	b.WriteString(`<p><i>Decoded here without signature verification, purely to show
	that a JWT payload is base64 -- not encryption. Anyone holding the token reads
	the claims. Module 2 verifies signatures properly.</i></p>`)
	return b.String()
}

func redactTokens(tok map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range tok {
		if s, ok := v.(string); ok && strings.HasSuffix(k, "token") && len(s) > 40 {
			out[k] = s[:24] + "…(" + fmt.Sprint(len(s)) + " chars)"
			continue
		}
		out[k] = v
	}
	return out
}

func decodeJWT(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "(opaque token, not a JWT)"
	}
	var out strings.Builder
	for i, label := range []string{"header", "payload"} {
		seg, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return "(undecodable)"
		}
		var pretty any
		json.Unmarshal(seg, &pretty)
		p, _ := json.MarshalIndent(pretty, "", "  ")
		out.WriteString(label + ":\n" + string(p) + "\n\n")
	}
	out.WriteString("signature: " + trunc(parts[2]))
	return out.String()
}

func redactForm(f url.Values) string {
	c := url.Values{}
	for k, v := range f {
		if k == "code" || k == "code_verifier" || k == "refresh_token" {
			c.Set(k, trunc(v[0]))
			continue
		}
		c[k] = v
	}
	return c.Encode()
}

func trunc(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

func setTemp(w http.ResponseWriter, name, val string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: val, Path: "/", HttpOnly: true, MaxAge: 600, SameSite: http.SameSiteLaxMode})
}
func getTemp(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}
func clearTemp(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1})
}

func page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>%s</title>
<style>body{font:14px/1.5 ui-monospace,Menlo,monospace;max-width:900px;margin:40px auto;padding:0 16px}
pre{background:#f4f4f5;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
h1{font-size:20px}h3{font-size:15px;margin-top:24px}</style>
<h1>%s</h1>%s`, title, title, body)
}
