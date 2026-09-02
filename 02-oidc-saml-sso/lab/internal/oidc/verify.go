// Package oidc implements JWT verification against a JWKS from scratch.
//
// You would use github.com/coreos/go-oidc or golang-jwt in production. This
// exists so that every check has a line number you can point at, because the
// famous JWT vulnerabilities are all *missing checks*, not broken crypto.
package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Discovery struct {
	Issuer                     string   `json:"issuer"`
	AuthorizationEndpoint      string   `json:"authorization_endpoint"`
	TokenEndpoint              string   `json:"token_endpoint"`
	UserinfoEndpoint           string   `json:"userinfo_endpoint"`
	JwksURI                    string   `json:"jwks_uri"`
	EndSessionEndpoint         string   `json:"end_session_endpoint"`
	IDTokenSigningAlgSupported []string `json:"id_token_signing_alg_values_supported"`
}

func Discover(issuer string) (*Discovery, error) {
	resp, err := http.Get(strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var d Discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, err
	}
	// The issuer in the document MUST equal the issuer you asked for.
	// Otherwise a hijacked discovery endpoint redefines who you trust.
	if strings.TrimRight(d.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return nil, fmt.Errorf("issuer mismatch: asked %q, document says %q", issuer, d.Issuer)
	}
	return &d, nil
}

// --- JWKS ---

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type KeySet struct {
	uri      string
	mu       sync.RWMutex
	keys     map[string]crypto.PublicKey
	fetched  time.Time
	minRetry time.Duration
}

func NewKeySet(jwksURI string) *KeySet {
	return &KeySet{uri: jwksURI, keys: map[string]crypto.PublicKey{}, minRetry: 5 * time.Minute}
}

func (ks *KeySet) Refresh() error {
	resp, err := http.Get(ks.uri)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	ks.mu.Lock()
	ks.keys, ks.fetched = keys, time.Now()
	ks.mu.Unlock()
	return nil
}

// Key looks up a signing key by `kid`. On a miss it refreshes once, rate-limited:
// that is how key ROTATION works. An IdP publishes the new key before it starts
// signing with it, and keeps the old one until every issued token has expired.
// A client that caches JWKS forever breaks at rotation; one that refetches on
// every request hands anyone a DoS amplifier against the IdP.
func (ks *KeySet) Key(kid string) (crypto.PublicKey, error) {
	ks.mu.RLock()
	k, ok := ks.keys[kid]
	stale := time.Since(ks.fetched) > ks.minRetry
	ks.mu.RUnlock()
	if ok {
		return k, nil
	}
	if !stale && !ks.fetched.IsZero() {
		return nil, fmt.Errorf("unknown kid %q (refresh rate-limited)", kid)
	}
	if err := ks.Refresh(); err != nil {
		return nil, err
	}
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	if k, ok := ks.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no key with kid %q in JWKS", kid)
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64uint(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		x, err := b64uint(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, err
		}
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported curve %s", k.Crv)
		}
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	}
	return nil, fmt.Errorf("unsupported kty %s", k.Kty)
}

func b64uint(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// --- token verification ---

type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type Claims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      Audience `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	Nbf      int64    `json:"nbf"`
	Nonce    string   `json:"nonce"`
	Azp      string   `json:"azp"`
	AuthTime int64    `json:"auth_time"`
	Acr      string   `json:"acr"`
	Amr      []string `json:"amr"`
	Sid      string   `json:"sid"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	Typ      string   `json:"typ"`
	Raw      map[string]any
}

// Audience handles the spec's annoyance: `aud` is either a string or an array.
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = []string{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

func (a Audience) Contains(s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

type VerifyOptions struct {
	Issuer    string
	Audience  string
	Nonce     string        // required for ID tokens obtained via the auth code flow
	MaxAge    time.Duration // if set, auth_time must be within this window
	Leeway    time.Duration // clock skew allowance; keep it small (<= 60s)
	AllowAlgs []string      // allowlist. NEVER derive the algorithm from the token
	Steps     []string      // populated with a human-readable trace of each check
}

// Verify performs every check the specs require, in order, recording each one.
// Read the failure paths: each corresponds to a documented attack.
func Verify(raw string, ks *KeySet, o *VerifyOptions) (*Claims, *Header, error) {
	step := func(f string, a ...any) { o.Steps = append(o.Steps, fmt.Sprintf(f, a...)) }

	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a JWS compact serialization (want 3 dot-separated parts, got %d)", len(parts))
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("bad header encoding: %w", err)
	}
	var h Header
	if err := json.Unmarshal(hb, &h); err != nil {
		return nil, nil, fmt.Errorf("bad header JSON: %w", err)
	}
	step("header alg=%s kid=%s typ=%s", h.Alg, h.Kid, h.Typ)

	// ATTACK 1: alg:none. A token with no signature at all. Reject before
	// touching anything else.
	if strings.EqualFold(h.Alg, "none") {
		return nil, &h, fmt.Errorf(`rejected alg "none": an unsigned token is an unauthenticated token`)
	}
	// ATTACK 2: algorithm confusion (RS256 -> HS256). If you look up the key by
	// the token's own `alg`, an attacker flips it to HS256 and signs with your
	// PUBLIC key -- which is public. The allowlist, not the token, decides.
	if len(o.AllowAlgs) == 0 {
		o.AllowAlgs = []string{"RS256", "ES256"}
	}
	allowed := false
	for _, a := range o.AllowAlgs {
		if a == h.Alg {
			allowed = true
		}
	}
	if !allowed {
		return nil, &h, fmt.Errorf("alg %q not in allowlist %v (algorithm-confusion defence)", h.Alg, o.AllowAlgs)
	}
	step("alg is in allowlist %v", o.AllowAlgs)

	pub, err := ks.Key(h.Kid)
	if err != nil {
		return nil, &h, fmt.Errorf("key lookup: %w", err)
	}
	step("found signing key kid=%s in JWKS", h.Kid)

	signed := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, &h, fmt.Errorf("bad signature encoding: %w", err)
	}
	digest := sha256.Sum256([]byte(signed))
	switch h.Alg {
	case "RS256":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, &h, fmt.Errorf("kid %s is not an RSA key", h.Kid)
		}
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
			return nil, &h, fmt.Errorf("signature invalid: %w", err)
		}
	case "ES256":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, &h, fmt.Errorf("kid %s is not an EC key", h.Kid)
		}
		if len(sig) != 64 {
			return nil, &h, fmt.Errorf("ES256 signature must be 64 bytes, got %d", len(sig))
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(ecPub, digest[:], r, s) {
			return nil, &h, fmt.Errorf("signature invalid")
		}
	}
	step("signature verified with the issuer's PUBLIC key")

	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, &h, fmt.Errorf("bad payload encoding: %w", err)
	}
	var c Claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, &h, fmt.Errorf("bad payload JSON: %w", err)
	}
	json.Unmarshal(pb, &c.Raw)

	// ATTACK 3: missing issuer check. Any IdP whose key you happen to trust
	// could otherwise mint tokens for your app.
	if o.Issuer != "" && strings.TrimRight(c.Iss, "/") != strings.TrimRight(o.Issuer, "/") {
		return nil, &h, fmt.Errorf("iss %q != expected %q", c.Iss, o.Issuer)
	}
	step("iss == %s", c.Iss)

	// ATTACK 4: missing audience check -- the confused deputy. A token minted
	// for a different client of the SAME issuer would otherwise be accepted.
	if o.Audience != "" {
		if !c.Aud.Contains(o.Audience) {
			return nil, &h, fmt.Errorf("aud %v does not contain %q", c.Aud, o.Audience)
		}
		// When aud has multiple values, azp must identify the party in use.
		if len(c.Aud) > 1 && c.Azp != "" && c.Azp != o.Audience {
			return nil, &h, fmt.Errorf("multiple aud values and azp=%q is not us", c.Azp)
		}
	}
	step("aud contains %s", o.Audience)

	leeway := o.Leeway
	if leeway == 0 {
		leeway = 60 * time.Second // small, deliberate clock-skew allowance
	}
	now := time.Now()
	if c.Exp == 0 {
		return nil, &h, fmt.Errorf("no exp claim: a token without an expiry never expires")
	}
	if now.After(time.Unix(c.Exp, 0).Add(leeway)) {
		return nil, &h, fmt.Errorf("token expired at %s", time.Unix(c.Exp, 0).UTC())
	}
	if c.Nbf != 0 && now.Add(leeway).Before(time.Unix(c.Nbf, 0)) {
		return nil, &h, fmt.Errorf("token not valid before %s", time.Unix(c.Nbf, 0).UTC())
	}
	if c.Iat != 0 && now.Add(leeway).Before(time.Unix(c.Iat, 0)) {
		return nil, &h, fmt.Errorf("token issued in the future (%s) -- check clock sync", time.Unix(c.Iat, 0).UTC())
	}
	step("exp/nbf/iat within %s leeway (expires in %s)", leeway, time.Until(time.Unix(c.Exp, 0)).Round(time.Second))

	// ATTACK 5: replay. The nonce ties this ID token to the authorization
	// request THIS browser started.
	if o.Nonce != "" {
		if c.Nonce == "" {
			return nil, &h, fmt.Errorf("nonce expected but absent from the token")
		}
		if c.Nonce != o.Nonce {
			return nil, &h, fmt.Errorf("nonce mismatch: possible replay")
		}
		step("nonce matches the one this browser sent")
	}

	// Step-up / freshness: max_age means "the user must have authenticated
	// within this window", checked against auth_time.
	if o.MaxAge > 0 {
		if c.AuthTime == 0 {
			return nil, &h, fmt.Errorf("max_age requested but auth_time absent")
		}
		if age := now.Sub(time.Unix(c.AuthTime, 0)); age > o.MaxAge+leeway {
			return nil, &h, fmt.Errorf("authentication is %s old, older than max_age %s -- re-authenticate", age.Round(time.Second), o.MaxAge)
		}
		step("auth_time within max_age %s", o.MaxAge)
	}

	return &c, &h, nil
}

// DecodeNoVerify is for display only. Never make a trust decision on its output.
func DecodeNoVerify(raw string) (header, payload map[string]any, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return nil, nil, fmt.Errorf("not a JWT")
	}
	dec := func(s string) (map[string]any, error) {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		return m, json.Unmarshal(b, &m)
	}
	if header, err = dec(parts[0]); err != nil {
		return nil, nil, err
	}
	payload, err = dec(parts[1])
	return header, payload, err
}
