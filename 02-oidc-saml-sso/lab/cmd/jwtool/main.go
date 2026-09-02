// jwtool — decode, verify, and forge JWTs so you can watch a verifier reject them.
//
//	jwtool decode        <token>          show header + payload, no verification
//	jwtool verify        <token>          full verification against the issuer's JWKS
//	jwtool jwks                           print the issuer's public keys
//	jwtool forge-none    <token>          ATTACK: alg:none, signature stripped
//	jwtool forge-hs256   <token>          ATTACK: RS256->HS256 confusion
//	jwtool tamper        <token>          ATTACK: flip a payload claim, keep the old signature
//
// Global flags (before the subcommand):
//
//	--issuer URL   expected issuer, also used for discovery/JWKS (default env ISSUER)
//	--aud AUD      expected audience for `verify`
//	--jwks URL     override the JWKS URL (default: discovered from --issuer)
//
// Every "forge"/"tamper" command prints the forged token AND then runs it through
// the real verifier so you see the rejection. The attacks are here to prove the
// checks work, not to be useful against anything.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"authlab/oidclab/internal/oidc"
)

func main() {
	issuer := flag.String("issuer", os.Getenv("ISSUER"), "expected issuer (discovery + JWKS)")
	aud := flag.String("aud", "", "expected audience (for verify)")
	jwks := flag.String("jwks", "", "JWKS URL override")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		usage()
	}
	cmd := args[0]

	switch cmd {
	case "decode":
		decode(arg(args, 1))
	case "verify":
		verify(arg(args, 1), *issuer, *aud, *jwks)
	case "jwks":
		showJWKS(*issuer, *jwks)
	case "forge-none":
		forgeNone(arg(args, 1), *issuer, *aud, *jwks)
	case "forge-hs256":
		forgeHS256(arg(args, 1), *issuer, *aud, *jwks)
	case "tamper":
		tamper(arg(args, 1), *issuer, *aud, *jwks)
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: jwtool [--issuer URL] [--aud AUD] [--jwks URL] <decode|verify|jwks|forge-none|forge-hs256|tamper> [token]")
	os.Exit(2)
}

func arg(a []string, i int) string {
	if i >= len(a) {
		fmt.Fprintln(os.Stderr, "this command needs a <token> argument")
		os.Exit(2)
	}
	return strings.TrimSpace(a[i])
}

func decode(raw string) {
	h, p, err := oidc.DecodeNoVerify(raw)
	if err != nil {
		fail("cannot decode: %v", err)
	}
	fmt.Println("header: ", mustJSON(h))
	fmt.Println("payload:", mustJSON(p))
	fmt.Println("\nThis is only base64 decoding. Anyone can read these claims and")
	fmt.Println("anyone can change them — nothing here proves the token is genuine.")
}

func keyset(issuer, jwks string) (*oidc.KeySet, error) {
	url := jwks
	if url == "" {
		if issuer == "" {
			return nil, fmt.Errorf("need --issuer or --jwks")
		}
		d, err := oidc.Discover(issuer)
		if err != nil {
			return nil, err
		}
		url = d.JwksURI
	}
	ks := oidc.NewKeySet(url)
	return ks, ks.Refresh()
}

func verify(raw, issuer, aud, jwks string) {
	ks, err := keyset(issuer, jwks)
	if err != nil {
		fail("jwks: %v", err)
	}
	opts := &oidc.VerifyOptions{Issuer: issuer, Audience: aud, AllowAlgs: []string{"RS256", "ES256"}}
	claims, _, err := oidc.Verify(raw, ks, opts)
	for _, s := range opts.Steps {
		fmt.Println("  ✓", s)
	}
	if err != nil {
		fmt.Println("  ✗ REJECTED:", err)
		os.Exit(1)
	}
	fmt.Printf("  ✓ ACCEPTED — sub=%s iss=%s aud=%v\n", claims.Sub, claims.Iss, claims.Aud)
}

func showJWKS(issuer, jwks string) {
	url := jwks
	if url == "" {
		d, err := oidc.Discover(issuer)
		if err != nil {
			fail("discovery: %v", err)
		}
		url = d.JwksURI
		fmt.Println("jwks_uri:", url)
	}
	// Fetch raw so the user sees the actual document.
	ks, err := keyset(issuer, jwks)
	if err != nil {
		fail("%v", err)
	}
	_ = ks
	fmt.Println("(keys loaded successfully; fetch", url, "in a browser to see the raw JSON)")
}

// runForged prints the forged token then feeds it to the real verifier.
func runForged(label, forged, issuer, aud, jwks string) {
	fmt.Printf("\n== %s ==\n", label)
	fmt.Println("forged token:", trunc(forged))
	ks, err := keyset(issuer, jwks)
	if err != nil {
		fmt.Println("(no issuer/jwks given, so cannot show the rejection live:", err, ")")
		return
	}
	opts := &oidc.VerifyOptions{Issuer: issuer, Audience: aud, AllowAlgs: []string{"RS256", "ES256"}}
	_, _, err = oidc.Verify(forged, ks, opts)
	if err != nil {
		fmt.Println("verifier says: ✗ REJECTED —", err)
		return
	}
	fmt.Println("verifier says: ✓ ACCEPTED  <-- THIS WOULD BE A VULNERABILITY")
}

func forgeNone(raw, issuer, aud, jwks string) {
	parts := split3(raw)
	forged := b64(`{"alg":"none","typ":"JWT"}`) + "." + parts[1] + "."
	fmt.Println("An unsigned token. A verifier that trusts the header's `alg`")
	fmt.Println("and skips signature checks for \"none\" would accept it.")
	runForged("ATTACK: alg:none", forged, issuer, aud, jwks)
}

func forgeHS256(raw, issuer, aud, jwks string) {
	parts := split3(raw)
	// The real attack uses the issuer's PUBLIC RSA key (from the JWKS) as the
	// HMAC secret. Here we use a placeholder; the point is that the ALLOWLIST
	// rejects HS256 before the secret ever matters.
	secret := []byte("the issuer's public key would go here")
	signing := b64(`{"alg":"HS256","typ":"JWT"}`) + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signing))
	forged := signing + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	fmt.Println("Header switched to HS256; signed with a symmetric key. If the")
	fmt.Println("verifier derives the algorithm from the token, an attacker signs")
	fmt.Println("with the issuer's published public key. The allowlist stops this.")
	runForged("ATTACK: RS256->HS256 confusion", forged, issuer, aud, jwks)
}

func tamper(raw, issuer, aud, jwks string) {
	parts := split3(raw)
	_, p, err := oidc.DecodeNoVerify(raw)
	if err != nil {
		fail("decode: %v", err)
	}
	p["sub"] = "admin"
	p["email"] = "attacker@evil.example"
	nb, _ := json.Marshal(p)
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(nb) + "." + parts[2]
	fmt.Println("Payload edited to sub=admin, but the ORIGINAL signature is reused.")
	fmt.Println("Because the signature covers header.payload, any edit invalidates it.")
	runForged("ATTACK: payload tampering with stale signature", forged, issuer, aud, jwks)
}

func split3(raw string) []string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		fail("need a 3-part JWT, got %d parts", len(parts))
	}
	return parts
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}
func trunc(s string) string {
	if len(s) > 72 {
		return s[:72] + "…"
	}
	return s
}
func fail(f string, a ...any) {
	fmt.Fprintf(os.Stderr, f+"\n", a...)
	os.Exit(1)
}
