// Module 10 lab — key & secret management.
//
// Answers three questions every identity system must, and most get wrong at
// least once:
//  1. WHERE does the JWT signing key live?      -> a KMS boundary (kms.go)
//  2. How do you ROTATE it with zero downtime?  -> kid + JWKS + retire-then-remove
//  3. How do you encrypt PII at rest & rotate   -> envelope encryption (envelope.go)
//     the master key without re-encrypting all data?
//
// No external services: the "KMS" is an in-process type whose whole point is
// that the rest of the program only calls sign()/wrap() and never sees a private
// key. Swap it for AWS KMS / Vault and the call sites don't change.
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
)

var k *kms

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	k = newKMS()

	mux := http.NewServeMux()
	// JWTs signed via the KMS.
	mux.HandleFunc("POST /token", handleIssueToken)
	mux.HandleFunc("POST /verify", handleVerifyToken)
	mux.HandleFunc("GET /.well-known/jwks.json", handleJWKS)
	// Signing-key rotation controls.
	mux.HandleFunc("GET /keys", handleKeys)
	mux.HandleFunc("POST /keys/rotate", handleRotateSigning)
	mux.HandleFunc("POST /keys/remove", handleRemoveKey)
	// PII envelope encryption + KEK rotation.
	mux.HandleFunc("POST /pii/encrypt", handlePIIEncrypt)
	mux.HandleFunc("POST /pii/decrypt", handlePIIDecrypt)
	mux.HandleFunc("POST /pii/rewrap", handlePIIRewrap)
	mux.HandleFunc("POST /kek/rotate", handleRotateKEK)
	mux.HandleFunc("GET /kek", handleKEKInfo)

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	addr := ":" + env("PORT", "8080")
	log.Printf("key-management lab on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
