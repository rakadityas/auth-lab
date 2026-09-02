package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// --- JWTs, signed through the KMS -------------------------------------------

// handleIssueToken builds a JWT and signs it via the KMS. The header carries the
// `kid` of the signing key so any verifier knows which JWKS key to use — this is
// the single field that makes rotation survivable.
func handleIssueToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Sub string `json:"sub"`
	}
	readJSON(r, &in)
	if in.Sub == "" {
		in.Sub = "demo-user"
	}

	// We don't know the kid until we sign, so sign the header+payload with a
	// placeholder-free approach: build payload, then header per current kid.
	_, kid, _ := k.sign([]byte("probe")) // cheap way to read current kid
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid}
	payload := map[string]any{"sub": in.Sub, "iat": time.Now().Unix(),
		"exp": time.Now().Add(15 * time.Minute).Unix()}

	signingInput := b64json(header) + "." + b64json(payload)
	sig, usedKid, err := k.sign([]byte(signingInput))
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": err.Error()})
		return
	}
	// If a rotation happened between the probe and the real sign, the header kid
	// could disagree; re-stamp to be safe.
	if usedKid != kid {
		header["kid"] = usedKid
		signingInput = b64json(header) + "." + b64json(payload)
		sig, _, _ = k.sign([]byte(signingInput))
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	jsonOut(w, 200, map[string]string{"token": token, "kid": usedKid})
}

// handleVerifyToken verifies a JWT: split it, read the kid from the header, and
// ask the KMS to verify with that kid's public key. Crucially this works for
// tokens signed by a now-RETIRED key, which is what makes rotation zero-downtime.
func handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	readJSON(r, &in)
	parts := strings.Split(in.Token, ".")
	if len(parts) != 3 {
		jsonOut(w, 400, map[string]string{"error": "malformed token"})
		return
	}
	hdrBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	json.Unmarshal(hdrBytes, &hdr)

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		jsonOut(w, 400, map[string]string{"error": "bad signature encoding"})
		return
	}
	signingInput := parts[0] + "." + parts[1]
	if err := k.verify([]byte(signingInput), sig, hdr.Kid); err != nil {
		jsonOut(w, 401, map[string]any{"valid": false, "kid": hdr.Kid, "error": err.Error()})
		return
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	json.Unmarshal(payload, &claims)
	jsonOut(w, 200, map[string]any{"valid": true, "kid": hdr.Kid, "claims": claims})
}

func handleJWKS(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, k.jwks()) }
func handleKeys(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, k.keyInfo()) }

func handleRotateSigning(w http.ResponseWriter, r *http.Request) {
	newKid, retiredKid := k.rotateSigning()
	jsonOut(w, 200, map[string]string{
		"new_current": newKid, "retired": retiredKid,
		"note": "new tokens sign with " + newKid + "; tokens from " + retiredKid + " still verify (it's in JWKS)"})
}

func handleRemoveKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Kid string `json:"kid"`
	}
	readJSON(r, &in)
	if err := k.removeKey(in.Kid); err != nil {
		jsonOut(w, 400, map[string]string{"error": err.Error()})
		return
	}
	jsonOut(w, 200, map[string]string{"status": "removed " + in.Kid,
		"note": "only safe after every token it signed has expired"})
}

// --- PII envelope encryption ------------------------------------------------

func handlePIIEncrypt(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Plaintext string `json:"plaintext"`
	}
	readJSON(r, &in)
	rec, err := k.encrypt(in.Plaintext)
	if err != nil {
		jsonOut(w, 500, map[string]string{"error": err.Error()})
		return
	}
	jsonOut(w, 200, rec)
}

func handlePIIDecrypt(w http.ResponseWriter, r *http.Request) {
	var rec encryptedRecord
	if err := readJSON(r, &rec); err != nil {
		jsonOut(w, 400, map[string]string{"error": "send an encrypted record"})
		return
	}
	pt, err := k.decrypt(&rec)
	if err != nil {
		jsonOut(w, 400, map[string]string{"error": err.Error()})
		return
	}
	jsonOut(w, 200, map[string]string{"plaintext": pt})
}

func handlePIIRewrap(w http.ResponseWriter, r *http.Request) {
	var rec encryptedRecord
	if err := readJSON(r, &rec); err != nil {
		jsonOut(w, 400, map[string]string{"error": "send an encrypted record"})
		return
	}
	before := rec.KEKVersion
	if err := k.rewrap(&rec); err != nil {
		jsonOut(w, 400, map[string]string{"error": err.Error()})
		return
	}
	jsonOut(w, 200, map[string]any{"rewrapped": true, "from_kek": before, "to_kek": rec.KEKVersion,
		"note": "ciphertext byte-identical; only the tiny wrapped DEK changed", "record": rec})
}

func handleRotateKEK(w http.ResponseWriter, r *http.Request) {
	ver := k.rotateKEK()
	jsonOut(w, 200, map[string]string{"new_current_kek": ver,
		"note": "existing records still decrypt under their old KEK version until rewrapped"})
}

func handleKEKInfo(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, k.kekInfo()) }

// --- helpers ----------------------------------------------------------------

func b64json(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

var _ = mustJSON // kept for demo/debug symmetry
