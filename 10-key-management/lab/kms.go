package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"
	"time"
)

// alias so the intent (which hash the RS256 signature uses) reads clearly.
const cryptoSHA256 = crypto.SHA256

// A stand-in for a Key Management Service (AWS KMS / GCP KMS / HashiCorp Vault /
// an HSM). The ONE idea that makes it a KMS and not "a variable holding a key":
//
//     the application asks the KMS to SIGN; the private key never leaves the KMS.
//
// Everywhere below, callers get signatures and public keys — never private key
// bytes. In production that boundary is a network/hardware boundary; here it's
// this type's unexported fields. Modeling it this way is the whole lesson: your
// app server being compromised must not leak the signing key, because the app
// server never had it.

type signingKey struct {
	kid       string
	priv      *rsa.PrivateKey
	createdAt time.Time
	retired   bool // still valid for VERIFY, no longer used to SIGN
}

type kms struct {
	mu      sync.RWMutex
	keys    map[string]*signingKey // kid -> key
	current string                 // kid used for NEW signatures

	// The Key-Encryption-Key for envelope encryption (§ envelope.go). Also
	// "inside" the KMS — the app never sees it.
	kek        map[string][]byte // version -> 32-byte AES key
	currentKEK string
}

func newKMS() *kms {
	k := &kms{keys: map[string]*signingKey{}, kek: map[string][]byte{}}
	k.generateSigningKey() // first signing key
	k.rotateKEK()          // first KEK
	return k
}

// generateSigningKey creates a new keypair inside the KMS and makes it current.
func (k *kms) generateSigningKey() string {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "sig-" + randHex(4)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[kid] = &signingKey{kid: kid, priv: priv, createdAt: time.Now()}
	k.current = kid
	return kid
}

// sign returns an RS256 signature over data, tagged with the kid used, so a
// verifier knows WHICH public key to check (survives rotation). The private key
// is used here and nowhere else.
func (k *kms) sign(data []byte) (sig []byte, kid string, err error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	sk := k.keys[k.current]
	if sk == nil {
		return nil, "", errors.New("no current signing key")
	}
	h := sha256.Sum256(data)
	sig, err = rsa.SignPKCS1v15(rand.Reader, sk.priv, cryptoSHA256, h[:])
	return sig, sk.kid, err
}

// verify checks a signature against the PUBLIC key for the given kid. Works for
// current AND retired keys — that's what makes rotation zero-downtime: tokens
// signed by a since-rotated key keep verifying until that key is fully removed.
func (k *kms) verify(data, sig []byte, kid string) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	sk := k.keys[kid]
	if sk == nil {
		return errors.New("unknown kid " + kid + " (key removed or never existed)")
	}
	h := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(&sk.priv.PublicKey, cryptoSHA256, h[:], sig)
}

// --- rotation control -------------------------------------------------------

// rotateSigning introduces a NEW current key and RETIRES the old one (kept for
// verification). It does NOT remove the old key — removing it too early would
// reject still-valid tokens. That two-phase retire-then-remove is the crux.
func (k *kms) rotateSigning() (newKid, retiredKid string) {
	k.mu.Lock()
	retiredKid = k.current
	if old := k.keys[retiredKid]; old != nil {
		old.retired = true
	}
	k.mu.Unlock()
	newKid = k.generateSigningKey()
	return newKid, retiredKid
}

// removeKey fully deletes a retired key. Only safe once every token it signed
// has expired (i.e. after at least one max-token-lifetime past retirement).
func (k *kms) removeKey(kid string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if kid == k.current {
		return errors.New("refusing to remove the current signing key")
	}
	if _, ok := k.keys[kid]; !ok {
		return errors.New("no such kid")
	}
	delete(k.keys, kid)
	return nil
}

// --- JWKS (public key publication) ------------------------------------------
//
// The verifier side (any relying party) fetches these public keys by kid. During
// rotation the JWKS contains BOTH the new and the retired key, so RPs can verify
// tokens from either — no coordinated flag-day deploy required.

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k *kms) jwks() map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var keys []jwk
	for _, sk := range k.keys {
		pub := sk.priv.PublicKey
		keys = append(keys, jwk{
			Kty: "RSA", Use: "sig", Kid: sk.kid, Alg: "RS256",
			N: b64u(pub.N.Bytes()),
			E: b64u(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	return map[string]any{"keys": keys}
}

func (k *kms) keyInfo() []map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var out []map[string]any
	for _, sk := range k.keys {
		out = append(out, map[string]any{
			"kid": sk.kid, "current": sk.kid == k.current,
			"retired": sk.retired, "created_at": sk.createdAt,
		})
	}
	return out
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
