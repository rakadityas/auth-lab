package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// Envelope encryption — how you encrypt PII at rest at scale without ever
// touching the master key per record, and how you rotate that master key
// without re-encrypting terabytes of data.
//
// Two-level keys:
//   KEK (Key-Encryption-Key) — the master, lives in the KMS, one (versioned).
//   DEK (Data-Encryption-Key) — a fresh random key PER RECORD (or per batch).
//
// To store a secret:
//   1. generate a random DEK
//   2. encrypt the data with the DEK (fast, symmetric AES-GCM)
//   3. encrypt (WRAP) the DEK with the KEK, via the KMS
//   4. store {wrapped_dek, kek_version, ciphertext} together
//
// The plaintext DEK exists only transiently in memory; at rest you have a
// KEK-wrapped DEK next to the ciphertext. The app never sees the KEK.

// rotateKEK creates a new KEK version and makes it current. Old versions are
// KEPT so data wrapped under them can still be unwrapped — same retire-don't-
// delete discipline as signing keys.
func (k *kms) rotateKEK() string {
	key := make([]byte, 32)
	rand.Read(key)
	ver := "kek-" + randHex(3)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.kek[ver] = key
	k.currentKEK = ver
	return ver
}

// wrapDEK encrypts a DEK under the CURRENT KEK. Returns (wrapped, version).
func (k *kms) wrapDEK(dek []byte) (wrapped []byte, version string, err error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	ct, err := aesGCMSeal(k.kek[k.currentKEK], dek)
	return ct, k.currentKEK, err
}

// unwrapDEK decrypts a wrapped DEK under the KEK VERSION it was wrapped with —
// which is why the version travels with the data. This is what lets an old KEK
// keep working after rotation.
func (k *kms) unwrapDEK(wrapped []byte, version string) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.kek[version]
	if !ok {
		return nil, errors.New("unknown KEK version " + version)
	}
	return aesGCMOpen(key, wrapped)
}

// rewrapDEK re-encrypts an already-wrapped DEK under the current KEK WITHOUT
// touching the ciphertext. This is the magic of envelope encryption: rotating
// the master key means re-wrapping small DEKs, not re-encrypting the data.
func (k *kms) rewrapDEK(wrapped []byte, oldVersion string) (newWrapped []byte, newVersion string, err error) {
	dek, err := k.unwrapDEK(wrapped, oldVersion)
	if err != nil {
		return nil, "", err
	}
	return k.wrapDEK(dek)
}

// --- record-level API the app uses ------------------------------------------

// encryptedRecord is what you'd store in a column: everything needed to decrypt
// EXCEPT the KEK (which stays in the KMS).
type encryptedRecord struct {
	KEKVersion string `json:"kek_version"`
	WrappedDEK string `json:"wrapped_dek"` // DEK encrypted under the KEK
	Ciphertext string `json:"ciphertext"`  // data encrypted under the DEK
}

func (k *kms) encrypt(plaintext string) (*encryptedRecord, error) {
	dek := make([]byte, 32)
	rand.Read(dek)
	ct, err := aesGCMSeal(dek, []byte(plaintext))
	if err != nil {
		return nil, err
	}
	wrapped, ver, err := k.wrapDEK(dek)
	if err != nil {
		return nil, err
	}
	// dek goes out of scope here — the plaintext key does not persist.
	return &encryptedRecord{KEKVersion: ver, WrappedDEK: b64u(wrapped), Ciphertext: b64u(ct)}, nil
}

func (k *kms) decrypt(rec *encryptedRecord) (string, error) {
	wrapped, _ := base64.RawURLEncoding.DecodeString(rec.WrappedDEK)
	ct, _ := base64.RawURLEncoding.DecodeString(rec.Ciphertext)
	dek, err := k.unwrapDEK(wrapped, rec.KEKVersion)
	if err != nil {
		return "", err
	}
	pt, err := aesGCMOpen(dek, ct)
	return string(pt), err
}

// rewrap upgrades a record to the current KEK without re-encrypting its data.
func (k *kms) rewrap(rec *encryptedRecord) error {
	wrapped, _ := base64.RawURLEncoding.DecodeString(rec.WrappedDEK)
	newWrapped, newVer, err := k.rewrapDEK(wrapped, rec.KEKVersion)
	if err != nil {
		return err
	}
	rec.WrappedDEK = b64u(newWrapped)
	rec.KEKVersion = newVer
	return nil
}

// --- AES-GCM helpers (nonce prepended to ciphertext) ------------------------

func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesGCMOpen(key, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, body := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, nil)
}

// kekInfo lists KEK versions (values never exposed).
func (k *kms) kekInfo() map[string]any {
	k.mu.RLock()
	defer k.mu.RUnlock()
	var vers []string
	for v := range k.kek {
		vers = append(vers, v)
	}
	return map[string]any{"versions": vers, "current": k.currentKEK}
}

// small helper so envelope records marshal predictably in demos
func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return strings.TrimSpace(string(b))
}
