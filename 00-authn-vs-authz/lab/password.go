package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Three hashing strategies live side by side so you can compare them in the lab.
// Only argon2id and bcrypt are acceptable for real password storage.

type argon2Params struct {
	memoryKiB   uint32
	iterations  uint32
	parallelism uint8
	saltLen     uint32
	keyLen      uint32
}

// OWASP Password Storage Cheat Sheet baseline for Argon2id: 19 MiB, t=2, p=1.
var defaultArgon2 = argon2Params{
	memoryKiB:   19 * 1024,
	iterations:  2,
	parallelism: 1,
	saltLen:     16,
	keyLen:      32,
}

func hashArgon2id(password string) (string, error) {
	p := defaultArgon2
	salt := make([]byte, p.saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.iterations, p.memoryKiB, p.parallelism, p.keyLen)
	// PHC string format: everything a verifier needs travels with the hash,
	// so parameters can be raised later without breaking old hashes.
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memoryKiB, p.iterations, p.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func verifyArgon2id(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("not an argon2id PHC string")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, err
	}
	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(want)))
	// Constant-time compare: a byte-by-byte `==` leaks how many bytes matched.
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func hashBcrypt(password string) (string, error) {
	// cost 12 ~= 250ms on modern hardware. bcrypt silently truncates at 72 bytes.
	b, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(b), err
}

func verifyBcrypt(password, encoded string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(encoded), []byte(password))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return false, nil
	}
	return false, err
}

// DO NOT USE. Present only so the lab can show how fast it is to attack.
func hashSHA256Insecure(password string) string {
	sum := sha256.Sum256([]byte(password))
	return "$sha256$" + hex.EncodeToString(sum[:])
}

func hashPassword(alg, password string) (string, error) {
	switch alg {
	case "bcrypt":
		return hashBcrypt(password)
	case "sha256":
		return hashSHA256Insecure(password), nil
	default:
		return hashArgon2id(password)
	}
}

func verifyPassword(password, encoded string) (bool, error) {
	switch {
	case strings.HasPrefix(encoded, "$argon2id$"):
		return verifyArgon2id(password, encoded)
	case strings.HasPrefix(encoded, "$2"):
		return verifyBcrypt(password, encoded)
	case strings.HasPrefix(encoded, "$sha256$"):
		return subtle.ConstantTimeCompare([]byte(hashSHA256Insecure(password)), []byte(encoded)) == 1, nil
	default:
		return false, errors.New("unknown hash format")
	}
}

// needsRehash tells you a stored hash was made with weaker parameters than the
// ones you use today. Real systems call this on every successful login and
// transparently upgrade the stored hash while they still hold the plaintext.
func needsRehash(encoded string) bool {
	if !strings.HasPrefix(encoded, "$argon2id$") {
		return true
	}
	var memory, iterations uint32
	var parallelism uint8
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return true
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return true
	}
	return memory < defaultArgon2.memoryKiB || iterations < defaultArgon2.iterations
}
