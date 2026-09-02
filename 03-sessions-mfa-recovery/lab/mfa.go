package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/redis/go-redis/v9"
)

// TOTP (RFC 6238): a shared secret plus the current 30-second time window run
// through HMAC-SHA1, truncated to 6 digits. The authenticator app and the server
// compute the same code independently -- nothing is transmitted per login except
// the 6 digits, so there is no code to intercept in transit that is not already
// expiring.

type MFAStore struct {
	rdb *redis.Client
}

func NewMFAStore(rdb *redis.Client) *MFAStore { return &MFAStore{rdb: rdb} }

func totpKey(user string) string   { return "totp:" + user }
func recoveryKey(u string) string  { return "recovery:" + u }
func replayKey(u, code string) string { return "totpseen:" + u + ":" + code }

// Enroll generates a secret and returns the otpauth:// URI the user scans as a QR
// code. The secret is stored PENDING and only activated once the user proves they
// can produce a valid code (so a failed enrollment cannot lock them out).
func (m *MFAStore) Enroll(ctx context.Context, user, issuer string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // SHA1 is what authenticator apps support
	})
	if err != nil {
		return nil, err
	}
	// Store pending, short TTL: enrollment must be completed promptly.
	if err := m.rdb.Set(ctx, totpKey(user)+":pending", key.Secret(), 10*time.Minute).Err(); err != nil {
		return nil, err
	}
	return key, nil
}

// Activate confirms enrollment: the user's first valid code proves the secret
// transferred correctly. Only then does TOTP become required for this account.
func (m *MFAStore) Activate(ctx context.Context, user, code string) (recovery []string, err error) {
	secret, err := m.rdb.Get(ctx, totpKey(user)+":pending").Result()
	if err == redis.Nil {
		return nil, fmt.Errorf("no pending enrollment")
	} else if err != nil {
		return nil, err
	}
	if !totp.Validate(code, secret) {
		return nil, fmt.Errorf("code did not validate; check the device clock")
	}
	pipe := m.rdb.TxPipeline()
	pipe.Set(ctx, totpKey(user), secret, 0)
	pipe.Del(ctx, totpKey(user)+":pending")
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	// Generate one-time recovery codes: the escape hatch when the device is lost.
	// Store only hashes; show the plaintext to the user exactly once.
	recovery, hashes := genRecoveryCodes(10)
	m.rdb.Del(ctx, recoveryKey(user))
	if len(hashes) > 0 {
		m.rdb.SAdd(ctx, recoveryKey(user), toAny(hashes)...)
	}
	return recovery, nil
}

func (m *MFAStore) Enabled(ctx context.Context, user string) bool {
	n, _ := m.rdb.Exists(ctx, totpKey(user)).Result()
	return n > 0
}

// Verify checks a TOTP code, with two production-critical details:
//   1. A validation WINDOW (accept the adjacent steps) tolerates clock drift.
//   2. Replay prevention: a 6-digit code is valid for ~30-90s, so a code sniffed
//      (phishing proxy, shoulder-surf) could be reused within that window. We
//      burn each accepted code for its remaining validity.
func (m *MFAStore) Verify(ctx context.Context, user, code string) (bool, error) {
	secret, err := m.rdb.Get(ctx, totpKey(user)).Result()
	if err == redis.Nil {
		return false, fmt.Errorf("mfa not enabled")
	} else if err != nil {
		return false, err
	}
	code = strings.TrimSpace(code)

	// Try recovery code first (a recovery code is longer and hyphenated).
	if strings.Contains(code, "-") {
		return m.consumeRecovery(ctx, user, code)
	}

	ok, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // accept the previous and next step: +/-30s of drift
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil || !ok {
		return false, nil
	}
	// Replay guard: this exact code cannot be used again for ~90s.
	set, _ := m.rdb.SetNX(ctx, replayKey(user, code), "1", 90*time.Second).Result()
	if !set {
		return false, fmt.Errorf("code already used (replay blocked)")
	}
	return true, nil
}

func (m *MFAStore) consumeRecovery(ctx context.Context, user, code string) (bool, error) {
	h := hashRecovery(code)
	// SREM returns 1 only if the member existed -> single use, atomic.
	n, err := m.rdb.SRem(ctx, recoveryKey(user), h).Result()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func genRecoveryCodes(n int) (plain []string, hashes []string) {
	for i := 0; i < n; i++ {
		c := randDigits(4) + "-" + randDigits(4) + "-" + randDigits(4)
		plain = append(plain, c)
		hashes = append(hashes, hashRecovery(c))
	}
	return
}

func hashRecovery(code string) string {
	// Recovery codes have high entropy, so a fast hash is acceptable here; using
	// SHA-256 keeps the dependency surface small. (Passwords are different --
	// see Module 0.)
	sum := sha256sum(code)
	return sum
}

func randDigits(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteString(d.String())
	}
	return b.String()
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

// constantTimeEq is used where we compare secrets we control on both sides.
func constantTimeEq(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

var _ = base64.RawURLEncoding
