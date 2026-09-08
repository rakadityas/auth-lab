package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
)

// ---------------------------------------------------------------------------
// A delivered one-time passcode ("OTP") is NOT TOTP (Module 3). TOTP is a shared
// secret both sides compute from the clock; nothing is transmitted. A delivered
// OTP is a secret the SERVER invents and then SENDS over a channel it does not
// control (email, SMS). That difference is the whole security model:
//
//   - the code exists in someone's inbox / carrier network, so it must be short-lived
//   - the code space is tiny (10^6), so it must be guess-capped, not just hashed
//   - sending costs real money and can wake a real phone, so *sending* is an
//     abusable action in its own right (OTP bombing / SMS toll fraud)
//
// Every field below exists to hold one of those three lines down.
// ---------------------------------------------------------------------------

const (
	otpTTL        = 5 * time.Minute  // short: it lives in an inbox
	maxAttempts   = 5                // 5 tries out of 1,000,000 -> 0.0005% per request
	resendCooloff = 30 * time.Second // per request
	sendQuotaWin  = time.Hour
	sendQuotaID   = 5 // sends per identifier per hour
	sendQuotaIP   = 20
)

// codeDigits is 6 in the real world. The brute-force demo shrinks it (OTP_DIGITS=4)
// purely so the attack finishes while you watch — the arithmetic the demo prints
// is the one that matters at 6.
var codeDigits = envInt("OTP_DIGITS", 6)

var codeSpace = func() *big.Int {
	n := big.NewInt(10)
	return n.Exp(n, big.NewInt(int64(codeDigits)), nil)
}()

var (
	errNotFound  = errors.New("otp: no such request")
	errTooMany   = errors.New("otp: too many attempts")
	errBadCode   = errors.New("otp: wrong code")
	errThrottled = errors.New("otp: try again later")
	errQuota     = errors.New("otp: send quota exceeded")
)

type OTPStore struct {
	rdb    *redis.Client
	pepper []byte
	safe   bool
}

func NewOTPStore(rdb *redis.Client, pepper []byte, safe bool) *OTPStore {
	return &OTPStore{rdb: rdb, pepper: pepper, safe: safe}
}

func reqKey(id string) string    { return "otp:req:" + id }
func resendKey(id string) string { return "otp:resend:" + id }
func quotaKey(k string) string   { return "otp:quota:" + k }

// newCode draws a uniform 6-digit code from crypto/rand.
//
// Do NOT use math/rand here. A predictable PRNG turns a 10^6 guess into a 1-guess
// attack: seed recovery from a handful of observed codes is a published attack
// class against exactly this feature.
func newCode() string {
	n, err := rand.Int(rand.Reader, codeSpace)
	if err != nil {
		panic(err) // a failing CSPRNG must never degrade to a weaker source
	}
	return fmt.Sprintf("%0*d", codeDigits, n.Int64())
}

// digest is a KEYED hash (HMAC) of requestID||code under a server-side pepper.
//
// Two things people get wrong here:
//  1. "We hash the OTP like a password." A bare SHA-256 of a 6-digit code is
//     reversible by enumerating all 10^6 inputs — microseconds. Only a key the
//     attacker does not have (the pepper, held outside the datastore) makes the
//     stored value useless after a database leak.
//  2. Binding the requestID in means a code is only valid for the request that
//     produced it — you cannot take the code mailed for request A and spend it on
//     a concurrently-open request B for another identifier.
func (s *OTPStore) digest(requestID, code string) string {
	m := hmac.New(sha256.New, s.pepper)
	m.Write([]byte(requestID))
	m.Write([]byte{0})
	m.Write([]byte(code))
	return hex.EncodeToString(m.Sum(nil))
}

type Request struct {
	ID         string
	Identifier string // email address or phone number
	Channel    string // "email" | "sms"
	Code       string // returned only to the sender, never stored in the clear (safe mode)
	ExpiresIn  int
}

// Start creates a code, stores only its digest, and returns the plaintext once so
// the caller can hand it to the delivery channel.
func (s *OTPStore) Start(ctx context.Context, identifier, channel, ip string) (*Request, error) {
	if s.safe {
		// Quota is charged at SEND time, not at verify time. The expensive,
		// abusable action is delivery: it costs money (SMS) and it interrupts a
		// human who may not have asked for it.
		if err := s.charge(ctx, "id:"+identifier, sendQuotaID); err != nil {
			return nil, err
		}
		if err := s.charge(ctx, "ip:"+ip, sendQuotaIP); err != nil {
			return nil, err
		}
	}

	id := randomToken(16)
	code := newCode()

	stored := s.digest(id, code)
	if !s.safe {
		stored = code // UNSAFE: plaintext code in the datastore
	}

	err := s.rdb.HSet(ctx, reqKey(id), map[string]any{
		"identifier": identifier,
		"channel":    channel,
		"code":       stored,
		"attempts":   0,
	}).Err()
	if err != nil {
		return nil, err
	}
	s.rdb.Expire(ctx, reqKey(id), otpTTL)

	return &Request{ID: id, Identifier: identifier, Channel: channel, Code: code, ExpiresIn: int(otpTTL.Seconds())}, nil
}

// Resend re-issues a NEW code for an existing request and invalidates the old one.
//
// Design note that trips teams up: if "resend" leaves the previous code valid, a
// user who taps resend four times has four live codes, and you have multiplied the
// attacker's guessing surface by four. One live code per request, always.
func (s *OTPStore) Resend(ctx context.Context, id, ip string) (*Request, error) {
	vals, err := s.rdb.HGetAll(ctx, reqKey(id)).Result()
	if err != nil || len(vals) == 0 {
		return nil, errNotFound
	}
	if s.safe {
		// SET NX as the cooloff lock: the first resend wins, the rest bounce.
		ok, err := s.rdb.SetNX(ctx, resendKey(id), "1", resendCooloff).Result()
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, errThrottled
		}
		if err := s.charge(ctx, "id:"+vals["identifier"], sendQuotaID); err != nil {
			return nil, err
		}
		if err := s.charge(ctx, "ip:"+ip, sendQuotaIP); err != nil {
			return nil, err
		}
	}

	code := newCode()
	stored := s.digest(id, code)
	if !s.safe {
		stored = code
	}
	// Overwriting "code" is what kills the previous one. Attempts reset with it.
	s.rdb.HSet(ctx, reqKey(id), "code", stored, "attempts", 0)
	s.rdb.Expire(ctx, reqKey(id), otpTTL)

	return &Request{ID: id, Identifier: vals["identifier"], Channel: vals["channel"], Code: code, ExpiresIn: int(otpTTL.Seconds())}, nil
}

// Verify checks a submitted code and, on success, BURNS the request.
//
// Order matters: increment the attempt counter BEFORE comparing. If you compare
// first and only count failures after an early return, any panic, timeout, or
// `continue` on the error path silently gives the attacker a free guess.
func (s *OTPStore) Verify(ctx context.Context, id, code string) (identifier string, left int, err error) {
	vals, e := s.rdb.HGetAll(ctx, reqKey(id)).Result()
	if e != nil || len(vals) == 0 {
		return "", 0, errNotFound
	}

	if s.safe {
		n, e := s.rdb.HIncrBy(ctx, reqKey(id), "attempts", 1).Result()
		if e != nil {
			return "", 0, e
		}
		if n > maxAttempts {
			// Burn the whole request. Do not merely reject this attempt: an
			// attacker who can keep the request alive can keep guessing.
			s.rdb.Del(ctx, reqKey(id))
			return "", 0, errTooMany
		}
		left = maxAttempts - int(n)
	} else {
		left = -1 // UNSAFE: unlimited guesses
	}

	want := vals["code"]
	got := code
	if s.safe {
		got = s.digest(id, code)
	}
	// Constant-time: a byte-by-byte comparison that returns early leaks how many
	// leading digits were right. Over enough requests that turns 10^6 into 10*6.
	if !hmac.Equal([]byte(want), []byte(got)) {
		return "", left, errBadCode
	}

	// Single use. The code is spent the instant it works — a code lifted from a
	// forwarded email or a shoulder-surfed lock screen is already dead.
	if s.safe {
		s.rdb.Del(ctx, reqKey(id))
	}
	return vals["identifier"], left, nil
}

// charge is a fixed-window counter. Real systems use a sliding window or token
// bucket; the teaching point is only that *sending* is metered per identifier AND
// per source, because the two abuses differ: one attacker hammering many phones
// (toll fraud) vs many sources hammering one phone (OTP bombing).
func (s *OTPStore) charge(ctx context.Context, k string, limit int) error {
	n, err := s.rdb.Incr(ctx, quotaKey(k)).Result()
	if err != nil {
		return err
	}
	if n == 1 {
		s.rdb.Expire(ctx, quotaKey(k), sendQuotaWin)
	}
	if int(n) > limit {
		return errQuota
	}
	return nil
}
