package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/redis/go-redis/v9"
)

// ---------------------------------------------------------------------------
// A magic link is the same primitive as an OTP with the entropy problem solved:
// instead of 6 digits a human must retype, the secret is 128+ bits carried in a
// URL. That removes the brute-force surface entirely — so there is no attempt cap
// here, and there does not need to be.
//
// What it does NOT remove:
//   - the channel is still email (inbox compromise = account compromise)
//   - links get forwarded, logged by scanners, and prefetched by clients
//   - the link may open in a DIFFERENT browser than the one that asked for it
// ---------------------------------------------------------------------------

const magicTTL = 10 * time.Minute

type MagicStore struct {
	rdb  *redis.Client
	safe bool
}

func NewMagicStore(rdb *redis.Client, safe bool) *MagicStore {
	return &MagicStore{rdb: rdb, safe: safe}
}

// Stored under the hash of the token: a leaked datastore then contains no usable
// links. Unlike a 6-digit OTP a plain SHA-256 is enough here — 128 bits of entropy
// is not enumerable, so no pepper is required.
func magicKey(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return "magic:" + hex.EncodeToString(sum[:])
}

type MagicLink struct {
	Token string
	// SameBrowser is a random value dropped in a cookie when the link is
	// requested and required back when it is consumed. It binds the click to the
	// device that asked, so a link forwarded to (or intercepted by) someone else
	// does not log them in.
	SameBrowser string
}

func (m *MagicStore) Issue(ctx context.Context, identifier string) (*MagicLink, error) {
	tok := randomToken(32)
	nonce := randomToken(16)
	err := m.rdb.HSet(ctx, magicKey(tok), map[string]any{
		"identifier": identifier,
		"nonce":      nonce,
	}).Err()
	if err != nil {
		return nil, err
	}
	m.rdb.Expire(ctx, magicKey(tok), magicTTL)
	return &MagicLink{Token: tok, SameBrowser: nonce}, nil
}

// Consume redeems a link exactly once.
//
// The DEL-and-check is the whole thing: Redis DEL returns how many keys it
// actually removed, so the goroutine that gets 1 is the single winner even if ten
// requests arrive at once (an email scanner prefetching the URL, then the human
// clicking it). Read-then-delete would let both through.
func (m *MagicStore) Consume(ctx context.Context, tok, browserNonce string) (string, error) {
	vals, err := m.rdb.HGetAll(ctx, magicKey(tok)).Result()
	if err != nil || len(vals) == 0 {
		return "", errNotFound
	}
	if m.safe {
		if browserNonce == "" || browserNonce != vals["nonce"] {
			return "", errBadCode // clicked from a different browser than requested it
		}
		if n, _ := m.rdb.Del(ctx, magicKey(tok)).Result(); n != 1 {
			return "", errNotFound // someone else redeemed it first
		}
	}
	return vals["identifier"], nil
}
