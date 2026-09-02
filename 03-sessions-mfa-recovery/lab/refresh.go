package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Refresh token rotation with reuse detection.
//
// The model: refresh tokens form a CHAIN within a "family". Each refresh mints a
// new refresh token and invalidates the one just used. If a token that was
// already used (rotated away) is ever presented again, that means two parties
// hold the same token -- a theft -- so the ENTIRE family is revoked, logging out
// the legitimate user too. That is the correct, conservative response: better a
// forced re-login than a live account takeover.

type refreshRecord struct {
	Family    string    `json:"family"`     // shared across the whole chain
	User      string    `json:"user"`
	Prev      string    `json:"prev"`       // token id this one replaced
	CreatedAt time.Time `json:"created_at"`
	Used      bool      `json:"used"`       // has it been rotated away?
}

type RefreshStore struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewRefreshStore(rdb *redis.Client, ttl time.Duration) *RefreshStore {
	return &RefreshStore{rdb: rdb, ttl: ttl}
}

// A refresh token the client sees is "<id>.<secret>". We store only a HASH of the
// secret, so a Redis dump does not hand an attacker working tokens. The id lets us
// find the record in O(1) without scanning.
func newRefreshToken() (clientToken, id, secretHash string) {
	idb := make([]byte, 16)
	sb := make([]byte, 32)
	rand.Read(idb)
	rand.Read(sb)
	id = base64.RawURLEncoding.EncodeToString(idb)
	secret := base64.RawURLEncoding.EncodeToString(sb)
	sum := sha256.Sum256([]byte(secret))
	return id + "." + secret, id, hex.EncodeToString(sum[:])
}

func refreshKey(id string) string      { return "rt:" + id }
func familyKey(family string) string   { return "rtfam:" + family }

func (s *RefreshStore) Issue(ctx context.Context, user string) (string, error) {
	family := randID()
	return s.mint(ctx, user, family, "")
}

func (s *RefreshStore) mint(ctx context.Context, user, family, prev string) (string, error) {
	clientToken, id, secretHash := newRefreshToken()
	rec := refreshRecord{Family: family, User: user, Prev: prev, CreatedAt: time.Now().UTC()}
	blob, _ := json.Marshal(rec)
	pipe := s.rdb.TxPipeline()
	// Store the record keyed by id, with the secret hash in a companion field.
	pipe.HSet(ctx, refreshKey(id), "rec", blob, "secret", secretHash)
	pipe.Expire(ctx, refreshKey(id), s.ttl)
	pipe.SAdd(ctx, familyKey(family), id)
	pipe.Expire(ctx, familyKey(family), s.ttl*2)
	if _, err := pipe.Exec(ctx); err != nil {
		return "", err
	}
	return clientToken, nil
}

var (
	errRefreshInvalid = errors.New("refresh token invalid or expired")
	errRefreshReuse   = errors.New("refresh token reuse detected: family revoked")
)

// Rotate consumes a refresh token and returns a fresh one. This is the heart of
// the scheme; read every branch.
func (s *RefreshStore) Rotate(ctx context.Context, clientToken string) (newToken, user string, err error) {
	id, secret, ok := splitToken(clientToken)
	if !ok {
		return "", "", errRefreshInvalid
	}
	vals, err := s.rdb.HGetAll(ctx, refreshKey(id)).Result()
	if err != nil {
		return "", "", err
	}
	if len(vals) == 0 {
		return "", "", errRefreshInvalid
	}

	var rec refreshRecord
	if err := json.Unmarshal([]byte(vals["rec"]), &rec); err != nil {
		return "", "", errRefreshInvalid
	}
	// Constant-time-ish secret check via hash comparison.
	sum := sha256.Sum256([]byte(secret))
	if hex.EncodeToString(sum[:]) != vals["secret"] {
		return "", "", errRefreshInvalid
	}

	// THE reuse check. If this token was already rotated away, someone is
	// replaying an old token. Nuke the whole family.
	if rec.Used {
		s.revokeFamily(ctx, rec.Family)
		return "", "", errRefreshReuse
	}

	// Mark this token used, then mint its successor in the same family.
	rec.Used = true
	blob, _ := json.Marshal(rec)
	s.rdb.HSet(ctx, refreshKey(id), "rec", blob)

	newToken, err = s.mint(ctx, rec.User, rec.Family, id)
	if err != nil {
		return "", "", err
	}
	return newToken, rec.User, nil
}

func (s *RefreshStore) revokeFamily(ctx context.Context, family string) {
	ids, _ := s.rdb.SMembers(ctx, familyKey(family)).Result()
	pipe := s.rdb.TxPipeline()
	for _, id := range ids {
		pipe.Del(ctx, refreshKey(id))
	}
	pipe.Del(ctx, familyKey(family))
	pipe.Exec(ctx)
}

func (s *RefreshStore) RevokeAllForUser(ctx context.Context, user string) {
	// In this simple store we scan families lazily; a production system keeps a
	// user->families index. Left as an exercise (see README).
	_ = user
}

func splitToken(t string) (id, secret string, ok bool) {
	for i := 0; i < len(t); i++ {
		if t[i] == '.' {
			return t[:i], t[i+1:], true
		}
	}
	return "", "", false
}

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- the stateless side of the ADR: short-lived JWT + denylist ---

// This lab issues an OPAQUE access token backed by Redis for simplicity, but the
// README's ADR compares that against a short-TTL signed JWT plus a denylist. The
// denylist primitive below is what that design needs.

func denyKey(jti string) string { return "deny:" + jti }

func (s *RefreshStore) Denylist(ctx context.Context, jti string, until time.Time) error {
	ttl := time.Until(until)
	if ttl <= 0 {
		return nil
	}
	return s.rdb.Set(ctx, denyKey(jti), "1", ttl).Err()
}

func (s *RefreshStore) IsDenied(ctx context.Context, jti string) bool {
	n, _ := s.rdb.Exists(ctx, denyKey(jti)).Result()
	return n > 0
}

func mustJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

var _ = fmt.Sprintf
