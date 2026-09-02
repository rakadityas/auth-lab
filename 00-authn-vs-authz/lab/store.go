package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type User struct {
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	ID        string    `json:"-"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
}

type Store struct {
	rdb        *redis.Client
	sessionTTL time.Duration
}

var errNotFound = errors.New("not found")

func NewStore(addr string, ttl time.Duration) *Store {
	return &Store{
		rdb:        redis.NewClient(&redis.Options{Addr: addr}),
		sessionTTL: ttl,
	}
}

// normalizeEmail lowercases and trims. Real systems must decide a policy for
// gmail-style dot/plus aliases and for Unicode; being inconsistent between
// signup and login is a classic account-takeover bug.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func userKey(email string) string    { return "user:" + normalizeEmail(email) }
func sessionKey(id string) string    { return "sess:" + id }
func userSessionsKey(e string) string { return "user_sessions:" + normalizeEmail(e) }

func (s *Store) CreateUser(ctx context.Context, u User) (bool, error) {
	blob, err := json.Marshal(u)
	if err != nil {
		return false, err
	}
	// SETNX: only the first signup for an address wins, atomically.
	return s.rdb.SetNX(ctx, userKey(u.Email), blob, 0).Result()
}

func (s *Store) GetUser(ctx context.Context, email string) (User, error) {
	var u User
	blob, err := s.rdb.Get(ctx, userKey(email)).Bytes()
	if errors.Is(err, redis.Nil) {
		return u, errNotFound
	}
	if err != nil {
		return u, err
	}
	return u, json.Unmarshal(blob, &u)
}

func (s *Store) UpdatePasswordHash(ctx context.Context, email, hash string) error {
	u, err := s.GetUser(ctx, email)
	if err != nil {
		return err
	}
	u.PasswordHash = hash
	blob, err := json.Marshal(u)
	if err != nil {
		return err
	}
	return s.rdb.Set(ctx, userKey(email), blob, 0).Err()
}

func newSessionID() (string, error) {
	// 256 bits of CSPRNG entropy. Never derive a session ID from user data,
	// a counter, or a timestamp.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Store) CreateSession(ctx context.Context, sess Session) (string, error) {
	id, err := newSessionID()
	if err != nil {
		return "", err
	}
	blob, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	pipe := s.rdb.TxPipeline()
	pipe.Set(ctx, sessionKey(id), blob, s.sessionTTL)
	// A per-user index is what makes "log out all other devices" possible.
	pipe.SAdd(ctx, userSessionsKey(sess.Email), id)
	pipe.Expire(ctx, userSessionsKey(sess.Email), s.sessionTTL*2)
	_, err = pipe.Exec(ctx)
	return id, err
}

func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var sess Session
	blob, err := s.rdb.Get(ctx, sessionKey(id)).Bytes()
	if errors.Is(err, redis.Nil) {
		return sess, errNotFound
	}
	if err != nil {
		return sess, err
	}
	if err := json.Unmarshal(blob, &sess); err != nil {
		return sess, err
	}
	sess.ID = id
	// Sliding expiration: every authenticated request extends the session.
	// Pair it with an absolute lifetime in production or sessions live forever.
	s.rdb.Expire(ctx, sessionKey(id), s.sessionTTL)
	return sess, nil
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	sess, err := s.GetSession(ctx, id)
	if err == nil {
		s.rdb.SRem(ctx, userSessionsKey(sess.Email), id)
	}
	return s.rdb.Del(ctx, sessionKey(id)).Err()
}

func (s *Store) ListSessions(ctx context.Context, email string) ([]Session, error) {
	ids, err := s.rdb.SMembers(ctx, userSessionsKey(email)).Result()
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(ids))
	for _, id := range ids {
		sess, err := s.GetSession(ctx, id)
		if errors.Is(err, errNotFound) {
			// Expired naturally; clean the index lazily.
			s.rdb.SRem(ctx, userSessionsKey(email), id)
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, nil
}

// DeleteOtherSessions is the server side of "log out all other devices".
func (s *Store) DeleteOtherSessions(ctx context.Context, email, keepID string) (int, error) {
	ids, err := s.rdb.SMembers(ctx, userSessionsKey(email)).Result()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if id == keepID {
			continue
		}
		s.rdb.Del(ctx, sessionKey(id))
		s.rdb.SRem(ctx, userSessionsKey(email), id)
		n++
	}
	return n, nil
}

// Throttle is a fixed-window counter. Real deployments prefer a sliding window
// or token bucket, but the teaching point is the same: throttle, do not lock.
func (s *Store) Throttle(ctx context.Context, bucket string, limit int64, window time.Duration) (bool, error) {
	key := fmt.Sprintf("throttle:%s", bucket)
	n, err := s.rdb.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}
	if n == 1 {
		s.rdb.Expire(ctx, key, window)
	}
	return n <= limit, nil
}
