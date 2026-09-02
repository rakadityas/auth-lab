package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// passkeyUser implements webauthn.User. In a real system this is your users
// table joined to a credentials table; the library only needs these four things.
type passkeyUser struct {
	id          []byte
	name        string
	credentials []webauthn.Credential
}

func (u *passkeyUser) WebAuthnID() []byte                         { return u.id }
func (u *passkeyUser) WebAuthnName() string                       { return u.name }
func (u *passkeyUser) WebAuthnDisplayName() string                { return u.name }
func (u *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

type userStore struct {
	mu sync.Mutex
	m  map[string]*passkeyUser
}

func newUserStore() *userStore { return &userStore{m: map[string]*passkeyUser{}} }

func (s *userStore) getOrCreate(name string) *passkeyUser {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.m[name]; ok {
		return u
	}
	// The user handle: a random, stable, NON-PII id for this account. The spec
	// says never derive it from an email/username — it can end up stored on the
	// authenticator and synced across a user's devices.
	id := make([]byte, 16)
	rand.Read(id)
	u := &passkeyUser{id: id, name: name}
	s.m[name] = u
	return u
}

func (s *userStore) get(name string) (*passkeyUser, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.m[name]
	return u, ok
}

func (s *userStore) addCredential(name string, c *webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.m[name]; ok {
		u.credentials = append(u.credentials, *c)
	}
}

// updateCredential persists the post-login state of a credential — critically
// the signature counter, which is the clone-detection signal (see README).
func (s *userStore) updateCredential(name string, c *webauthn.Credential) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.m[name]
	if !ok {
		return
	}
	for i := range u.credentials {
		if string(u.credentials[i].ID) == string(c.ID) {
			u.credentials[i] = *c
			return
		}
	}
}

func randID() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
