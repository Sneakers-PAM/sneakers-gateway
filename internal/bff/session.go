// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"sync"
	"time"
)

// Tokens is a backend credential and its lifetime in seconds: a Kratos
// session_token parked for the 2-step login, or a Polis access token.
type Tokens struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// Session is the server-side state behind an opaque session cookie: the
// Kratos session_token, the derived app actor, a CSRF token, and expiry.
// JSON-tagged so it round-trips through the Redis store.
type Session struct {
	AccessToken string    `json:"access_token"`
	ExpiresAt   time.Time `json:"expires_at"`
	CSRFToken   string    `json:"csrf_token"`
	UserID      string    `json:"user_id"` // the sneakers identity user id (adopted/provisioned at login)
	// Subject is the login subject (the Kratos identity id); the request gate
	// re-resolves it to the live identity ActorContext (roles + group names) on
	// every request so membership/role changes take effect without re-login.
	Subject string `json:"subject"`
	// MFAVerified records whether the session was issued after a verified second
	// factor. Server-side marker only; set by the 2-step MFA flow.
	MFAVerified bool `json:"mfa_verified"`
	// MFAVerifiedAt is when this session last proved a second factor: at
	// login, at enrollment, or through a step-up. The vault decides whether it
	// is fresh enough for a sensitive action.
	MFAVerifiedAt time.Time `json:"mfa_verified_at,omitzero"`
	// StepUpFailures counts wrong step-up proofs since the last good one; at
	// maxPendingAttempts the session is revoked.
	StepUpFailures int `json:"step_up_failures,omitempty"`
	// Enrolled records whether the user has a confirmed MFA factor. Captured at
	// login (from identity's GetMfaStatus) and flipped true when this session
	// completes enrollment, so the not-enforced setup banner reflects reality
	// without an identity round-trip on every session check.
	Enrolled bool `json:"enrolled"`
	// IssuedAt is when the session was created. A session issued before the
	// appliance's sessionsEndedAt is ended (see EndSessionsBefore).
	IssuedAt time.Time `json:"issued_at,omitzero"`
}

// SessionStore is the persistence seam. memStore is the dev/single-gateway
// implementation; redisStore (github.com/redis/go-redis/v9, keyed
// "sneakers:sess:<id>") is the multi-instance / restart-surviving one.
type SessionStore interface {
	Create(ctx context.Context, id string, sess Session) error
	Save(ctx context.Context, id string, sess Session) error
	Get(ctx context.Context, id string) (Session, bool, error)
	Delete(ctx context.Context, id string) error
	// DeleteByUser revokes EVERY active session for a user id (admin factor
	// removal / account recovery — the target must be kicked out so a lost-device
	// reset forces re-enrollment). Idempotent: a user with no sessions is a no-op.
	DeleteByUser(ctx context.Context, userID string) error
}

// memStore is a process-local, TTL-expiring session store (dev/single-gateway).
type memStore struct {
	mu   sync.RWMutex
	ttl  time.Duration
	data map[string]memEntry
}

type memEntry struct {
	sess    Session
	expires time.Time
}

// NewMemStore builds an in-memory session store with the given idle TTL.
func NewMemStore(ttl time.Duration) *memStore {
	return &memStore{ttl: ttl, data: map[string]memEntry{}}
}

func (m *memStore) Create(ctx context.Context, id string, sess Session) error {
	return m.Save(ctx, id, sess)
}

func (m *memStore) Save(_ context.Context, id string, sess Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[id] = memEntry{sess: sess, expires: time.Now().Add(m.ttl)}
	return nil
}

func (m *memStore) Get(_ context.Context, id string) (Session, bool, error) {
	m.mu.RLock()
	e, ok := m.data[id]
	m.mu.RUnlock()
	if !ok {
		return Session{}, false, nil
	}
	if time.Now().After(e.expires) {
		_ = m.Delete(context.Background(), id)
		return Session{}, false, nil
	}
	return e.sess, true, nil
}

func (m *memStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, id)
	return nil
}

func (m *memStore) DeleteByUser(_ context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, e := range m.data {
		if e.sess.UserID == userID {
			delete(m.data, id)
		}
	}
	return nil
}
