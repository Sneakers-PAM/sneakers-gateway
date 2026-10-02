// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

// Redis-backed session + pending stores built on the resilient
// github.com/Bugs5382/go-redis wrapper (option-based Connect with a startup
// Ping, pooling, and command retries). Sessions survive gateway restarts and
// are shared across replicas; the pending store is the single-use seam where
// the 2-step MFA flow parks Keycloak tokens between password grant and factor
// verification.
//
// The wrapper's UniversalClient and Nil sentinel are used directly for
// Set/Get/Del/SetNX/GETDEL; go-redis/v9 itself supplies only ParseURL and
// KeepTTL.

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	bredis "github.com/Bugs5382/go-redis"
	goredis "github.com/redis/go-redis/v9"
)

const (
	sessPrefix    = "sneakers:sess:"
	pendingPrefix = "sneakers:pendauth:"
	// userSessPrefix indexes a user's live session ids as a Redis SET, so an admin
	// factor removal can revoke every session for a user id (DeleteByUser). The set
	// carries the session TTL (refreshed on each Save) and self-heals: an entry may
	// outlive its session key, but DeleteByUser DELs each id (a no-op if already
	// gone) before dropping the set.
	userSessPrefix = "sneakers:usersess:"
)

// ParseRedisURL builds a resilient client from a redis:// or rediss:// URL
// (e.g. redis://localhost:26379/0). The URL supplies the addr, password, DB, and
// TLS config; the client is then constructed through the Bugs5382 go-redis
// wrapper, which applies the resilient defaults and verifies readiness with a
// Ping before returning. ctx bounds the dial and that Ping.
func ParseRedisURL(ctx context.Context, url string) (*bredis.Client, error) {
	opt, err := goredis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	opts := []bredis.Option{
		bredis.WithAddr(opt.Addr),
		bredis.WithDB(opt.DB),
	}
	if opt.Password != "" {
		opts = append(opts, bredis.WithPassword(opt.Password))
	}
	if opt.TLSConfig != nil {
		opts = append(opts, bredis.WithTLS(opt.TLSConfig))
	}
	return bredis.Connect(ctx, opts...)
}

// ---- session store ----------------------------------------------------------

type redisStore struct {
	c     bredis.UniversalClient
	ttlFn func() time.Duration
}

// NewRedisStore builds a Redis SessionStore whose entries expire after the TTL
// returned by ttlFn. ttlFn is evaluated on every Save so a sliding renewal
// always applies the current admin-configured session lifetime.
func NewRedisStore(c *bredis.Client, ttlFn func() time.Duration) SessionStore {
	return &redisStore{c: c.Redis(), ttlFn: ttlFn}
}

func (s *redisStore) Create(ctx context.Context, id string, sess Session) error {
	return s.Save(ctx, id, sess)
}

func (s *redisStore) Save(ctx context.Context, id string, sess Session) error {
	b, err := json.Marshal(sess) // #nosec G117 -- the server-side session record: its tokens stay in the gateway's Redis and never reach the browser
	if err != nil {
		return err
	}
	ttl := s.ttlFn()
	if err := s.c.Set(ctx, sessPrefix+id, b, ttl).Err(); err != nil {
		return err
	}
	// Index the session under its user id so DeleteByUser can revoke all of a
	// user's sessions. Idempotent SADD; the set's TTL tracks the session TTL and
	// is refreshed on every (sliding) Save. A failure here must not fail the write
	// — the session is already persisted — so the index is best-effort.
	if sess.UserID != "" {
		key := userSessPrefix + sess.UserID
		_ = s.c.SAdd(ctx, key, id).Err()
		_ = s.c.Expire(ctx, key, ttl).Err()
	}
	return nil
}

func (s *redisStore) Get(ctx context.Context, id string) (Session, bool, error) {
	b, err := s.c.Get(ctx, sessPrefix+id).Bytes()
	if errors.Is(err, bredis.Nil) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	var sess Session
	if err := json.Unmarshal(b, &sess); err != nil {
		return Session{}, false, err
	}
	return sess, true, nil
}

func (s *redisStore) Delete(ctx context.Context, id string) error {
	return s.c.Del(ctx, sessPrefix+id).Err()
}

func (s *redisStore) DeleteByUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	key := userSessPrefix + userID
	ids, err := s.c.SMembers(ctx, key).Result()
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		keys := make([]string, len(ids))
		for i, id := range ids {
			keys[i] = sessPrefix + id
		}
		// DEL is a no-op for ids whose session key already expired (stale index).
		if err := s.c.Del(ctx, keys...).Err(); err != nil {
			return err
		}
	}
	return s.c.Del(ctx, key).Err()
}

// ---- pending store (2-step MFA seam) ----------------------------------------

// Pending parks the Keycloak tokens between a successful password grant and a
// verified second factor. Short-lived + single-use. The tokens are NEVER
// returned to the client — only the opaque pending id is.
type Pending struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id"`
	// KeycloakSubject is the verified token `sub`, carried through so the promoted
	// session records it (the request gate re-resolves it per request).
	KeycloakSubject string `json:"keycloak_subject"`
	// Factors is the set of second-factor kinds the user can satisfy for THIS
	// login (from identity.ListUserFactors), captured at the password step. The
	// kind-dispatched verify only honours a kind that is offered here, so a client
	// can never verify against a factor the user does not have.
	Factors []string `json:"factors,omitempty"`
	// Attempts counts failed factor verifies; at maxPendingAttempts the record is
	// discarded and the user must restart login (the per-pending verify budget).
	Attempts int `json:"attempts"`
	// WebauthnSessionID holds the identity assert-ceremony handle between the
	// passkey begin and the verify — server-side only, never sent to the client.
	WebauthnSessionID string `json:"webauthn_session_id,omitempty"`
}

// PendingStore is the single-use, TTL-bounded 2-step-login seam.
type PendingStore interface {
	// Create writes a new pending record with the store's TTL.
	Create(ctx context.Context, id string, p Pending) error
	// Get reads a record without consuming it (verify + attempt bookkeeping).
	Get(ctx context.Context, id string) (Pending, bool, error)
	// Save updates an EXISTING record in place, preserving its remaining TTL.
	// Saving a missing/expired id is a silent no-op so an in-flight attempt
	// update can never resurrect an expired login.
	Save(ctx context.Context, id string, p Pending) error
	// Consume atomically fetches AND deletes the record (single-use, GETDEL).
	Consume(ctx context.Context, id string) (Pending, bool, error)
	// Delete drops a record (e.g. attempt budget exhausted).
	Delete(ctx context.Context, id string) error
}

type redisPending struct {
	c   bredis.UniversalClient
	ttl time.Duration
}

// NewRedisPendingStore builds a Redis PendingStore. TTL bounds the login window.
func NewRedisPendingStore(c *bredis.Client, ttl time.Duration) PendingStore {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &redisPending{c: c.Redis(), ttl: ttl}
}

func (p *redisPending) Create(ctx context.Context, id string, rec Pending) error {
	b, err := json.Marshal(rec) // #nosec G117 -- the server-side pending-login record: its tokens stay in the gateway's Redis and never reach the browser
	if err != nil {
		return err
	}
	// SetNX so a pending id is never resurrected/overwritten.
	return p.c.SetNX(ctx, pendingPrefix+id, b, p.ttl).Err()
}

func (p *redisPending) Get(ctx context.Context, id string) (Pending, bool, error) {
	b, err := p.c.Get(ctx, pendingPrefix+id).Bytes()
	if errors.Is(err, bredis.Nil) {
		return Pending{}, false, nil
	}
	if err != nil {
		return Pending{}, false, err
	}
	var rec Pending
	if err := json.Unmarshal(b, &rec); err != nil {
		return Pending{}, false, err
	}
	return rec, true, nil
}

func (p *redisPending) Save(ctx context.Context, id string, rec Pending) error {
	b, err := json.Marshal(rec) // #nosec G117 -- the server-side pending-login record: its tokens stay in the gateway's Redis and never reach the browser
	if err != nil {
		return err
	}
	// XX (only if exists) + KEEPTTL: never create, never extend the login window.
	return p.c.SetXX(ctx, pendingPrefix+id, b, goredis.KeepTTL).Err()
}

func (p *redisPending) Delete(ctx context.Context, id string) error {
	return p.c.Del(ctx, pendingPrefix+id).Err()
}

func (p *redisPending) Consume(ctx context.Context, id string) (Pending, bool, error) {
	b, err := p.c.GetDel(ctx, pendingPrefix+id).Bytes() // atomic single-use
	if errors.Is(err, bredis.Nil) {
		return Pending{}, false, nil
	}
	if err != nil {
		return Pending{}, false, err
	}
	var rec Pending
	if err := json.Unmarshal(b, &rec); err != nil {
		return Pending{}, false, err
	}
	return rec, true, nil
}
