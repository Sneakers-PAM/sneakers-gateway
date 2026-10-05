// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"
)

// cutoffStore ends every session issued before a cutoff: Get refuses such a
// session and deletes it. Create stamps IssuedAt. A session stored without
// an issue time counts as issued before any cutoff.
type cutoffStore struct {
	SessionStore
	cutoff func() time.Time
	now    func() time.Time
	log    log.Logger
}

// EndSessionsBefore wraps store so that, whenever cutoff returns a non-zero
// time, sessions issued before it are ended. The appliance sets the cutoff
// (its ConfigMap's sessionsEndedAt) to sign everyone out when it enters
// maintenance; every gateway replica applies it, and it holds across
// restarts. lg may be nil.
func EndSessionsBefore(store SessionStore, cutoff func() time.Time, lg log.Logger) SessionStore {
	return &cutoffStore{SessionStore: store, cutoff: cutoff, now: time.Now, log: lg}
}

func (s *cutoffStore) Create(ctx context.Context, id string, sess Session) error {
	if sess.IssuedAt.IsZero() {
		sess.IssuedAt = s.now().UTC()
	}
	return s.SessionStore.Create(ctx, id, sess)
}

func (s *cutoffStore) Get(ctx context.Context, id string) (Session, bool, error) {
	sess, ok, err := s.SessionStore.Get(ctx, id)
	if err != nil || !ok {
		return sess, ok, err
	}
	c := s.cutoff()
	if c.IsZero() || !sess.IssuedAt.Before(c) {
		return sess, true, nil
	}
	if err := s.Delete(ctx, id); err != nil {
		return Session{}, false, err
	}
	if s.log != nil {
		s.log.Ctx(ctx).Info("session ended: issued before the appliance's sessionsEndedAt",
			log.F("user_id", sess.UserID), log.F("issued_at", sess.IssuedAt), log.F("cutoff", c))
	}
	return Session{}, false, nil
}
