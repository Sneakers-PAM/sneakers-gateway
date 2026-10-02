// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc"
)

// barrierRefreshAuth is a concurrency-oriented authClient test double for
// the concurrent-refresh race. Unlike
// fakeRefreshAuth (token_refresh_test.go), which is only ever called by one
// goroutine at a time, this fake is invoked from N concurrent goroutines: it
// counts REFRESH CALLS (i.e. distinct singleflight "flights"), not callers,
// and blocks the first call on a channel so the test can deterministically
// hold it in-flight until every concurrent caller has joined it — that is
// what makes "exactly one backend Refresh call for N concurrent requests"
// something the test can assert rather than hope for.
type barrierRefreshAuth struct {
	mu    sync.Mutex
	calls int

	// entered is closed the instant the first (leader) call enters Refresh,
	// i.e. once the singleflight call is registered and in-flight.
	entered chan struct{}
	// release is closed by the test once every concurrent caller has had a
	// chance to join the in-flight call; only then does Refresh return.
	release chan struct{}

	firstResult AuthResult
	firstErr    error
	// laterErr, if set, is returned by any Refresh call beyond the first. In
	// the real Keycloak-rotation scenario this models the backend rejecting a
	// second refresh attempt with the now-rotated-out refresh token
	// (invalid_grant) — exactly the failure an uncoalesced losing goroutine
	// would hit. Coalescing must keep calls at 1, so this must never surface.
	laterErr error
}

func newBarrierRefreshAuth() *barrierRefreshAuth {
	return &barrierRefreshAuth{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *barrierRefreshAuth) VerifyPassword(_ context.Context, _, _ string) (AuthResult, error) {
	return AuthResult{}, errors.New("barrierRefreshAuth: VerifyPassword not used")
}

func (b *barrierRefreshAuth) Refresh(_ context.Context, _ string) (AuthResult, error) {
	b.mu.Lock()
	b.calls++
	n := b.calls
	b.mu.Unlock()
	if n == 1 {
		close(b.entered)
	}
	<-b.release
	if n == 1 {
		return b.firstResult, b.firstErr
	}
	if b.laterErr != nil {
		return AuthResult{}, b.laterErr
	}
	return b.firstResult, b.firstErr
}

func (b *barrierRefreshAuth) Logout(_ context.Context, _ string) error { return nil }

func (b *barrierRefreshAuth) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

// lockedIdentity wraps fakeIdentity with a mutex around ResolveUserContext so
// N goroutines can safely share one fake identity backend concurrently
// (fakeIdentity's request-recording fields are otherwise unsynchronized,
// which is fine for every other, single-goroutine test in this package but
// would be a data race here under -race).
type lockedIdentity struct {
	*fakeIdentity
	mu sync.Mutex
}

func (l *lockedIdentity) ResolveUserContext(ctx context.Context, in *identityv1.ResolveUserContextRequest, opts ...grpc.CallOption) (*identityv1.ResolveUserContextResponse, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fakeIdentity.ResolveUserContext(ctx, in, opts...)
}

// concurrentResult is one goroutine's outcome from requestWithSession.
type concurrentResult struct {
	code int
	ran  bool
}

// fireConcurrentRequests drives n concurrent SessionActor requests for the
// same sid against a barrierRefreshAuth-backed Handler, deterministically
// ensuring all n have joined the singleflight call before the backend
// Refresh is allowed to return:
//  1. the first (leader) goroutine is started alone and the test waits for
//     it to actually enter Refresh (ba.entered) — by the time Refresh runs,
//     singleflight has already registered the call, so any Do for the same
//     key from this point on is guaranteed to join it rather than start a
//     new flight;
//  2. the remaining n-1 (follower) goroutines are then started, and the test
//     waits for all of them to have been scheduled before adding a small
//     fixed margin so they reach the Do() call (there is no blocking I/O or
//     channel op between goroutine start and Do(), so this is not a racy
//     retry loop — it is scheduling headroom for CPU-bound code); only then
//     is the backend call released.
func fireConcurrentRequests(h *Handler, sid string, n int, ba *barrierRefreshAuth) []concurrentResult {
	results := make([]concurrentResult, n)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		rec, ran := requestWithSession(h, sid)
		results[0] = concurrentResult{rec.Code, ran}
	}()
	<-ba.entered

	var launched sync.WaitGroup
	launched.Add(n - 1)
	for i := 1; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			launched.Done()
			rec, ran := requestWithSession(h, sid)
			results[i] = concurrentResult{rec.Code, ran}
		}(i)
	}
	launched.Wait()
	time.Sleep(20 * time.Millisecond) // scheduling headroom, see doc comment above
	close(ba.release)

	wg.Wait()
	return results
}

// expiredSessionFixture bundles a Handler wired to its own JWKS server/signing
// key with a stored session whose access token has already expired (but
// whose Redis ExpiresAt is far in the future, isolating
// verifyKeycloakAccessToken's reactive refresh path from the pre-expiry
// proactive one) — the same shape TestSessionActor_ExpiredAccessToken_*
// (token_refresh_test.go) uses. signNew lets a test mint an
// additional, still-valid access token against the SAME key/kid, e.g. to
// stand in for the winner's freshly-refreshed token.
type expiredSessionFixture struct {
	h       *Handler
	signNew func() string
}

func newExpiredSessionFixture(t *testing.T, sid string, ba *barrierRefreshAuth) expiredSessionFixture {
	t.Helper()
	jwks, key := jwksServer(t, "k1")
	expiredClaims := goodClaims()
	expiredClaims["exp"] = time.Now().Add(-time.Hour).Unix()
	expiredAT := sign(t, key, "k1", expiredClaims)

	fid := &lockedIdentity{fakeIdentity: &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}}
	h := &Handler{Store: NewMemStore(time.Hour), Verifier: newTestVerifier(jwks.URL), Identity: fid, Auth: ba, TTL: time.Hour}

	sess := Session{
		AccessToken: expiredAT, RefreshToken: "RT1", ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: "csrf-1", UserID: "usr-42", KeycloakSubject: "kc-abc-123",
	}
	_ = h.Store.Create(context.Background(), sid, sess)

	return expiredSessionFixture{h: h, signNew: func() string {
		return sign(t, key, "k1", goodClaims())
	}}
}

// TestRefreshSession_ConcurrentRequests_Coalesce_SingleBackendRefresh is the
// core concurrency case: N concurrent requests for the SAME session, all
// hitting the same expired access token, must coalesce into exactly ONE
// backend Refresh call — not N. Without coalescing, every goroutine calls
// h.auth().Refresh independently, so this fails with calls == N (or, with a
// rotation-aware fake, calls > 1 and some requests failing — see the
// rotation-safety test below).
func TestRefreshSession_ConcurrentRequests_Coalesce_SingleBackendRefresh(t *testing.T) {
	const n = 20
	ba := newBarrierRefreshAuth()
	fx := newExpiredSessionFixture(t, "sid1", ba)
	ba.firstResult = AuthResult{AccessToken: fx.signNew(), RefreshToken: "RT2", ExpiresAt: time.Now().Add(2 * time.Minute), Subject: "kc-abc-123"}

	results := fireConcurrentRequests(fx.h, "sid1", n, ba)

	if got := ba.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 backend Refresh call for %d concurrent requests, got %d", n, got)
	}
	for i, r := range results {
		if r.code != http.StatusOK || !r.ran {
			t.Fatalf("result[%d]: expected 200 pass-through, got code=%d ran=%v", i, r.code, r.ran)
		}
	}
	sess, ok, _ := fx.h.Store.Get(context.Background(), "sid1")
	if !ok {
		t.Fatal("session was deleted; expected it to survive the coalesced refresh")
	}
	if sess.RefreshToken != "RT2" {
		t.Fatalf("expected session to carry the winner's refreshed token RT2, got %q", sess.RefreshToken)
	}
}

// TestRefreshSession_ConcurrentRequests_RotationSafe_LosersNeverUseStaleToken
// models Keycloak refresh-token ROTATION directly: a second backend Refresh
// call (i.e. anything beyond the coalesced first) would fail with
// invalid_grant, because the winner's call already rotated RT1 -> RT2 and KC
// invalidated RT1. Without coalescing, every losing goroutine independently
// calls Refresh(RT1) after the winner has rotated it, hits exactly this
// invalid_grant, and gets session_expired -> Store.Delete despite the session
// having just been legitimately refreshed. With coalescing, that second call
// must never happen, so every one of the N callers must succeed.
func TestRefreshSession_ConcurrentRequests_RotationSafe_LosersNeverUseStaleToken(t *testing.T) {
	const n = 20
	ba := newBarrierRefreshAuth()
	ba.laterErr = errors.New("invalid_grant") // any call beyond the coalesced first simulates the rotated-out RT1 being rejected
	fx := newExpiredSessionFixture(t, "sid1", ba)
	ba.firstResult = AuthResult{AccessToken: fx.signNew(), RefreshToken: "RT2", ExpiresAt: time.Now().Add(2 * time.Minute), Subject: "kc-abc-123"}

	results := fireConcurrentRequests(fx.h, "sid1", n, ba)

	if got := ba.callCount(); got != 1 {
		t.Fatalf("rotation-unsafe: expected exactly 1 backend Refresh call (a second would hit invalid_grant), got %d", got)
	}
	for i, r := range results {
		if r.code != http.StatusOK || !r.ran {
			t.Fatalf("result[%d]: expected 200 pass-through (no spurious logout from a rotated-out token), got code=%d ran=%v", i, r.code, r.ran)
		}
	}
	if _, ok, _ := fx.h.Store.Get(context.Background(), "sid1"); !ok {
		t.Fatal("session was deleted; a rotation-safe coalesced refresh must never spuriously log the user out")
	}
}

// TestRefreshSession_ConcurrentRequests_GenuineFailure_AllFailClosed is the
// fail-closed counterpart: when the refresh token really is dead (the single
// coalesced Refresh call itself fails), EVERY concurrent caller must observe
// session_expired and the session must be deleted — coalescing must never
// paper over a genuine failure. This preserves the MFA-always / fail-closed
// posture: a real credential problem still forces re-authentication for all
// concurrent requests, not just some.
func TestRefreshSession_ConcurrentRequests_GenuineFailure_AllFailClosed(t *testing.T) {
	const n = 20
	ba := newBarrierRefreshAuth()
	ba.firstErr = errors.New("invalid_grant")
	fx := newExpiredSessionFixture(t, "sid1", ba)

	results := fireConcurrentRequests(fx.h, "sid1", n, ba)

	if got := ba.callCount(); got != 1 {
		t.Fatalf("expected exactly 1 backend Refresh attempt even on failure, got %d", got)
	}
	for i, r := range results {
		if r.code != http.StatusUnauthorized || r.ran {
			t.Fatalf("result[%d]: expected 401 fail-closed with next NOT run, got code=%d ran=%v", i, r.code, r.ran)
		}
	}
	if _, ok, _ := fx.h.Store.Get(context.Background(), "sid1"); ok {
		t.Fatal("session should have been deleted after a genuine, coalesced refresh failure")
	}
}
