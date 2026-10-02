// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

// fakeRefreshAuth is a minimal authClient test double used to drive
// resolveSessionActor's Keycloak-branch expired-access-token refresh path
// without a live Keycloak token endpoint. refreshCalls counts
// Refresh invocations so tests can assert whether a refresh was attempted.
type fakeRefreshAuth struct {
	result       AuthResult
	err          error
	refreshCalls int
}

func (f *fakeRefreshAuth) VerifyPassword(_ context.Context, _, _ string) (AuthResult, error) {
	return AuthResult{}, errors.New("fakeRefreshAuth: VerifyPassword not used")
}

func (f *fakeRefreshAuth) Refresh(_ context.Context, _ string) (AuthResult, error) {
	f.refreshCalls++
	if f.err != nil {
		return AuthResult{}, f.err
	}
	return f.result, nil
}

func (f *fakeRefreshAuth) Logout(_ context.Context, _ string) error { return nil }

// requestWithSession drives resolveSessionActor through the real HTTP gate
// (SessionActor) so these tests exercise the exact code path a browser
// request takes, matching the package's existing TestSessionActor_* style.
func requestWithSession(h *Handler, sid string) (*httptest.ResponseRecorder, bool) {
	ran := false
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rec := httptest.NewRecorder()
	h.SessionActor(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })).ServeHTTP(rec, req)
	return rec, ran
}

// TestSessionActor_ExpiredAccessToken_RefreshSucceeds_KeepsSessionAlive is the
// core case: an access token that has already EXPIRED (past
// its own exp claim), with the session's Redis-tracked ExpiresAt still far in
// the future (so the pre-expiry proactive-refresh block above does NOT fire —
// this isolates the reactive Verify-failure refresh path under test) and a
// refresh token present, must be transparently refreshed and the request let
// through — not treated as a logout.
func TestSessionActor_ExpiredAccessToken_RefreshSucceeds_KeepsSessionAlive(t *testing.T) {
	jwks, key := jwksServer(t, "k1")
	expiredClaims := goodClaims()
	expiredClaims["exp"] = time.Now().Add(-time.Hour).Unix()
	expiredAT := sign(t, key, "k1", expiredClaims)
	newAT := sign(t, key, "k1", goodClaims())

	fakeAuth := &fakeRefreshAuth{result: AuthResult{
		AccessToken: newAT, RefreshToken: "RT2", ExpiresAt: time.Now().Add(2 * time.Minute), Subject: "kc-abc-123",
	}}
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := &Handler{Store: NewMemStore(time.Hour), Verifier: newTestVerifier(jwks.URL), Identity: fid, Auth: fakeAuth, TTL: time.Hour}

	sess := Session{
		AccessToken: expiredAT, RefreshToken: "RT1", ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: "csrf-1", UserID: "usr-42", KeycloakSubject: "kc-abc-123",
	}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	rec, ran := requestWithSession(h, "sid1")

	if rec.Code != http.StatusOK || !ran {
		t.Fatalf("expected authed pass-through 200 after transparent refresh, got %d ran=%v body=%s", rec.Code, ran, rec.Body)
	}
	if fakeAuth.refreshCalls != 1 {
		t.Fatalf("expected exactly 1 refresh call, got %d", fakeAuth.refreshCalls)
	}
	refreshed, ok, _ := h.Store.Get(context.Background(), "sid1")
	if !ok {
		t.Fatal("session was deleted; expected it to survive the transparent refresh")
	}
	if refreshed.AccessToken != newAT || refreshed.RefreshToken != "RT2" {
		t.Fatalf("session tokens not updated from refresh: %+v", refreshed)
	}
	if !refreshed.ExpiresAt.After(time.Now()) {
		t.Fatalf("refreshed session ExpiresAt not updated to the future: %v", refreshed.ExpiresAt)
	}
}

// TestSessionActor_ExpiredAccessToken_RefreshFails_SessionExpired: when the
// access token is expired and the refresh call itself fails (revoked/expired
// refresh token), the session must be deleted and the request rejected with
// session_expired — the same fail-closed outcome as the pre-expiry block's
// own refresh failure.
func TestSessionActor_ExpiredAccessToken_RefreshFails_SessionExpired(t *testing.T) {
	jwks, key := jwksServer(t, "k1")
	expiredClaims := goodClaims()
	expiredClaims["exp"] = time.Now().Add(-time.Hour).Unix()
	expiredAT := sign(t, key, "k1", expiredClaims)

	fakeAuth := &fakeRefreshAuth{err: errors.New("invalid_grant")}
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := &Handler{Store: NewMemStore(time.Hour), Verifier: newTestVerifier(jwks.URL), Identity: fid, Auth: fakeAuth, TTL: time.Hour}

	sess := Session{
		AccessToken: expiredAT, RefreshToken: "RT1", ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: "csrf-1", UserID: "usr-42", KeycloakSubject: "kc-abc-123",
	}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	rec, ran := requestWithSession(h, "sid1")

	if rec.Code != http.StatusUnauthorized || ran {
		t.Fatalf("expected 401 fail-closed with next NOT run, got %d ran=%v body=%s", rec.Code, ran, rec.Body)
	}
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "session_expired" {
		t.Fatalf("expected error=session_expired, got %+v", out)
	}
	if fakeAuth.refreshCalls != 1 {
		t.Fatalf("expected exactly 1 refresh attempt, got %d", fakeAuth.refreshCalls)
	}
	if _, ok, _ := h.Store.Get(context.Background(), "sid1"); ok {
		t.Fatal("session should have been deleted after a failed refresh")
	}
}

// TestSessionActor_NonExpiryVerifyFailure_NeverRefreshes: a verify failure
// that is NOT an expiry (here: a signature mismatch — the token is signed by
// a key the JWKS endpoint never served, i.e. tampering) must fail closed
// immediately with token_verify and must NEVER attempt a refresh — refreshing
// past a signature/iss/aud failure would let a tampered credential ride a
// legitimate refresh token to a session.
func TestSessionActor_NonExpiryVerifyFailure_NeverRefreshes(t *testing.T) {
	jwks, _ := jwksServer(t, "k1")         // JWKS serves a DIFFERENT key than...
	_, otherKey := jwksServer(t, "unused") // ...the one that signs this token
	badAT := sign(t, otherKey, "k1", goodClaims())

	fakeAuth := &fakeRefreshAuth{result: AuthResult{AccessToken: "should-not-be-used", ExpiresAt: time.Now().Add(time.Hour)}}
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := &Handler{Store: NewMemStore(time.Hour), Verifier: newTestVerifier(jwks.URL), Identity: fid, Auth: fakeAuth, TTL: time.Hour}

	sess := Session{
		AccessToken: badAT, RefreshToken: "RT1", ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: "csrf-1", UserID: "usr-42", KeycloakSubject: "kc-abc-123",
	}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	rec, ran := requestWithSession(h, "sid1")

	if rec.Code != http.StatusUnauthorized || ran {
		t.Fatalf("expected 401 fail-closed with next NOT run, got %d ran=%v body=%s", rec.Code, ran, rec.Body)
	}
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "token_verify" {
		t.Fatalf("expected error=token_verify, got %+v", out)
	}
	if fakeAuth.refreshCalls != 0 {
		t.Fatalf("a non-expiry verify failure must NEVER trigger a refresh, got %d refresh calls", fakeAuth.refreshCalls)
	}
	if _, ok, _ := h.Store.Get(context.Background(), "sid1"); ok {
		t.Fatal("session should have been deleted after a non-expiry verify failure")
	}
}

// TestSessionActor_ValidToken_PassesThroughWithoutRefreshing: the ordinary,
// unexpired case passes straight through — no refresh attempted.
func TestSessionActor_ValidToken_PassesThroughWithoutRefreshing(t *testing.T) {
	jwks, key := jwksServer(t, "k1")
	at := sign(t, key, "k1", goodClaims())

	fakeAuth := &fakeRefreshAuth{result: AuthResult{AccessToken: "should-not-be-used", ExpiresAt: time.Now().Add(time.Hour)}}
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := &Handler{Store: NewMemStore(time.Hour), Verifier: newTestVerifier(jwks.URL), Identity: fid, Auth: fakeAuth, TTL: time.Hour}

	sess := Session{
		AccessToken: at, RefreshToken: "RT1", ExpiresAt: time.Now().Add(time.Hour),
		CSRFToken: "csrf-1", UserID: "usr-42", KeycloakSubject: "kc-abc-123",
	}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	rec, ran := requestWithSession(h, "sid1")

	if rec.Code != http.StatusOK || !ran {
		t.Fatalf("expected authed pass-through 200, got %d ran=%v body=%s", rec.Code, ran, rec.Body)
	}
	if fakeAuth.refreshCalls != 0 {
		t.Fatalf("a valid, unexpired token must not trigger a refresh, got %d refresh calls", fakeAuth.refreshCalls)
	}
}
