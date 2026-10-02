// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestKCVerifiedAuth_VerifyPassword_ReturnsVerifiedSubjectEmailUsernameName(t *testing.T) {
	jwks, key := jwksServer(t, "k1")
	at := sign(t, key, "k1", loginClaims())
	kcSrv := tokenServer(t, at)
	a := &kcVerifiedAuth{
		kc:       NewKCClient(kcSrv.URL, kcSrv.URL+"/logout", testClient, "s3cret"),
		verifier: newTestVerifier(jwks.URL),
	}

	ar, err := a.VerifyPassword(context.Background(), "alice", "good")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ar.Subject != "kc-abc-123" || ar.Email != "alice@example.org" || ar.Username != "alice@dev" || ar.Name != "Alice Example" {
		t.Fatalf("wrong AuthResult: %+v", ar)
	}
	if ar.AccessToken != at || ar.RefreshToken != "RT" {
		t.Fatalf("tokens not carried through: %+v", ar)
	}
}

func TestKCVerifiedAuth_VerifyPassword_UnverifiableTokenFailsClosedWithDistinctSentinel(t *testing.T) {
	jwks, _ := jwksServer(t, "k1")         // JWKS serves a DIFFERENT key than...
	_, otherKey := jwksServer(t, "unused") // ...the one that signs this token
	kcSrv := tokenServer(t, sign(t, otherKey, "k1", loginClaims()))
	a := &kcVerifiedAuth{kc: NewKCClient(kcSrv.URL, kcSrv.URL+"/logout", testClient, "s3cret"), verifier: newTestVerifier(jwks.URL)}

	// The password grant succeeded (Keycloak accepted the credentials) but the
	// resulting token fails JWKS verification — this must be distinguishable
	// from a bad password (ErrInvalidCredentials), so Login can return its
	// own distinct 401 {"error": "token_verify"} for it.
	_, err := a.VerifyPassword(context.Background(), "alice", "good")
	if !errors.Is(err, ErrTokenVerifyFailed) {
		t.Fatalf("expected ErrTokenVerifyFailed for an unverifiable token, got %v", err)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("an unverifiable token must NOT also satisfy ErrInvalidCredentials, got %v", err)
	}
}

func TestKCVerifiedAuth_Refresh_LeavesSubjectEmailEmpty(t *testing.T) {
	jwks, key := jwksServer(t, "k1")
	at := sign(t, key, "k1", loginClaims())
	kcSrv := tokenServer(t, at)
	a := &kcVerifiedAuth{kc: NewKCClient(kcSrv.URL, kcSrv.URL+"/logout", testClient, "s3cret"), verifier: newTestVerifier(jwks.URL)}

	ar, err := a.Refresh(context.Background(), "some-refresh-token")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// Refresh does NOT verify (resolveSessionActor re-verifies every request for
	// the Keycloak backend) — Subject/Email are
	// intentionally left empty; nothing downstream reads them off a Refresh result.
	if ar.Subject != "" || ar.Email != "" {
		t.Fatalf("Refresh should not populate Subject/Email, got %+v", ar)
	}
	if ar.AccessToken != at || ar.ExpiresAt.Before(time.Now()) {
		t.Fatalf("Refresh result wrong: %+v", ar)
	}
}

func TestHandler_Auth_FallsBackToKCVerifiedAuthWhenAuthUnset(t *testing.T) {
	jwks, _ := jwksServer(t, "k1")
	h := &Handler{KC: NewKCClient("http://unused", "http://unused", testClient, "s3cret"), Verifier: newTestVerifier(jwks.URL)}
	if _, ok := h.auth().(*kcVerifiedAuth); !ok {
		t.Fatalf("expected auth() to fall back to *kcVerifiedAuth when Auth is unset, got %T", h.auth())
	}
}

func TestHandler_BackendToken_PicksRefreshTokenForKeycloakAccessTokenForKratos(t *testing.T) {
	sess := Session{AccessToken: "AT", RefreshToken: "RT"}
	h := &Handler{} // Backend == "" behaves as keycloak
	if got := h.backendToken(sess); got != "RT" {
		t.Fatalf("keycloak backendToken = %q; want RT", got)
	}
	h.Backend = backendKratos
	if got := h.backendToken(sess); got != "AT" {
		t.Fatalf("kratos backendToken = %q; want AT", got)
	}
}
