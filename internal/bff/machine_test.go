// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

var errUnreachable = errors.New("identity: unreachable")

// TestMachineActor_ValidBearer_BuildsMachineActorContext proves a request
// carrying a Bearer token that identity.VerifyApiToken resolves as valid
// reaches next with a machine ActorContext on its context: principal_kind
// SERVICE_ACCOUNT, principal_id the resolved service-account id. No cookie or
// CSRF header is present — the machine path authenticates on the bearer alone.
func TestMachineActor_ValidBearer_BuildsMachineActorContext(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{
		Valid: true, ServiceAccountId: "sa-42", Name: "ci-bot", Scope: "sneakers-secrets",
	}}
	h := &Handler{Identity: fid}

	var gotActor *vaultv1.ActorContext
	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		gotActor = resolvers.MachineActorOf(r.Context())
	})

	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer sa-token-plaintext")
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if !ran {
		t.Fatal("expected next to run for a valid bearer token")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 pass-through, got %d body=%s", rec.Code, rec.Body)
	}
	if fid.verifyApiTokenReq == nil || fid.verifyApiTokenReq.GetToken() != "sa-token-plaintext" {
		t.Fatalf("VerifyApiToken not called with the bearer token: %+v", fid.verifyApiTokenReq)
	}
	if gotActor == nil {
		t.Fatal("expected a machine ActorContext on the request context")
	}
	if gotActor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT {
		t.Fatalf("expected PRINCIPAL_KIND_SERVICE_ACCOUNT, got %v", gotActor.GetPrincipalKind())
	}
	if gotActor.GetPrincipalId() != "sa-42" {
		t.Fatalf("expected principal_id=sa-42, got %q", gotActor.GetPrincipalId())
	}
}

// TestMachineActor_InvalidToken_401sAndDoesNotCallNext covers an identity
// VerifyApiToken response of valid=false (unknown/expired/revoked token,
// per identity's fail-closed no-leak contract): the middleware must 401 and
// never invoke next.
func TestMachineActor_InvalidToken_401sAndDoesNotCallNext(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{Valid: false}}
	h := &Handler{Identity: fid}

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })

	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer garbage-token")
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if ran {
		t.Fatal("next must NOT run for an invalid token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestMachineActor_AbsentBearer_401sWithoutCallingIdentity covers a request
// with no Authorization header at all (or a malformed one): the middleware
// must fail closed WITHOUT even calling identity.
func TestMachineActor_AbsentBearer_401sWithoutCallingIdentity(t *testing.T) {
	cases := []struct {
		name string
		auth string
	}{
		{"no header", ""},
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
		{"empty bearer", "Bearer "},
		{"bearer no space", "Bearer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{Valid: true, ServiceAccountId: "sa-42"}}
			h := &Handler{Identity: fid}

			ran := false
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })

			req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.MachineActor(next).ServeHTTP(rec, req)

			if ran {
				t.Fatalf("next must NOT run for %q", tc.name)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 for %q, got %d", tc.name, rec.Code)
			}
			if fid.verifyApiTokenReq != nil {
				t.Fatalf("identity.VerifyApiToken must NOT be called with no/malformed bearer (%q)", tc.name)
			}
		})
	}
}

// TestMachineActor_IdentityError_401sFailClosed mirrors resolveSessionActor's
// fail-closed posture: identity being unreachable must never be treated as an
// implicit grant.
func TestMachineActor_IdentityError_401sFailClosed(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenErr: errUnreachable}
	h := &Handler{Identity: fid}

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })

	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if ran {
		t.Fatal("next must NOT run when identity is unreachable")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestMachineActor_NoCookieCSRFOrMFARequired proves the machine path never
// consults the session cookie, CSRF header, or MFA posture: a Handler with NO
// Store/session wiring at all still authenticates purely off the bearer token.
func TestMachineActor_NoCookieCSRFOrMFARequired(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{Valid: true, ServiceAccountId: "sa-1"}}
	// Deliberately no Store, no MfaEnforced, no CSRF wiring.
	h := &Handler{Identity: fid}

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })

	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer sa-token")
	// No cookie, no X-CSRF-Token header set.
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through with no cookie/CSRF, got ran=%v code=%d", ran, rec.Code)
	}
}
