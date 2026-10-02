// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// OIDC machine-auth path: MachineActor is pluggable. Alongside the opaque
// service-account API token (verified via identity.VerifyApiToken), a caller
// may present a Hydra-issued OIDC/OAuth2 JWT (client-credentials): the
// bearer's signature/iss/aud are verified by the reused bff.Verifier (JWKS),
// then the verified `sub` (the OAuth2 client_id) is resolved to a service
// account via identity.ResolveServiceAccountByOidc. Both paths land on the SAME
// resolvers.WithMachineActor(ctx, principalID, groupNames) funnel. Fails closed
// exactly like the opaque path: any verify error, resolve error, or
// valid=false is a 401 and next is never called — MachineActor does not
// distinguish WHY. When no OIDC verifier is wired (Hydra not configured),
// a JWT-shaped bearer simply fails closed; the opaque path is unaffected.
package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"github.com/golang-jwt/jwt/v5"
)

const (
	oidcTestIssuer   = "http://sneakers-hydra:4444/"
	oidcTestAudience = "sneakers-mcp"
)

// newOidcTestVerifier mirrors newTestVerifier (jwks_test.go) but with an
// empty clientID, matching main.go's Hydra wiring: Hydra client-credentials
// tokens carry no azp.
func newOidcTestVerifier(jwksURL string) *Verifier {
	return NewVerifier(jwksURL, oidcTestIssuer, oidcTestAudience, "", time.Minute, 30*time.Second)
}

// oidcGoodClaims includes a "scope" claim (OAuth2 convention: a
// space-delimited string of the client's granted scopes) because that claim
// — NOT ResolveServiceAccountByOidcResponse.Scope, which identity never
// populates (service_accounts has no scope column; scope lives on
// api_tokens, and an OIDC client has none) — is oidcVerifier's actual source
// of RACI scope. See TestMachineActor_JWTBearer_ResolvesViaOidcToMachineActorContext.
func oidcGoodClaims(clientID, scope string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": oidcTestIssuer, "aud": oidcTestAudience, "sub": clientID, "scope": scope,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
}

// TestMachineActor_JWTBearer_ResolvesViaOidcToMachineActorContext proves a
// JWT bearer that verifies (signature+iss+aud) and whose sub resolves via
// ResolveServiceAccountByOidc reaches next with a machine ActorContext:
// principal_id = the resolved service-account id, groups = identity's
// group_names (the JWT's OWN "scope" claim, forwarded to identity and
// resolved there against allowed_groups; see machine_scope_groups_test.go).
func TestMachineActor_JWTBearer_ResolvesViaOidcToMachineActorContext(t *testing.T) {
	srv, key := jwksServer(t, "hk1")
	fid := &fakeIdentity{resolveOidcResp: &identityv1.ResolveServiceAccountByOidcResponse{
		Valid: true, ServiceAccountId: "sa-mcp-1", AllowedGroups: []string{"sneakers-secrets", "mcp-agents"},
		GroupNames: []string{"sneakers-secrets", "mcp-agents"},
	}}
	h := &Handler{Identity: fid, MachineOidcVerifier: newOidcTestVerifier(srv.URL), MachineOidcIssuer: oidcTestIssuer}

	tok := sign(t, key, "hk1", oidcGoodClaims("hydra-client-abc", "sneakers-secrets mcp-agents"))

	var gotActor *vaultv1.ActorContext
	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		gotActor = resolvers.MachineActorOf(r.Context())
	})

	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through, ran=%v code=%d body=%s", ran, rec.Code, rec.Body)
	}
	if fid.resolveOidcReq == nil || fid.resolveOidcReq.GetOidcIssuer() != oidcTestIssuer || fid.resolveOidcReq.GetOidcSubject() != "hydra-client-abc" {
		t.Fatalf("ResolveServiceAccountByOidc not called with (issuer, sub): %+v", fid.resolveOidcReq)
	}
	if fid.verifyApiTokenReq != nil {
		t.Fatal("VerifyApiToken must NOT be called for a JWT bearer")
	}
	if gotActor == nil || gotActor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT {
		t.Fatalf("expected PRINCIPAL_KIND_SERVICE_ACCOUNT, got %+v", gotActor)
	}
	if gotActor.GetPrincipalId() != "sa-mcp-1" {
		t.Fatalf("principal_id = %q, want sa-mcp-1", gotActor.GetPrincipalId())
	}
	wantGroups := []string{"sneakers-secrets", "mcp-agents"}
	if len(gotActor.GetGroupNames()) != len(wantGroups) || gotActor.GetGroupNames()[0] != wantGroups[0] || gotActor.GetGroupNames()[1] != wantGroups[1] {
		t.Fatalf("group_names = %v, want %v", gotActor.GetGroupNames(), wantGroups)
	}
}

// oidcGoodClaimsScp is oidcGoodClaims but carries the granted scope as `scp`
// (a JSON array of strings) rather than `scope` (a space-delimited string).
// This is Hydra's (fosite) JWTScopeFieldList shape — the v2.x default — and
// must be accepted exactly like oidcGoodClaims's `scope` string.
func oidcGoodClaimsScp(clientID string, scopes ...string) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": oidcTestIssuer, "aud": oidcTestAudience, "sub": clientID, "scp": scopes,
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
}

// TestMachineActor_JWTBearer_ScpArrayClaim_ResolvesToSameGroupNames proves a
// Hydra-shaped token that carries granted scopes as `scp` (a JSON array),
// rather than the `scope` space-delimited string exercised above, is
// forwarded to identity as the same space-delimited scope, and so yields the
// same GroupNames. Without this, a Hydra deployment using the default
// JWTScopeFieldList would authenticate every OIDC caller (verify succeeds)
// but derive zero RACI groups, denying every secret.
func TestMachineActor_JWTBearer_ScpArrayClaim_ResolvesToSameGroupNames(t *testing.T) {
	srv, key := jwksServer(t, "hk1")
	fid := &fakeIdentity{resolveOidcResp: &identityv1.ResolveServiceAccountByOidcResponse{
		Valid: true, ServiceAccountId: "sa-mcp-1", AllowedGroups: []string{"sneakers-secrets", "mcp-agents"},
		GroupNames: []string{"sneakers-secrets", "mcp-agents"},
	}}
	h := &Handler{Identity: fid, MachineOidcVerifier: newOidcTestVerifier(srv.URL), MachineOidcIssuer: oidcTestIssuer}

	tok := sign(t, key, "hk1", oidcGoodClaimsScp("hydra-client-abc", "sneakers-secrets", "mcp-agents"))

	var gotActor *vaultv1.ActorContext
	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		gotActor = resolvers.MachineActorOf(r.Context())
	})

	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through, ran=%v code=%d body=%s", ran, rec.Code, rec.Body)
	}
	if gotActor == nil || gotActor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT {
		t.Fatalf("expected PRINCIPAL_KIND_SERVICE_ACCOUNT, got %+v", gotActor)
	}
	if got := fid.resolveOidcReq.GetScope(); got != "sneakers-secrets mcp-agents" {
		t.Fatalf("scope forwarded to identity = %q, want the scp array space-joined", got)
	}
	wantGroups := []string{"sneakers-secrets", "mcp-agents"}
	if len(gotActor.GetGroupNames()) != len(wantGroups) || gotActor.GetGroupNames()[0] != wantGroups[0] || gotActor.GetGroupNames()[1] != wantGroups[1] {
		t.Fatalf("group_names = %v, want %v", gotActor.GetGroupNames(), wantGroups)
	}
}

// TestMachineActor_OpaqueBearer_StillTakesSATokenPath proves an opaque
// (non-JWT) bearer keeps taking the existing VerifyApiToken path even when an
// OIDC verifier is wired — the two paths are dispatched on the bearer's own
// shape, never on which verifiers happen to be configured.
func TestMachineActor_OpaqueBearer_StillTakesSATokenPath(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{
		Valid: true, ServiceAccountId: "sa-42", Scope: "sneakers-secrets",
	}}
	srv, _ := jwksServer(t, "hk1")
	h := &Handler{Identity: fid, MachineOidcVerifier: newOidcTestVerifier(srv.URL), MachineOidcIssuer: oidcTestIssuer}

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer sa-token-plaintext")
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("expected pass-through via SA-token path, ran=%v code=%d", ran, rec.Code)
	}
	if fid.verifyApiTokenReq == nil || fid.verifyApiTokenReq.GetToken() != "sa-token-plaintext" {
		t.Fatalf("VerifyApiToken not called with the opaque bearer: %+v", fid.verifyApiTokenReq)
	}
	if fid.resolveOidcReq != nil {
		t.Fatal("ResolveServiceAccountByOidc must NOT be called for an opaque bearer")
	}
}

// TestMachineActor_InvalidOrUnknownIssuerJWT_401sAndDoesNotCallNext covers a
// JWT that fails bff.Verifier.Verify itself (wrong issuer here — signature,
// expiry etc are already covered by jwks_test.go): 401, next never runs, and
// identity.ResolveServiceAccountByOidc is never even called.
func TestMachineActor_InvalidOrUnknownIssuerJWT_401sAndDoesNotCallNext(t *testing.T) {
	srv, key := jwksServer(t, "hk1")
	fid := &fakeIdentity{}
	h := &Handler{Identity: fid, MachineOidcVerifier: newOidcTestVerifier(srv.URL), MachineOidcIssuer: oidcTestIssuer}

	c := oidcGoodClaims("hydra-client-abc", "sneakers-secrets")
	c["iss"] = "http://evil/"
	tok := sign(t, key, "hk1", c)

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if ran {
		t.Fatal("next must NOT run for an invalid/unknown-issuer JWT")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if fid.resolveOidcReq != nil {
		t.Fatal("ResolveServiceAccountByOidc must NOT be called when JWT verification itself fails")
	}
}

// TestMachineActor_UnresolvableOrDisabledSA_401sAndDoesNotCallNext covers a
// syntactically/cryptographically valid JWT whose sub identity reports
// valid=false for (unknown OR disabled — identity deliberately does not
// distinguish, per ResolveServiceAccountByOidc's contract): 401, next never
// runs.
func TestMachineActor_UnresolvableOrDisabledSA_401sAndDoesNotCallNext(t *testing.T) {
	srv, key := jwksServer(t, "hk1")
	fid := &fakeIdentity{resolveOidcResp: &identityv1.ResolveServiceAccountByOidcResponse{Valid: false}}
	h := &Handler{Identity: fid, MachineOidcVerifier: newOidcTestVerifier(srv.URL), MachineOidcIssuer: oidcTestIssuer}

	tok := sign(t, key, "hk1", oidcGoodClaims("hydra-client-unknown", "sneakers-secrets"))

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if ran {
		t.Fatal("next must NOT run for an unresolvable/disabled service account")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// TestMachineActor_OidcUnconfigured_JWTFailsClosedSATokenPathUnaffected covers
// Hydra disabled: HYDRA_ISSUER is unset in main.go, so
// Handler.MachineOidcVerifier is nil. A JWT-shaped bearer must fail closed with
// 401 WITHOUT calling identity at all, and the opaque SA-token path on the very
// same Handler must be completely unaffected.
func TestMachineActor_OidcUnconfigured_JWTFailsClosedSATokenPathUnaffected(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{Valid: true, ServiceAccountId: "sa-42"}}
	h := &Handler{Identity: fid} // no MachineOidcVerifier wired: inert OIDC path

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer aaa.bbb.ccc")
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)
	if ran || rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 fail-closed with next NOT run when OIDC unconfigured, ran=%v code=%d", ran, rec.Code)
	}
	if fid.verifyApiTokenReq != nil {
		t.Fatal("VerifyApiToken must NOT be called for a JWT-shaped bearer even when OIDC is unconfigured")
	}
	if fid.resolveOidcReq != nil {
		t.Fatal("ResolveServiceAccountByOidc must NOT be called when no OIDC verifier is wired")
	}

	ran2 := false
	next2 := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran2 = true })
	req2 := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req2.Header.Set("Authorization", "Bearer sa-token-plaintext")
	rec2 := httptest.NewRecorder()
	h.MachineActor(next2).ServeHTTP(rec2, req2)
	if !ran2 || rec2.Code != http.StatusOK {
		t.Fatalf("expected opaque SA-token path pass-through unaffected, ran=%v code=%d", ran2, rec2.Code)
	}
}
