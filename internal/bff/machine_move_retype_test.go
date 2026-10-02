// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/machineresolvers"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// countingVault fails the test's expectations if any move/change-type call
// reaches vault: a disabled or unknown service account must be stopped at
// MachineActor, before the machine schema ever runs.
type countingVault struct {
	vaultv1.VaultServiceClient
	calls int
}

func (v *countingVault) MoveSecretForPrincipal(context.Context, *vaultv1.MoveSecretForPrincipalRequest, ...grpc.CallOption) (*vaultv1.MoveSecretForPrincipalResponse, error) {
	v.calls++
	return &vaultv1.MoveSecretForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1"}}, nil
}

func (v *countingVault) ChangeSecretTypeForPrincipal(context.Context, *vaultv1.ChangeSecretTypeForPrincipalRequest, ...grpc.CallOption) (*vaultv1.ChangeSecretTypeForPrincipalResponse, error) {
	v.calls++
	return &vaultv1.ChangeSecretTypeForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1"}}, nil
}

// machineEndpoint wires MachineActor in front of the real machine schema, as
// cmd/gateway/main.go mounts /machine/graphql.
func machineEndpoint(h *Handler, v vaultv1.VaultServiceClient) http.Handler {
	gql := handler.New(machineresolvers.NewExecutableSchema(machineresolvers.Config{
		Resolvers: &machineresolvers.Resolver{Vault: v},
	}))
	gql.AddTransport(transport.POST{})
	return h.MachineActor(gql)
}

const (
	moveMutation   = `{"query":"mutation { moveSecretForPrincipal(id: \"s1\", destFolderId: \"f2\") { id } }"}`
	retypeMutation = `{"query":"mutation { changeSecretTypeForPrincipal(id: \"s1\", newTypeId: \"type-web-password\") { fieldKeys } }"}`
)

func postMachine(t *testing.T, h http.Handler, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// A disabled service account (identity reports valid=false for its API token)
// cannot move or retype anything: 401 and vault is never called.
func TestMachineMoveRetype_DisabledServiceAccountTokenNeverReachesVault(t *testing.T) {
	v := &countingVault{}
	h := machineEndpoint(&Handler{Identity: &fakeIdentity{
		verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{Valid: false},
	}}, v)
	for _, body := range []string{moveMutation, retypeMutation} {
		if rec := postMachine(t, h, "sa-token-of-disabled-account", body); rec.Code != http.StatusUnauthorized {
			t.Fatalf("disabled SA: want 401, got %d body=%s", rec.Code, rec.Body)
		}
	}
	if v.calls != 0 {
		t.Fatalf("vault called %d times for a disabled SA", v.calls)
	}
}

// Same for the OIDC (Hydra JWT) path: a verified token whose client resolves
// to a disabled/unlinked SA is a 401 before the schema runs.
func TestMachineMoveRetype_DisabledServiceAccountOidcNeverReachesVault(t *testing.T) {
	srv, key := jwksServer(t, "mk1")
	v := &countingVault{}
	h := machineEndpoint(&Handler{
		Identity:            &fakeIdentity{resolveOidcResp: &identityv1.ResolveServiceAccountByOidcResponse{Valid: false}},
		MachineOidcVerifier: newOidcTestVerifier(srv.URL), MachineOidcIssuer: oidcTestIssuer,
	}, v)
	tok := sign(t, key, "mk1", oidcGoodClaims("hydra-client-disabled", "sneakers-secrets"))
	for _, body := range []string{moveMutation, retypeMutation} {
		if rec := postMachine(t, h, tok, body); rec.Code != http.StatusUnauthorized {
			t.Fatalf("disabled SA (OIDC): want 401, got %d body=%s", rec.Code, rec.Body)
		}
	}
	if v.calls != 0 {
		t.Fatalf("vault called %d times for a disabled SA", v.calls)
	}
}

// Control: an enabled SA does reach vault through the same wiring, so the
// denials above are the middleware's doing, not a broken harness.
func TestMachineMoveRetype_EnabledServiceAccountReachesVault(t *testing.T) {
	v := &countingVault{}
	h := machineEndpoint(&Handler{Identity: &fakeIdentity{
		verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{Valid: true, ServiceAccountId: "sa-1", Scope: "sneakers-secrets"},
	}}, v)
	for _, body := range []string{moveMutation, retypeMutation} {
		if rec := postMachine(t, h, "sa-token", body); rec.Code != http.StatusOK {
			t.Fatalf("enabled SA: want 200, got %d body=%s", rec.Code, rec.Body)
		}
	}
	if v.calls != 2 {
		t.Fatalf("vault calls = %d, want 2", v.calls)
	}
}
