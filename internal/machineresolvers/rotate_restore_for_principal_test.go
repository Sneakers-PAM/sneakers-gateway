// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

// rotateRestoreVault is a fake VaultServiceClient for #169's new machine
// mutations: rotate a secret the principal may author, and restore a prior
// version.
type rotateRestoreVault struct {
	vaultv1.VaultServiceClient
	lastRotate  *vaultv1.RotateSecretForPrincipalRequest
	lastRestore *vaultv1.RestoreSecretVersionForPrincipalRequest
}

func (f *rotateRestoreVault) RotateSecretForPrincipal(_ context.Context, in *vaultv1.RotateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.RotateSecretForPrincipalResponse, error) {
	f.lastRotate = in
	return &vaultv1.RotateSecretForPrincipalResponse{
		Secret:   &vaultv1.Secret{Id: in.GetSecretId(), Name: "host-a admin"},
		NewValue: "new-pw-123",
	}, nil
}

func (f *rotateRestoreVault) RestoreSecretVersionForPrincipal(_ context.Context, in *vaultv1.RestoreSecretVersionForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.RestoreSecretVersionForPrincipalResponse, error) {
	f.lastRestore = in
	return &vaultv1.RestoreSecretVersionForPrincipalResponse{Secret: &vaultv1.Secret{Id: in.GetSecretId(), Name: "host-a admin"}}, nil
}

func newRotateRestoreClient(fv *rotateRestoreVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)))
	}))
}

// TestRotateSecretForPrincipal_AlwaysReturnsTheNewValue proves the gateway
// bridges rotateSecretForPrincipal straight through, including the value
// (unlike generateSecretForPrincipal's opt-in generatedValue).
func TestRotateSecretForPrincipal_AlwaysReturnsTheNewValue(t *testing.T) {
	fv := &rotateRestoreVault{}
	c := newRotateRestoreClient(fv)
	var resp struct {
		RotateSecretForPrincipal struct {
			Secret   struct{ ID string }
			NewValue string
		}
	}
	c.MustPost(`mutation { rotateSecretForPrincipal(secretId:"s1") { secret { id } newValue } }`, &resp)
	if fv.lastRotate.GetSecretId() != "s1" {
		t.Fatalf("rotate request = %+v", fv.lastRotate)
	}
	if resp.RotateSecretForPrincipal.NewValue != "new-pw-123" {
		t.Fatalf("newValue = %q, want new-pw-123", resp.RotateSecretForPrincipal.NewValue)
	}
}

// TestRestoreSecretVersionForPrincipal_BridgesToVault proves the restore
// mutation passes the version number straight through.
func TestRestoreSecretVersionForPrincipal_BridgesToVault(t *testing.T) {
	fv := &rotateRestoreVault{}
	c := newRotateRestoreClient(fv)
	var resp struct {
		RestoreSecretVersionForPrincipal struct{ ID string }
	}
	c.MustPost(`mutation { restoreSecretVersionForPrincipal(secretId:"s1", versionNo:1) { id } }`, &resp)
	if fv.lastRestore.GetSecretId() != "s1" || fv.lastRestore.GetVersionNo() != 1 {
		t.Fatalf("restore request = %+v", fv.lastRestore)
	}
}
