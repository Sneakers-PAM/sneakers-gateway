// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

// fakeVault embeds the client interface (nil) so it satisfies the type; only
// RevealSecretFieldForPrincipal is exercised here — mirrors
// internal/resolvers/resolver_test.go's fakeVault pattern.
type fakeVault struct {
	vaultv1.VaultServiceClient
	lastReq *vaultv1.RevealSecretFieldForPrincipalRequest
}

func (f *fakeVault) RevealSecretFieldForPrincipal(_ context.Context, req *vaultv1.RevealSecretFieldForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldForPrincipalResponse, error) {
	f.lastReq = req
	return &vaultv1.RevealSecretFieldForPrincipalResponse{Value: "Sup3r$ecret"}, nil
}

// newClient wires the machine gqlgen handler over a fake vault, injecting a
// fixed machine actor (id + scope) as bff.MachineActor does in production.
func newClient(fv *fakeVault, saID, scope string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithMachineActor(r.Context(), saID, strings.Fields(scope))))
	})
	return gqlclient.New(wrapped)
}

func TestRevealSecretFieldForPrincipal_ForwardsMachineActorAndReturnsValue(t *testing.T) {
	fv := &fakeVault{}
	c := newClient(fv, "sa-42", "sneakers-secrets")
	var resp struct{ RevealSecretFieldForPrincipal string }
	c.MustPost(`mutation { revealSecretFieldForPrincipal(id:"s1", fieldKey:"password") }`, &resp)

	if fv.lastReq == nil {
		t.Fatal("vault.RevealSecretFieldForPrincipal was not called")
	}
	actor := fv.lastReq.GetActor()
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT {
		t.Fatalf("actor.PrincipalKind = %v, want SERVICE_ACCOUNT", actor.GetPrincipalKind())
	}
	if actor.GetPrincipalId() != "sa-42" {
		t.Fatalf("actor.PrincipalId = %q, want sa-42", actor.GetPrincipalId())
	}
	if fv.lastReq.GetId() != "s1" || fv.lastReq.GetFieldKey() != "password" {
		t.Fatalf("id/fieldKey not forwarded: %+v", fv.lastReq)
	}
	if resp.RevealSecretFieldForPrincipal != "Sup3r$ecret" {
		t.Fatalf("revealed = %q", resp.RevealSecretFieldForPrincipal)
	}
}

func TestMachineHealth_ReturnsTrue(t *testing.T) {
	c := newClient(&fakeVault{}, "sa-1", "")
	var resp struct{ MachineHealth bool }
	c.MustPost(`{ machineHealth }`, &resp)
	if !resp.MachineHealth {
		t.Fatal("machineHealth = false, want true")
	}
}
