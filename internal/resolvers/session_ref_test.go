// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

type sessionRefVault struct {
	vaultv1.VaultServiceClient
	reveal *vaultv1.RevealSecretFieldRequest
}

func (f *sessionRefVault) RevealSecretField(_ context.Context, req *vaultv1.RevealSecretFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	f.reveal = req
	return &vaultv1.RevealSecretFieldResponse{Value: "example-value"}, nil
}

// Every vault call made for a person carries their web session reference,
// so the vault can tell a person's own session from a caller that only
// claims to be one.
func TestAWebRevealCarriesTheSessionRef(t *testing.T) {
	v := &sessionRefVault{}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: v}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithSessionRef(WithActor(r.Context(), "u-bob"), "ref-web-3")))
	}))
	var resp struct{ RevealSecretField string }
	c.MustPost(`mutation { revealSecretField(id: "s-1", fieldKey: "password") }`, &resp)
	a := v.reveal.GetActor()
	if a.GetUserId() != "u-bob" || a.GetSessionRef() != "ref-web-3" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		t.Fatalf("vault actor = %+v", a)
	}
}

// The broker passes the person's web session reference on to the key reveal.
func TestBrokerActorCarriesTheWebSessionRef(t *testing.T) {
	got := brokerActor(&vaultv1.ActorContext{UserId: "u-1", SessionRef: "ref-web-4"})
	if got.GetSessionRef() != "ref-web-4" {
		t.Fatalf("broker actor = %+v", got)
	}
}
