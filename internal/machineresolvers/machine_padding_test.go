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

// Base64 padding and embedded newlines are where a trim or a normalising
// decode would silently corrupt a stored credential.
var paddedValues = []string{"abc=", "abc==", "YWJjZA==", "x=\n="}

type paddingVault struct {
	vaultv1.VaultServiceClient

	createFields   map[string]string
	generateFields map[string]string
	revealValue    string
}

func (f *paddingVault) CreateSecretForPrincipal(_ context.Context, req *vaultv1.CreateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.CreateSecretForPrincipalResponse, error) {
	f.createFields = req.GetFields()
	return &vaultv1.CreateSecretForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1"}}, nil
}

func (f *paddingVault) GenerateSecretForPrincipal(_ context.Context, req *vaultv1.GenerateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.GenerateSecretForPrincipalResponse, error) {
	f.generateFields = req.GetFields()
	return &vaultv1.GenerateSecretForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1"}}, nil
}

func (f *paddingVault) RevealSecretFieldForPrincipal(_ context.Context, _ *vaultv1.RevealSecretFieldForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldForPrincipalResponse, error) {
	return &vaultv1.RevealSecretFieldForPrincipalResponse{Value: f.revealValue}, nil
}

func newPaddingClient(fv *paddingVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithMachineActor(r.Context(), "sa-1", nil)))
	}))
}

func paddedFieldsVar(v string) gqlclient.Option {
	return gqlclient.Var("fields", []map[string]string{{"key": "apiKey", "value": v}})
}

func TestCreateSecretForPrincipal_PassesPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		fv := &paddingVault{}
		var resp struct{ CreateSecretForPrincipal struct{ ID string } }
		newPaddingClient(fv).MustPost(`mutation($fields:[SecretFieldInput!]!){ createSecretForPrincipal(folderId:"f1", typeId:"t1", name:"n", fields:$fields){ id } }`, &resp, paddedFieldsVar(v))
		if got := fv.createFields["apiKey"]; got != v {
			t.Fatalf("vault got %q, want %q", got, v)
		}
	}
}

func TestGenerateSecretForPrincipal_PassesPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		fv := &paddingVault{}
		var resp struct {
			GenerateSecretForPrincipal struct{ Secret struct{ ID string } }
		}
		newPaddingClient(fv).MustPost(`mutation($fields:[SecretFieldInput!]!){ generateSecretForPrincipal(folderId:"f1", typeId:"t1", name:"n", fields:$fields){ secret { id } } }`, &resp, paddedFieldsVar(v))
		if got := fv.generateFields["apiKey"]; got != v {
			t.Fatalf("vault got %q, want %q", got, v)
		}
	}
}

func TestRevealSecretFieldForPrincipal_ReturnsPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		fv := &paddingVault{revealValue: v}
		var resp struct{ RevealSecretFieldForPrincipal string }
		newPaddingClient(fv).MustPost(`mutation { revealSecretFieldForPrincipal(id:"s1", fieldKey:"apiKey") }`, &resp)
		if resp.RevealSecretFieldForPrincipal != v {
			t.Fatalf("revealed %q, want %q", resp.RevealSecretFieldForPrincipal, v)
		}
	}
}
