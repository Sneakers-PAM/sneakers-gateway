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
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// Base64 padding and embedded newlines are where a trim or a normalising
// decode would silently corrupt a stored credential.
var paddedValues = []string{"abc=", "abc==", "YWJjZA==", "x=\n="}

type paddingVault struct {
	fakeVault

	createFields map[string]string
	updateFields map[string]string
	revealValue  string
}

func (f *paddingVault) CreateSecret(_ context.Context, req *vaultv1.CreateSecretRequest, _ ...grpc.CallOption) (*vaultv1.CreateSecretResponse, error) {
	f.createFields = req.GetFields()
	return &vaultv1.CreateSecretResponse{Secret: &vaultv1.Secret{Id: "s1"}}, nil
}

func (f *paddingVault) UpdateSecret(_ context.Context, req *vaultv1.UpdateSecretRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecretResponse, error) {
	f.updateFields = req.GetFields()
	return &vaultv1.UpdateSecretResponse{Secret: &vaultv1.Secret{Id: "s1"}}, nil
}

func (f *paddingVault) RevealSecretField(_ context.Context, _ *vaultv1.RevealSecretFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	return &vaultv1.RevealSecretFieldResponse{Value: f.revealValue}, nil
}

func newPaddingClient(fv *paddingVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-1")))
	}))
}

func paddedFieldsVar(v string) gqlclient.Option {
	return gqlclient.Var("fields", []map[string]string{{"key": "apiKey", "value": v}})
}

func TestCreateSecret_PassesPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		fv := &paddingVault{}
		var resp struct{ CreateSecret struct{ ID string } }
		newPaddingClient(fv).MustPost(`mutation($fields:[KeyValueInput!]!){ createSecret(input:{name:"n", folderId:"f1", typeId:"t1", fields:$fields}){ id } }`, &resp, paddedFieldsVar(v))
		if got := fv.createFields["apiKey"]; got != v {
			t.Fatalf("vault got %q, want %q", got, v)
		}
	}
}

func TestUpdateSecret_PassesPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		fv := &paddingVault{}
		var resp struct{ UpdateSecret struct{ ID string } }
		newPaddingClient(fv).MustPost(`mutation($fields:[KeyValueInput!]){ updateSecret(id:"s1", input:{fields:$fields}){ id } }`, &resp, paddedFieldsVar(v))
		if got := fv.updateFields["apiKey"]; got != v {
			t.Fatalf("vault got %q, want %q", got, v)
		}
	}
}

func TestRevealSecretField_ReturnsPaddedValueExactly(t *testing.T) {
	for _, v := range paddedValues {
		fv := &paddingVault{revealValue: v}
		var resp struct{ RevealSecretField string }
		newPaddingClient(fv).MustPost(`mutation { revealSecretField(id:"s1", fieldKey:"apiKey") }`, &resp)
		if resp.RevealSecretField != v {
			t.Fatalf("revealed %q, want %q", resp.RevealSecretField, v)
		}
	}
}
