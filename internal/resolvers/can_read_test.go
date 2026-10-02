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

// canRead comes from the vault on secretsInFolder and secret, so the web app
// can show a secret the user can see but not read as locked.

type fakeCanReadVault struct {
	vaultv1.VaultServiceClient
	secrets []*vaultv1.Secret
}

func (f *fakeCanReadVault) ListSecretsInFolder(_ context.Context, _ *vaultv1.ListSecretsInFolderRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretsInFolderResponse, error) {
	return &vaultv1.ListSecretsInFolderResponse{Secrets: f.secrets}, nil
}

func (f *fakeCanReadVault) GetSecret(_ context.Context, req *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	for _, s := range f.secrets {
		if s.GetId() == req.GetId() {
			return &vaultv1.GetSecretResponse{Secret: s}, nil
		}
	}
	return &vaultv1.GetSecretResponse{}, nil
}

func TestCanReadReachesTheClient(t *testing.T) {
	fv := &fakeCanReadVault{secrets: []*vaultv1.Secret{
		{Id: "s-open", Name: "open", FolderId: "f", CanRead: true},
		{Id: "s-locked", Name: "locked", FolderId: "f"},
	}}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-morgan")))
	}))

	var list struct {
		SecretsInFolder []struct {
			ID      string
			CanRead *bool
		}
	}
	c.MustPost(`{ secretsInFolder(folderId: "f") { id canRead } }`, &list)
	got := map[string]*bool{}
	for _, s := range list.SecretsInFolder {
		got[s.ID] = s.CanRead
	}
	if got["s-open"] == nil || !*got["s-open"] || got["s-locked"] == nil || *got["s-locked"] {
		t.Fatalf("secretsInFolder canRead = %v", got)
	}

	var one struct {
		Secret struct{ CanRead *bool }
	}
	c.MustPost(`{ secret(id: "s-locked") { canRead } }`, &one)
	if one.Secret.CanRead == nil || *one.Secret.CanRead {
		t.Fatalf("secret canRead = %v, want false", one.Secret.CanRead)
	}
}
