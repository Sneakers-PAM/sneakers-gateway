// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The manual secret order: Secret.position from the vault, and
// reorderSecrets passing the caller's order to the vault's ReorderSecrets.

type secretOrderVault struct {
	vaultv1.VaultServiceClient
	secrets []*vaultv1.Secret
	last    *vaultv1.ReorderSecretsRequest
	err     error
}

func (f *secretOrderVault) ListSecretsInFolder(context.Context, *vaultv1.ListSecretsInFolderRequest, ...grpc.CallOption) (*vaultv1.ListSecretsInFolderResponse, error) {
	return &vaultv1.ListSecretsInFolderResponse{Secrets: f.secrets}, nil
}

func (f *secretOrderVault) ReorderSecrets(_ context.Context, in *vaultv1.ReorderSecretsRequest, _ ...grpc.CallOption) (*vaultv1.ReorderSecretsResponse, error) {
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	byID := map[string]*vaultv1.Secret{}
	for _, s := range f.secrets {
		byID[s.GetId()] = s
	}
	var out []*vaultv1.Secret
	for i, id := range in.GetOrderedIds() {
		s := byID[id]
		s.Position = int32(i + 1) // #nosec G115 -- a test list
		s.CanRead = true
		out = append(out, s)
	}
	return &vaultv1.ReorderSecretsResponse{Secrets: out}, nil
}

func newSecretOrderClient(fv *secretOrderVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-morgan")))
	}))
}

func TestSecretPositionReachesTheClient(t *testing.T) {
	fv := &secretOrderVault{secrets: []*vaultv1.Secret{
		{Id: "s1", Name: "b", FolderId: "f", Position: 1},
		{Id: "s2", Name: "a", FolderId: "f", Position: 2},
	}}
	var resp struct {
		SecretsInFolder []struct {
			ID       string
			Position int
		}
	}
	newSecretOrderClient(fv).MustPost(`{ secretsInFolder(folderId:"f") { id position } }`, &resp)
	if len(resp.SecretsInFolder) != 2 || resp.SecretsInFolder[0].Position != 1 || resp.SecretsInFolder[1].Position != 2 {
		t.Fatalf("positions = %+v", resp.SecretsInFolder)
	}
}

func TestReorderSecretsPassesTheOrderAndReturnsIt(t *testing.T) {
	fv := &secretOrderVault{secrets: []*vaultv1.Secret{
		{Id: "s1", Name: "a", FolderId: "f", Position: 1},
		{Id: "s2", Name: "b", FolderId: "f", Position: 2},
	}}
	var resp struct {
		ReorderSecrets []struct {
			ID       string
			Position int
			CanRead  *bool
		}
	}
	newSecretOrderClient(fv).MustPost(`mutation { reorderSecrets(folderId:"f", orderedIds:["s2","s1"]) { id position canRead } }`, &resp)
	if fv.last.GetFolderId() != "f" || strings.Join(fv.last.GetOrderedIds(), ",") != "s2,s1" || fv.last.GetActor().GetUserId() != "user-morgan" {
		t.Fatalf("vault request = %+v", fv.last)
	}
	got := resp.ReorderSecrets
	if len(got) != 2 || got[0].ID != "s2" || got[0].Position != 1 || got[1].ID != "s1" || got[1].Position != 2 {
		t.Fatalf("response = %+v", got)
	}
	if got[0].CanRead == nil || !*got[0].CanRead {
		t.Fatal("canRead must come through from the vault")
	}
}

func TestReorderSecretsPassesVaultRefusals(t *testing.T) {
	fv := &secretOrderVault{err: status.Error(codes.InvalidArgument, "ordered_ids must name every active secret in the folder exactly once")}
	var resp map[string]any
	err := newSecretOrderClient(fv).Post(`mutation { reorderSecrets(folderId:"f", orderedIds:["s1"]) { id } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "exactly once") {
		t.Fatalf("err %v, want the vault's refusal", err)
	}
}
