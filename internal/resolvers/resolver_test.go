// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// fakeVault embeds the client interface (nil) so it satisfies the type; only
// the methods a test exercises are overridden. Any other call would panic —
// which is fine, the tests don't make them.
type fakeVault struct {
	vaultv1.VaultServiceClient
	lastActor     string
	genKeyPairErr error
}

func (f *fakeVault) ListSecretTypes(_ context.Context, _ *vaultv1.ListSecretTypesRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretTypesResponse, error) {
	return &vaultv1.ListSecretTypesResponse{Types: []*vaultv1.SecretType{
		{Id: "type-password", Name: "Password", Origin: vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM, Fields: []*vaultv1.SecretFieldDef{
			{Key: "password", Label: "Password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		}},
	}}, nil
}

func (f *fakeVault) ListFolders(_ context.Context, req *vaultv1.ListFoldersRequest, _ ...grpc.CallOption) (*vaultv1.ListFoldersResponse, error) {
	f.lastActor = req.GetActor().GetUserId()
	return &vaultv1.ListFoldersResponse{Folders: []*vaultv1.Folder{
		{Id: "f1", Name: "Platform Team", Scope: vaultv1.FolderScope_FOLDER_SCOPE_GROUP, GroupId: "group-platform"},
	}}, nil
}

func (f *fakeVault) RevealSecretField(_ context.Context, req *vaultv1.RevealSecretFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	f.lastActor = req.GetActor().GetUserId()
	return &vaultv1.RevealSecretFieldResponse{Value: "Sup3r$ecret"}, nil
}

func (f *fakeVault) GenerateKeyPair(_ context.Context, req *vaultv1.GenerateKeyPairRequest, _ ...grpc.CallOption) (*vaultv1.GenerateKeyPairResponse, error) {
	f.lastActor = req.GetActor().GetUserId()
	if f.genKeyPairErr != nil {
		return nil, f.genKeyPairErr
	}
	return &vaultv1.GenerateKeyPairResponse{PrivateKey: "PRIVATE-KEY-MATERIAL", PublicKey: "PUBLIC-KEY-MATERIAL"}, nil
}

// newClient wires the gqlgen handler over a fake vault, injecting a fixed
// no-auth actor (as the HTTP layer does in production).
func newClient(fv *fakeVault, actor string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	})
	return gqlclient.New(wrapped)
}

func TestSecretTypesEnumConversion(t *testing.T) {
	c := newClient(&fakeVault{}, "user-morgan")
	var resp struct {
		SecretTypes []struct {
			ID, Name, Origin string
			Fields           []struct{ Kind string }
		}
	}
	c.MustPost(`{ secretTypes { id name origin fields { kind } } }`, &resp)
	if len(resp.SecretTypes) != 1 {
		t.Fatalf("got %d types, want 1", len(resp.SecretTypes))
	}
	if resp.SecretTypes[0].Origin != "system" {
		t.Fatalf("origin = %q, want system", resp.SecretTypes[0].Origin)
	}
	if resp.SecretTypes[0].Fields[0].Kind != "password" {
		t.Fatalf("field kind = %q, want password", resp.SecretTypes[0].Fields[0].Kind)
	}
}

func TestFoldersForwardsActor(t *testing.T) {
	fv := &fakeVault{}
	c := newClient(fv, "user-morgan")
	var resp struct {
		Folders []struct {
			ID    string
			Scope string
		}
	}
	c.MustPost(`{ folders { id scope } }`, &resp)
	if fv.lastActor != "user-morgan" {
		t.Fatalf("actor forwarded = %q, want user-morgan", fv.lastActor)
	}
	if len(resp.Folders) != 1 || resp.Folders[0].Scope != "group" {
		t.Fatalf("folders = %+v, want 1 group folder", resp.Folders)
	}
}

func TestRevealForwardsActorAndReturnsValue(t *testing.T) {
	fv := &fakeVault{}
	c := newClient(fv, "user-clarke")
	var resp struct{ RevealSecretField string }
	c.MustPost(`mutation { revealSecretField(id:"s1", fieldKey:"password") }`, &resp)
	if fv.lastActor != "user-clarke" {
		t.Fatalf("reveal actor = %q, want user-clarke", fv.lastActor)
	}
	if resp.RevealSecretField != "Sup3r$ecret" {
		t.Fatalf("revealed = %q", resp.RevealSecretField)
	}
}

func TestGenerateKeyPairForwardsActorAndReturnsKeyPair(t *testing.T) {
	fv := &fakeVault{}
	c := newClient(fv, "user-clarke")
	var resp struct {
		GenerateKeyPair struct{ PrivateKey, PublicKey string }
	}
	c.MustPost(`mutation { generateKeyPair(format: "rsa2048") { privateKey publicKey } }`, &resp)
	if fv.lastActor != "user-clarke" {
		t.Fatalf("actor forwarded = %q, want user-clarke", fv.lastActor)
	}
	if resp.GenerateKeyPair.PrivateKey != "PRIVATE-KEY-MATERIAL" || resp.GenerateKeyPair.PublicKey != "PUBLIC-KEY-MATERIAL" {
		t.Fatalf("keypair = %+v, want mapped vault response", resp.GenerateKeyPair)
	}
}

func TestGenerateKeyPairPropagatesVaultError(t *testing.T) {
	fv := &fakeVault{genKeyPairErr: errors.New("vault: key generation failed")}
	c := newClient(fv, "user-clarke")
	var resp struct {
		GenerateKeyPair struct{ PrivateKey, PublicKey string }
	}
	if err := c.Post(`mutation { generateKeyPair(format: "rsa2048") { privateKey publicKey } }`, &resp); err == nil {
		t.Fatal("expected error from vault to propagate, got nil")
	}
}
