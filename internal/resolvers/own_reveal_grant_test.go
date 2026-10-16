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

// ownGrantVault is a fake VaultServiceClient for the "own" RACI grant value
// (#170) round-tripping through setFolderRuleset.
type ownGrantVault struct {
	vaultv1.VaultServiceClient
	lastRuleset *vaultv1.SetFolderRulesetRequest
}

func (f *ownGrantVault) SetFolderRuleset(_ context.Context, in *vaultv1.SetFolderRulesetRequest, _ ...grpc.CallOption) (*vaultv1.SetFolderRulesetResponse, error) {
	f.lastRuleset = in
	return &vaultv1.SetFolderRulesetResponse{}, nil
}

// GetFolderRuleset and ListFolders are called by buildFolderRuleset after a
// save, to return the freshly persisted ruleset; a folder with no ancestors
// keeps that walk a no-op.
func (f *ownGrantVault) GetFolderRuleset(_ context.Context, in *vaultv1.GetFolderRulesetRequest, _ ...grpc.CallOption) (*vaultv1.GetFolderRulesetResponse, error) {
	if f.lastRuleset == nil {
		return &vaultv1.GetFolderRulesetResponse{}, nil
	}
	return &vaultv1.GetFolderRulesetResponse{Owners: f.lastRuleset.GetOwners(), Rules: f.lastRuleset.GetRules()}, nil
}

func (f *ownGrantVault) ListFolders(_ context.Context, _ *vaultv1.ListFoldersRequest, _ ...grpc.CallOption) (*vaultv1.ListFoldersResponse, error) {
	return &vaultv1.ListFoldersResponse{}, nil
}

func newOwnGrantClient(fv *ownGrantVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-carol")))
	}))
}

// TestSetFolderRuleset_OwnGrantRoundTrips proves the "own" RACI grant value
// (#170's "contribute, own reveal" cell) passes through setFolderRuleset to
// the vault's grants map unchanged.
func TestSetFolderRuleset_OwnGrantRoundTrips(t *testing.T) {
	fv := &ownGrantVault{}
	c := newOwnGrantClient(fv)
	var resp struct {
		SetFolderRuleset struct{ FolderID string }
	}
	c.MustPost(`mutation {
		setFolderRuleset(folderId: "f1", owners: ["user-carol"], rules: [
			{subjectKind: user, subjectName: "sa-laps", grants: [{action: R, value: allow}, {action: C, value: own}]}
		]) { folderId }
	}`, &resp)
	if fv.lastRuleset == nil || len(fv.lastRuleset.GetRules()) != 1 {
		t.Fatalf("want 1 rule sent to vault, got %+v", fv.lastRuleset)
	}
	grants := fv.lastRuleset.GetRules()[0].GetGrants()
	if grants["C"] != "own" || grants["R"] != "allow" {
		t.Fatalf("grants = %+v, want C=own R=allow", grants)
	}
}
