// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"

	"net/http"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// fakeOwnerVault is a minimal vault fake covering only the calls
// folderRuleset/inheritedOwners makes: ListFolders (for the ancestor chain)
// and GetFolderRuleset (per folder, keyed by folder id).
type fakeOwnerVault struct {
	vaultv1.VaultServiceClient
	folders  []*vaultv1.Folder
	rulesets map[string]*vaultv1.GetFolderRulesetResponse
}

func (f *fakeOwnerVault) ListFolders(_ context.Context, _ *vaultv1.ListFoldersRequest, _ ...grpc.CallOption) (*vaultv1.ListFoldersResponse, error) {
	return &vaultv1.ListFoldersResponse{Folders: f.folders}, nil
}

func (f *fakeOwnerVault) GetFolderRuleset(_ context.Context, req *vaultv1.GetFolderRulesetRequest, _ ...grpc.CallOption) (*vaultv1.GetFolderRulesetResponse, error) {
	if rs, ok := f.rulesets[req.GetFolderId()]; ok {
		return rs, nil
	}
	return &vaultv1.GetFolderRulesetResponse{}, nil
}

func newOwnerClient(fv *fakeOwnerVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-morgan")))
	})
	return gqlclient.New(wrapped)
}

// TestFolderRulesetInheritsOwnersFromAncestor covers this case:
// a folder with no owners of its own ("World") sits under a parent ("Hello")
// that owns it. The Sharing page needs folderRuleset(World).inheritedOwners
// to surface Hello's owner — folderRuleset.owners alone only ever carries
// the folder's own owners, never inherited ones.
func TestFolderRulesetInheritsOwnersFromAncestor(t *testing.T) {
	fv := &fakeOwnerVault{
		folders: []*vaultv1.Folder{
			{Id: "folder-hello", Name: "Hello"},
			{Id: "folder-world", Name: "World", ParentId: "folder-hello"},
		},
		rulesets: map[string]*vaultv1.GetFolderRulesetResponse{
			"folder-hello": {Owners: []string{"user-morgan"}},
			"folder-world": {Owners: []string{}},
		},
	}
	c := newOwnerClient(fv)

	var resp struct {
		FolderRuleset struct {
			Owners          []string
			InheritedOwners []struct {
				UserID         string `json:"userId"`
				FromFolderID   string `json:"fromFolderId"`
				FromFolderName string `json:"fromFolderName"`
			}
		}
	}
	err := c.Post(`query { folderRuleset(folderId: "folder-world") {
		owners
		inheritedOwners { userId fromFolderId fromFolderName }
	} }`, &resp)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(resp.FolderRuleset.Owners) != 0 {
		t.Fatalf("expected World to have no owners of its own, got %v", resp.FolderRuleset.Owners)
	}
	if len(resp.FolderRuleset.InheritedOwners) != 1 {
		t.Fatalf("expected exactly one inherited owner, got %v", resp.FolderRuleset.InheritedOwners)
	}
	got := resp.FolderRuleset.InheritedOwners[0]
	if got.UserID != "user-morgan" || got.FromFolderID != "folder-hello" || got.FromFolderName != "Hello" {
		t.Fatalf("unexpected inherited owner: %+v", got)
	}
}

// TestFolderRulesetInheritedOwnersDedupeNearestWins verifies that when the
// same user owns multiple ancestors, only the nearest ancestor's tag surfaces
// — and that a personal-scope ancestor's implicit owner_user_id counts as an
// owner even though it never appears in that folder's ruleset.owners.
func TestFolderRulesetInheritedOwnersDedupeNearestWins(t *testing.T) {
	fv := &fakeOwnerVault{
		folders: []*vaultv1.Folder{
			{Id: "folder-root", Name: "Root", Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: "user-morgan"},
			{Id: "folder-mid", Name: "Mid", ParentId: "folder-root", Owners: []string{"user-morgan"}},
			{Id: "folder-leaf", Name: "Leaf", ParentId: "folder-mid"},
		},
		rulesets: map[string]*vaultv1.GetFolderRulesetResponse{
			"folder-mid": {Owners: []string{"user-morgan"}},
		},
	}
	c := newOwnerClient(fv)

	var resp struct {
		FolderRuleset struct {
			InheritedOwners []struct {
				UserID       string `json:"userId"`
				FromFolderID string `json:"fromFolderId"`
			}
		}
	}
	err := c.Post(`query { folderRuleset(folderId: "folder-leaf") {
		inheritedOwners { userId fromFolderId }
	} }`, &resp)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if len(resp.FolderRuleset.InheritedOwners) != 1 {
		t.Fatalf("expected user-morgan deduped to a single entry, got %v", resp.FolderRuleset.InheritedOwners)
	}
	if got := resp.FolderRuleset.InheritedOwners[0]; got.UserID != "user-morgan" || got.FromFolderID != "folder-mid" {
		t.Fatalf("expected nearest ancestor (folder-mid) to win, got %+v", got)
	}
}
