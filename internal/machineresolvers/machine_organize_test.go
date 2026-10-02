// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type organizeVault struct {
	vaultv1.VaultServiceClient

	lastRenameSecret *vaultv1.RenameSecretForPrincipalRequest
	lastUpdate       *vaultv1.UpdateSecretFieldsForPrincipalRequest
	updateResp       *vaultv1.UpdateSecretFieldsForPrincipalResponse
	lastCreateFolder *vaultv1.CreateFolderForPrincipalRequest
	lastRenameFolder *vaultv1.RenameFolderForPrincipalRequest
	lastListFolders  *vaultv1.ListFoldersForPrincipalRequest
	listFolders      []*vaultv1.Folder
	listErr          error
	err              error
}

func (f *organizeVault) ListFoldersForPrincipal(_ context.Context, in *vaultv1.ListFoldersForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.ListFoldersForPrincipalResponse, error) {
	f.lastListFolders = in
	if f.listErr != nil {
		return nil, f.listErr
	}
	return &vaultv1.ListFoldersForPrincipalResponse{Folders: f.listFolders}, nil
}

func (f *organizeVault) RenameSecretForPrincipal(_ context.Context, in *vaultv1.RenameSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.RenameSecretForPrincipalResponse, error) {
	f.lastRenameSecret = in
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.RenameSecretForPrincipalResponse{Secret: &vaultv1.Secret{Id: in.GetId(), Name: in.GetName(), FolderId: "f1", TypeId: "type-password", TargetId: "t1"}}, nil
}

func (f *organizeVault) UpdateSecretFieldsForPrincipal(_ context.Context, in *vaultv1.UpdateSecretFieldsForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecretFieldsForPrincipalResponse, error) {
	f.lastUpdate = in
	if f.err != nil {
		return nil, f.err
	}
	return f.updateResp, nil
}

func (f *organizeVault) CreateFolderForPrincipal(_ context.Context, in *vaultv1.CreateFolderForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.CreateFolderForPrincipalResponse, error) {
	f.lastCreateFolder = in
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.CreateFolderForPrincipalResponse{Folder: &vaultv1.Folder{Id: "f9", Name: in.GetName(), ParentId: in.GetParentId(), CanManage: true}}, nil
}

func (f *organizeVault) RenameFolderForPrincipal(_ context.Context, in *vaultv1.RenameFolderForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.RenameFolderForPrincipalResponse, error) {
	f.lastRenameFolder = in
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.RenameFolderForPrincipalResponse{Folder: &vaultv1.Folder{Id: in.GetId(), Name: in.GetName(), CanManage: true}}, nil
}

type principalFolderResp struct {
	ID, Name, Path string
	ParentID       *string
	CanAuthor      bool
}

func TestRenameSecretForPrincipal_ForwardsActorAndMapsSummary(t *testing.T) {
	fv := &organizeVault{}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		RenameSecretForPrincipal struct{ ID, Name, FolderID, TypeID, TargetID string }
	}
	c.MustPost(`mutation { renameSecretForPrincipal(id: "s1", name: "svc-web") { id name folderId typeId targetId } }`, &resp)

	if fv.lastRenameSecret == nil {
		t.Fatal("vault.RenameSecretForPrincipal was not called")
	}
	assertMachineActor(t, fv.lastRenameSecret.GetActor(), "sa-7")
	if fv.lastRenameSecret.GetId() != "s1" || fv.lastRenameSecret.GetName() != "svc-web" {
		t.Fatalf("args not forwarded: %+v", fv.lastRenameSecret)
	}
	got := resp.RenameSecretForPrincipal
	if got.ID != "s1" || got.Name != "svc-web" || got.FolderID != "f1" || got.TypeID != "type-password" || got.TargetID != "t1" {
		t.Fatalf("summary mapped wrong: %+v", got)
	}
}

func TestRenameSecretForPrincipal_VaultErrorSurfaces(t *testing.T) {
	fv := &organizeVault{err: status.Error(codes.FailedPrecondition, "secret is retired")}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ RenameSecretForPrincipal *struct{ ID string } }
	err := c.Post(`mutation { renameSecretForPrincipal(id: "s1", name: "x") { id } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "secret is retired") {
		t.Fatalf("want the vault error surfaced, got %v", err)
	}
}

func TestUpdateSecretFieldsForPrincipal_ForwardsFieldsAndReturnsKeysOnly(t *testing.T) {
	fv := &organizeVault{updateResp: &vaultv1.UpdateSecretFieldsForPrincipalResponse{
		Secret:           &vaultv1.Secret{Id: "s1", Name: "svc", FolderId: "f1", TypeId: "type-password"},
		ChangedFieldKeys: []string{"notes", "password"},
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		UpdateSecretFieldsForPrincipal struct {
			Secret           struct{ ID, Name string }
			ChangedFieldKeys []string
		}
	}
	c.MustPost(`mutation { updateSecretFieldsForPrincipal(id: "s1", fields: [{key: "password", value: "n3w-Value"}, {key: "notes", value: ""}]) {
		secret { id name } changedFieldKeys } }`, &resp)

	if fv.lastUpdate == nil {
		t.Fatal("vault.UpdateSecretFieldsForPrincipal was not called")
	}
	assertMachineActor(t, fv.lastUpdate.GetActor(), "sa-7")
	f := fv.lastUpdate.GetFields()
	notes, hasNotes := f["notes"]
	if fv.lastUpdate.GetId() != "s1" || len(f) != 2 || f["password"] != "n3w-Value" || !hasNotes || notes != "" {
		t.Fatalf("args not forwarded: %+v", fv.lastUpdate)
	}
	got := resp.UpdateSecretFieldsForPrincipal
	if got.Secret.ID != "s1" || got.Secret.Name != "svc" || strings.Join(got.ChangedFieldKeys, ",") != "notes,password" {
		t.Fatalf("result mapped wrong: %+v", got)
	}
}

func TestUpdateSecretFieldsForPrincipal_NoChangeReturnsEmptyKeys(t *testing.T) {
	fv := &organizeVault{updateResp: &vaultv1.UpdateSecretFieldsForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1"}}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		UpdateSecretFieldsForPrincipal struct{ ChangedFieldKeys []string }
	}
	c.MustPost(`mutation { updateSecretFieldsForPrincipal(id: "s1", fields: [{key: "notes", value: "same"}]) { changedFieldKeys } }`, &resp)
	if resp.UpdateSecretFieldsForPrincipal.ChangedFieldKeys == nil || len(resp.UpdateSecretFieldsForPrincipal.ChangedFieldKeys) != 0 {
		t.Fatalf("want [], got %#v", resp.UpdateSecretFieldsForPrincipal.ChangedFieldKeys)
	}
}

func TestUpdateSecretFieldsForPrincipal_DuplicateKeyRejectedWithoutCallingVault(t *testing.T) {
	fv := &organizeVault{}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		UpdateSecretFieldsForPrincipal *struct{ ChangedFieldKeys []string }
	}
	err := c.Post(`mutation { updateSecretFieldsForPrincipal(id: "s1", fields: [{key: "notes", value: "a"}, {key: "notes", value: "b"}]) { changedFieldKeys } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "duplicate field key") {
		t.Fatalf("want duplicate-key error, got %v", err)
	}
	if fv.lastUpdate != nil {
		t.Fatal("vault was called despite a duplicate key")
	}
}

func TestUpdateSecretFieldsForPrincipal_VaultErrorSurfaces(t *testing.T) {
	fv := &organizeVault{err: status.Error(codes.FailedPrecondition, "only notes and description may change on a managed type")}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		UpdateSecretFieldsForPrincipal *struct{ ChangedFieldKeys []string }
	}
	err := c.Post(`mutation { updateSecretFieldsForPrincipal(id: "s1", fields: [{key: "password", value: "x"}]) { changedFieldKeys } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "managed type") {
		t.Fatalf("want the vault error surfaced, got %v", err)
	}
}

func TestCreateFolderForPrincipal_ForwardsActorAndMapsFolder(t *testing.T) {
	fv := &organizeVault{}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ CreateFolderForPrincipal principalFolderResp }
	c.MustPost(`mutation { createFolderForPrincipal(parentId: "f1", name: "web") { id name parentId path canAuthor } }`, &resp)

	if fv.lastCreateFolder == nil {
		t.Fatal("vault.CreateFolderForPrincipal was not called")
	}
	assertMachineActor(t, fv.lastCreateFolder.GetActor(), "sa-7")
	if fv.lastCreateFolder.GetParentId() != "f1" || fv.lastCreateFolder.GetName() != "web" {
		t.Fatalf("args not forwarded: %+v", fv.lastCreateFolder)
	}
	got := resp.CreateFolderForPrincipal
	if got.ID != "f9" || got.Name != "web" || got.ParentID == nil || *got.ParentID != "f1" || got.Path != "web" || !got.CanAuthor {
		t.Fatalf("folder mapped wrong: %+v", got)
	}
}

func TestCreateFolderForPrincipal_VaultErrorSurfaces(t *testing.T) {
	fv := &organizeVault{err: status.Error(codes.AlreadyExists, "a folder with that name already exists here")}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ CreateFolderForPrincipal *struct{ ID string } }
	err := c.Post(`mutation { createFolderForPrincipal(parentId: "f1", name: "web") { id } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want the vault error surfaced, got %v", err)
	}
}

func TestRenameFolderForPrincipal_ForwardsActorAndMapsFolder(t *testing.T) {
	fv := &organizeVault{}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ RenameFolderForPrincipal principalFolderResp }
	c.MustPost(`mutation { renameFolderForPrincipal(id: "f2", name: "ops") { id name parentId path canAuthor } }`, &resp)

	if fv.lastRenameFolder == nil {
		t.Fatal("vault.RenameFolderForPrincipal was not called")
	}
	assertMachineActor(t, fv.lastRenameFolder.GetActor(), "sa-7")
	if fv.lastRenameFolder.GetId() != "f2" || fv.lastRenameFolder.GetName() != "ops" {
		t.Fatalf("args not forwarded: %+v", fv.lastRenameFolder)
	}
	got := resp.RenameFolderForPrincipal
	if got.ID != "f2" || got.Name != "ops" || got.ParentID != nil || got.Path != "ops" || !got.CanAuthor {
		t.Fatalf("folder mapped wrong: %+v", got)
	}
}

func TestRenameFolderForPrincipal_VaultErrorSurfaces(t *testing.T) {
	fv := &organizeVault{err: status.Error(codes.PermissionDenied, "not permitted to rename this folder")}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ RenameFolderForPrincipal *struct{ ID string } }
	err := c.Post(`mutation { renameFolderForPrincipal(id: "f2", name: "ops") { id } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("want the vault error surfaced, got %v", err)
	}
}

func TestCreateFolderForPrincipal_ReturnsFullVisiblePath(t *testing.T) {
	fv := &organizeVault{listFolders: []*vaultv1.Folder{
		{Id: "f1", Name: "Infrastructure", CanManage: true},
		{Id: "f9", Name: "AD", ParentId: "f1", CanManage: true},
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ CreateFolderForPrincipal principalFolderResp }
	c.MustPost(`mutation { createFolderForPrincipal(parentId: "f1", name: "AD") { id name parentId path canAuthor } }`, &resp)

	if fv.lastListFolders == nil {
		t.Fatal("vault.ListFoldersForPrincipal was not called")
	}
	assertMachineActor(t, fv.lastCreateFolder.GetActor(), "sa-7")
	assertMachineActor(t, fv.lastListFolders.GetActor(), "sa-7")
	got := resp.CreateFolderForPrincipal
	if got.ID != "f9" || got.Name != "AD" || got.ParentID == nil || *got.ParentID != "f1" || got.Path != "Infrastructure/AD" || !got.CanAuthor {
		t.Fatalf("folder mapped wrong: %+v", got)
	}
}

func TestRenameFolderForPrincipal_ReturnsFullVisiblePathWithNewName(t *testing.T) {
	fv := &organizeVault{listFolders: []*vaultv1.Folder{
		{Id: "f1", Name: "Infrastructure", CanManage: true},
		{Id: "f2", Name: "ops", ParentId: "f1", CanManage: true},
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ RenameFolderForPrincipal principalFolderResp }
	c.MustPost(`mutation { renameFolderForPrincipal(id: "f2", name: "ops") { id name parentId path canAuthor } }`, &resp)

	if fv.lastListFolders == nil {
		t.Fatal("vault.ListFoldersForPrincipal was not called")
	}
	assertMachineActor(t, fv.lastRenameFolder.GetActor(), "sa-7")
	assertMachineActor(t, fv.lastListFolders.GetActor(), "sa-7")
	got := resp.RenameFolderForPrincipal
	if got.ID != "f2" || got.Name != "ops" || got.ParentID == nil || *got.ParentID != "f1" || got.Path != "Infrastructure/ops" || !got.CanAuthor {
		t.Fatalf("folder mapped wrong: %+v", got)
	}
}

func TestCreateFolderForPrincipal_FallsBackToNameWhenNotListed(t *testing.T) {
	fv := &organizeVault{listFolders: []*vaultv1.Folder{
		{Id: "f1", Name: "Infrastructure", CanManage: true},
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ CreateFolderForPrincipal principalFolderResp }
	c.MustPost(`mutation { createFolderForPrincipal(parentId: "f1", name: "AD") { id name path } }`, &resp)

	if got := resp.CreateFolderForPrincipal; got.ID != "f9" || got.Path != "AD" {
		t.Fatalf("want fallback to the name, got %+v", got)
	}
}

func TestRenameFolderForPrincipal_FallsBackToNameWhenListingFails(t *testing.T) {
	fv := &organizeVault{listErr: status.Error(codes.Unavailable, "vault unavailable")}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ RenameFolderForPrincipal principalFolderResp }
	c.MustPost(`mutation { renameFolderForPrincipal(id: "f2", name: "ops") { id name path } }`, &resp)

	if got := resp.RenameFolderForPrincipal; got.ID != "f2" || got.Path != "ops" {
		t.Fatalf("want fallback to the name, got %+v", got)
	}
}
