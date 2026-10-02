// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"strings"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeMutateVault records the move/change-type requests and can return a
// vault error, so the resolvers' thin pass-through (machine actor, args, error
// surfacing) is pinned without a real vault.
type fakeMutateVault struct {
	vaultv1.VaultServiceClient

	lastMoveReq   *vaultv1.MoveSecretForPrincipalRequest
	moveResp      *vaultv1.MoveSecretForPrincipalResponse
	lastRetypeReq *vaultv1.ChangeSecretTypeForPrincipalRequest
	retypeResp    *vaultv1.ChangeSecretTypeForPrincipalResponse
	err           error
}

func (f *fakeMutateVault) MoveSecretForPrincipal(_ context.Context, req *vaultv1.MoveSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.MoveSecretForPrincipalResponse, error) {
	f.lastMoveReq = req
	return f.moveResp, f.err
}

func (f *fakeMutateVault) ChangeSecretTypeForPrincipal(_ context.Context, req *vaultv1.ChangeSecretTypeForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.ChangeSecretTypeForPrincipalResponse, error) {
	f.lastRetypeReq = req
	return f.retypeResp, f.err
}

func assertMachineActor(t *testing.T, a *vaultv1.ActorContext, id string) {
	t.Helper()
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT || a.GetPrincipalId() != id {
		t.Fatalf("actor = %v/%q, want SERVICE_ACCOUNT/%q", a.GetPrincipalKind(), a.GetPrincipalId(), id)
	}
	if a.GetIsSiteAdmin() || a.GetIsRoot() || a.GetUserId() != "" {
		t.Fatalf("machine actor must carry no human identity or admin flags: %+v", a)
	}
}

func TestMoveSecretForPrincipal_ForwardsMachineActorAndArgs(t *testing.T) {
	fv := &fakeMutateVault{moveResp: &vaultv1.MoveSecretForPrincipalResponse{
		Secret: &vaultv1.Secret{Id: "s1", Name: "svc", FolderId: "f-dst", TypeId: "type-password"},
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "sneakers-secrets")
	var resp struct {
		MoveSecretForPrincipal struct{ ID, FolderID string }
	}
	c.MustPost(`mutation { moveSecretForPrincipal(id: "s1", destFolderId: "f-dst") { id folderId } }`, &resp)

	if fv.lastMoveReq == nil {
		t.Fatal("vault.MoveSecretForPrincipal was not called")
	}
	assertMachineActor(t, fv.lastMoveReq.GetActor(), "sa-7")
	if fv.lastMoveReq.GetId() != "s1" || fv.lastMoveReq.GetDestFolderId() != "f-dst" {
		t.Fatalf("args not forwarded: %+v", fv.lastMoveReq)
	}
	if resp.MoveSecretForPrincipal.ID != "s1" || resp.MoveSecretForPrincipal.FolderID != "f-dst" {
		t.Fatalf("summary mapped wrong: %+v", resp.MoveSecretForPrincipal)
	}
}

func TestMoveSecretForPrincipal_VaultDenialSurfacesAsError(t *testing.T) {
	fv := &fakeMutateVault{err: status.Error(codes.PermissionDenied, "not permitted to move the secret to that folder")}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ MoveSecretForPrincipal *struct{ ID string } }
	err := c.Post(`mutation { moveSecretForPrincipal(id: "s1", destFolderId: "f-dst") { id } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("want the vault PermissionDenied surfaced, got %v", err)
	}
}

func TestChangeSecretTypeForPrincipal_ForwardsMappingAndFields(t *testing.T) {
	fv := &fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{
		Secret:    &vaultv1.Secret{Id: "s1", Name: "svc", FolderId: "f", TypeId: "type-web-password"},
		FieldKeys: []string{"password", "url", "username"},
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		ChangeSecretTypeForPrincipal struct {
			Secret    struct{ ID, TypeID string }
			FieldKeys []string
		}
	}
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-web-password",
		fieldMapping: [{from: "notes", to: "description"}],
		fields: [{key: "url", value: "https://x.test"}]) { secret { id typeId } fieldKeys } }`, &resp)

	r := fv.lastRetypeReq
	if r == nil {
		t.Fatal("vault.ChangeSecretTypeForPrincipal was not called")
	}
	assertMachineActor(t, r.GetActor(), "sa-7")
	if r.GetId() != "s1" || r.GetNewTypeId() != "type-web-password" ||
		r.GetFieldMapping()["notes"] != "description" || len(r.GetFieldMapping()) != 1 ||
		r.GetFields()["url"] != "https://x.test" || len(r.GetFields()) != 1 {
		t.Fatalf("args not forwarded: %+v", r)
	}
	got := resp.ChangeSecretTypeForPrincipal
	if got.Secret.TypeID != "type-web-password" || strings.Join(got.FieldKeys, ",") != "password,url,username" {
		t.Fatalf("result mapped wrong: %+v", got)
	}
}

func TestChangeSecretTypeForPrincipal_OmittedOptionalArgsForwardEmpty(t *testing.T) {
	fv := &fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1"}}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		ChangeSecretTypeForPrincipal struct{ FieldKeys []string }
	}
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-secure-note") { fieldKeys } }`, &resp)
	if len(fv.lastRetypeReq.GetFieldMapping()) != 0 || len(fv.lastRetypeReq.GetFields()) != 0 {
		t.Fatalf("expected empty mapping/fields, got %+v", fv.lastRetypeReq)
	}
	if resp.ChangeSecretTypeForPrincipal.FieldKeys == nil {
		t.Fatal("fieldKeys must be a non-null list")
	}
}

// A repeated mapping source would silently last-write-win, so it is rejected
// before vault is called (mirrors fieldMap's duplicate-key rule).
func TestChangeSecretTypeForPrincipal_DuplicateMappingRejectedWithoutCallingVault(t *testing.T) {
	fv := &fakeMutateVault{}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ ChangeSecretTypeForPrincipal *struct{ FieldKeys []string } }
	err := c.Post(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "t",
		fieldMapping: [{from: "notes", to: "a"}, {from: "notes", to: "b"}]) { fieldKeys } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "duplicate field mapping") {
		t.Fatalf("want duplicate field mapping error, got %v", err)
	}
	if fv.lastRetypeReq != nil {
		t.Fatal("vault must not be called on a duplicate mapping")
	}
	err = c.Post(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "t",
		fields: [{key: "url", value: "v1"}, {key: "url", value: "v2"}]) { fieldKeys } }`, &resp)
	if err == nil || fv.lastRetypeReq != nil {
		t.Fatalf("duplicate field key must be rejected without calling vault, err=%v", err)
	}
	if strings.Contains(err.Error(), "v1") || strings.Contains(err.Error(), "v2") {
		t.Fatalf("error leaks a field value: %v", err)
	}
}

func TestChangeSecretTypeForPrincipal_VaultDenialSurfacesAsError(t *testing.T) {
	fv := &fakeMutateVault{err: status.Error(codes.FailedPrecondition, "type change would drop the value of field(s) notes")}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct{ ChangeSecretTypeForPrincipal *struct{ FieldKeys []string } }
	err := c.Post(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-secure-note") { fieldKeys } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "would drop") {
		t.Fatalf("want the vault FailedPrecondition surfaced, got %v", err)
	}
}
