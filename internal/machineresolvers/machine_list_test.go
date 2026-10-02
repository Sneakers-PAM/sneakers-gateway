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
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// listVault fakes the two catalog RPCs behind foldersForPrincipal/secretTypes.
type listVault struct {
	vaultv1.VaultServiceClient

	lastFoldersReq *vaultv1.ListFoldersForPrincipalRequest
	foldersResp    *vaultv1.ListFoldersForPrincipalResponse
	typesCalled    bool
	typesResp      *vaultv1.ListSecretTypesResponse
}

func (f *listVault) ListFoldersForPrincipal(_ context.Context, req *vaultv1.ListFoldersForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.ListFoldersForPrincipalResponse, error) {
	f.lastFoldersReq = req
	return f.foldersResp, nil
}

func (f *listVault) ListSecretTypes(_ context.Context, _ *vaultv1.ListSecretTypesRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretTypesResponse, error) {
	f.typesCalled = true
	return f.typesResp, nil
}

func TestFoldersForPrincipal_ForwardsActorAndBuildsPaths(t *testing.T) {
	fv := &listVault{foldersResp: &vaultv1.ListFoldersForPrincipalResponse{Folders: []*vaultv1.Folder{
		{Id: "f-infra", Name: "Infrastructure"},
		{Id: "f-sa", Name: "Service Accounts", ParentId: "f-infra", CanManage: true},
		// Parent not visible to the principal: the path starts at the first
		// visible ancestor, here the folder itself.
		{Id: "f-deep", Name: "Keytabs", ParentId: "f-hidden", CanManage: true},
	}}}
	var resp struct {
		FoldersForPrincipal []struct {
			ID        string
			Name      string
			ParentID  *string
			Path      string
			CanAuthor bool
		}
	}
	newListClient(fv).MustPost(`query { foldersForPrincipal { id name parentId path canAuthor } }`, &resp)

	req := fv.lastFoldersReq
	if req == nil {
		t.Fatal("vault.ListFoldersForPrincipal was not called")
	}
	if req.GetActor().GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT || req.GetActor().GetPrincipalId() != "sa-42" {
		t.Fatalf("machine actor not forwarded: %+v", req.GetActor())
	}
	got := resp.FoldersForPrincipal
	if len(got) != 3 {
		t.Fatalf("got %d folders, want 3", len(got))
	}
	if got[0].ParentID != nil || got[0].Path != "Infrastructure" || got[0].CanAuthor {
		t.Fatalf("top-level folder mapped wrong: %+v", got[0])
	}
	if got[1].ParentID == nil || *got[1].ParentID != "f-infra" || got[1].Path != "Infrastructure/Service Accounts" || !got[1].CanAuthor {
		t.Fatalf("child folder mapped wrong: %+v", got[1])
	}
	if got[2].Path != "Keytabs" {
		t.Fatalf("folder under a hidden parent: path = %q, want Keytabs", got[2].Path)
	}
}

// Filters apply in the gateway, after fetching the whole visible tree, so a
// filtered child still gets its full path.
func TestFoldersForPrincipal_FiltersKeepFullPaths(t *testing.T) {
	fv := &listVault{foldersResp: &vaultv1.ListFoldersForPrincipalResponse{Folders: []*vaultv1.Folder{
		{Id: "f-infra", Name: "Infrastructure"},
		{Id: "f-sa", Name: "Service Accounts", ParentId: "f-infra"},
		{Id: "f-net", Name: "Network", ParentId: "f-infra"},
		{Id: "f-other", Name: "Service Desk"},
	}}}
	var resp struct{ FoldersForPrincipal []struct{ ID, Path string } }
	newListClient(fv).MustPost(`query { foldersForPrincipal(query: "SERVICE", parentId: "f-infra") { id path } }`, &resp)

	if q, p := fv.lastFoldersReq.GetQuery(), fv.lastFoldersReq.GetParentId(); q != "" || p != "" {
		t.Fatalf("vault must be asked for the whole visible tree, got query=%q parentId=%q", q, p)
	}
	got := resp.FoldersForPrincipal
	if len(got) != 1 || got[0].ID != "f-sa" || got[0].Path != "Infrastructure/Service Accounts" {
		t.Fatalf("filtered folders wrong: %+v", got)
	}
}

func TestFoldersForPrincipal_ParentCycleTerminates(t *testing.T) {
	fv := &listVault{foldersResp: &vaultv1.ListFoldersForPrincipalResponse{Folders: []*vaultv1.Folder{
		{Id: "a", Name: "A", ParentId: "b"},
		{Id: "b", Name: "B", ParentId: "a"},
	}}}
	var resp struct{ FoldersForPrincipal []struct{ Path string } }
	newListClient(fv).MustPost(`query { foldersForPrincipal { path } }`, &resp)
	if len(resp.FoldersForPrincipal) != 2 || resp.FoldersForPrincipal[0].Path != "B/A" {
		t.Fatalf("cycle paths wrong: %+v", resp.FoldersForPrincipal)
	}
}

func TestSecretTypes_MapsFieldsWithoutDefaults(t *testing.T) {
	fv := &listVault{typesResp: &vaultv1.ListSecretTypesResponse{Types: []*vaultv1.SecretType{
		{Id: "type-password", Name: "Password", Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Label: "Username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT, Required: true},
			{Key: "password", Label: "Password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Required: true, DefaultValue: "never-exposed"},
			{Key: "notes", Label: "Notes", Kind: vaultv1.FieldKind_FIELD_KIND_MULTILINE},
		}},
	}}}
	var resp struct {
		SecretTypes []struct {
			ID     string
			Name   string
			Fields []struct {
				Key      string
				Label    string
				Kind     string
				Required bool
			}
		}
	}
	newListClient(fv).MustPost(`query { secretTypes { id name fields { key label kind required } } }`, &resp)

	if !fv.typesCalled {
		t.Fatal("vault.ListSecretTypes was not called")
	}
	if len(resp.SecretTypes) != 1 || resp.SecretTypes[0].ID != "type-password" || resp.SecretTypes[0].Name != "Password" {
		t.Fatalf("types mapped wrong: %+v", resp.SecretTypes)
	}
	f := resp.SecretTypes[0].Fields
	if len(f) != 3 || f[0].Key != "username" || f[0].Kind != "TEXT" || !f[0].Required ||
		f[1].Kind != "PASSWORD" || f[2].Kind != "MULTILINE" || f[2].Required {
		t.Fatalf("fields mapped wrong: %+v", f)
	}
}

// newListClient serves the machine schema over fv as service account sa-42,
// the same wiring as newPrincipalClient.
func newListClient(fv *listVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithMachineActor(r.Context(), "sa-42", []string{"Infrastructure"})))
	}))
}
