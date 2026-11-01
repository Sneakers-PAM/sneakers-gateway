// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/maintenance"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

type extensionVault struct {
	vaultv1.VaultServiceClient

	available  []*vaultv1.SecretType
	lastImport *vaultv1.ImportExtensionForPrincipalRequest
	err        error
}

func (f *extensionVault) ListAvailableExtensions(_ context.Context, _ *vaultv1.ListAvailableExtensionsRequest, _ ...grpc.CallOption) (*vaultv1.ListAvailableExtensionsResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.ListAvailableExtensionsResponse{Extensions: f.available}, nil
}

func (f *extensionVault) ImportExtensionForPrincipal(_ context.Context, in *vaultv1.ImportExtensionForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.ImportExtensionForPrincipalResponse, error) {
	f.lastImport = in
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.ImportExtensionForPrincipalResponse{Type: &vaultv1.SecretType{Id: in.GetId(), Name: "Example Cloud"}}, nil
}

func newExtensionClient(fv *extensionVault, mode *maintenance.Mode) *client.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	h.Use(maintenance.Guard{Mode: mode, Allowed: maintenance.MachineAllowed})
	h.SetErrorPresenter(gqlerr.Present)
	return client.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)
		ctx = resolvers.WithTokenOwnerSiteAdmin(ctx)
		ctx = resolvers.WithTokenClientKind(ctx, "mcp")
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func TestAvailableExtensions_MapsThePacks(t *testing.T) {
	fv := &extensionVault{available: []*vaultv1.SecretType{{
		Id: "ext-example", Name: "Example Cloud",
		Fields: []*vaultv1.SecretFieldDef{{Key: "apiKey", Label: "API key", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Required: true, Sensitive: true, DefaultValue: "hidden"}},
	}}}
	var resp struct {
		AvailableExtensions []struct {
			ID, Name string
			Fields   []map[string]any
		}
	}
	newExtensionClient(fv, nil).MustPost(`query { availableExtensions { id name fields { key label kind required sensitive } } }`, &resp)
	if len(resp.AvailableExtensions) != 1 || resp.AvailableExtensions[0].ID != "ext-example" || resp.AvailableExtensions[0].Fields[0]["kind"] != "PASSWORD" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestAvailableExtensions_NoPacksIsAnEmptyList(t *testing.T) {
	var resp struct{ AvailableExtensions []struct{ ID string } }
	newExtensionClient(&extensionVault{}, nil).MustPost(`query { availableExtensions { id } }`, &resp)
	if resp.AvailableExtensions == nil || len(resp.AvailableExtensions) != 0 {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestImportExtension_SendsTheMachineActorToTheVault(t *testing.T) {
	fv := &extensionVault{}
	var resp struct{ ImportExtension struct{ ID, Name string } }
	newExtensionClient(fv, nil).MustPost(`mutation { importExtension(id: "ext-example") { id name } }`, &resp)

	if resp.ImportExtension.ID != "ext-example" || resp.ImportExtension.Name != "Example Cloud" {
		t.Fatalf("resp = %+v", resp)
	}
	a := fv.lastImport.GetActor()
	if fv.lastImport.GetId() != "ext-example" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN ||
		a.GetUserId() != "u-ada" || a.GetTokenId() != "utok-1" || !a.GetTokenOwnerIsSiteAdmin() || a.GetTokenClientKind() != "mcp" {
		t.Fatalf("request = %+v", fv.lastImport)
	}
	if a.GetIsSiteAdmin() || a.GetIsRoot() {
		t.Fatalf("a token must not carry admin authority: %+v", a)
	}
}

func TestImportExtension_RefusalPassesThroughUnchanged(t *testing.T) {
	const reason = "NOT_SITE_ADMIN"
	st, err := status.New(codes.PermissionDenied, "this needs a site admin").WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "sneakers.vault"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newExtensionClient(&extensionVault{err: st.Err()}, nil).RawPost(`mutation { importExtension(id: "ext-example") { id } }`)
	if err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	if err := json.NewEncoder(&body).Encode(resp.Errors); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.String(), reason) {
		t.Fatalf("errors = %s, want %s", body.String(), reason)
	}
}

func TestImportExtension_MaintenanceRefusesIt(t *testing.T) {
	fv := &extensionVault{}
	var resp struct{ ImportExtension struct{ ID string } }
	err := newExtensionClient(fv, maintenance.New(true, nil)).Post(`mutation { importExtension(id: "ext-example") { id } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), maintenance.Reason) {
		t.Fatalf("err = %v, want the %s refusal", err, maintenance.Reason)
	}
	if fv.lastImport != nil {
		t.Fatal("the vault must not be asked")
	}
}

func TestMaintenance_ListingPacksStaysOpen(t *testing.T) {
	var resp struct{ AvailableExtensions []struct{ ID string } }
	newExtensionClient(&extensionVault{}, maintenance.New(true, nil)).MustPost(`query { availableExtensions { id } }`, &resp)
}

// Only catalogued packs: pasted JSON stays on the human schema.
func TestMachineSchemaHasNoJSONImport(t *testing.T) {
	es := NewExecutableSchema(Config{Resolvers: &Resolver{}})
	if f := es.Schema().Types["Mutation"].Fields.ForName("importExtensionFromJson"); f != nil {
		t.Fatal("the machine schema exposes importExtensionFromJson")
	}
}
