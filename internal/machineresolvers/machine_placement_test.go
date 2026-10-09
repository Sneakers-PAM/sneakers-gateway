// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

// placementVault holds a shared folder and the caller's Personal tree (whose
// master root the caller can't see), and records what the create calls got.
type placementVault struct {
	vaultv1.VaultServiceClient
	folders  []*vaultv1.Folder
	listed   bool
	created  *vaultv1.CreateSecretForPrincipalRequest
	generate *vaultv1.GenerateSecretForPrincipalRequest
}

func (f *placementVault) ListFoldersForPrincipal(_ context.Context, _ *vaultv1.ListFoldersForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.ListFoldersForPrincipalResponse, error) {
	f.listed = true
	return &vaultv1.ListFoldersForPrincipalResponse{Folders: f.folders}, nil
}

func (f *placementVault) CreateSecretForPrincipal(_ context.Context, req *vaultv1.CreateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.CreateSecretForPrincipalResponse, error) {
	f.created = req
	return &vaultv1.CreateSecretForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1", Name: req.GetName(), FolderId: req.GetFolderId(), TypeId: req.GetTypeId()}}, nil
}

func (f *placementVault) GenerateSecretForPrincipal(_ context.Context, req *vaultv1.GenerateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.GenerateSecretForPrincipalResponse, error) {
	f.generate = req
	return &vaultv1.GenerateSecretForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s2", Name: req.GetName(), FolderId: req.GetFolderId(), TypeId: req.GetTypeId()}}, nil
}

func newPlacementVault() *placementVault {
	return &placementVault{folders: []*vaultv1.Folder{
		{Id: "f-shared", Name: "Infrastructure", Scope: vaultv1.FolderScope_FOLDER_SCOPE_GROUP, CanManage: true},
		{Id: "f-mine", Name: "Personal", ParentId: "f-personal-root", Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, CanManage: true},
		{Id: "f-mine-lab", Name: "Lab", ParentId: "f-mine", Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, CanManage: true},
	}}
}

// asUserToken is a personal token whose owner is "ada", ada.lovelace@example.org.
func asUserToken(ctx context.Context) context.Context {
	ctx = resolvers.WithUserTokenActor(ctx, "user-ada", "utok-1", nil)
	return resolvers.WithCallerIdentity(ctx, "ada", "Ada.Lovelace@example.org")
}

func asServiceAccount(ctx context.Context) context.Context {
	return resolvers.WithMachineActor(ctx, "sa-1", nil)
}

func placementClient(fv *placementVault, as func(context.Context) context.Context) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(as(r.Context())))
	}))
}

type placementResult struct {
	FolderID          string
	RequestedFolderID string
	Rule              string
	Reason            string
}

func create(t *testing.T, fv *placementVault, as func(context.Context) context.Context, args string) (string, placementResult) {
	t.Helper()
	return createIn(t, fv, as, "f-shared", args)
}

func createIn(t *testing.T, fv *placementVault, as func(context.Context) context.Context, folder, args string) (string, placementResult) {
	t.Helper()
	var resp struct {
		CreateSecretForPrincipal struct {
			FolderID  string
			Placement placementResult
		}
	}
	placementClient(fv, as).MustPost(`mutation { createSecretForPrincipal(folderId: "`+folder+`", typeId: "type-password", `+args+`) {
		folderId placement { folderId requestedFolderId rule reason } } }`, &resp)
	if fv.created == nil {
		t.Fatal("vault CreateSecretForPrincipal was not called")
	}
	return resp.CreateSecretForPrincipal.FolderID, resp.CreateSecretForPrincipal.Placement
}

func TestPlacement_CallerNamedSecretGoesToTheirPersonalFolder(t *testing.T) {
	cases := map[string]string{
		"name":                `name: "Router - admin ADA (lab)", fields: [{key: "password", value: "p"}]`,
		"username field":      `name: "VPN", fields: [{key: "username", value: "ada"}]`,
		"email field":         `name: "SaaS", fields: [{key: "email", value: "ADA.LOVELACE@EXAMPLE.ORG"}]`,
		"login field":         `name: "SaaS", fields: [{key: "login", value: "ada.lovelace@example.org"}]`,
		"clientEmail field":   `name: "SaaS", fields: [{key: "clientEmail", value: "ada.lovelace@example.org"}]`,
		"account field":       `name: "SaaS", fields: [{key: "account", value: "CORP\\ada"}]`,
		"name, trailing stop": `name: "VPN for ada.", fields: []`,
	}
	for what, args := range cases {
		fv := newPlacementVault()
		folder, p := create(t, fv, asUserToken, args)
		if fv.created.GetFolderId() != "f-mine" || folder != "f-mine" || p.FolderID != "f-mine" || p.RequestedFolderID != "f-shared" || p.Rule != "PERSONAL_DEFAULT" {
			t.Errorf("%s: vault folder %q, placement %+v", what, fv.created.GetFolderId(), p)
			continue
		}
		part := strings.TrimSuffix(strings.TrimSuffix(what, ", trailing stop"), " field")
		if !strings.Contains(p.Reason, part) || !strings.Contains(p.Reason, "keepFolder") {
			t.Errorf("%s: reason %q should name the matching part and how to keep the folder", what, p.Reason)
		}
		if strings.Contains(strings.ToLower(p.Reason), "ada") {
			t.Errorf("%s: reason %q echoes the caller's identity", what, p.Reason)
		}
	}
}

func TestPlacement_NoMatchStaysInTheRequestedFolder(t *testing.T) {
	cases := map[string]string{
		"longer word":     `name: "adam_backup on canada01", fields: [{key: "username", value: "adams"}]`,
		"dotted name":     `name: "VPN", fields: [{key: "username", value: "ada.smith@example.org"}]`,
		"secret value":    `name: "svc-backup", fields: [{key: "username", value: "svc-backup"}, {key: "password", value: "ada"}]`,
		"api key value":   `name: "svc", fields: [{key: "userApiKey", value: "ada"}]`,
		"unrelated field": `name: "svc", fields: [{key: "notes", value: "ask ada"}]`,
	}
	for what, args := range cases {
		fv := newPlacementVault()
		_, p := create(t, fv, asUserToken, args)
		if fv.created.GetFolderId() != "f-shared" || p.Rule != "REQUESTED" {
			t.Errorf("%s: vault folder %q, placement %+v", what, fv.created.GetFolderId(), p)
		}
		if fv.listed {
			t.Errorf("%s: folders were listed without a match", what)
		}
	}
}

func TestPlacement_TheOtherRules(t *testing.T) {
	cases := []struct {
		what, requested, args, folder, rule string
		prep                                func(*placementVault)
		as                                  func(context.Context) context.Context
	}{
		{what: "keepFolder", requested: "f-shared", args: `name: "admin ada", fields: [], keepFolder: true`, folder: "f-shared", rule: "KEPT_BY_CALLER"},
		{what: "already personal", requested: "f-mine-lab", args: `name: "admin ada", fields: []`, folder: "f-mine-lab", rule: "ALREADY_PERSONAL"},
		{what: "no personal folder", requested: "f-shared", args: `name: "admin ada", fields: []`, folder: "f-shared", rule: "NO_PERSONAL_FOLDER",
			prep: func(fv *placementVault) { fv.folders = fv.folders[:1] }},
		{what: "service account", requested: "f-shared", args: `name: "admin ada", fields: [{key: "username", value: "ada"}]`, folder: "f-shared", rule: "REQUESTED", as: asServiceAccount},
	}
	for _, c := range cases {
		fv := newPlacementVault()
		if c.prep != nil {
			c.prep(fv)
		}
		as := c.as
		if as == nil {
			as = asUserToken
		}
		_, p := createIn(t, fv, as, c.requested, c.args)
		if fv.created.GetFolderId() != c.folder || p.FolderID != c.folder || p.RequestedFolderID != c.requested || p.Rule != c.rule {
			t.Errorf("%s: vault folder %q, placement %+v, want %s in %s", c.what, fv.created.GetFolderId(), p, c.rule, c.folder)
		}
		if c.as != nil && fv.listed {
			t.Errorf("%s: a service account's create listed folders", c.what)
		}
	}
}

func TestPlacement_GenerateFollowsTheSameRules(t *testing.T) {
	gen := func(fv *placementVault, args string) placementResult {
		var resp struct {
			GenerateSecretForPrincipal struct {
				Secret struct {
					FolderID  string
					Placement placementResult
				}
			}
		}
		placementClient(fv, asUserToken).MustPost(`mutation { generateSecretForPrincipal(folderId: "f-shared", typeId: "type-password", `+args+`) {
			secret { folderId placement { folderId requestedFolderId rule reason } } } }`, &resp)
		return resp.GenerateSecretForPrincipal.Secret.Placement
	}
	fv := newPlacementVault()
	if p := gen(fv, `name: "lab vpn", fields: [{key: "username", value: "ada"}]`); fv.generate.GetFolderId() != "f-mine" || p.Rule != "PERSONAL_DEFAULT" || !strings.Contains(p.Reason, "username field") {
		t.Errorf("match: vault folder %q, placement %+v", fv.generate.GetFolderId(), p)
	}
	fv = newPlacementVault()
	if p := gen(fv, `name: "admin ada", fields: [], keepFolder: true`); fv.generate.GetFolderId() != "f-shared" || p.Rule != "KEPT_BY_CALLER" {
		t.Errorf("keepFolder: vault folder %q, placement %+v", fv.generate.GetFolderId(), p)
	}
	fv = newPlacementVault()
	if p := gen(fv, `name: "svc-backup", fields: []`); fv.generate.GetFolderId() != "f-shared" || p.Rule != "REQUESTED" || fv.listed {
		t.Errorf("no match: vault folder %q, placement %+v, listed %v", fv.generate.GetFolderId(), p, fv.listed)
	}
}
