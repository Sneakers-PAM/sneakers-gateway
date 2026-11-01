// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
)

func TestWithTokenOwnerSiteAdmin_OnlyAUserTokenActorCarriesIt(t *testing.T) {
	bg := context.Background()
	for name, tc := range map[string]struct {
		ctx  context.Context
		want bool
	}{
		"user token":        {WithTokenOwnerSiteAdmin(WithUserTokenActor(bg, "u-ada", "utok-1", nil)), true},
		"user token unset":  {WithUserTokenActor(bg, "u-ada", "utok-1", nil), false},
		"service account":   {WithTokenOwnerSiteAdmin(WithMachineActor(bg, "sa-1", nil)), false},
		"no machine actor":  {WithTokenOwnerSiteAdmin(bg), false},
		"human session":     {WithTokenOwnerSiteAdmin(WithActorInfo(WithActor(bg, "u-ada"), true, true, nil)), false},
		"kept after groups": {WithMachineGroupIDs(WithTokenOwnerSiteAdmin(WithUserTokenActor(bg, "u-ada", "utok-1", nil)), []string{"g-1"}), true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := MachineActorOf(tc.ctx).GetTokenOwnerIsSiteAdmin(); got != tc.want {
				t.Fatalf("token_owner_is_site_admin = %v, want %v", got, tc.want)
			}
		})
	}
}

type topLevelSettingsVault struct {
	vaultv1.VaultServiceClient

	stored     bool
	lastUpdate *vaultv1.UpdateSecuritySettingsRequest
	lastCreate *vaultv1.CreateFolderRequest
	createErr  error
}

func (f *topLevelSettingsVault) CreateFolder(_ context.Context, req *vaultv1.CreateFolderRequest, _ ...grpc.CallOption) (*vaultv1.CreateFolderResponse, error) {
	f.lastCreate = req
	if f.createErr != nil {
		return nil, f.createErr
	}
	return &vaultv1.CreateFolderResponse{Folder: &vaultv1.Folder{Id: "f9", Name: req.GetName()}}, nil
}

func (f *topLevelSettingsVault) GetSecuritySettings(context.Context, *vaultv1.GetSecuritySettingsRequest, ...grpc.CallOption) (*vaultv1.GetSecuritySettingsResponse, error) {
	return &vaultv1.GetSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{RestrictTopLevelFolders: f.stored}}, nil
}

func (f *topLevelSettingsVault) UpdateSecuritySettings(_ context.Context, req *vaultv1.UpdateSecuritySettingsRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecuritySettingsResponse, error) {
	f.lastUpdate = req
	if req.RestrictTopLevelFolders != nil {
		f.stored = *req.RestrictTopLevelFolders
	}
	return &vaultv1.UpdateSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{RestrictTopLevelFolders: f.stored}}, nil
}

func topLevelSettingsClient(fv *topLevelSettingsVault) *gqlclient.Client {
	return topLevelClientAs(fv, true)
}

func topLevelClientAs(fv *topLevelSettingsVault, siteAdmin bool) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, MFAMaxAge: time.Hour}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActorInfo(WithActor(r.Context(), "u-ada"), siteAdmin, false, nil)))
	}))
}

// The gateway adds no rule for a person either: a plain user's top-level
// create goes to the vault with an empty parent.
func TestCreateFolder_PlainUserTopLevelCreateReachesTheVault(t *testing.T) {
	fv := &topLevelSettingsVault{}
	var m struct{ CreateFolder struct{ ID string } }
	topLevelClientAs(fv, false).MustPost(`mutation { createFolder(name: "Infrastructure") { id } }`, &m)
	if fv.lastCreate == nil || fv.lastCreate.GetParentId() != "" || fv.lastCreate.GetActor().GetIsSiteAdmin() {
		t.Fatalf("request = %+v", fv.lastCreate)
	}
}

func TestCreateFolder_RestrictedRefusalPassesThroughUnchanged(t *testing.T) {
	const reason = "TOP_LEVEL_FOLDERS_RESTRICTED"
	const msg = `top-level folders are restricted to admins by the "Restrict top-level folders to admins" setting`
	st, err := status.New(codes.PermissionDenied, msg).WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "sneakers.vault"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := topLevelClientAs(&topLevelSettingsVault{createErr: st.Err()}, false).RawPost(`mutation { createFolder(name: "Infrastructure") { id } }`)
	if err != nil {
		t.Fatal(err)
	}
	var errs []struct {
		Message    string
		Extensions struct{ Code, Reason, Domain string }
	}
	if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
		t.Fatalf("errors = %s (%v)", resp.Errors, err)
	}
	e := errs[0]
	if e.Extensions.Code != "PERMISSION_DENIED" || e.Extensions.Reason != reason || e.Extensions.Domain != "sneakers.vault" {
		t.Fatalf("extensions = %+v", e.Extensions)
	}
	if want := "rpc error: code = PermissionDenied desc = " + msg; e.Message != want {
		t.Fatalf("message = %q, want %q", e.Message, want)
	}
}

func TestSecuritySettingsReadTheTopLevelFolderSetting(t *testing.T) {
	var q struct {
		SecuritySettings struct{ RestrictTopLevelFolders bool }
	}
	topLevelSettingsClient(&topLevelSettingsVault{stored: true}).MustPost(`{ securitySettings { restrictTopLevelFolders } }`, &q)
	if !q.SecuritySettings.RestrictTopLevelFolders {
		t.Fatal("the stored setting did not come back")
	}
}

func TestSecuritySettingsWriteTheTopLevelFolderSettingAsTheActor(t *testing.T) {
	fv := &topLevelSettingsVault{}
	var m struct {
		UpdateSecuritySettings struct{ RestrictTopLevelFolders bool }
	}
	topLevelSettingsClient(fv).MustPost(`mutation { updateSecuritySettings(input: {restrictTopLevelFolders: true}) { restrictTopLevelFolders } }`, &m)
	got := fv.lastUpdate.RestrictTopLevelFolders
	if got == nil || !*got || !m.UpdateSecuritySettings.RestrictTopLevelFolders {
		t.Fatalf("request = %+v, resp = %+v", fv.lastUpdate, m)
	}
	if a := fv.lastUpdate.GetActor(); a.GetUserId() != "u-ada" || !a.GetIsSiteAdmin() {
		t.Fatalf("actor = %+v, the vault can't check site admin without it", a)
	}
}

// A partial update that doesn't name the setting leaves it unset, so the vault
// doesn't change it.
func TestSecuritySettingsPartialUpdateLeavesTheTopLevelFolderSettingUnset(t *testing.T) {
	fv := &topLevelSettingsVault{stored: true}
	var m struct {
		UpdateSecuritySettings struct{ RestrictTopLevelFolders bool }
	}
	topLevelSettingsClient(fv).MustPost(`mutation { updateSecuritySettings(input: {requireMfaForReveal: true}) { restrictTopLevelFolders } }`, &m)
	if fv.lastUpdate.RestrictTopLevelFolders != nil || !m.UpdateSecuritySettings.RestrictTopLevelFolders {
		t.Fatalf("request = %+v, resp = %+v", fv.lastUpdate, m)
	}
}

func TestWithTokenClientKind_OnlyAUserTokenActorCarriesIt(t *testing.T) {
	bg := context.Background()
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"user token":       {WithTokenClientKind(WithUserTokenActor(bg, "u-ada", "utok-1", nil), "mcp"), "mcp"},
		"service account":  {WithTokenClientKind(WithMachineActor(bg, "sa-1", nil), "mcp"), ""},
		"no machine actor": {WithTokenClientKind(bg, "mcp"), ""},
	} {
		t.Run(name, func(t *testing.T) {
			if got := MachineActorOf(tc.ctx).GetTokenClientKind(); got != tc.want {
				t.Fatalf("token_client_kind = %q, want %q", got, tc.want)
			}
		})
	}
}
