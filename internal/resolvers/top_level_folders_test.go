// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"google.golang.org/grpc"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
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
}

func (f *topLevelSettingsVault) GetSecuritySettings(context.Context, *vaultv1.GetSecuritySettingsRequest, ...grpc.CallOption) (*vaultv1.GetSecuritySettingsResponse, error) {
	return &vaultv1.GetSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{AgentsMayCreateTopLevelFolders: f.stored}}, nil
}

func (f *topLevelSettingsVault) UpdateSecuritySettings(_ context.Context, req *vaultv1.UpdateSecuritySettingsRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecuritySettingsResponse, error) {
	f.lastUpdate = req
	if req.AgentsMayCreateTopLevelFolders != nil {
		f.stored = *req.AgentsMayCreateTopLevelFolders
	}
	return &vaultv1.UpdateSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{AgentsMayCreateTopLevelFolders: f.stored}}, nil
}

func topLevelSettingsClient(fv *topLevelSettingsVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, MFAMaxAge: time.Hour}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActorInfo(WithActor(r.Context(), "u-ada"), true, false, nil)))
	}))
}

func TestSecuritySettingsReadTheTopLevelFolderSetting(t *testing.T) {
	var q struct {
		SecuritySettings struct{ AgentsMayCreateTopLevelFolders bool }
	}
	topLevelSettingsClient(&topLevelSettingsVault{stored: true}).MustPost(`{ securitySettings { agentsMayCreateTopLevelFolders } }`, &q)
	if !q.SecuritySettings.AgentsMayCreateTopLevelFolders {
		t.Fatal("the stored setting did not come back")
	}
}

func TestSecuritySettingsWriteTheTopLevelFolderSettingAsTheActor(t *testing.T) {
	fv := &topLevelSettingsVault{}
	var m struct {
		UpdateSecuritySettings struct{ AgentsMayCreateTopLevelFolders bool }
	}
	topLevelSettingsClient(fv).MustPost(`mutation { updateSecuritySettings(input: {agentsMayCreateTopLevelFolders: true}) { agentsMayCreateTopLevelFolders } }`, &m)
	got := fv.lastUpdate.AgentsMayCreateTopLevelFolders
	if got == nil || !*got || !m.UpdateSecuritySettings.AgentsMayCreateTopLevelFolders {
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
		UpdateSecuritySettings struct{ AgentsMayCreateTopLevelFolders bool }
	}
	topLevelSettingsClient(fv).MustPost(`mutation { updateSecuritySettings(input: {requireMfaForReveal: true}) { agentsMayCreateTopLevelFolders } }`, &m)
	if fv.lastUpdate.AgentsMayCreateTopLevelFolders != nil || !m.UpdateSecuritySettings.AgentsMayCreateTopLevelFolders {
		t.Fatalf("request = %+v, resp = %+v", fv.lastUpdate, m)
	}
}
