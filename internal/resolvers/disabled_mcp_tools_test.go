// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// mcpToolsVault stands in for the vault's security settings: it keeps the
// disabled list the way the vault does (a present list replaces it, an absent
// one keeps it) and records every update it receives.
type mcpToolsVault struct {
	vaultv1.VaultServiceClient
	names   []string
	updates []*vaultv1.UpdateSecuritySettingsRequest
}

func (v *mcpToolsVault) GetSecuritySettings(context.Context, *vaultv1.GetSecuritySettingsRequest, ...grpc.CallOption) (*vaultv1.GetSecuritySettingsResponse, error) {
	return &vaultv1.GetSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{DisabledMcpTools: v.names}}, nil
}

func (v *mcpToolsVault) UpdateSecuritySettings(_ context.Context, req *vaultv1.UpdateSecuritySettingsRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecuritySettingsResponse, error) {
	v.updates = append(v.updates, req)
	if req.GetDisabledMcpTools() != nil {
		v.names = req.GetDisabledMcpTools().GetNames()
	}
	return &vaultv1.UpdateSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{DisabledMcpTools: v.names}}, nil
}

func mcpToolsClient(v *mcpToolsVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: v}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "u-1")))
	}))
}

const setMcpTools = `mutation($t: [String!]) { updateSecuritySettings(input: {disabledMcpTools: $t}) { disabledMcpTools } }`

func TestSecuritySettingsListTheDisabledMcpTools(t *testing.T) {
	c := mcpToolsClient(&mcpToolsVault{names: []string{"get_secret", "rotate_secret"}})
	var q struct {
		SecuritySettings struct{ DisabledMcpTools []string }
	}
	c.MustPost(`{ securitySettings { disabledMcpTools } }`, &q)
	if !slices.Equal(q.SecuritySettings.DisabledMcpTools, []string{"get_secret", "rotate_secret"}) {
		t.Fatalf("disabledMcpTools = %v", q.SecuritySettings.DisabledMcpTools)
	}
}

func TestSecuritySettingsListNoDisabledMcpToolsAsAnEmptyList(t *testing.T) {
	c := mcpToolsClient(&mcpToolsVault{})
	var q struct {
		SecuritySettings struct{ DisabledMcpTools *[]string }
	}
	c.MustPost(`{ securitySettings { disabledMcpTools } }`, &q)
	if q.SecuritySettings.DisabledMcpTools == nil || len(*q.SecuritySettings.DisabledMcpTools) != 0 {
		t.Fatalf("disabledMcpTools = %v, want an empty list (the field is non-null)", q.SecuritySettings.DisabledMcpTools)
	}
}

func TestUpdateSecuritySettingsSendsTheTrimmedDedupedMcpTools(t *testing.T) {
	v := &mcpToolsVault{}
	var m struct {
		UpdateSecuritySettings struct{ DisabledMcpTools []string }
	}
	mcpToolsClient(v).MustPost(setMcpTools, &m, gqlclient.Var("t", []string{" get_secret", "rotate_secret ", "get_secret", "", "  "}))
	if len(v.updates) != 1 || !slices.Equal(v.updates[0].GetDisabledMcpTools().GetNames(), []string{"get_secret", "rotate_secret"}) {
		t.Fatalf("vault got %v", v.updates)
	}
	if !slices.Equal(m.UpdateSecuritySettings.DisabledMcpTools, []string{"get_secret", "rotate_secret"}) {
		t.Fatalf("mutation returned %v", m.UpdateSecuritySettings.DisabledMcpTools)
	}
	if v.updates[0].GetActor() == nil {
		t.Fatal("the update must carry the caller's actor so the vault can check site admin and audit it")
	}
}

func TestUpdateSecuritySettingsWithAnEmptyListTurnsEveryToolBackOn(t *testing.T) {
	v := &mcpToolsVault{names: []string{"get_secret"}}
	var m struct {
		UpdateSecuritySettings struct{ DisabledMcpTools []string }
	}
	mcpToolsClient(v).MustPost(setMcpTools, &m, gqlclient.Var("t", []string{}))
	if len(v.updates) != 1 || v.updates[0].GetDisabledMcpTools() == nil || len(v.updates[0].GetDisabledMcpTools().GetNames()) != 0 {
		t.Fatalf("an empty list must reach the vault as a present, empty list; got %v", v.updates)
	}
	if len(m.UpdateSecuritySettings.DisabledMcpTools) != 0 {
		t.Fatalf("disabledMcpTools = %v", m.UpdateSecuritySettings.DisabledMcpTools)
	}
}

func TestUpdateSecuritySettingsWithoutMcpToolsKeepsTheList(t *testing.T) {
	v := &mcpToolsVault{names: []string{"get_secret"}}
	var m struct {
		UpdateSecuritySettings struct{ DisabledMcpTools []string }
	}
	mcpToolsClient(v).MustPost(`mutation { updateSecuritySettings(input: {requireMfaForReveal: true}) { disabledMcpTools } }`, &m)
	if len(v.updates) != 1 || v.updates[0].GetDisabledMcpTools() != nil {
		t.Fatalf("an update that omits the list must not send one; got %v", v.updates[0].GetDisabledMcpTools())
	}
}

func TestUpdateSecuritySettingsRefusesAnOversizedMcpToolList(t *testing.T) {
	long := strings.Repeat("a", maxMcpToolNameLen+1)
	many := make([]string, maxMcpTools+1)
	for i := range many {
		many[i] = "tool_" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + strings.Repeat("y", i/26)
	}
	for name, names := range map[string][]string{"a name that is too long": {long}, "too many names": many} {
		t.Run(name, func(t *testing.T) {
			v := &mcpToolsVault{}
			var m struct {
				UpdateSecuritySettings struct{ DisabledMcpTools []string }
			}
			if err := mcpToolsClient(v).Post(setMcpTools, &m, gqlclient.Var("t", names)); err == nil {
				t.Fatal("want an error")
			}
			if len(v.updates) != 0 {
				t.Fatal("the vault must not be called with a list the gateway refused")
			}
		})
	}
}
