// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"slices"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

type disabledToolsVault struct {
	vaultv1.VaultServiceClient
	names []string
}

func (v disabledToolsVault) GetSecuritySettings(context.Context, *vaultv1.GetSecuritySettingsRequest, ...grpc.CallOption) (*vaultv1.GetSecuritySettingsResponse, error) {
	return &vaultv1.GetSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{DisabledMcpTools: v.names}}, nil
}

func disabledToolsClient(v disabledToolsVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: v}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)))
	}))
}

func TestDisabledMcpToolsListsTheNamesTheVaultHolds(t *testing.T) {
	var q struct{ DisabledMcpTools []string }
	disabledToolsClient(disabledToolsVault{names: []string{"get_secret", "rotate_secret"}}).MustPost(`{ disabledMcpTools }`, &q)
	if !slices.Equal(q.DisabledMcpTools, []string{"get_secret", "rotate_secret"}) {
		t.Fatalf("disabledMcpTools = %v", q.DisabledMcpTools)
	}
}

func TestDisabledMcpToolsIsAnEmptyListWhenNothingIsOff(t *testing.T) {
	var q struct{ DisabledMcpTools *[]string }
	disabledToolsClient(disabledToolsVault{}).MustPost(`{ disabledMcpTools }`, &q)
	if q.DisabledMcpTools == nil || len(*q.DisabledMcpTools) != 0 {
		t.Fatalf("disabledMcpTools = %v, want an empty list (the field is non-null)", q.DisabledMcpTools)
	}
}

// The machine schema reads the list and never writes it: changing it is an
// admin's act on /graphql.
func TestTheMachineSchemaHasNoWayToSetDisabledMcpTools(t *testing.T) {
	var m struct{}
	if err := disabledToolsClient(disabledToolsVault{}).Post(`mutation { updateSecuritySettings(input: {}) { disabledMcpTools } }`, &m); err == nil {
		t.Fatal("the machine schema must not expose updateSecuritySettings")
	}
}
