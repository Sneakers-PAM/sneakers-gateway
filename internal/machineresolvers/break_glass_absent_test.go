// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

// Break-glass is for people only: the machine schema, the only one tokens,
// service accounts, OAuth clients and the MCP can reach, has no break-glass
// field, so a token's breakGlassSecret fails validation and the vault is
// never asked.
func TestMachineSchemaHasNoBreakGlass(t *testing.T) {
	es := NewExecutableSchema(Config{Resolvers: &Resolver{}})
	for _, def := range []string{"Query", "Mutation", "Subscription"} {
		d := es.Schema().Types[def]
		if d == nil {
			continue
		}
		for _, f := range d.Fields {
			if strings.Contains(strings.ToLower(f.Name), "breakglass") {
				t.Fatalf("machine schema exposes %s.%s", def, f.Name)
			}
		}
	}

	v := &fakeVault{}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: v}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := resolvers.WithUserTokenActor(r.Context(), "u-admin", "tok-1", nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	resp, err := c.RawPost(`mutation { breakGlassSecret(secretId: "s-1", reason: "outage", code: "123456") { key value } }`)
	if err == nil || !strings.Contains(err.Error(), `Cannot query field \"breakGlassSecret\"`) {
		t.Fatalf("resp = %+v, err = %v", resp, err)
	}
	if v.lastReq != nil {
		t.Fatal("the vault must never be asked")
	}
}
