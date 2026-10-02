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
)

func whoamiClient(with func(context.Context) context.Context) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(with(r.Context())))
	}))
}

func TestMachineWhoamiNamesAPersonalTokenAndItsOwner(t *testing.T) {
	var resp struct {
		MachineWhoami struct{ Kind, UserID, PrincipalID string }
	}
	whoamiClient(func(ctx context.Context) context.Context {
		return resolvers.WithUserTokenActor(ctx, "u-ada", "utok-1", nil)
	}).MustPost(`{ machineWhoami { kind userId principalId } }`, &resp)
	if got := resp.MachineWhoami; got.Kind != "user_token" || got.UserID != "u-ada" || got.PrincipalID != "utok-1" {
		t.Fatalf("whoami = %+v", got)
	}
}

func TestMachineWhoamiNamesAServiceAccount(t *testing.T) {
	var resp struct {
		MachineWhoami struct{ Kind, UserID, PrincipalID string }
	}
	whoamiClient(func(ctx context.Context) context.Context {
		return resolvers.WithMachineActor(ctx, "sa-backup", nil)
	}).MustPost(`{ machineWhoami { kind userId principalId } }`, &resp)
	if got := resp.MachineWhoami; got.Kind != "service_account" || got.UserID != "" || got.PrincipalID != "sa-backup" {
		t.Fatalf("whoami = %+v", got)
	}
}
