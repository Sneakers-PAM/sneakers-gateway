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
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/maintenance"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

func TestMaintenanceRefusesAMachineMutation(t *testing.T) {
	fv := &paddingVault{revealValue: "v"}
	mode := maintenance.New(true, nil)
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	h.Use(maintenance.Guard{Mode: mode, Allowed: maintenance.MachineAllowed})
	h.SetErrorPresenter(gqlerr.Present)
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithMachineActor(r.Context(), "sa-1", nil)))
	}))

	var created struct{ CreateFolderForPrincipal struct{ ID string } }
	err := c.Post(`mutation { createFolderForPrincipal(parentId:"f1", name:"n") { id } }`, &created)
	if err == nil || !strings.Contains(err.Error(), maintenance.Reason) {
		t.Fatalf("err = %v, want the %s refusal", err, maintenance.Reason)
	}

	var revealed struct{ RevealSecretFieldForPrincipal string }
	c.MustPost(`mutation { revealSecretFieldForPrincipal(id:"s1", fieldKey:"apiKey") }`, &revealed)
	if revealed.RevealSecretFieldForPrincipal != "v" {
		t.Fatalf("revealed = %q", revealed.RevealSecretFieldForPrincipal)
	}
}
