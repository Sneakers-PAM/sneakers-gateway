// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/maintenance"
)

func newMaintenanceClient(fv *fakeVault, mode *maintenance.Mode) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Maintenance: mode}}))
	h.AddTransport(transport.POST{})
	h.Use(maintenance.Guard{Mode: mode, Allowed: maintenance.HumanAllowed})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-clarke")))
	}))
}

// reason returns the first GraphQL error's reason extension.
func reason(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("want an error, got none")
	}
	var errs []struct {
		Extensions map[string]any `json:"extensions"`
	}
	if jerr := json.Unmarshal([]byte(err.Error()), &errs); jerr != nil || len(errs) == 0 {
		t.Fatalf("unexpected error shape: %v", err)
	}
	r, _ := errs[0].Extensions["reason"].(string)
	return r
}

func TestMaintenanceRefusesAMutation(t *testing.T) {
	fv := &fakeVault{}
	c := newMaintenanceClient(fv, maintenance.New(true, nil))
	var resp struct{ GenerateKeyPair struct{ PublicKey string } }
	err := c.Post(`mutation { generateKeyPair(format: "rsa2048") { publicKey } }`, &resp)
	if got := reason(t, err); got != maintenance.Reason {
		t.Fatalf("reason = %q, want %s", got, maintenance.Reason)
	}
	if fv.lastActor != "" {
		t.Fatal("the refused mutation still reached the vault")
	}
}

func TestMaintenanceStillAllowsAReveal(t *testing.T) {
	fv := &fakeVault{}
	c := newMaintenanceClient(fv, maintenance.New(true, nil))
	var resp struct{ RevealSecretField string }
	c.MustPost(`mutation { revealSecretField(id:"s1", fieldKey:"password") }`, &resp)
	if resp.RevealSecretField != "Sup3r$ecret" {
		t.Fatalf("revealed = %q", resp.RevealSecretField)
	}
}

func TestMaintenanceStillAllowsQueries(t *testing.T) {
	c := newMaintenanceClient(&fakeVault{}, maintenance.New(true, nil))
	var resp struct{ Folders []struct{ ID string } }
	c.MustPost(`{ folders { id } }`, &resp)
	if len(resp.Folders) != 1 {
		t.Fatalf("folders = %+v", resp.Folders)
	}
}

func TestMutationsWorkWithMaintenanceOff(t *testing.T) {
	fv := &fakeVault{}
	c := newMaintenanceClient(fv, maintenance.New(false, nil))
	var resp struct{ GenerateKeyPair struct{ PublicKey string } }
	c.MustPost(`mutation { generateKeyPair(format: "rsa2048") { publicKey } }`, &resp)
	if resp.GenerateKeyPair.PublicKey == "" {
		t.Fatal("no key pair with maintenance off")
	}
}

func TestTheMaintenanceQueryReportsTheState(t *testing.T) {
	on := true
	mode := maintenance.New(false, func() (bool, string) { return on, "upgrade to 0.2.0" })
	c := newMaintenanceClient(&fakeVault{}, mode)
	var resp struct {
		Maintenance struct {
			ReadOnly bool
			Reason   *string
		}
	}
	c.MustPost(`{ maintenance { readOnly reason } }`, &resp)
	if !resp.Maintenance.ReadOnly || resp.Maintenance.Reason == nil || !strings.Contains(*resp.Maintenance.Reason, "0.2.0") {
		t.Fatalf("maintenance = %+v", resp.Maintenance)
	}
	on = false
	c.MustPost(`{ maintenance { readOnly reason } }`, &resp)
	if resp.Maintenance.ReadOnly || resp.Maintenance.Reason != nil {
		t.Fatalf("maintenance after it ended = %+v", resp.Maintenance)
	}
}
