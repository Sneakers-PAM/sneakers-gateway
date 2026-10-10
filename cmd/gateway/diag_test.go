// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
)

func statusOf(r diag.Report, name string) (diag.Status, string) {
	for _, c := range append(append([]diag.Component{}, r.Services...), r.ThirdParty...) {
		if c.Name == name {
			return c.Status, c.Version
		}
	}
	return "", ""
}

func TestNewDiagnostics_NoauthHasNoLoginBackends(t *testing.T) {
	t.Setenv("HYDRA_ENABLED", "")
	getenv := func(k string) string {
		return map[string]string{"SNEAKERS_APPLIANCE_VERSION": "v0.1.0", "OAUTH_PUBLIC_URL": "https://pam.example.org/app"}[k]
	}
	r := newDiagnostics(getenv, "noauth", diagServices{}, nil, nil, log.Nop()).Report(context.Background())
	for _, name := range []string{"kratos", "hydra", "polis", "valkey", "mcp", "identity"} {
		if st, _ := statusOf(r, name); st != diag.StatusNotConfigured {
			t.Errorf("%s = %s, want NOT_CONFIGURED", name, st)
		}
	}
	if st, _ := statusOf(r, "connector"); st != "" {
		t.Errorf("connector with a nil vault client = %s, want no entry at all", st)
	}
	if r.Appliance != "v0.1.0" || r.PublicURL != "https://pam.example.org" || r.Gateway.Name != "gateway" {
		t.Errorf("appliance/public/gateway = %q/%q/%q", r.Appliance, r.PublicURL, r.Gateway.Name)
	}
}

// TestNewDiagnostics_ConnectorEntriesComeFromVault: each connector vault has
// heard from is its own Services entry named "connector" (the worker id is
// the pod's registration, not a name to show), with vault's reported build
// and last contact; the gateway never dials one.
func TestNewDiagnostics_ConnectorEntriesComeFromVault(t *testing.T) {
	vault := &fakeVault{connectors: &vaultv1.ListConnectorsResponse{Connectors: []*vaultv1.ConnectorContact{
		{WorkerId: "sneakers/sneakers-connector", Version: "v0.1.0", Commit: "abc123", LastContactAt: "2026-10-05T12:00:00Z"},
		{WorkerId: "worker-b"},
	}}}
	r := newDiagnostics(func(string) string { return "" }, "noauth", diagServices{}, vault, nil, log.Nop()).Report(context.Background())
	var conns []diag.Component
	for _, c := range r.Services {
		if strings.Contains(c.Name, "sneakers/") || strings.HasPrefix(c.Name, "connector:") {
			t.Fatalf("a connector entry is named after its worker id: %q", c.Name)
		}
		if c.Name == "connector" {
			conns = append(conns, c)
		}
	}
	if len(conns) != 2 {
		t.Fatalf("connector entries = %+v, want one per worker", conns)
	}
	a, b := conns[0], conns[1]
	if a.Status != diag.StatusOK || a.Version != "v0.1.0" || a.Commit != "abc123" || a.LastContactAt != "2026-10-05T12:00:00Z" {
		t.Fatalf("first connector = %+v, want OK v0.1.0 abc123 and the contact time", a)
	}
	if b.Status != diag.StatusOK || b.Version != diag.Unknown || b.LastContactAt != "" {
		t.Fatalf("second connector (never sent a build) = %+v, want OK unknown with no contact time", b)
	}
}

// TestNewDiagnostics_ProductAndBox: the product's version and, on the
// appliance, the box's values come from the environment the bundle sets.
func TestNewDiagnostics_ProductAndBox(t *testing.T) {
	vars := map[string]string{
		"SNEAKERS_PRODUCT_VERSION":       "0.1.0",
		"SNEAKERS_APPLIANCE_VERSION":     "0.1.0-m",
		"SNEAKERS_APPLIANCE_WEB_VERSION": "0.1.0-m",
		"SNEAKERS_APPLIANCE_FQDN":        "box1.example.org",
	}
	r := newDiagnostics(func(k string) string { return vars[k] }, "noauth", diagServices{}, nil, nil, log.Nop()).Report(context.Background())
	if r.ProductVersion != "0.1.0" {
		t.Fatalf("product = %q", r.ProductVersion)
	}
	if r.Box == nil || *r.Box != (diag.Box{BaseOS: "0.1.0-m", BaseWeb: "0.1.0-m", FQDN: "box1.example.org"}) {
		t.Fatalf("box = %+v", r.Box)
	}
	r = newDiagnostics(func(k string) string { return map[string]string{"SNEAKERS_PRODUCT_VERSION": "0.1.0"}[k] }, "noauth", diagServices{}, nil, nil, log.Nop()).Report(context.Background())
	if r.Box != nil {
		t.Fatalf("box off the appliance = %+v, want nil", r.Box)
	}
}

func TestNewDiagnostics_VaultUnreachableAddsNoConnectorEntries(t *testing.T) {
	vault := &fakeVault{connectorsErr: errors.New("vault: unavailable")}
	r := newDiagnostics(func(string) string { return "" }, "noauth", diagServices{}, vault, nil, log.Nop()).Report(context.Background())
	if len(r.Services) == 0 {
		t.Fatal("expected the other services to still report")
	}
	for _, c := range r.Services {
		if c.Name == "connector" {
			t.Fatalf("expected no connector entries when vault can't answer, got %+v", c)
		}
	}
}

func TestNewDiagnostics_RealModeReadsKratosHydraPolisAndMCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/version":
			_, _ = w.Write([]byte(`{"version":"v1.3.1"}`))
		case "/version":
			_, _ = w.Write([]byte(`{"version":"v2.3.0"}`))
		case "/api/health":
			_, _ = w.Write([]byte(`{"version":"25.2.0"}`))
		case "/livez":
			w.Header().Set("Sneakers-Version", "v0.1.0")
			w.Header().Set("Sneakers-Commit", "abc")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("HYDRA_ENABLED", "true")
	vars := map[string]string{
		"KRATOS_ADMIN_URL": srv.URL + "/",
		"HYDRA_JWKS_URL":   srv.URL + "/.well-known/jwks.json",
		"POLIS_PUBLIC_URL": "https://sso.example.org",
		"POLIS_ISSUER_URL": srv.URL,
		"MCP_HEALTH_URL":   srv.URL + "/livez",
	}
	info := func(context.Context) (string, error) { return "valkey_version:8.1.1\r\n", nil }
	r := newDiagnostics(func(k string) string { return vars[k] }, "real", diagServices{}, nil, info, log.Nop()).Report(context.Background())
	want := map[string]string{"kratos": "v1.3.1", "hydra": "v2.3.0", "polis": "25.2.0", "mcp": "v0.1.0", "valkey": "8.1.1"}
	for name, v := range want {
		if st, got := statusOf(r, name); st != diag.StatusOK || got != v {
			t.Errorf("%s = %s %q, want OK %q", name, st, got, v)
		}
	}
}
