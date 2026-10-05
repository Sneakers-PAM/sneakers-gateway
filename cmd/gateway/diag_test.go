// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/Bugs5382/go-log"
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
	r := newDiagnostics(getenv, "noauth", diagServices{}, nil, log.Nop()).Report(context.Background())
	for _, name := range []string{"kratos", "hydra", "polis", "valkey", "connector", "mcp", "identity"} {
		if st, _ := statusOf(r, name); st != diag.StatusNotConfigured {
			t.Errorf("%s = %s, want NOT_CONFIGURED", name, st)
		}
	}
	if r.Appliance != "v0.1.0" || r.PublicURL != "https://pam.example.org" || r.Gateway.Name != "gateway" {
		t.Errorf("appliance/public/gateway = %q/%q/%q", r.Appliance, r.PublicURL, r.Gateway.Name)
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
		case "/health":
			_, _ = w.Write([]byte(`{"status":"ok","version":"v0.1.0","commit":"abc"}`))
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
		"MCP_HEALTH_URL":   srv.URL + "/health",
	}
	info := func(context.Context) (string, error) { return "valkey_version:8.1.1\r\n", nil }
	r := newDiagnostics(func(k string) string { return vars[k] }, "real", diagServices{}, info, log.Nop()).Report(context.Background())
	want := map[string]string{"kratos": "v1.3.1", "hydra": "v2.3.0", "polis": "25.2.0", "mcp": "v0.1.0", "valkey": "8.1.1"}
	for name, v := range want {
		if st, got := statusOf(r, name); st != diag.StatusOK || got != v {
			t.Errorf("%s = %s %q, want OK %q", name, st, got, v)
		}
	}
}
