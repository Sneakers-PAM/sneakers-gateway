// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
	"google.golang.org/grpc"
)

// diagServices are the Sneakers-PAM services the diagnostics read, in report
// order. A nil conn is reported as not configured.
type diagServices struct {
	identity, vault, workflow, audit, notify, sshbroker grpc.ClientConnInterface
}

// newDiagnostics builds the diagnostics collector from the gateway's
// configuration. valkeyInfo is nil when the gateway has no Valkey client.
// The connector itself is never dialled: it's a pull-based worker, so its
// entries come from vault's ListConnectors through the typed vault client.
func newDiagnostics(getenv func(string) string, authMode string, s diagServices, vault vaultv1.VaultServiceClient, valkeyInfo func(context.Context) (string, error), lg log.Logger) *diag.Collector {
	httpc := &http.Client{Timeout: 2 * time.Second}
	bi := buildinfo.Get()

	kratos := ""
	if authMode == "real" {
		kratos = endpoint(envOr(getenv, "KRATOS_ADMIN_URL", "http://sneakers-kratos:4434"), "/admin/version")
	}
	hydra := ""
	if envTrue("HYDRA_ENABLED") {
		base := getenv("HYDRA_ADMIN_URL")
		if base == "" {
			base = originOf(envOr(getenv, "HYDRA_JWKS_URL", "http://sneakers-hydra:4444/.well-known/jwks.json"))
		}
		hydra = endpoint(base, "/version")
	}
	polis := ""
	if getenv("POLIS_PUBLIC_URL") != "" {
		polis = endpoint(envOr(getenv, "POLIS_ISSUER_URL", "http://sneakers-polis:5225"), "/api/health")
	}

	// The appliance bundle sets all three from the box's own values
	// (docs/configuration.md); off the appliance none is set.
	var box *diag.Box
	if v := getenv("SNEAKERS_APPLIANCE_VERSION"); v != "" {
		box = &diag.Box{BaseOS: v, BaseWeb: getenv("SNEAKERS_APPLIANCE_WEB_VERSION"), FQDN: getenv("SNEAKERS_APPLIANCE_FQDN")}
	}

	return &diag.Collector{
		Gateway:        diag.Component{Name: "gateway", Version: bi.Version, Commit: bi.Commit, Status: diag.StatusOK},
		PublicURL:      getenv("OAUTH_PUBLIC_URL"),
		ProductVersion: getenv("SNEAKERS_PRODUCT_VERSION"),
		Appliance:      getenv("SNEAKERS_APPLIANCE_VERSION"),
		Box:            box,
		Services: []diag.Probe{
			diag.GRPCHealth("identity", s.identity),
			diag.GRPCHealth("vault", s.vault),
			diag.GRPCHealth("workflow", s.workflow),
			diag.GRPCHealth("audit", s.audit),
			diag.GRPCHealth("notify", s.notify),
			diag.GRPCHealth("sshbroker", s.sshbroker),
			diag.HTTPVersion("mcp", httpc, getenv("MCP_HEALTH_URL")),
		},
		ThirdParty: []diag.Probe{
			diag.HTTPVersion("kratos", httpc, kratos),
			diag.HTTPVersion("hydra", httpc, hydra),
			diag.HTTPVersion("polis", httpc, polis),
			diag.Valkey(valkeyInfo),
			diag.InCluster(),
		},
		Connectors: vaultConnectors(vault),
		Log:        lg,
	}
}

// vaultConnectors reads the connector workers vault has heard from
// (ListConnectors), one Component per worker named "connector" with its
// last reported build and contact time. The worker id is how the worker
// registered (its pod's namespace and name), not a name to show. A nil vault client reads
// nothing; vault being unreachable is already reported on vault's own
// GRPCHealth entry, so a read failure here just adds no entries.
func vaultConnectors(vault vaultv1.VaultServiceClient) diag.MultiProbe {
	return func(ctx context.Context) []diag.Component {
		if vault == nil {
			return nil
		}
		resp, err := vault.ListConnectors(ctx, &vaultv1.ListConnectorsRequest{})
		if err != nil {
			return nil
		}
		conns := resp.GetConnectors()
		out := make([]diag.Component, 0, len(conns))
		for _, c := range conns {
			comp := diag.Component{Name: "connector", Version: c.GetVersion(), Commit: c.GetCommit(), Status: diag.StatusOK}
			if t, err := time.Parse(time.RFC3339, c.GetLastContactAt()); err == nil {
				comp.LastContactAt = t.UTC().Format(time.RFC3339)
			}
			out = append(out, comp)
		}
		return out
	}
}

func envOr(getenv func(string) string, k, def string) string {
	if v := getenv(k); v != "" {
		return v
	}
	return def
}

// endpoint joins a configured base URL and a fixed path; an empty base stays
// empty (not configured).
func endpoint(base, path string) string {
	if base == "" {
		return ""
	}
	return strings.TrimRight(base, "/") + path
}

// originOf is the scheme and host of a URL, or "" when it has none.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
