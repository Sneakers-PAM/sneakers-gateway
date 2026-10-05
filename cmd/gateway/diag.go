// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/buildinfo"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
	"google.golang.org/grpc"
)

// diagServices are the Sneakers-PAM services the diagnostics read, in report
// order. A nil conn is reported as not configured.
type diagServices struct {
	identity, vault, workflow, audit, notify, sshbroker, connector grpc.ClientConnInterface
}

// newDiagnostics builds the diagnostics collector from the gateway's
// configuration. valkeyInfo is nil when the gateway has no Valkey client.
func newDiagnostics(getenv func(string) string, authMode string, s diagServices, valkeyInfo func(context.Context) (string, error), lg log.Logger) *diag.Collector {
	httpc := &http.Client{Timeout: 2 * time.Second}
	v, c := buildinfo.Info()

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

	return &diag.Collector{
		Gateway:   diag.Component{Name: "gateway", Version: v, Commit: c, Status: diag.StatusOK},
		PublicURL: getenv("OAUTH_PUBLIC_URL"),
		Appliance: getenv("SNEAKERS_APPLIANCE_VERSION"),
		Services: []diag.Probe{
			diag.GRPCHealth("identity", s.identity),
			diag.GRPCHealth("vault", s.vault),
			diag.GRPCHealth("workflow", s.workflow),
			diag.GRPCHealth("audit", s.audit),
			diag.GRPCHealth("notify", s.notify),
			diag.GRPCHealth("sshbroker", s.sshbroker),
			diag.GRPCHealth("connector", s.connector),
			diag.HTTPVersion("mcp", httpc, getenv("MCP_HEALTH_URL")),
		},
		ThirdParty: []diag.Probe{
			diag.HTTPVersion("kratos", httpc, kratos),
			diag.HTTPVersion("hydra", httpc, hydra),
			diag.HTTPVersion("polis", httpc, polis),
			diag.Valkey(valkeyInfo),
			diag.InCluster(),
		},
		Log: lg,
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
