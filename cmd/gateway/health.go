// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/health"
	"google.golang.org/grpc"
)

// newHealthChecker lists the gateway's readiness dependencies. Required: in
// real mode Valkey (sessions) and Kratos (login), and in every mode identity,
// which resolves the actor of every request. The other services, Polis and
// Hydra only degrade it: each backs some operations, not all of them.
// valkeyPing is nil in noauth mode, which has no session store.
func newHealthChecker(getenv func(string) string, authMode string, s diagServices, valkeyPing func(context.Context) error, lg log.Logger) *health.Checker {
	httpc := &http.Client{Timeout: health.DefaultTimeout}
	var deps []health.Dep
	if authMode == "real" {
		deps = append(deps,
			health.Dep{Name: "valkey", Required: true, Check: valkeyPing},
			health.Dep{Name: "kratos", Required: true, Check: health.HTTP(httpc, endpoint(envOr(getenv, "KRATOS_PUBLIC_URL", "http://sneakers-kratos:4433"), "/health/ready"))},
		)
	}
	peer := func(name string, conn grpc.ClientConnInterface, required bool) {
		check := func(context.Context) error { return errNotDialled }
		if conn != nil {
			check = health.GRPC(conn)
		}
		deps = append(deps, health.Dep{Name: name, Required: required, Check: check})
	}
	peer("identity", s.identity, true)
	peer("vault", s.vault, false)
	peer("workflow", s.workflow, false)
	peer("audit", s.audit, false)
	peer("notify", s.notify, false)
	peer("sshbroker", s.sshbroker, false)
	if envTrue("HYDRA_ENABLED") {
		base := getenv("HYDRA_ADMIN_URL")
		if base == "" {
			base = originOf(envOr(getenv, "HYDRA_JWKS_URL", "http://sneakers-hydra:4444/.well-known/jwks.json"))
		}
		deps = append(deps, health.Dep{Name: "hydra", Check: health.HTTP(httpc, endpoint(base, "/health/ready"))})
	}
	if getenv("POLIS_PUBLIC_URL") != "" {
		deps = append(deps, health.Dep{Name: "polis", Check: health.HTTP(httpc, endpoint(envOr(getenv, "POLIS_ISSUER_URL", "http://sneakers-polis:5225"), "/api/health"))})
	}
	return &health.Checker{Deps: deps, Log: lg}
}

// errNotDialled is a peer the gateway has no connection to.
var errNotDialled = &health.StatusError{Code: http.StatusServiceUnavailable}

// mountHealth serves /livez (the process only), /readyz (the dependencies)
// and the existing /health, all outside auth.
func mountHealth(mux *http.ServeMux, c *health.Checker, authMode string) {
	mux.Handle("/livez", c.Livez())
	mux.Handle("/readyz", c.Readyz())
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"` + authMode + `"}`))
	})
}

// gatewayDependencies gives the diagnostics the gateway's own readiness.
func gatewayDependencies(c *health.Checker) func(context.Context) []diag.Dependency {
	return func(ctx context.Context) []diag.Dependency {
		r := c.Report(ctx)
		out := make([]diag.Dependency, 0, len(r.Dependencies))
		for _, d := range r.Dependencies {
			out = append(out, diag.Dependency{Name: d.Name, State: d.State, Required: d.Required, Error: d.Error, Version: d.Version})
		}
		return out
	}
}
