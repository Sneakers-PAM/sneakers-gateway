// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	"github.com/Bugs5382/go-buildinfo/httpbuildinfo"
	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// headerPrefix starts the build and dependency headers /readyz and /livez
// carry: Sneakers-Version, Sneakers-Commit, Sneakers-Depstate-<name>.
const headerPrefix = "sneakers"

// cacheTTL is how long a check's result is reused; checkTimeout bounds each
// check.
const (
	cacheTTL     = 5 * time.Second
	checkTimeout = time.Second
)

// healthDeps lists the gateway's readiness dependencies. Required: in real
// mode Valkey (sessions) and Kratos (login), and in every mode identity, which
// resolves the actor of every request. The other services, Polis and Hydra
// only degrade it: each backs some operations, not all of them. valkeyPing is
// nil in noauth mode, which has no session store.
func healthDeps(getenv func(string) string, authMode string, s diagServices, valkeyPing func(context.Context) error) []health.Dependency {
	httpc := &http.Client{Timeout: checkTimeout}
	var deps []health.Dependency
	if authMode == "real" {
		deps = append(deps,
			health.Dependency{Name: "valkey", Required: true, Check: valkeyPing},
			health.Dependency{Name: "kratos", Required: true, Check: checkHTTP(httpc, endpoint(envOr(getenv, "KRATOS_PUBLIC_URL", "http://sneakers-kratos:4433"), "/health/ready"))},
		)
	}
	peer := func(name string, conn grpc.ClientConnInterface, required bool) {
		check := func(context.Context) error { return errNotDialled }
		if conn != nil {
			check = grpcPeer(conn)
		}
		deps = append(deps, health.Dependency{Name: name, Required: required, Check: check})
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
		deps = append(deps, health.Dependency{Name: "hydra", Check: checkHTTP(httpc, endpoint(base, "/health/ready"))})
	}
	if getenv("POLIS_PUBLIC_URL") != "" {
		deps = append(deps, health.Dependency{Name: "polis", Check: checkHTTP(httpc, endpoint(envOr(getenv, "POLIS_ISSUER_URL", "http://sneakers-polis:5225"), "/api/health"))})
	}
	return deps
}

// newChecker is go-buildinfo's checker over deps, each check's error tagged
// with the class the diagnostics know (refused, unavailable, unauthenticated)
// where go-buildinfo's own class would differ. opts follow the defaults, so a
// test can shorten the TTL.
func newChecker(lg log.Logger, deps []health.Dependency, opts ...health.Option) (*health.Checker, error) {
	c := health.New(append([]health.Option{health.WithTTL(cacheTTL), health.WithTimeout(checkTimeout), health.WithLogger(lg)}, opts...)...)
	for i := range deps {
		if deps[i].Check != nil {
			deps[i].Check = classified(deps[i].Check)
		}
	}
	return c, c.Register(deps...)
}

func classified(check func(context.Context) error) func(context.Context) error {
	return func(ctx context.Context) error {
		err := check(ctx)
		if c := classOf(err); c != "" {
			return health.Classify(err, c)
		}
		return err
	}
}

// classOf is the class for errors go-buildinfo would report differently, ""
// to keep its own (timeout, error).
func classOf(err error) string {
	var se *statusError
	var gs interface{ GRPCStatus() *status.Status }
	var ne net.Error
	switch {
	case err == nil, errors.Is(err, context.DeadlineExceeded):
		return ""
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.As(err, &se):
		if se.code == http.StatusUnauthorized || se.code == http.StatusForbidden {
			return "unauthenticated"
		}
		return health.ClassError
	case errors.As(err, &gs):
		switch gs.GRPCStatus().Code() {
		case codes.DeadlineExceeded:
			return health.ClassTimeout
		case codes.Unavailable:
			return "unavailable"
		case codes.Unauthenticated, codes.PermissionDenied:
			return "unauthenticated"
		}
		return health.ClassError
	case errors.As(err, &ne):
		if ne.Timeout() {
			return health.ClassTimeout
		}
		return "unavailable"
	}
	return ""
}

// statusError is an HTTP check's non-success answer.
type statusError struct{ code int }

func (e *statusError) Error() string { return fmt.Sprintf("status %d", e.code) }

// errNotDialled is a peer the gateway has no connection to.
var errNotDialled = &statusError{code: http.StatusServiceUnavailable}

// errNotServing is a peer that answers but isn't ready.
var errNotServing = status.Error(codes.Unavailable, "peer not serving")

// grpcPeer checks another service's readiness through its standard health
// check (service "").
func grpcPeer(conn grpc.ClientConnInterface) func(context.Context) error {
	hc := healthpb.NewHealthClient(conn)
	return func(ctx context.Context) error {
		resp, err := hc.Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			return err
		}
		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			return errNotServing
		}
		return nil
	}
}

// checkHTTP checks that a GET of url answers 2xx.
func checkHTTP(client *http.Client, url string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return &statusError{code: resp.StatusCode}
		}
		return nil
	}
}

// mountHealth serves go-buildinfo's /livez (the process only) and /readyz
// (the dependencies), outside auth. Both carry the build headers.
func mountHealth(mux *http.ServeMux, c *health.Checker) error {
	h, err := httpbuildinfo.New(httpbuildinfo.WithPrefix(headerPrefix), httpbuildinfo.WithChecker(c))
	if err != nil {
		return err
	}
	mux.Handle("/livez", h.Livez())
	mux.Handle("/readyz", h.Readyz())
	return nil
}

// gatewayDependencies gives the diagnostics the gateway's own readiness.
func gatewayDependencies(c *health.Checker) func(context.Context) []diag.Dependency {
	return func(ctx context.Context) []diag.Dependency {
		r := c.Report(ctx)
		out := make([]diag.Dependency, 0, len(r.Dependencies))
		for _, d := range r.Dependencies {
			out = append(out, diag.Dependency{Name: d.Name, State: string(d.State), Required: d.Required, Error: d.Error, Version: d.Version})
		}
		return out
	}
}
