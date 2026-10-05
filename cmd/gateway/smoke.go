// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// smokeTimeout bounds each read the smoke route makes.
const smokeTimeout = 3 * time.Second

// smokeCheck is one read the smoke route makes.
type smokeCheck struct {
	name string
	run  func(context.Context) error
}

// smokeChecks are the appliance's post-upgrade reads: a real query through
// identity and vault (each reads its database), the readiness of workflow and
// audit, and, in real mode, the session store. Nothing is cached.
func smokeChecks(identity identityv1.IdentityServiceClient, vault vaultv1.VaultServiceClient, s diagServices, valkeyPing func(context.Context) error) []smokeCheck {
	checks := []smokeCheck{
		{"identity", func(ctx context.Context) error {
			_, err := identity.GetSetupState(ctx, &identityv1.GetSetupStateRequest{})
			return err
		}},
		{"vault", func(ctx context.Context) error {
			_, err := vault.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
			return err
		}},
	}
	for _, p := range []struct {
		name string
		conn grpc.ClientConnInterface
	}{{"workflow", s.workflow}, {"audit", s.audit}} {
		check := func(context.Context) error { return errNotDialled }
		if p.conn != nil {
			check = grpcPeer(p.conn)
		}
		checks = append(checks, smokeCheck{p.name, check})
	}
	if valkeyPing != nil {
		checks = append(checks, smokeCheck{"valkey", valkeyPing})
	}
	return checks
}

type smokeResult struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// smokeHandler serves GET /smoke: it runs every check and answers 200 when
// each succeeds, 503 otherwise. A failure carries its class only, never the
// error text.
func smokeHandler(checks []smokeCheck, lg log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		start := time.Now()
		all := true
		out := make([]smokeResult, 0, len(checks))
		for _, c := range checks {
			ctx, cancel := context.WithTimeout(r.Context(), smokeTimeout)
			t0 := time.Now()
			err := c.run(ctx)
			cancel()
			res := smokeResult{Name: c.name, OK: err == nil}
			if err != nil {
				all = false
				res.Error = classOf(err)
				if res.Error == "" {
					res.Error = health.ClassError
				}
				lg.Ctx(r.Context()).Warn("smoke read failed", log.F("check", c.name), log.F("class", res.Error),
					log.F("dur", float64(time.Since(t0))/float64(time.Millisecond)), log.F("error", err.Error()))
			}
			out = append(out, res)
		}
		code := http.StatusOK
		if !all {
			code = http.StatusServiceUnavailable
		}
		lg.Ctx(r.Context()).Info("smoke", log.F("ok", all), log.F("dur", float64(time.Since(start))/float64(time.Millisecond)))
		writeSmoke(w, code, map[string]any{"ok": all, "checks": out})
	})
}

func writeSmoke(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
