// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/bff"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/health"
)

func depsOf(c *health.Checker) map[string]bool {
	out := map[string]bool{}
	for _, d := range c.Deps {
		out[d.Name] = d.Required
	}
	return out
}

func TestNewHealthChecker_NoauthNeedsOnlyIdentity(t *testing.T) {
	t.Setenv("HYDRA_ENABLED", "")
	c := newHealthChecker(func(string) string { return "" }, "noauth", diagServices{}, nil, log.Nop())
	want := map[string]bool{"identity": true, "vault": false, "workflow": false, "audit": false, "notify": false, "sshbroker": false}
	got := depsOf(c)
	if len(got) != len(want) {
		t.Fatalf("deps = %v, want %v", got, want)
	}
	for k, req := range want {
		if r, ok := got[k]; !ok || r != req {
			t.Fatalf("deps = %v, want %v", got, want)
		}
	}
}

func TestNewHealthChecker_RealModeRequiresValkeyAndKratos(t *testing.T) {
	ready := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/ready", "/api/health":
			if !ready {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("HYDRA_ENABLED", "true")
	vars := map[string]string{
		"KRATOS_PUBLIC_URL": srv.URL + "/",
		"HYDRA_JWKS_URL":    srv.URL + "/.well-known/jwks.json",
		"POLIS_PUBLIC_URL":  "https://sso.example.test",
		"POLIS_ISSUER_URL":  srv.URL,
	}
	valkeyUp := true
	ping := func(context.Context) error {
		if valkeyUp {
			return nil
		}
		return errors.New("dial valkey.example.test:6379: refused")
	}
	c := newHealthChecker(func(k string) string { return vars[k] }, "real", diagServices{}, ping, log.Nop())
	requireDeps(t, c, map[string]bool{"valkey": true, "kratos": true, "identity": true, "hydra": false, "polis": false})
	onlyDeps(c, "valkey", "kratos", "hydra", "polis") // the gRPC peers have no conn here
	now := time.Now()
	c.Now = func() time.Time { return now }

	if r := c.Report(context.Background()); r.Status != health.StateOK {
		t.Fatalf("healthy: %+v", r)
	}
	ready = false
	now = now.Add(health.CacheTTL + time.Second)
	r := c.Report(context.Background())
	if r.Status != health.StateDown || r.Dependencies[2].State != health.StateDegraded || r.Dependencies[3].State != health.StateDegraded {
		t.Fatalf("kratos, hydra and polis not ready: %+v, want down with hydra and polis degraded", r)
	}
	ready, valkeyUp = true, false
	now = now.Add(health.CacheTTL + time.Second)
	if r := c.Report(context.Background()); r.Status != health.StateDown || r.Dependencies[0].Error != health.ClassError {
		t.Fatalf("valkey down: %+v", r)
	}
}

func requireDeps(t *testing.T, c *health.Checker, want map[string]bool) {
	t.Helper()
	got := depsOf(c)
	for name, req := range want {
		if r, ok := got[name]; !ok || r != req {
			t.Fatalf("deps = %v; %s should be present with required=%v", got, name, req)
		}
	}
}

func onlyDeps(c *health.Checker, names ...string) {
	keep := c.Deps[:0]
	for _, d := range c.Deps {
		if slices.Contains(names, d.Name) {
			keep = append(keep, d)
		}
	}
	c.Deps = keep
}

func TestHealthRoutes(t *testing.T) {
	down := true
	c := &health.Checker{Deps: []health.Dep{{Name: "valkey", Required: true, Check: func(context.Context) error {
		if down {
			return errors.New("refused")
		}
		return nil
	}}}}
	mux := http.NewServeMux()
	mountHealth(mux, c, "real")
	for path, want := range map[string]int{"/livez": 200, "/readyz": 503, "/health": 200} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Fatalf("%s = %d, want %d", path, rec.Code, want)
		}
	}
}

// TestValkeyReadinessAgainstARealValkey stops a real Valkey mid-test. It runs
// when GATEWAY_TEST_VALKEY_URL and GATEWAY_TEST_VALKEY_CONTAINER name a
// throwaway container published on a fixed port.
func TestValkeyReadinessAgainstARealValkey(t *testing.T) {
	url, name := os.Getenv("GATEWAY_TEST_VALKEY_URL"), os.Getenv("GATEWAY_TEST_VALKEY_CONTAINER")
	if url == "" || name == "" {
		t.Skip("GATEWAY_TEST_VALKEY_URL and GATEWAY_TEST_VALKEY_CONTAINER not set")
	}
	ctx := context.Background()
	rc, err := bff.ParseRedisURL(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := &health.Checker{
		Deps: []health.Dep{{Name: "valkey", Required: true, Check: func(ctx context.Context) error { return rc.Redis().Ping(ctx).Err() }}},
		Now:  func() time.Time { return now },
	}
	mux := http.NewServeMux()
	mountHealth(mux, c, "real")
	probe := func(path string) (int, health.Report) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		var r health.Report
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return rec.Code, r
	}
	docker := func(args ...string) {
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("docker %v: %v %s", args, err, out)
		}
	}
	if code, r := probe("/readyz"); code != 200 {
		t.Fatalf("valkey up: %d %+v", code, r)
	}
	docker("stop", "-t", "1", name)
	t.Cleanup(func() { _ = exec.Command("docker", "start", name).Run() })
	now = now.Add(health.CacheTTL + time.Second)
	if code, r := probe("/readyz"); code != 503 || r.Dependencies[0].State != health.StateDown {
		t.Fatalf("valkey stopped: %d %+v, want 503 down", code, r)
	}
	if code, _ := probe("/livez"); code != 200 {
		t.Fatalf("liveness with valkey stopped = %d", code)
	}
	docker("start", name)
	deadline := time.Now().Add(20 * time.Second)
	for {
		now = now.Add(health.CacheTTL + time.Second)
		code, r := probe("/readyz")
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("valkey restarted but readiness stayed %d %+v", code, r)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
