// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
)

// backgroundRoutes serves /readyz from the checker the gateway runs:
// checked in the background every 50 ms, each check bounded by 200 ms.
func backgroundRoutes(t *testing.T, deps ...health.Dependency) *http.ServeMux {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := startChecker(ctx, log.Nop(), deps, health.WithTTL(50*time.Millisecond), health.WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	return routes(t, c)
}

// eventually waits up to 2 s for /readyz to answer code with every
// dependency checked (none pending).
func eventually(t *testing.T, mux http.Handler, code int) readyBody {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, r, _, body := get(t, mux, "/readyz")
		if got == code && !slices.ContainsFunc(r.Dependencies, func(d health.DependencyReport) bool { return d.Error == health.ClassPending }) {
			return r
		}
		if time.Now().After(deadline) {
			t.Fatalf("/readyz stayed %d %s, want %d", got, body, code)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A dependency that hangs (a dropped connection) must never hold /readyz:
// the probes that read it (the kubelet's, the MCP server's) give up after a
// second, and the gateway would read as unready while every required
// dependency is up.
func TestReadyzNeverWaitsOnAHangingDependency(t *testing.T) {
	hang := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	mux := backgroundRoutes(t,
		health.Dependency{Name: "identity", Required: true, Check: (&toggle{}).check},
		health.Dependency{Name: "hydra", Check: hang},
	)
	r := eventually(t, mux, http.StatusOK)
	if r.Status != health.StateDegraded || r.Dependencies[1].Error != "timeout" {
		t.Fatalf("report = %+v", r)
	}
	var slowest time.Duration
	for end := time.Now().Add(time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		started := time.Now()
		code, _, _, body := get(t, mux, "/readyz")
		if d := time.Since(started); d > slowest {
			slowest = d
		}
		if code != http.StatusOK {
			t.Fatalf("/readyz = %d %s", code, body)
		}
	}
	if slowest > 50*time.Millisecond {
		t.Fatalf("the slowest /readyz took %v, want under 50ms", slowest)
	}
}

// The background answers still follow the dependency, down and back up, and
// a required dependency with no answer yet holds readiness.
func TestBackgroundChecksFollowTheDependency(t *testing.T) {
	valkey := &toggle{err: syscall.ECONNREFUSED}
	mux := backgroundRoutes(t, health.Dependency{Name: "valkey", Required: true, Check: valkey.check})
	r := eventually(t, mux, http.StatusServiceUnavailable)
	if r.Dependencies[0].Error != "refused" {
		t.Fatalf("report = %+v", r)
	}
	valkey.set(nil)
	eventually(t, mux, http.StatusOK)
	valkey.set(syscall.ECONNREFUSED)
	eventually(t, mux, http.StatusServiceUnavailable)
}

func TestARequiredDependencyWithNoAnswerYetIsNotReady(t *testing.T) {
	never := func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := startChecker(ctx, log.Nop(), []health.Dependency{{Name: "identity", Required: true, Check: never}}, health.WithTimeout(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	code, r, _, body := get(t, routes(t, c), "/readyz")
	if code != http.StatusServiceUnavailable || r.Dependencies[0].Error != "pending" || time.Since(started) > 50*time.Millisecond {
		t.Fatalf("/readyz = %d %s after %v", code, body, time.Since(started))
	}
}
