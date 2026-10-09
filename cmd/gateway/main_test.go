// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

// TestClampSessionTTL covers the [15m, 60m] window and the 30m default for an
// unset/zero value.
func TestClampSessionTTL(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero defaults to 30m", 0, sessionTTLDefault},
		{"negative defaults to 30m", -time.Minute, sessionTTLDefault},
		{"below min clamps up to 15m", 5 * time.Minute, sessionTTLMin},
		{"at min passes through", sessionTTLMin, sessionTTLMin},
		{"in window passes through", 45 * time.Minute, 45 * time.Minute},
		{"at max passes through", sessionTTLMax, sessionTTLMax},
		{"above max clamps down to 60m", 8 * time.Hour, sessionTTLMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clampSessionTTL(tc.in); got != tc.want {
				t.Errorf("clampSessionTTL(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// fakeVault is a minimal VaultServiceClient stub: only the methods this
// package's tests use are implemented; every other method is unused.
// Embedding the interface satisfies the type without hand-writing the full
// surface.
type fakeVault struct {
	vaultv1.VaultServiceClient
	seconds int32
	err     error
	calls   int

	connectors    *vaultv1.ListConnectorsResponse
	connectorsErr error
}

func (f *fakeVault) GetSecuritySettings(_ context.Context, _ *vaultv1.GetSecuritySettingsRequest, _ ...grpc.CallOption) (*vaultv1.GetSecuritySettingsResponse, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.GetSecuritySettingsResponse{
		Settings: &vaultv1.SecuritySettings{SessionTtlSeconds: f.seconds},
	}, nil
}

func (f *fakeVault) ListConnectors(context.Context, *vaultv1.ListConnectorsRequest, ...grpc.CallOption) (*vaultv1.ListConnectorsResponse, error) {
	return f.connectors, f.connectorsErr
}

// TestSessionTTLProviderSourcedFromSettings verifies the provider reads the TTL
// from vault SecuritySettings and clamps it to the supported window.
func TestSessionTTLProviderSourcedFromSettings(t *testing.T) {
	cases := []struct {
		name    string
		seconds int32
		want    time.Duration
	}{
		{"in-window 45m", 2700, 45 * time.Minute},
		{"unset defaults to 30m", 0, sessionTTLDefault},
		{"below min clamps to 15m", 300, sessionTTLMin},
		{"above max clamps to 60m", 100000, sessionTTLMax},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newSessionTTLProvider(&fakeVault{seconds: tc.seconds})
			got, err := p.refresh(context.Background())
			if err != nil {
				t.Fatalf("refresh: %v", err)
			}
			if got != tc.want {
				t.Errorf("refresh resolved = %v, want %v", got, tc.want)
			}
			if p.get() != tc.want {
				t.Errorf("cached get() = %v, want %v", p.get(), tc.want)
			}
		})
	}
}

// TestSessionTTLProviderFallbackOnUnavailable verifies that a vault read failure
// retains the last known good value (seeded to the 30m default) instead of
// zeroing the TTL, so authentication keeps working while vault is unreachable.
func TestSessionTTLProviderFallbackOnUnavailable(t *testing.T) {
	// Fresh provider: no successful read yet, so it holds the seeded default.
	down := &fakeVault{err: errors.New("vault unreachable")}
	p := newSessionTTLProvider(down)
	got, err := p.refresh(context.Background())
	if err == nil {
		t.Fatalf("refresh: expected error, got nil")
	}
	if got != sessionTTLDefault || p.get() != sessionTTLDefault {
		t.Fatalf("fallback TTL = %v (cached %v), want %v", got, p.get(), sessionTTLDefault)
	}

	// After a good read, a later failure must retain the previously cached value.
	ok := &fakeVault{seconds: 2700}
	p2 := newSessionTTLProvider(ok)
	if _, err := p2.refresh(context.Background()); err != nil {
		t.Fatalf("refresh (good): %v", err)
	}
	p2.vault = down
	got2, err := p2.refresh(context.Background())
	if err == nil {
		t.Fatalf("refresh (down): expected error, got nil")
	}
	if got2 != 45*time.Minute || p2.get() != 45*time.Minute {
		t.Fatalf("retained TTL = %v (cached %v), want %v", got2, p2.get(), 45*time.Minute)
	}
}

func TestMCPEnabledByDefault(t *testing.T) {
	for v, want := range map[string]bool{"": true, "true": true, " TRUE ": true, "1": true, "false": false, " False": false, "0": false} {
		if got := switchOn(v); got != want {
			t.Errorf("MCP_ENABLED=%q: enabled=%v, want %v", v, got, want)
		}
	}
}

// TestOTLPEndpointUnsetStaysEmpty covers #53: an unset or empty
// OTEL_EXPORTER_OTLP_ENDPOINT must reach go-otel's Init as "", which it
// treats as export-off, not as a localhost:4317 default nothing is
// listening on.
func TestOTLPEndpointUnsetStaysEmpty(t *testing.T) {
	if got := otlpEndpoint(envOf(map[string]string{})); got != "" {
		t.Errorf("otlpEndpoint with nothing set: got %q, want empty", got)
	}
	if got := otlpEndpoint(envOf(map[string]string{"OTHER_VAR": "x"})); got != "" {
		t.Errorf("otlpEndpoint with an unrelated var set: got %q, want empty", got)
	}
	if got := otlpEndpoint(envOf(map[string]string{"OTEL_EXPORTER_OTLP_ENDPOINT": "collector:4317"})); got != "collector:4317" {
		t.Errorf("otlpEndpoint passthrough: got %q, want %q", got, "collector:4317")
	}
}

// TestWSUpgradeErrorWritesNothing covers #32: the upgrader's Error handler
// must only log, never write to the ResponseWriter. gqlgen's transport always
// sends its own 400 after an Upgrade error, so a second write here would
// double up (net/http's "superfluous response.WriteHeader" warning).
func TestWSUpgradeErrorWritesNothing(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	wsUpgradeError(zerolog.Nop())(rec, req, http.StatusForbidden, errors.New("cross-origin"))
	if rec.Code != http.StatusOK {
		t.Errorf("wsUpgradeError wrote status %d, want untouched (%d)", rec.Code, http.StatusOK)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("wsUpgradeError wrote %q to the body, want none", rec.Body.String())
	}
}
