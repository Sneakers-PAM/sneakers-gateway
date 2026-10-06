// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
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

// fakeVault is a minimal VaultServiceClient stub: only GetSecuritySettings is
// implemented; every other method is unused by these tests. Embedding the
// interface satisfies the type without hand-writing the full surface.
type fakeVault struct {
	vaultv1.VaultServiceClient
	seconds int32
	err     error
	calls   int
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
