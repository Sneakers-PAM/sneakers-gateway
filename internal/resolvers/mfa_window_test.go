// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// settingsVault answers the security-settings reads and writes.
type settingsVault struct {
	vaultv1.VaultServiceClient
}

func (settingsVault) GetSecuritySettings(context.Context, *vaultv1.GetSecuritySettingsRequest, ...grpc.CallOption) (*vaultv1.GetSecuritySettingsResponse, error) {
	return &vaultv1.GetSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{RequireMfaForReveal: true}}, nil
}

func (settingsVault) UpdateSecuritySettings(_ context.Context, req *vaultv1.UpdateSecuritySettingsRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecuritySettingsResponse, error) {
	return &vaultv1.UpdateSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{RequireMfaForReveal: req.GetRequireMfaForReveal()}}, nil
}

func settingsClient(window time.Duration) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: settingsVault{}, MFAMaxAge: window}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "u-1")))
	}))
}

// The settings report the MFA window the gateway enforces, in seconds: the
// configured MFA_MAX_AGE, the 30-minute default when unset, and 0 when every
// sensitive action asks.
func TestSecuritySettingsReportTheMFAWindow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		window time.Duration
		want   int
	}{
		{"configured", 90 * time.Minute, 5400},
		{"unset", 0, 1800},
		// bff.MFAEveryTime, what MFA_MAX_AGE=0 parses to.
		{"every time", time.Nanosecond, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := settingsClient(tc.window)
			var q struct {
				SecuritySettings struct{ MfaMaxAgeSeconds int }
			}
			c.MustPost(`{ securitySettings { mfaMaxAgeSeconds } }`, &q)
			if q.SecuritySettings.MfaMaxAgeSeconds != tc.want {
				t.Fatalf("query mfaMaxAgeSeconds = %d, want %d", q.SecuritySettings.MfaMaxAgeSeconds, tc.want)
			}
			var m struct {
				UpdateSecuritySettings struct{ MfaMaxAgeSeconds int }
			}
			c.MustPost(`mutation { updateSecuritySettings(input: {requireMfaForReveal: true}) { mfaMaxAgeSeconds } }`, &m)
			if m.UpdateSecuritySettings.MfaMaxAgeSeconds != tc.want {
				t.Fatalf("mutation mfaMaxAgeSeconds = %d, want %d", m.UpdateSecuritySettings.MfaMaxAgeSeconds, tc.want)
			}
		})
	}
}
