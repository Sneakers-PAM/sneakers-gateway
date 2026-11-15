// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/netpolicy"
)

// networkPolicyRefresh is how often the gateway re-reads the internal-only
// setting, so an admin's change takes effect within seconds, without a restart.
const networkPolicyRefresh = 15 * time.Second

// vaultNetworkSettings reads the internal-only setting, its allowed networks
// and require-managed from the vault's security settings.
type vaultNetworkSettings struct{ vault vaultv1.VaultServiceClient }

func (v vaultNetworkSettings) Settings(ctx context.Context) (netpolicy.Settings, error) {
	resp, err := v.vault.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		return netpolicy.Settings{}, err
	}
	s := resp.GetSettings()
	return netpolicy.Settings{InternalOnly: s.GetInternalOnly(), Networks: s.GetAllowedNetworks(), RequireManaged: s.GetRequireManaged()}, nil
}

// requireManaged adapts the provider to the OAuth server's view of it.
func requireManaged(p *netpolicy.Provider) func() (on, known bool) {
	return func() (bool, bool) {
		pub := p.Published()
		return pub.RequireManaged, pub.Known
	}
}
