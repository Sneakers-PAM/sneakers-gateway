// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

// networkPolicyRefresh is how often the gateway re-reads the internal-only
// setting, so an admin's change takes effect within seconds, without a restart.
const networkPolicyRefresh = 15 * time.Second

// vaultNetworkSettings reads the internal-only setting and its allowed
// networks from the vault's security settings.
type vaultNetworkSettings struct{ vault vaultv1.VaultServiceClient }

func (v vaultNetworkSettings) Settings(ctx context.Context) (bool, []string, error) {
	resp, err := v.vault.GetSecuritySettings(ctx, &vaultv1.GetSecuritySettingsRequest{})
	if err != nil {
		return false, nil, err
	}
	s := resp.GetSettings()
	return s.GetInternalOnly(), s.GetAllowedNetworks(), nil
}
