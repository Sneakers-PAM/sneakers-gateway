// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
)

// resolveSSHEndpoint turns a targetId into host + port via the vault's
// ListTargets/ListConnections (no single join RPC exists).
func (r *mutationResolver) resolveSSHEndpoint(ctx context.Context, targetID string) (string, int, error) {
	tl, err := r.Vault.ListTargets(ctx, &vaultv1.ListTargetsRequest{Actor: actorOf(ctx)})
	if err != nil {
		return "", 0, err
	}
	var host, connID string
	for _, t := range tl.GetTargets() {
		if t.GetId() == targetID {
			host, connID = t.GetHostname(), t.GetConnectionId()
			break
		}
	}
	if host == "" {
		return "", 0, fmt.Errorf("target not found")
	}
	cl, err := r.Vault.ListConnections(ctx, &vaultv1.ListConnectionsRequest{})
	if err != nil {
		return "", 0, err
	}
	for _, c := range cl.GetConnections() {
		if c.GetId() == connID {
			if c.GetProtocol() != "ssh" {
				return "", 0, fmt.Errorf("connection is not ssh")
			}
			return host, int(c.GetPort()), nil
		}
	}
	return "", 0, fmt.Errorf("connection not found")
}
