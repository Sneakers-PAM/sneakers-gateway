// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"slices"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/sshbroker/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

// resolveSSHEndpoint turns a targetId into host + port, plus the target's
// pinned SSH host keys for the broker, via the vault's
// ListTargets/ListConnections (no single join RPC exists). wantConnID, when
// non-empty, must name one of the target's own connections; empty picks the
// target's default connection.
func (r *mutationResolver) resolveSSHEndpoint(ctx context.Context, targetID, wantConnID string) (string, int, []string, error) {
	tl, err := r.Vault.ListTargets(ctx, &vaultv1.ListTargetsRequest{Actor: actorOf(ctx)})
	if err != nil {
		return "", 0, nil, err
	}
	var host, defaultConnID string
	var conns []*vaultv1.TargetConnection
	var hostKeys []string
	for _, t := range tl.GetTargets() {
		if t.GetId() == targetID {
			host, defaultConnID, conns, hostKeys = t.GetHostname(), t.GetConnectionId(), t.GetConnections(), t.GetSshHostKeys()
			break
		}
	}
	if host == "" {
		return "", 0, nil, fmt.Errorf("target not found")
	}
	connID := defaultConnID
	if wantConnID != "" {
		if !slices.ContainsFunc(conns, func(c *vaultv1.TargetConnection) bool { return c.GetConnectionId() == wantConnID }) {
			return "", 0, nil, fmt.Errorf("connection does not belong to this target")
		}
		connID = wantConnID
	}
	cl, err := r.Vault.ListConnections(ctx, &vaultv1.ListConnectionsRequest{})
	if err != nil {
		return "", 0, nil, err
	}
	for _, c := range cl.GetConnections() {
		if c.GetId() == connID {
			if c.GetProtocol() != "ssh" {
				return "", 0, nil, fmt.Errorf("connection is not ssh")
			}
			return host, int(c.GetPort()), hostKeys, nil
		}
	}
	return "", 0, nil, fmt.Errorf("connection not found")
}

// HostKeysForSave returns the SSH host keys a target save sends. The vault
// replaces a target's pins on every save, so an edit that leaves the field out
// (given nil) sends the pins the target already has; a create, or an explicit
// list (empty included), sends given as is.
func HostKeysForSave(ctx context.Context, v vaultv1.VaultServiceClient, actor *vaultv1.ActorContext, id string, given []string) ([]string, error) {
	if given != nil || id == "" {
		return given, nil
	}
	tl, err := v.ListTargets(ctx, &vaultv1.ListTargetsRequest{Actor: actor})
	if err != nil {
		return nil, err
	}
	for _, t := range tl.GetTargets() {
		if t.GetId() == id {
			return t.GetSshHostKeys(), nil
		}
	}
	return nil, nil
}

// brokerActor is the vault actor in the broker's form. The broker passes it
// through to the vault and refuses every principal kind but a person; the two
// PrincipalKind enums share names and numbers.
func brokerActor(actor *vaultv1.ActorContext) *sshbrokerv1.ActorContext {
	return &sshbrokerv1.ActorContext{
		UserId:        actor.GetUserId(),
		IsSiteAdmin:   actor.GetIsSiteAdmin(),
		IsRoot:        actor.GetIsRoot(),
		GroupNames:    actor.GetGroupNames(),
		PrincipalKind: sshbrokerv1.PrincipalKind(actor.GetPrincipalKind()),
	}
}
