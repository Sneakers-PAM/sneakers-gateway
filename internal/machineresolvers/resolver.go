// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package machineresolvers is the gqlgen executable schema for the gateway's
// machine-only GraphQL surface: served on a DISTINCT endpoint
// (/machine/graphql) behind bff.MachineActor, generated from
// graphql/machine.graphqls via gqlgen-machine.yml. Kept as its own package
// (not folded into internal/resolvers) so the human GraphQL
// schema/resolvers/generated code stays separate — a machine-scoped mutation can
// never leak into the human /graphql surface by accident of a shared
// executable schema.
package machineresolvers

import (
	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

// This file is not regenerated. It's the dependency-injection root.

// Resolver holds the backend client the machine GraphQL surface resolves
// against. Only vault is needed today (RevealSecretFieldForPrincipal); add
// more only if a future machine-path capability needs them.
type Resolver struct {
	Vault vaultv1.VaultServiceClient
	// PublicURL is the Sneakers UI base, for the approval link on a secret use.
	PublicURL string
	// ApprovalRunLinks points a use's approvalUrl at its run's page,
	// <PublicURL>/approvals/run/<runId>, when it has a run id
	// (APPROVAL_RUN_LINKS). Off, every link is <PublicURL>/approvals.
	ApprovalRunLinks bool
	// ActiveUsers lists the active people for the vault's approval
	// decisions; nil means unknown (never a single-user install).
	ActiveUsers *resolvers.ActiveUsers
	// Log is the request logger; nil logs nothing.
	Log log.Logger
}

func (r *Resolver) logger() log.Logger {
	if r.Log == nil {
		return log.Nop()
	}
	return r.Log
}
