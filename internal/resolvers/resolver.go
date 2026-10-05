// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"time"

	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	notifyv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/notify/v1"
	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/sshbroker/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
)

// This file is not regenerated. It's the dependency-injection root.

// Resolver holds the backend clients the GraphQL server resolves against.
type Resolver struct {
	Vault     vaultv1.VaultServiceClient
	Identity  identityv1.IdentityServiceClient
	Workflow  workflowv1.WorkflowServiceClient
	Audit     auditv1.AuditServiceClient
	Notify    notifyv1.NotifyServiceClient
	SSHBroker sshbrokerv1.SSHBrokerServiceClient
	// HydraIssuer is the gateway's configured Hydra issuer
	// (env HYDRA_ISSUER), used as the OIDC issuer for LinkOidcClient — the
	// admin picks the service account and the OAuth2 client_id (oidcSubject);
	// the issuer itself is always this trusted server-side value, never
	// caller-supplied. Empty when Hydra is not configured.
	HydraIssuer string
	// Diag gathers the component versions for the diagnostics query.
	Diag *diag.Collector
}

// workflowActorOf is the acting user for the workflow service (its
// ActorContext is a distinct type from the vault's). The access fields feed
// the vault's RACI decision on check-out.
func workflowActorOf(ctx context.Context) *workflowv1.ActorContext {
	i := infoFrom(ctx)
	return &workflowv1.ActorContext{
		UserId:            actorFrom(ctx),
		MfaVerifiedAtUnix: mfaUnix(ctx),
		GroupNames:        i.groups,
		GroupIds:          ActorGroupIDs(ctx),
		IsSiteAdmin:       i.siteAdmin,
		IsRoot:            i.root,
	}
}

// actorKey carries the no-auth dev identity (X-Dev-User) through the request
// context so resolvers can forward it as the vault ActorContext.
type actorKey struct{}

// WithActor stores the acting user id on the context (set by the HTTP layer).
func WithActor(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

func actorFrom(ctx context.Context) string {
	u, _ := ctx.Value(actorKey{}).(string)
	return u
}

// actorInfo carries the gateway-resolved authz attributes for the acting user
// (site-admin / root / group memberships), used to build the vault ActorContext
// for firewall-RACI evaluation.
type actorInfo struct {
	siteAdmin bool
	root      bool
	groups    []string
}

type actorInfoKey struct{}

// WithActorInfo attaches the resolved authz attributes (set by the HTTP layer
// after looking the acting user up in the identity service).
func WithActorInfo(ctx context.Context, siteAdmin, root bool, groups []string) context.Context {
	return context.WithValue(ctx, actorInfoKey{}, actorInfo{siteAdmin: siteAdmin, root: root, groups: groups})
}

func infoFrom(ctx context.Context) actorInfo {
	i, _ := ctx.Value(actorInfoKey{}).(actorInfo)
	return i
}

type groupIDsKey struct{}

// WithActorGroupIDs attaches the signed-in user's directory group ids (the
// same groups as WithActorInfo's names), which GROUP rules match on.
func WithActorGroupIDs(ctx context.Context, ids []string) context.Context {
	return context.WithValue(ctx, groupIDsKey{}, ids)
}

// ActorGroupIDs returns the signed-in user's directory group ids.
func ActorGroupIDs(ctx context.Context) []string {
	ids, _ := ctx.Value(groupIDsKey{}).([]string)
	return ids
}

type recoveryKey struct{}

// WithActorRecovery records that the signed-in user holds the recovery role.
// The vault trusts it only from the gateway, and needs it (with a fresh MFA)
// for prior-version values and restore.
func WithActorRecovery(ctx context.Context, recovery bool) context.Context {
	return context.WithValue(ctx, recoveryKey{}, recovery)
}

func actorRecovery(ctx context.Context) bool {
	r, _ := ctx.Value(recoveryKey{}).(bool)
	return r
}

type mfaVerifiedAtKey struct{}

// WithMFAVerifiedAt attaches when the human session last proved a second
// factor (set by the session gate; never for machine callers).
func WithMFAVerifiedAt(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, mfaVerifiedAtKey{}, t)
}

// MFAVerifiedAt returns the session's last second-factor proof, or the zero
// time when there is none.
func MFAVerifiedAt(ctx context.Context) time.Time {
	t, _ := ctx.Value(mfaVerifiedAtKey{}).(time.Time)
	return t
}

// mfaUnix is MFAVerifiedAt in Unix seconds, 0 when unknown.
func mfaUnix(ctx context.Context) int64 {
	t := MFAVerifiedAt(ctx)
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func actorOf(ctx context.Context) *vaultv1.ActorContext {
	i := infoFrom(ctx)
	return &vaultv1.ActorContext{
		UserId:            actorFrom(ctx),
		IsSiteAdmin:       i.siteAdmin,
		IsRoot:            i.root,
		GroupNames:        i.groups,
		GroupIds:          ActorGroupIDs(ctx),
		MfaVerifiedAtUnix: mfaUnix(ctx),
		IsRecovery:        actorRecovery(ctx),
	}
}

// machineActor carries the verified non-human principal: a
// service-account identity resolved by the gateway's MachineActor middleware
// from an Authorization: Bearer credential. Unlike the human actor
// (userID + siteAdmin/root/groups), a machine principal is never
// site-admin/root and its RACI groups come only from identity's resolution of
// its scope (VerifyApiTokenResponse.group_names or
// ResolveServiceAccountByOidcResponse.group_names), never from a raw split of
// the scope string.
type machineActor struct {
	principalID string
	groupNames  []string
	userID      string
	tokenID     string
	groupIDs    []string
}

type machineActorKey struct{}

// WithMachineActor stores the verified service-account principal (id + the
// identity-resolved RACI group names) on the context. Set by bff.MachineActor
// after a Bearer credential verifies; read back by MachineActorOf when
// building the vault ActorContext for a machine-path resolver. groupNames are
// used verbatim (they may contain spaces, e.g. "Help Desk").
func WithMachineActor(ctx context.Context, principalID string, groupNames []string) context.Context {
	return context.WithValue(ctx, machineActorKey{}, machineActor{principalID: principalID, groupNames: groupNames})
}

func machineActorFrom(ctx context.Context) (machineActor, bool) {
	m, ok := ctx.Value(machineActorKey{}).(machineActor)
	return m, ok
}

// MachineActorOf builds the vault ActorContext for a verified machine
// principal: PrincipalKind SERVICE_ACCOUNT, PrincipalId the service-account id,
// and GroupNames the identity-resolved group names; a machine actor is never
// site-admin/root. If no machine actor is on ctx (MachineActor didn't run, or
// ran and rejected the request) this returns a zero-value ActorContext, which
// resolves NO RACI grants — fail-closed.
func MachineActorOf(ctx context.Context) *vaultv1.ActorContext {
	m, _ := machineActorFrom(ctx)
	if m.tokenID != "" {
		return &vaultv1.ActorContext{
			PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN,
			UserId:        m.userID,
			TokenId:       m.tokenID,
			GroupNames:    append([]string(nil), m.groupNames...),
			GroupIds:      append([]string(nil), m.groupIDs...),
		}
	}
	return &vaultv1.ActorContext{
		PrincipalKind: vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		PrincipalId:   m.principalID,
		GroupNames:    append([]string(nil), m.groupNames...),
		GroupIds:      append([]string(nil), m.groupIDs...),
	}
}

// WithUserTokenActor stores a verified personal token's owner. The resulting
// ActorContext never carries admin or root authority, whatever the owner's
// roles; vault enforces the remaining personal-token limits.
func WithUserTokenActor(ctx context.Context, userID, tokenID string, groupNames []string) context.Context {
	return context.WithValue(ctx, machineActorKey{}, machineActor{userID: userID, tokenID: tokenID, groupNames: groupNames})
}

// WithMachineGroupIDs adds the directory group ids (the same groups as the
// machine actor's names) to the machine actor already on ctx.
func WithMachineGroupIDs(ctx context.Context, ids []string) context.Context {
	m, ok := machineActorFrom(ctx)
	if !ok {
		return ctx
	}
	m.groupIDs = ids
	return context.WithValue(ctx, machineActorKey{}, m)
}

// CallerID names the caller for logs: the signed-in user, a personal token's
// user, or a service account's id. It never returns a token.
func CallerID(ctx context.Context) string {
	if u := actorFrom(ctx); u != "" {
		return u
	}
	m, _ := machineActorFrom(ctx)
	if m.userID != "" {
		return m.userID
	}
	return m.principalID
}
