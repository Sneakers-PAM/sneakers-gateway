// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/sshbroker/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

// openSSHSessionTimeout bounds the whole ticket request: the vault reads and
// the broker's CreateSession. Each call is quick when its service is up, so a
// stall means a service isn't answering, and the terminal gets that as an
// error instead of waiting for good.
var openSSHSessionTimeout = 15 * time.Second

// sshOpenLog logs one openSshSession: who asked and for what on the way in,
// the target once it's known, and the outcome with its duration. It logs
// ids, the address and durations only, never the ticket or a secret value.
type sshOpenLog struct {
	l       log.Logger
	started time.Time
}

func (r *mutationResolver) sshOpen(ctx context.Context, actorUserID, secretID, connectionID string) *sshOpenLog {
	l := r.logger(ctx).With(log.F("actor_user_id", actorUserID), log.F("secret_id", secretID), log.F("connection_id", connectionID))
	l.Info("ssh session requested")
	return &sshOpenLog{l: l, started: time.Now()}
}

func (o *sshOpenLog) target(targetID string) { o.l = o.l.With(log.F("target_id", targetID)) }

func (o *sshOpenLog) endpoint(host string, port, hostKeys int) {
	o.l = o.l.With(log.F("host", host), log.F("port", port))
	o.l.Debug("ssh session target resolved", log.F("host_keys", hostKeys))
}

func (o *sshOpenLog) issued(sessionID string) {
	o.l.Info("ssh session ticket issued", log.F("session_id", sessionID), log.F("duration_ms", time.Since(o.started).Milliseconds()))
}

// failed logs the step that failed and returns the error for the client.
// When the request ran out of time it names the service that didn't answer;
// any other error passes through unchanged.
func (o *sshOpenLog) failed(ctx context.Context, step, service string, err error) error {
	if service != "" && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = status.Errorf(codes.DeadlineExceeded, "%s didn't answer within %s while opening the session", service, openSSHSessionTimeout)
	}
	o.l.Warn("ssh session ticket failed", log.F("step", step), log.F("error", err.Error()), log.F("duration_ms", time.Since(o.started).Milliseconds()))
	return err
}

// chooseTarget resolves which of a secret's attached targets to open a
// session on (#168): required when there's more than one, defaults to the
// only one when there's exactly one, and must be one of the attached
// targets when given explicitly. sshbroker independently re-checks
// attachment before any auth is sent; this is the user-facing half of that
// same rule (a clear error instead of a bare refusal).
func chooseTarget(attached []string, wanted string) (string, error) {
	if len(attached) == 0 {
		return "", fmt.Errorf("secret has no target host")
	}
	if wanted == "" {
		if len(attached) > 1 {
			return "", fmt.Errorf("secret has more than one target: targetId is required")
		}
		return attached[0], nil
	}
	if !slices.Contains(attached, wanted) {
		return "", fmt.Errorf("target is not attached to this secret")
	}
	return wanted, nil
}

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
