// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/sshbroker/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc/codes"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/safeconv"
)

// Trust on first use for SSH host keys. A scan only reports what the target
// offers. A pin binds to the exact fingerprint the person confirmed: the
// gateway scans again and pins only when the target still offers that key.
// Nothing is ever pinned automatically.

func errHostKeyPinNotAdmin() error {
	return gatewayError(codes.PermissionDenied, "SSH host keys are pinned by a site admin", "HOST_KEY_PIN_NOT_ADMIN")
}

func errHostKeyChanged() error {
	return gatewayError(codes.FailedPrecondition, "the target now offers a different host key; scan it again", "HOST_KEY_CHANGED")
}

func errNoSSHConnection() error {
	return gatewayError(codes.FailedPrecondition, "the target has no SSH connection", "TARGET_NO_SSH_CONNECTION")
}

// hostKeyPinActor is the actor for a scan or a pin: a person who is a site
// admin or root, the same people the vault lets change a target's pins.
// Anyone else is refused before the broker or the vault is asked.
func hostKeyPinActor(ctx context.Context) (*vaultv1.ActorContext, error) {
	if _, machine := machineActorFrom(ctx); machine {
		return nil, errHostKeyPinNotAdmin()
	}
	a := actorOf(ctx)
	if uid := a.GetUserId(); uid == "" || uid == "system" {
		return nil, errHostKeyPinNotAdmin()
	}
	if a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || (!a.GetIsSiteAdmin() && !a.GetIsRoot()) {
		return nil, errHostKeyPinNotAdmin()
	}
	return a, nil
}

// sshScanTarget finds the target and the host and port of its SSH
// connection: the default when that is SSH, otherwise the first SSH entry.
func (r *Resolver) sshScanTarget(ctx context.Context, actor *vaultv1.ActorContext, targetID string) (*vaultv1.Target, string, int, error) {
	tl, err := r.Vault.ListTargets(ctx, &vaultv1.ListTargetsRequest{Actor: actor})
	if err != nil {
		return nil, "", 0, err
	}
	var target *vaultv1.Target
	for _, t := range tl.GetTargets() {
		if t.GetId() == targetID {
			target = t
			break
		}
	}
	if target == nil {
		return nil, "", 0, gatewayError(codes.NotFound, "target not found", "TARGET_NOT_FOUND")
	}
	cl, err := r.Vault.ListConnections(ctx, &vaultv1.ListConnectionsRequest{})
	if err != nil {
		return nil, "", 0, err
	}
	sshPort := map[string]int{}
	for _, c := range cl.GetConnections() {
		if c.GetProtocol() == "ssh" {
			sshPort[c.GetId()] = int(c.GetPort())
		}
	}
	ids := []string{target.GetConnectionId()}
	for _, c := range target.GetConnections() {
		if c.GetIsDefault() {
			ids = append([]string{c.GetConnectionId()}, ids...)
		}
	}
	for _, c := range target.GetConnections() {
		ids = append(ids, c.GetConnectionId())
	}
	for _, id := range ids {
		if port, ok := sshPort[id]; ok {
			return target, target.GetHostname(), port, nil
		}
	}
	return nil, "", 0, errNoSSHConnection()
}

// scanHostKey asks the broker for the key the target's SSH connection offers.
func (r *Resolver) scanHostKey(ctx context.Context, actor *vaultv1.ActorContext, targetID string) (*vaultv1.Target, *sshbrokerv1.ScanHostKeyResponse, error) {
	target, host, port, err := r.sshScanTarget(ctx, actor, targetID)
	if err != nil {
		return nil, nil, err
	}
	start := time.Now()
	resp, err := r.SSHBroker.ScanHostKey(ctx, &sshbrokerv1.ScanHostKeyRequest{
		Host: host, Port: safeconv.Int32(port), TargetId: targetID,
		ActorUserId: actor.GetUserId(), Actor: brokerActor(actor),
	})
	l := r.logger(ctx)
	if err != nil {
		l.Warn("host key scan failed", log.F("target_id", targetID), log.F("duration_ms", time.Since(start).Milliseconds()), log.F("error", err.Error()))
		return nil, nil, err
	}
	l.Info("host key scanned", log.F("target_id", targetID), log.F("host_key_fingerprint", resp.GetFingerprintSha256()), log.F("duration_ms", time.Since(start).Milliseconds()))
	return target, resp, nil
}

// hostKeyPinned reports whether pins already hold key (authorized_keys form,
// compared on algorithm and key, ignoring any comment).
func hostKeyPinned(pins []string, key string) bool {
	want := strings.Fields(key)
	if len(want) < 2 {
		return false
	}
	for _, p := range pins {
		if f := strings.Fields(p); len(f) >= 2 && f[0] == want[0] && f[1] == want[1] {
			return true
		}
	}
	return false
}

// pinTargetHostKey pins the key the target offers now, only when its
// fingerprint is exactly the confirmed one.
func (r *Resolver) pinTargetHostKey(ctx context.Context, targetID, fingerprint string) (*vaultv1.Target, error) {
	actor, err := hostKeyPinActor(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(fingerprint) == "" {
		return nil, gatewayError(codes.InvalidArgument, "fingerprint is required", "HOST_KEY_FINGERPRINT_REQUIRED")
	}
	target, scan, err := r.scanHostKey(ctx, actor, targetID)
	if err != nil {
		return nil, err
	}
	l := r.logger(ctx)
	if scan.GetFingerprintSha256() != fingerprint {
		l.Warn("host key pin refused: the offered key changed", log.F("target_id", targetID),
			log.F("confirmed_fingerprint", fingerprint), log.F("offered_fingerprint", scan.GetFingerprintSha256()))
		r.auditHostKeyPin(ctx, actor, targetID, "mismatch", map[string]string{
			"fingerprint_sha256": fingerprint, "offered_fingerprint_sha256": scan.GetFingerprintSha256(),
		})
		return nil, errHostKeyChanged()
	}
	if hostKeyPinned(target.GetSshHostKeys(), scan.GetPublicKey()) {
		l.Info("host key already pinned", log.F("target_id", targetID), log.F("host_key_fingerprint", fingerprint))
		return target, nil
	}
	target.SshHostKeys = append(append([]string{}, target.GetSshHostKeys()...), scan.GetPublicKey())
	saved, err := r.Vault.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: actor, Target: target})
	if err != nil {
		l.Warn("host key pin: target save failed", log.F("target_id", targetID), log.F("error", err.Error()))
		return nil, err
	}
	r.auditHostKeyPin(ctx, actor, targetID, "pinned", map[string]string{
		"fingerprint_sha256": fingerprint, "key_type": scan.GetKeyType(),
	})
	l.Info("host key pinned", log.F("target_id", targetID), log.F("host_key_fingerprint", fingerprint))
	return saved.GetTarget(), nil
}

// auditHostKeyPin records a pin decision as target.host_key.pin, with
// fingerprints only. Best effort: a failed write is logged. The vault audits
// the pin list change itself.
func (r *Resolver) auditHostKeyPin(ctx context.Context, actor *vaultv1.ActorContext, targetID, outcome string, attrs map[string]string) {
	if r.Audit == nil {
		return
	}
	a := map[string]string{"outcome": outcome}
	for k, v := range attrs {
		a[k] = v
	}
	if _, err := r.Audit.RecordEvent(ctx, &auditv1.RecordEventRequest{
		Tier: auditv1.Tier_TIER_AUDIT, Action: "target.host_key.pin", ActorUserId: actor.GetUserId(),
		Subject: targetID, Attributes: a, OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		r.logger(ctx).Error(err, "host key pin audit failed", log.F("target_id", targetID))
	}
}
