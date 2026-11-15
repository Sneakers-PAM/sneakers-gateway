// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	connectorv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/connector/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/safeconv"
)

// Trust on first use for a target's TLS certificate (sneakers-gateway#178),
// the same rules as the SSH host key pair in host_key_tofu.go: a scan only
// reports what the target sends; a pin binds to the exact fingerprint the
// person confirmed, after a fresh scan still offers it. Nothing is pinned
// automatically, and a token never scans or pins.

func errTLSCertPinNotAdmin() error {
	return gatewayError(codes.PermissionDenied,
		"TLS certificates are pinned by a person in the web app. An agent's token can't change them, even an admin's.",
		"TLS_CERT_PIN_NOT_ADMIN")
}

func errTLSCertPinNotOwner() error {
	return gatewayError(codes.PermissionDenied,
		"TLS certificates on a personal target are pinned by its owner, and on a shared target by a site admin.",
		"TLS_CERT_PIN_NOT_OWNER")
}

func errTLSCertChanged() error {
	return gatewayError(codes.FailedPrecondition, "the target no longer offers that certificate; scan it again", "TLS_CERT_CHANGED")
}

func errTLSCertNotPinnable() error {
	return gatewayError(codes.FailedPrecondition,
		"pinning that certificate alone would not let the connector trust the target (expired, wrong name, or not its issuer)",
		"TLS_CERT_NOT_PINNABLE")
}

func errNoTLSConnection() error {
	return gatewayError(codes.FailedPrecondition, "the target has no TLS connection", "TARGET_NO_TLS_CONNECTION")
}

func errTLSFingerprintInvalid() error {
	return gatewayError(codes.InvalidArgument, "fingerprint must be 64 hex digits (SHA-256)", "TLS_CERT_FINGERPRINT_INVALID")
}

func errConnectorUnavailable() error {
	return gatewayError(codes.Unavailable, "the connector is not configured on this server", "CONNECTOR_UNAVAILABLE")
}

// tlsPinActor is the actor for a scan or a pin: a person, never a token.
func tlsPinActor(ctx context.Context) (*vaultv1.ActorContext, error) {
	if _, machine := machineActorFrom(ctx); machine {
		return nil, errTLSCertPinNotAdmin()
	}
	a := actorOf(ctx)
	if uid := a.GetUserId(); uid == "" || uid == "system" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, errTLSCertPinNotAdmin()
	}
	return a, nil
}

// normalizeTLSFingerprint reduces what a person pasted to 64 lowercase hex
// digits: an optional "sha256:" prefix and colons are dropped.
func normalizeTLSFingerprint(in string) (string, bool) {
	s := strings.ToLower(strings.TrimSpace(in))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.ReplaceAll(s, ":", "")
	if len(s) != 64 {
		return "", false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return s, true
}

// tlsScanTarget finds the target and the host and port of its TLS
// connection: the default when that uses TLS, otherwise the first one that
// does. SSH is never a TLS connection here: its host key is the other pair.
func (r *Resolver) tlsScanTarget(ctx context.Context, actor *vaultv1.ActorContext, targetID string) (*vaultv1.Target, string, int, error) {
	target, err := r.pinnableTarget(ctx, actor, targetID, "TLS certificate", errTLSCertPinNotOwner)
	if err != nil {
		return nil, "", 0, err
	}
	cl, err := r.Vault.ListConnections(ctx, &vaultv1.ListConnectionsRequest{})
	if err != nil {
		return nil, "", 0, err
	}
	tlsPort := map[string]int{}
	for _, c := range cl.GetConnections() {
		if c.GetUseTls() && c.GetProtocol() != "ssh" {
			tlsPort[c.GetId()] = int(c.GetPort())
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
		if port, ok := tlsPort[id]; ok {
			return target, target.GetHostname(), port, nil
		}
	}
	return nil, "", 0, errNoTLSConnection()
}

// tlsCertScan is one scan's answer: the target and what the connector read.
type tlsCertScan struct {
	target *vaultv1.Target
	resp   *connectorv1.ScanTLSCertificateResponse
}

// scanTLSCertificate asks the connector for the chain the target's TLS
// connection sends.
func (r *Resolver) scanTLSCertificate(ctx context.Context, actor *vaultv1.ActorContext, targetID string) (*tlsCertScan, error) {
	if r.Connector == nil {
		return nil, errConnectorUnavailable()
	}
	target, host, port, err := r.tlsScanTarget(ctx, actor, targetID)
	if err != nil {
		return nil, err
	}
	l := r.logger(ctx)
	l.Debug("TLS certificate scan", log.F("target_id", targetID), log.F("address", net.JoinHostPort(host, strconv.Itoa(port))))
	start := time.Now()
	resp, err := r.Connector.ScanTLSCertificate(ctx, &connectorv1.ScanTLSCertificateRequest{
		Host: host, Port: safeconv.Int32(port), TargetId: targetID,
		ActorUserId: actor.GetUserId(), Actor: connectorActor(actor),
	})
	if err != nil {
		l.Warn("TLS certificate scan failed", log.F("target_id", targetID), log.F("duration_ms", time.Since(start).Milliseconds()), log.F("error", err.Error()))
		return nil, err
	}
	l.Info("TLS certificate scanned", log.F("target_id", targetID), log.F("certificates", len(resp.GetChain())),
		log.F("system_trusted", resp.GetSystemTrusted()), log.F("duration_ms", time.Since(start).Milliseconds()))
	return &tlsCertScan{target: target, resp: resp}, nil
}

// connectorActor is the vault actor in the connector's form (the principal
// kinds share names and numbers).
func connectorActor(actor *vaultv1.ActorContext) *connectorv1.ActorContext {
	return &connectorv1.ActorContext{
		UserId:        actor.GetUserId(),
		IsSiteAdmin:   actor.GetIsSiteAdmin(),
		IsRoot:        actor.GetIsRoot(),
		GroupNames:    actor.GetGroupNames(),
		PrincipalKind: connectorv1.PrincipalKind(actor.GetPrincipalKind()),
		SessionRef:    actor.GetSessionRef(),
	}
}

// tsPtr is a certificate date as RFC 3339 UTC, nil when the connector sent none.
func tsPtr(t *timestamppb.Timestamp) *string {
	if t == nil {
		return nil
	}
	s := t.AsTime().UTC().Format(time.RFC3339)
	return &s
}

// tlsCertPinned reports whether pins already hold fp (compared as bare
// lowercase hex, which is how the vault stores them).
func tlsCertPinned(pins []string, fp string) bool {
	for _, p := range pins {
		if n, ok := normalizeTLSFingerprint(p); ok && n == fp {
			return true
		}
	}
	return false
}

func (r *Resolver) scanTargetTLSCertificate(ctx context.Context, targetID string) (*TargetTLSCertificateScan, error) {
	actor, err := tlsPinActor(ctx)
	if err != nil {
		return nil, err
	}
	scanned, err := r.scanTLSCertificate(ctx, actor, targetID)
	if err != nil {
		return nil, err
	}
	resp := scanned.resp
	out := &TargetTLSCertificateScan{
		TargetID: targetID, Address: resp.GetAddress(), ServerName: resp.GetServerName(), TLSVersion: resp.GetTlsVersion(),
		Chain: make([]*TargetTLSCertificate, 0, len(resp.GetChain())), SystemTrusted: resp.GetSystemTrusted(),
		SystemTrustDetail: strPtr(resp.GetSystemTrustDetail()), HostNameMatches: resp.GetHostNameMatches(),
	}
	for _, c := range resp.GetChain() {
		out.Chain = append(out.Chain, &TargetTLSCertificate{
			Subject: c.GetSubject(), CommonName: c.GetCommonName(),
			DNSNames: append([]string{}, c.GetDnsNames()...), IPAddresses: append([]string{}, c.GetIpAddresses()...),
			Issuer: c.GetIssuer(), NotBefore: tsPtr(c.GetNotBefore()), NotAfter: tsPtr(c.GetNotAfter()),
			Fingerprint: c.GetFingerprintSha256(), SerialNumber: c.GetSerialNumber(), IsCa: c.GetIsCa(), SelfSigned: c.GetSelfSigned(),
			Pinnable: c.GetPinnable(), Pinned: tlsCertPinned(scanned.target.GetTlsCertPins(), c.GetFingerprintSha256()),
		})
	}
	return out, nil
}

// pinTargetTLSCertificate pins the certificate the target offers now, only
// when its fingerprint is exactly the confirmed one.
func (r *Resolver) pinTargetTLSCertificate(ctx context.Context, targetID, fingerprint string) (*vaultv1.Target, error) {
	actor, err := tlsPinActor(ctx)
	if err != nil {
		return nil, err
	}
	fp, ok := normalizeTLSFingerprint(fingerprint)
	if !ok {
		return nil, errTLSFingerprintInvalid()
	}
	scanned, err := r.scanTLSCertificate(ctx, actor, targetID)
	if err != nil {
		return nil, err
	}
	target := scanned.target
	l := r.logger(ctx)
	var offered *connectorv1.ScannedCertificate
	for _, c := range scanned.resp.GetChain() {
		if c.GetFingerprintSha256() == fp {
			offered = c
			break
		}
	}
	if offered == nil {
		l.Warn("TLS certificate pin refused: the target no longer offers it", log.F("target_id", targetID), log.F("confirmed_fingerprint", fp))
		r.auditTLSCertPin(ctx, actor, targetID, "mismatch", map[string]string{"fingerprint_sha256": fp})
		return nil, errTLSCertChanged()
	}
	if !offered.GetPinnable() {
		l.Warn("TLS certificate pin refused: not pinnable", log.F("target_id", targetID), log.F("confirmed_fingerprint", fp))
		return nil, errTLSCertNotPinnable()
	}
	if tlsCertPinned(target.GetTlsCertPins(), fp) {
		l.Info("TLS certificate already pinned", log.F("target_id", targetID), log.F("fingerprint", fp))
		return target, nil
	}
	target.TlsCertPins = append(append([]string{}, target.GetTlsCertPins()...), fp)
	saved, err := r.Vault.SaveTarget(ctx, &vaultv1.SaveTargetRequest{Actor: actor, Target: target})
	if err != nil {
		l.Warn("TLS certificate pin: target save failed", log.F("target_id", targetID), log.F("error", err.Error()))
		return nil, err
	}
	r.auditTLSCertPin(ctx, actor, targetID, "pinned", map[string]string{"fingerprint_sha256": fp})
	l.Info("TLS certificate pinned", log.F("target_id", targetID), log.F("fingerprint", fp))
	return saved.GetTarget(), nil
}

// auditTLSCertPin records a pin decision as target.tls_cert.pin, with
// fingerprints only. Best effort: a failed write is logged.
func (r *Resolver) auditTLSCertPin(ctx context.Context, actor *vaultv1.ActorContext, targetID, outcome string, attrs map[string]string) {
	if r.Audit == nil {
		return
	}
	a := map[string]string{"outcome": outcome}
	for k, v := range attrs {
		a[k] = v
	}
	if _, err := r.Audit.RecordEvent(ctx, &auditv1.RecordEventRequest{
		Tier: auditv1.Tier_TIER_AUDIT, Action: "target.tls_cert.pin", ActorUserId: actor.GetUserId(),
		Subject: targetID, Attributes: a, OccurredAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		r.logger(ctx).Error(err, "TLS certificate pin audit failed", log.F("target_id", targetID))
	}
}

// TLSPinsForSave keeps a target's current TLS pins across a save that
// doesn't carry them: the vault replaces the whole list, so an update from
// the web app would otherwise clear them.
func TLSPinsForSave(ctx context.Context, v vaultv1.VaultServiceClient, actor *vaultv1.ActorContext, id string) ([]string, error) {
	if id == "" {
		return nil, nil
	}
	tl, err := v.ListTargets(ctx, &vaultv1.ListTargetsRequest{Actor: actor})
	if err != nil {
		return nil, err
	}
	for _, t := range tl.GetTargets() {
		if t.GetId() == id {
			return t.GetTlsCertPins(), nil
		}
	}
	return nil, nil
}
