// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/sshbroker/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Trust on first use: scanTargetHostKey shows what the target offers and pins
// nothing; pinTargetHostKey pins only the key whose fingerprint the person
// confirmed, after a fresh scan still returns it.

const (
	tofuKey   = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOfferedHostKeyPlaceholder"
	tofuFP    = "SHA256:offered-fingerprint"
	otherKey  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtherHostKeyPlaceholder"
	otherFP   = "SHA256:other-fingerprint"
	tofuOldPn = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIExistingPin old-pin"
)

// tofuVault serves one target with an SSH connection that isn't its default,
// and records SaveTarget.
type tofuVault struct {
	vaultv1.VaultServiceClient
	target   *vaultv1.Target
	lastSave *vaultv1.SaveTargetRequest
}

func (f *tofuVault) ListTargets(context.Context, *vaultv1.ListTargetsRequest, ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{f.target}}, nil
}

func (f *tofuVault) ListConnections(context.Context, *vaultv1.ListConnectionsRequest, ...grpc.CallOption) (*vaultv1.ListConnectionsResponse, error) {
	return &vaultv1.ListConnectionsResponse{Connections: []*vaultv1.Connection{
		{Id: "conn-winrm", Protocol: "winrm", Port: 5986},
		{Id: "conn-ssh", Protocol: "ssh", Port: 2222},
	}}, nil
}

func (f *tofuVault) SaveTarget(_ context.Context, in *vaultv1.SaveTargetRequest, _ ...grpc.CallOption) (*vaultv1.SaveTargetResponse, error) {
	f.lastSave = in
	return &vaultv1.SaveTargetResponse{Target: in.GetTarget()}, nil
}

func newTofuVault() *tofuVault {
	return &tofuVault{target: &vaultv1.Target{
		Id: "target-1", Name: "app01", Hostname: "app01.example.org", ConnectionId: "conn-winrm",
		Connections: []*vaultv1.TargetConnection{
			{ConnectionId: "conn-winrm", IsDefault: true},
			{ConnectionId: "conn-ssh"},
		},
		Description: "keep me",
		SshHostKeys: []string{tofuOldPn},
	}}
}

// scanBroker answers ScanHostKey with the key it is set to offer.
type scanBroker struct {
	sshbrokerv1.SSHBrokerServiceClient
	key, fp string
	err     error
	scans   []*sshbrokerv1.ScanHostKeyRequest
}

func (b *scanBroker) ScanHostKey(_ context.Context, in *sshbrokerv1.ScanHostKeyRequest, _ ...grpc.CallOption) (*sshbrokerv1.ScanHostKeyResponse, error) {
	b.scans = append(b.scans, in)
	if b.err != nil {
		return nil, b.err
	}
	return &sshbrokerv1.ScanHostKeyResponse{KeyType: "ssh-ed25519", PublicKey: b.key, FingerprintSha256: b.fp}, nil
}

type tofuAudit struct {
	auditv1.AuditServiceClient
	events []*auditv1.RecordEventRequest
}

func (a *tofuAudit) RecordEvent(_ context.Context, in *auditv1.RecordEventRequest, _ ...grpc.CallOption) (*auditv1.RecordEventResponse, error) {
	a.events = append(a.events, in)
	return &auditv1.RecordEventResponse{}, nil
}

func newTofuClient(fv *tofuVault, fb *scanBroker, fa *tofuAudit, siteAdmin bool) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, SSHBroker: fb, Audit: fa}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActorInfo(WithActor(r.Context(), "user-admin"), siteAdmin, false, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

type scanResp struct {
	ScanTargetHostKey struct {
		TargetID, KeyType, PublicKey, Fingerprint string
		Pinned                                    bool
	}
}

const scanQuery = `{ scanTargetHostKey(targetId:"target-1") { targetId keyType publicKey fingerprint pinned } }`

func pinMutation(fp string) string {
	return `mutation { pinTargetHostKey(targetId:"target-1", fingerprint:"` + fp + `") { id sshHostKeys } }`
}

func TestScanTargetHostKeyReturnsTheOfferedKeyAndPinsNothing(t *testing.T) {
	fv, fb, fa := newTofuVault(), &scanBroker{key: tofuKey, fp: tofuFP}, &tofuAudit{}
	var resp scanResp
	newTofuClient(fv, fb, fa, true).MustPost(scanQuery, &resp)
	got := resp.ScanTargetHostKey
	if got.TargetID != "target-1" || got.KeyType != "ssh-ed25519" || got.PublicKey != tofuKey || got.Fingerprint != tofuFP || got.Pinned {
		t.Fatalf("scan = %+v", got)
	}
	if fv.lastSave != nil {
		t.Fatal("a scan must never pin")
	}
	if len(fb.scans) != 1 {
		t.Fatalf("broker scans = %d, want 1", len(fb.scans))
	}
	s := fb.scans[0]
	if s.GetHost() != "app01.example.org" || s.GetPort() != 2222 || s.GetTargetId() != "target-1" ||
		s.GetActorUserId() != "user-admin" || s.GetActor().GetUserId() != "user-admin" {
		t.Fatalf("scan request = %+v, want the target's SSH connection", s)
	}
}

func TestScanTargetHostKeyReportsAKeyAlreadyPinned(t *testing.T) {
	fv := newTofuVault()
	fv.target.SshHostKeys = []string{tofuKey + " a-comment"}
	var resp scanResp
	newTofuClient(fv, &scanBroker{key: tofuKey, fp: tofuFP}, &tofuAudit{}, true).MustPost(scanQuery, &resp)
	if !resp.ScanTargetHostKey.Pinned {
		t.Fatal("a key the target already pins must report pinned")
	}
}

func TestHostKeyTofuIsForSiteAdmins(t *testing.T) {
	fv, fb := newTofuVault(), &scanBroker{key: tofuKey, fp: tofuFP}
	c := newTofuClient(fv, fb, &tofuAudit{}, false)
	var resp map[string]any
	for _, q := range []string{scanQuery, pinMutation(tofuFP)} {
		err := c.Post(q, &resp)
		if err == nil || !strings.Contains(err.Error(), "site admin") {
			t.Fatalf("%s: err %v, want a site-admin refusal", q, err)
		}
	}
	if len(fb.scans) != 0 || fv.lastSave != nil {
		t.Fatalf("a refused caller reached the broker (%d scans) or the vault (%v)", len(fb.scans), fv.lastSave)
	}
}

func TestHostKeyTofuRefusesATargetWithoutSSH(t *testing.T) {
	fv, fb := newTofuVault(), &scanBroker{key: tofuKey, fp: tofuFP}
	fv.target.Connections = []*vaultv1.TargetConnection{{ConnectionId: "conn-winrm", IsDefault: true}}
	var resp map[string]any
	if err := newTofuClient(fv, fb, &tofuAudit{}, true).Post(scanQuery, &resp); err == nil || !strings.Contains(err.Error(), "SSH connection") {
		t.Fatalf("err %v, want no SSH connection", err)
	}
	if len(fb.scans) != 0 {
		t.Fatal("no scan without an SSH connection")
	}
}

func TestPinTargetHostKeyPinsTheConfirmedKey(t *testing.T) {
	fv, fb, fa := newTofuVault(), &scanBroker{key: tofuKey, fp: tofuFP}, &tofuAudit{}
	var resp struct {
		PinTargetHostKey struct {
			ID          string
			SSHHostKeys []string
		}
	}
	newTofuClient(fv, fb, fa, true).MustPost(pinMutation(tofuFP), &resp)
	if len(fb.scans) != 1 {
		t.Fatalf("pin must scan afresh: %d scans", len(fb.scans))
	}
	if fv.lastSave == nil {
		t.Fatal("not saved")
	}
	saved := fv.lastSave.GetTarget()
	if strings.Join(saved.GetSshHostKeys(), "|") != tofuOldPn+"|"+tofuKey {
		t.Fatalf("saved pins = %q, want the old pin plus the scanned key", saved.GetSshHostKeys())
	}
	if saved.GetDescription() != "keep me" || len(saved.GetConnections()) != 2 || saved.GetName() != "app01" {
		t.Fatalf("pinning changed other target fields: %+v", saved)
	}
	if fv.lastSave.GetActor().GetUserId() != "user-admin" {
		t.Fatalf("saved as %q", fv.lastSave.GetActor().GetUserId())
	}
	if len(resp.PinTargetHostKey.SSHHostKeys) != 2 {
		t.Fatalf("response pins = %q", resp.PinTargetHostKey.SSHHostKeys)
	}
	assertPinnedAudit(t, lastTofuEvent(t, fa))
}

func assertPinnedAudit(t *testing.T, ev *auditv1.RecordEventRequest) {
	t.Helper()
	if ev.GetAction() != "target.host_key.pin" || ev.GetSubject() != "target-1" || ev.GetActorUserId() != "user-admin" ||
		ev.GetAttributes()["fingerprint_sha256"] != tofuFP || ev.GetAttributes()["outcome"] != "pinned" {
		t.Fatalf("audit = %+v", ev)
	}
	for k, v := range ev.GetAttributes() {
		if strings.Contains(v, "AAAA") {
			t.Fatalf("audit attribute %s carries the key", k)
		}
	}
}

func TestPinTargetHostKeyRefusesAChangedKey(t *testing.T) {
	fv, fb, fa := newTofuVault(), &scanBroker{key: otherKey, fp: otherFP}, &tofuAudit{}
	var resp map[string]any
	err := newTofuClient(fv, fb, fa, true).Post(pinMutation(tofuFP), &resp)
	if err == nil || !strings.Contains(err.Error(), "HOST_KEY_CHANGED") {
		t.Fatalf("err %v, want HOST_KEY_CHANGED", err)
	}
	if fv.lastSave != nil {
		t.Fatal("a mismatched key must never be pinned")
	}
	ev := lastTofuEvent(t, fa)
	if ev.GetAction() != "target.host_key.pin" || ev.GetAttributes()["outcome"] != "mismatch" ||
		ev.GetAttributes()["fingerprint_sha256"] != tofuFP || ev.GetAttributes()["offered_fingerprint_sha256"] != otherFP {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestPinTargetHostKeyNeedsAFingerprint(t *testing.T) {
	fv, fb := newTofuVault(), &scanBroker{key: tofuKey, fp: tofuFP}
	var resp map[string]any
	if err := newTofuClient(fv, fb, &tofuAudit{}, true).Post(pinMutation("  "), &resp); err == nil {
		t.Fatal("an empty fingerprint must be refused")
	}
	if len(fb.scans) != 0 || fv.lastSave != nil {
		t.Fatal("nothing may happen without a fingerprint")
	}
}

func TestPinTargetHostKeyAlreadyPinnedSavesNothing(t *testing.T) {
	fv, fb := newTofuVault(), &scanBroker{key: tofuKey, fp: tofuFP}
	fv.target.SshHostKeys = []string{tofuKey}
	var resp struct {
		PinTargetHostKey struct {
			ID          string
			SSHHostKeys []string
		}
	}
	newTofuClient(fv, fb, &tofuAudit{}, true).MustPost(pinMutation(tofuFP), &resp)
	if fv.lastSave != nil {
		t.Fatal("an already pinned key needs no save")
	}
	if len(resp.PinTargetHostKey.SSHHostKeys) != 1 {
		t.Fatalf("pins = %q", resp.PinTargetHostKey.SSHHostKeys)
	}
}

func TestPinTargetHostKeyPassesBrokerRefusals(t *testing.T) {
	fv := newTofuVault()
	fb := &scanBroker{err: status.Error(codes.ResourceExhausted, "too many host key scans; try again shortly")}
	var resp map[string]any
	if err := newTofuClient(fv, fb, &tofuAudit{}, true).Post(pinMutation(tofuFP), &resp); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("err %v, want the broker's refusal", err)
	}
	if fv.lastSave != nil {
		t.Fatal("no pin without a fresh scan")
	}
}

func lastTofuEvent(t *testing.T, fa *tofuAudit) *auditv1.RecordEventRequest {
	t.Helper()
	if len(fa.events) == 0 {
		t.Fatal("no audit event")
	}
	return fa.events[len(fa.events)-1]
}
