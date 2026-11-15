// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	connectorv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/connector/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Trust on first use for a target's TLS certificate: scanTargetTlsCertificate
// shows the chain the target sends and pins nothing; pinTargetTlsCertificate
// pins only the fingerprint the person saw, after a fresh scan still offers it.

const (
	leafFP  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	caFP    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	otherCF = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	oldPin  = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

// tlsVault serves one target with an LDAPS connection and an SSH one, and
// records SaveTarget.
type tlsVault struct {
	vaultv1.VaultServiceClient
	target   *vaultv1.Target
	lastSave *vaultv1.SaveTargetRequest
}

func (f *tlsVault) ListTargets(context.Context, *vaultv1.ListTargetsRequest, ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{f.target}}, nil
}

func (f *tlsVault) ListConnections(context.Context, *vaultv1.ListConnectionsRequest, ...grpc.CallOption) (*vaultv1.ListConnectionsResponse, error) {
	return &vaultv1.ListConnectionsResponse{Connections: []*vaultv1.Connection{
		{Id: "conn-ssh", Protocol: "ssh", Port: 22},
		{Id: "conn-ldaps", Protocol: "ldap", Port: 636, UseTls: true},
		{Id: "conn-ldap", Protocol: "ldap", Port: 389},
	}}, nil
}

func (f *tlsVault) SaveTarget(_ context.Context, in *vaultv1.SaveTargetRequest, _ ...grpc.CallOption) (*vaultv1.SaveTargetResponse, error) {
	f.lastSave = in
	return &vaultv1.SaveTargetResponse{Target: in.GetTarget()}, nil
}

func newTLSVault() *tlsVault {
	return &tlsVault{target: &vaultv1.Target{
		Id: "target-1", Name: "dc01", Hostname: "dc01.example.org", ConnectionId: "conn-ssh",
		Connections: []*vaultv1.TargetConnection{
			{ConnectionId: "conn-ssh", IsDefault: true},
			{ConnectionId: "conn-ldap"},
			{ConnectionId: "conn-ldaps"},
		},
		Description: "keep me",
		TlsCertPins: []string{oldPin},
		SshHostKeys: []string{tofuOldPn},
	}}
}

type scanConnector struct {
	connectorv1.ConnectorServiceClient
	resp  *connectorv1.ScanTLSCertificateResponse
	err   error
	scans []*connectorv1.ScanTLSCertificateRequest
}

func (c *scanConnector) ScanTLSCertificate(_ context.Context, in *connectorv1.ScanTLSCertificateRequest, _ ...grpc.CallOption) (*connectorv1.ScanTLSCertificateResponse, error) {
	c.scans = append(c.scans, in)
	if c.err != nil {
		return nil, c.err
	}
	return c.resp, nil
}

func newScanConnector() *scanConnector {
	return &scanConnector{resp: &connectorv1.ScanTLSCertificateResponse{
		Address: "192.0.2.10:636", ServerName: "dc01.example.org", TlsVersion: "TLS 1.3",
		HostNameMatches: true, SystemTrusted: false, SystemTrustDetail: "unknown authority",
		Chain: []*connectorv1.ScannedCertificate{
			{
				Subject: "CN=dc01.example.org,O=Example Org", CommonName: "dc01.example.org",
				DnsNames: []string{"dc01.example.org"}, IpAddresses: []string{"192.0.2.10"},
				Issuer:            "CN=Example Org CA",
				NotBefore:         timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
				NotAfter:          timestamppb.New(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)),
				FingerprintSha256: leafFP, SerialNumber: "01", Pinnable: true,
			},
			{
				Subject: "CN=Example Org CA", CommonName: "Example Org CA", Issuer: "CN=Example Org CA",
				NotBefore:         timestamppb.New(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
				NotAfter:          timestamppb.New(time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)),
				FingerprintSha256: caFP, SerialNumber: "02", IsCa: true, SelfSigned: true, Pinnable: true,
			},
		},
	}}
}

func newTLSClientAs(fv *tlsVault, fc *scanConnector, fa *tofuAudit, userID string, siteAdmin bool) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Connector: fc, Audit: fa}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActorInfo(WithActor(r.Context(), userID), siteAdmin, false, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func newTLSClient(fv *tlsVault, fc *scanConnector, fa *tofuAudit, siteAdmin bool) *gqlclient.Client {
	return newTLSClientAs(fv, fc, fa, "user-admin", siteAdmin)
}

const tlsScanQuery = `{ scanTargetTlsCertificate(targetId:"target-1") {
  targetId address serverName tlsVersion systemTrusted systemTrustDetail hostNameMatches
  chain { subject commonName dnsNames ipAddresses issuer notBefore notAfter fingerprint serialNumber isCa selfSigned pinnable pinned } } }`

func tlsPinMutation(fp string) string {
	return `mutation { pinTargetTlsCertificate(targetId:"target-1", fingerprint:"` + fp + `") { id tlsCertPins } }`
}

func TestScanTargetTlsCertificateReturnsTheChainAndPinsNothing(t *testing.T) {
	fv, fc := newTLSVault(), newScanConnector()
	var resp struct {
		ScanTargetTlsCertificate struct {
			TargetID, Address, ServerName, TLSVersion string
			SystemTrusted, HostNameMatches            bool
			SystemTrustDetail                         string
			Chain                                     []struct {
				Subject, CommonName, Issuer, Fingerprint, SerialNumber string
				DNSNames, IPAddresses                                  []string
				NotBefore, NotAfter                                    string
				IsCa, SelfSigned, Pinnable, Pinned                     bool
			}
		}
	}
	newTLSClient(fv, fc, &tofuAudit{}, true).MustPost(tlsScanQuery, &resp)
	got := resp.ScanTargetTlsCertificate
	if len(got.Chain) != 2 {
		t.Fatalf("chain = %+v", got.Chain)
	}
	leaf, ca := got.Chain[0], got.Chain[1]
	for name, pair := range map[string][2]any{
		"targetId": {got.TargetID, "target-1"}, "address": {got.Address, "192.0.2.10:636"},
		"serverName": {got.ServerName, "dc01.example.org"}, "tlsVersion": {got.TLSVersion, "TLS 1.3"},
		"systemTrusted": {got.SystemTrusted, false}, "hostNameMatches": {got.HostNameMatches, true},
		"systemTrustDetail": {got.SystemTrustDetail, "unknown authority"},
		"leaf.subject":      {leaf.Subject, "CN=dc01.example.org,O=Example Org"}, "leaf.fingerprint": {leaf.Fingerprint, leafFP},
		"leaf.issuer": {leaf.Issuer, "CN=Example Org CA"}, "leaf.dns": {strings.Join(leaf.DNSNames, ","), "dc01.example.org"},
		"leaf.ip": {strings.Join(leaf.IPAddresses, ","), "192.0.2.10"}, "leaf.serial": {leaf.SerialNumber, "01"},
		"leaf.notBefore": {leaf.NotBefore, "2026-01-01T00:00:00Z"}, "leaf.notAfter": {leaf.NotAfter, "2027-01-01T00:00:00Z"},
		"leaf.isCa": {leaf.IsCa, false}, "leaf.selfSigned": {leaf.SelfSigned, false},
		"leaf.pinnable": {leaf.Pinnable, true}, "leaf.pinned": {leaf.Pinned, false},
		"ca.isCa": {ca.IsCa, true}, "ca.selfSigned": {ca.SelfSigned, true}, "ca.fingerprint": {ca.Fingerprint, caFP},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %v, want %v", name, pair[0], pair[1])
		}
	}
	if fv.lastSave != nil {
		t.Fatal("a scan must never pin")
	}
	if len(fc.scans) != 1 {
		t.Fatalf("connector scans = %d, want 1", len(fc.scans))
	}
	s := fc.scans[0]
	if s.GetHost() != "dc01.example.org" || s.GetPort() != 636 || s.GetTargetId() != "target-1" ||
		s.GetActorUserId() != "user-admin" || s.GetActor().GetUserId() != "user-admin" {
		t.Fatalf("scan request = %+v, want the target's TLS connection, not its SSH or plain LDAP one", s)
	}
}

func TestScanTargetTlsCertificateMarksAPinnedCertificate(t *testing.T) {
	fv := newTLSVault()
	var resp struct {
		ScanTargetTlsCertificate struct{ Chain []struct{ Pinned bool } }
	}
	fv.target.TlsCertPins = []string{oldPin, leafFP}
	newTLSClient(fv, newScanConnector(), &tofuAudit{}, true).MustPost(
		`{ scanTargetTlsCertificate(targetId:"target-1") { chain { pinned } } }`, &resp)
	c := resp.ScanTargetTlsCertificate.Chain
	if !c[0].Pinned || c[1].Pinned {
		t.Fatalf("pinned flags = %+v, want the leaf only", c)
	}
}

func TestTLSCertPinRefusesANonAdminOnASharedTarget(t *testing.T) {
	fv, fc := newTLSVault(), newScanConnector()
	c := newTLSClient(fv, fc, &tofuAudit{}, false)
	var resp map[string]any
	for _, q := range []string{tlsScanQuery, tlsPinMutation(leafFP)} {
		if err := c.Post(q, &resp); err == nil || !strings.Contains(err.Error(), "TLS_CERT_PIN_NOT_OWNER") {
			t.Fatalf("%s: err %v, want TLS_CERT_PIN_NOT_OWNER", q, err)
		}
	}
	if len(fc.scans) != 0 || fv.lastSave != nil {
		t.Fatalf("a refused caller reached the connector (%d scans) or the vault (%v)", len(fc.scans), fv.lastSave)
	}
}

func TestTLSCertPinRefusesAnotherPersonsPersonalTarget(t *testing.T) {
	fv, fc := newTLSVault(), newScanConnector()
	fv.target.OwnerUserId = "user-dana"
	c := newTLSClientAs(fv, fc, &tofuAudit{}, "user-eli", false)
	var resp map[string]any
	for _, q := range []string{tlsScanQuery, tlsPinMutation(leafFP)} {
		if err := c.Post(q, &resp); err == nil || !strings.Contains(err.Error(), "TLS_CERT_PIN_NOT_OWNER") {
			t.Fatalf("%s: err %v, want TLS_CERT_PIN_NOT_OWNER", q, err)
		}
	}
	if len(fc.scans) != 0 || fv.lastSave != nil {
		t.Fatal("a refused caller reached the connector or the vault")
	}
}

func TestTLSCertPinLetsTheOwnerPinTheirPersonalTarget(t *testing.T) {
	fv, fc, fa := newTLSVault(), newScanConnector(), &tofuAudit{}
	fv.target.OwnerUserId = "user-dana"
	var resp map[string]any
	newTLSClientAs(fv, fc, fa, "user-dana", false).MustPost(tlsPinMutation(leafFP), &resp)
	if fv.lastSave == nil || fv.lastSave.GetActor().GetUserId() != "user-dana" {
		t.Fatalf("pin not saved as the owner: %v", fv.lastSave)
	}
}

// A token is never a person: refused before the vault or the connector is
// asked, even when its owner is the target's owner.
func TestTLSCertPinRefusesAToken(t *testing.T) {
	fv, fc := newTLSVault(), newScanConnector()
	fv.target.OwnerUserId = "user-dana"
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Connector: fc, Audit: &tofuAudit{}}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithMachineActor(WithActorInfo(WithActor(r.Context(), "user-dana"), true, false, nil), "sa-1", nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	var resp map[string]any
	for _, q := range []string{tlsScanQuery, tlsPinMutation(leafFP)} {
		err := c.Post(q, &resp)
		if err == nil || !strings.Contains(err.Error(), "TLS_CERT_PIN_NOT_ADMIN") || !strings.Contains(err.Error(), "token") {
			t.Fatalf("%s: err %v, want the person-only refusal", q, err)
		}
	}
	if len(fc.scans) != 0 || fv.lastSave != nil {
		t.Fatal("a token reached the connector or the vault")
	}
}

func TestTLSCertScanRefusesATargetWithoutATLSConnection(t *testing.T) {
	fv, fc := newTLSVault(), newScanConnector()
	fv.target.Connections = []*vaultv1.TargetConnection{{ConnectionId: "conn-ssh", IsDefault: true}, {ConnectionId: "conn-ldap"}}
	var resp map[string]any
	if err := newTLSClient(fv, fc, &tofuAudit{}, true).Post(tlsScanQuery, &resp); err == nil || !strings.Contains(err.Error(), "TARGET_NO_TLS_CONNECTION") {
		t.Fatalf("err %v, want TARGET_NO_TLS_CONNECTION", err)
	}
	if len(fc.scans) != 0 {
		t.Fatal("no scan without a TLS connection")
	}
}

func TestPinTargetTlsCertificatePinsTheConfirmedFingerprint(t *testing.T) {
	fv, fc, fa := newTLSVault(), newScanConnector(), &tofuAudit{}
	var resp struct {
		PinTargetTlsCertificate struct {
			ID          string
			TLSCertPins []string
		}
	}
	// The person may paste it the way a browser shows it.
	newTLSClient(fv, fc, fa, true).MustPost(tlsPinMutation("SHA256:"+strings.ToUpper(leafFP)), &resp)
	if len(fc.scans) != 1 {
		t.Fatalf("pin must scan afresh: %d scans", len(fc.scans))
	}
	if fv.lastSave == nil {
		t.Fatal("not saved")
	}
	saved := fv.lastSave.GetTarget()
	if strings.Join(saved.GetTlsCertPins(), "|") != oldPin+"|"+leafFP {
		t.Fatalf("saved pins = %q, want the old pin plus the confirmed one", saved.GetTlsCertPins())
	}
	if saved.GetDescription() != "keep me" || len(saved.GetConnections()) != 3 || saved.GetName() != "dc01" ||
		len(saved.GetSshHostKeys()) != 1 {
		t.Fatalf("pinning changed other target fields: %+v", saved)
	}
	if fv.lastSave.GetActor().GetUserId() != "user-admin" {
		t.Fatalf("saved as %q", fv.lastSave.GetActor().GetUserId())
	}
	if len(resp.PinTargetTlsCertificate.TLSCertPins) != 2 {
		t.Fatalf("response pins = %q", resp.PinTargetTlsCertificate.TLSCertPins)
	}
	ev := lastTofuEvent(t, fa)
	if ev.GetAction() != "target.tls_cert.pin" || ev.GetSubject() != "target-1" || ev.GetActorUserId() != "user-admin" ||
		ev.GetAttributes()["outcome"] != "pinned" || ev.GetAttributes()["fingerprint_sha256"] != leafFP {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestPinTargetTlsCertificateCanPinAnIssuingCertificate(t *testing.T) {
	fv := newTLSVault()
	var resp map[string]any
	newTLSClient(fv, newScanConnector(), &tofuAudit{}, true).MustPost(tlsPinMutation(caFP), &resp)
	if fv.lastSave == nil || fv.lastSave.GetTarget().GetTlsCertPins()[1] != caFP {
		t.Fatalf("saved = %+v", fv.lastSave)
	}
}

func TestPinTargetTlsCertificateRefusesAChangedCertificate(t *testing.T) {
	fv, fc, fa := newTLSVault(), newScanConnector(), &tofuAudit{}
	var resp map[string]any
	err := newTLSClient(fv, fc, fa, true).Post(tlsPinMutation(otherCF), &resp)
	if err == nil || !strings.Contains(err.Error(), "TLS_CERT_CHANGED") {
		t.Fatalf("err %v, want TLS_CERT_CHANGED", err)
	}
	if fv.lastSave != nil {
		t.Fatal("a certificate the target no longer offers must never be pinned")
	}
	ev := lastTofuEvent(t, fa)
	if ev.GetAction() != "target.tls_cert.pin" || ev.GetAttributes()["outcome"] != "mismatch" ||
		ev.GetAttributes()["fingerprint_sha256"] != otherCF {
		t.Fatalf("audit = %+v", ev)
	}
}

func TestPinTargetTlsCertificateRefusesACertificateThatWouldNotWork(t *testing.T) {
	fv, fc := newTLSVault(), newScanConnector()
	fc.resp.Chain[0].Pinnable = false
	var resp map[string]any
	err := newTLSClient(fv, fc, &tofuAudit{}, true).Post(tlsPinMutation(leafFP), &resp)
	if err == nil || !strings.Contains(err.Error(), "TLS_CERT_NOT_PINNABLE") {
		t.Fatalf("err %v, want TLS_CERT_NOT_PINNABLE", err)
	}
	if fv.lastSave != nil {
		t.Fatal("nothing may be pinned")
	}
}

func TestPinTargetTlsCertificateNeedsAValidFingerprint(t *testing.T) {
	for _, fp := range []string{"  ", "not-hex", "abcd"} {
		fv, fc := newTLSVault(), newScanConnector()
		var resp map[string]any
		if err := newTLSClient(fv, fc, &tofuAudit{}, true).Post(tlsPinMutation(fp), &resp); err == nil || !strings.Contains(err.Error(), "TLS_CERT_FINGERPRINT_INVALID") {
			t.Fatalf("%q: err %v, want TLS_CERT_FINGERPRINT_INVALID", fp, err)
		}
		if len(fc.scans) != 0 || fv.lastSave != nil {
			t.Fatalf("%q: nothing may happen without a valid fingerprint", fp)
		}
	}
}

func TestPinTargetTlsCertificateAlreadyPinnedSavesNothing(t *testing.T) {
	fv := newTLSVault()
	fv.target.TlsCertPins = []string{leafFP}
	var resp struct {
		PinTargetTlsCertificate struct {
			ID          string
			TLSCertPins []string
		}
	}
	newTLSClient(fv, newScanConnector(), &tofuAudit{}, true).MustPost(tlsPinMutation(leafFP), &resp)
	if fv.lastSave != nil {
		t.Fatal("an already pinned certificate needs no save")
	}
	if len(resp.PinTargetTlsCertificate.TLSCertPins) != 1 {
		t.Fatalf("pins = %q", resp.PinTargetTlsCertificate.TLSCertPins)
	}
}

func TestPinTargetTlsCertificatePassesConnectorRefusals(t *testing.T) {
	fv, fc := newTLSVault(), newScanConnector()
	fc.err = status.Error(codes.ResourceExhausted, "too many certificate scans; try again shortly")
	var resp map[string]any
	if err := newTLSClient(fv, fc, &tofuAudit{}, true).Post(tlsPinMutation(leafFP), &resp); err == nil || !strings.Contains(err.Error(), "too many") {
		t.Fatalf("err %v, want the connector's refusal", err)
	}
	if fv.lastSave != nil {
		t.Fatal("no pin without a fresh scan")
	}
}

func TestScanTargetTlsCertificateSaysSoWhenTheConnectorIsNotConfigured(t *testing.T) {
	fv := newTLSVault()
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Audit: &tofuAudit{}}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActorInfo(WithActor(r.Context(), "user-admin"), true, false, nil)))
	}))
	var resp map[string]any
	if err := c.Post(tlsScanQuery, &resp); err == nil || !strings.Contains(err.Error(), "CONNECTOR_UNAVAILABLE") {
		t.Fatalf("err %v, want CONNECTOR_UNAVAILABLE", err)
	}
}

// A save from the web app carries no TLS pins; the vault replaces the whole
// list, so the gateway must keep the target's current ones (as it does the
// SSH host keys).
func TestSaveTargetKeepsTheTLSCertPins(t *testing.T) {
	fv := newTLSVault()
	var resp map[string]any
	newTLSClient(fv, newScanConnector(), &tofuAudit{}, true).MustPost(
		`mutation { saveTarget(input:{id:"target-1", name:"dc01", hostname:"dc01.example.org", connectionId:"conn-ssh"}) { id } }`, &resp)
	if fv.lastSave == nil || strings.Join(fv.lastSave.GetTarget().GetTlsCertPins(), "|") != oldPin {
		t.Fatalf("saved = %+v, want the existing TLS pin kept", fv.lastSave)
	}
}
