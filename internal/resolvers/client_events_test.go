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
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/maintenance"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// What the phone apps report about themselves: a screenshot or screen
// recording while a secret or sensitive screen is open (#146), and a secret
// opened from a QR scan (#149). Both land in the audit log for a signed-in
// person, never carry a secret value, and say nothing about a secret the
// caller can't see.

// eventVault knows one secret the caller can see. Any other id is unknown, and
// secret-hidden answers PermissionDenied, so the tests show both refusals read
// the same.
type eventVault struct {
	vaultv1.VaultServiceClient
}

func (eventVault) GetSecret(_ context.Context, in *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	switch in.GetId() {
	case "secret-1":
		return &vaultv1.GetSecretResponse{Secret: &vaultv1.Secret{Id: "secret-1", Name: "db01 admin"}}, nil
	case "secret-hidden":
		return nil, status.Error(codes.PermissionDenied, "no access")
	}
	return nil, status.Error(codes.NotFound, "secret not found")
}

type eventAudit struct {
	auditv1.AuditServiceClient
	events []*auditv1.RecordEventRequest
	err    error
}

func (a *eventAudit) RecordEvent(_ context.Context, in *auditv1.RecordEventRequest, _ ...grpc.CallOption) (*auditv1.RecordEventResponse, error) {
	if a.err != nil {
		return nil, a.err
	}
	a.events = append(a.events, in)
	return &auditv1.RecordEventResponse{}, nil
}

func newEventClient(fa *eventAudit, userID string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: eventVault{}, Audit: fa}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if userID != "" {
			ctx = WithActorInfo(WithActor(ctx, userID), false, false, nil)
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func reasonOfErr(t *testing.T, err error) string {
	t.Helper()
	if err == nil {
		t.Fatal("want an error")
	}
	for _, r := range []string{"SECRET_NOT_FOUND", "CLIENT_EVENT_INVALID", "CLIENT_EVENT_NOT_PERSON", "AUDIT_UNAVAILABLE"} {
		if strings.Contains(err.Error(), r) {
			return r
		}
	}
	return err.Error()
}

const captureMutation = `mutation($in: ScreenCaptureInput!) { reportScreenCapture(input: $in) }`

func TestReportScreenCaptureRecordsWhoWhichSecretAndDevice(t *testing.T) {
	for kind, action := range map[string]string{"SCREENSHOT": "client.screenshot", "SCREEN_RECORDING": "client.screen_recording"} {
		fa := &eventAudit{}
		var resp struct{ ReportScreenCapture bool }
		err := newEventClient(fa, "user-ada").Post(captureMutation, &resp, gqlclient.Var("in", map[string]any{
			"kind": kind, "secretId": "secret-1", "clientKind": "ios", "device": "Ada's iPhone",
		}))
		if err != nil || !resp.ReportScreenCapture {
			t.Fatalf("%s: err %v resp %v", kind, err, resp)
		}
		if len(fa.events) != 1 {
			t.Fatalf("%s: %d events, want 1", kind, len(fa.events))
		}
		ev := fa.events[0]
		if ev.GetAction() != action || ev.GetActorUserId() != "user-ada" || ev.GetSubject() != "secret-1" ||
			ev.GetTier() != auditv1.Tier_TIER_AUDIT || ev.GetOccurredAt() == "" ||
			ev.GetAttributes()["client_kind"] != "ios" || ev.GetAttributes()["device"] != "Ada's iPhone" {
			t.Fatalf("%s: event = %+v", kind, ev)
		}
		for k, v := range ev.GetAttributes() {
			if strings.Contains(strings.ToLower(k+v), "value") && k != "client_kind" {
				t.Fatalf("%s: attribute %s=%s must not carry a value", kind, k, v)
			}
		}
	}
}

func TestReportScreenCaptureForAScreenNeedsNoSecret(t *testing.T) {
	fa := &eventAudit{}
	var resp struct{ ReportScreenCapture bool }
	err := newEventClient(fa, "user-ada").Post(captureMutation, &resp, gqlclient.Var("in", map[string]any{
		"kind": "SCREENSHOT", "screen": "reveal", "clientKind": "android",
	}))
	if err != nil || len(fa.events) != 1 {
		t.Fatalf("err %v events %d", err, len(fa.events))
	}
	ev := fa.events[0]
	if ev.GetSubject() != "" || ev.GetAttributes()["screen"] != "reveal" || ev.GetAttributes()["client_kind"] != "android" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestReportScreenCaptureRefusesWithoutASession(t *testing.T) {
	fa := &eventAudit{}
	var resp struct{ ReportScreenCapture bool }
	err := newEventClient(fa, "").Post(captureMutation, &resp, gqlclient.Var("in", map[string]any{
		"kind": "SCREENSHOT", "screen": "reveal", "clientKind": "ios",
	}))
	if got := reasonOfErr(t, err); got != "CLIENT_EVENT_NOT_PERSON" || len(fa.events) != 0 {
		t.Fatalf("reason %q events %d, want a refusal that records nothing", got, len(fa.events))
	}
}

func TestReportScreenCaptureRefusesAnUnknownOrHiddenSecretTheSameWay(t *testing.T) {
	var msgs []string
	for _, id := range []string{"secret-unknown", "secret-hidden"} {
		fa := &eventAudit{}
		var resp struct{ ReportScreenCapture bool }
		err := newEventClient(fa, "user-ada").Post(captureMutation, &resp, gqlclient.Var("in", map[string]any{
			"kind": "SCREENSHOT", "secretId": id, "clientKind": "ios",
		}))
		if got := reasonOfErr(t, err); got != "SECRET_NOT_FOUND" || len(fa.events) != 0 {
			t.Fatalf("%s: reason %q events %d", id, got, len(fa.events))
		}
		msgs = append(msgs, strings.ReplaceAll(err.Error(), id, "ID"))
	}
	if msgs[0] != msgs[1] {
		t.Fatalf("an unknown and a hidden secret must read the same: %q vs %q", msgs[0], msgs[1])
	}
}

func TestReportScreenCaptureRefusesBadInput(t *testing.T) {
	for name, in := range map[string]map[string]any{
		"neither a secret nor a screen": {"kind": "SCREENSHOT", "clientKind": "ios"},
		"both a secret and a screen":    {"kind": "SCREENSHOT", "secretId": "secret-1", "screen": "reveal", "clientKind": "ios"},
		"an empty client kind":          {"kind": "SCREENSHOT", "screen": "reveal", "clientKind": ""},
		"a client kind with spaces":     {"kind": "SCREENSHOT", "screen": "reveal", "clientKind": "i os"},
		"a long device":                 {"kind": "SCREENSHOT", "screen": "reveal", "clientKind": "ios", "device": strings.Repeat("d", 200)},
		"a device with a line break":    {"kind": "SCREENSHOT", "screen": "reveal", "clientKind": "ios", "device": "a\nb"},
		"a screen with a line break":    {"kind": "SCREENSHOT", "screen": "re\nveal", "clientKind": "ios"},
	} {
		fa := &eventAudit{}
		var resp struct{ ReportScreenCapture bool }
		err := newEventClient(fa, "user-ada").Post(captureMutation, &resp, gqlclient.Var("in", in))
		if got := reasonOfErr(t, err); got != "CLIENT_EVENT_INVALID" || len(fa.events) != 0 {
			t.Errorf("%s: reason %q events %d", name, got, len(fa.events))
		}
	}
}

func TestReportScreenCaptureFailsWhenTheAuditCannotBeWritten(t *testing.T) {
	fa := &eventAudit{err: status.Error(codes.Unavailable, "audit down")}
	var resp struct{ ReportScreenCapture bool }
	err := newEventClient(fa, "user-ada").Post(captureMutation, &resp, gqlclient.Var("in", map[string]any{
		"kind": "SCREENSHOT", "screen": "reveal", "clientKind": "ios",
	}))
	if got := reasonOfErr(t, err); got != "AUDIT_UNAVAILABLE" {
		t.Fatalf("reason %q: the app must be told so it can retry", got)
	}
}

const scanMutation = `mutation($in: SecretScanInput!) { recordSecretScan(input: $in) }`

func TestRecordSecretScanRecordsAScanOpen(t *testing.T) {
	fa := &eventAudit{}
	var resp struct{ RecordSecretScan bool }
	err := newEventClient(fa, "user-ada").Post(scanMutation, &resp, gqlclient.Var("in", map[string]any{
		"secretId": "secret-1", "clientKind": "ios", "device": "Ada's iPhone",
	}))
	if err != nil || !resp.RecordSecretScan || len(fa.events) != 1 {
		t.Fatalf("err %v resp %v events %d", err, resp, len(fa.events))
	}
	ev := fa.events[0]
	if ev.GetAction() != "secret.qr_scan" || ev.GetActorUserId() != "user-ada" || ev.GetSubject() != "secret-1" ||
		ev.GetAttributes()["client_kind"] != "ios" || ev.GetAttributes()["device"] != "Ada's iPhone" || ev.GetOccurredAt() == "" {
		t.Fatalf("event = %+v", ev)
	}
}

func TestRecordSecretScanRefusesAScanOfASecretTheCallerCannotSee(t *testing.T) {
	for _, id := range []string{"secret-unknown", "secret-hidden"} {
		fa := &eventAudit{}
		var resp struct{ RecordSecretScan bool }
		err := newEventClient(fa, "user-ada").Post(scanMutation, &resp, gqlclient.Var("in", map[string]any{"secretId": id, "clientKind": "ios"}))
		if got := reasonOfErr(t, err); got != "SECRET_NOT_FOUND" || len(fa.events) != 0 {
			t.Fatalf("%s: reason %q events %d, want a refusal that records nothing", id, got, len(fa.events))
		}
		if strings.Contains(err.Error(), "db01") || strings.Contains(err.Error(), "no access") {
			t.Fatalf("%s: the refusal leaks: %v", id, err)
		}
	}
}

func TestRecordSecretScanRefusesWithoutASession(t *testing.T) {
	fa := &eventAudit{}
	var resp struct{ RecordSecretScan bool }
	err := newEventClient(fa, "").Post(scanMutation, &resp, gqlclient.Var("in", map[string]any{"secretId": "secret-1", "clientKind": "ios"}))
	if got := reasonOfErr(t, err); got != "CLIENT_EVENT_NOT_PERSON" || len(fa.events) != 0 {
		t.Fatalf("reason %q events %d", got, len(fa.events))
	}
}

func TestClientEventsStayOpenInMaintenance(t *testing.T) {
	for _, m := range []string{"reportScreenCapture", "recordSecretScan"} {
		found := false
		for _, a := range maintenance.HumanAllowed {
			found = found || a == m
		}
		if !found {
			t.Errorf("%s writes only an audit event and must stay open in read-only maintenance", m)
		}
	}
}
