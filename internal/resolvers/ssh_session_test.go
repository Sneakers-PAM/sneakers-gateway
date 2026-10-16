// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	log "github.com/Bugs5382/go-log"
	sshbrokerv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/sshbroker/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// fakeSSHVault serves the non-sensitive vault calls OpenSSHSession needs:
// GetSecret (type gate), ListTargets, ListConnections and GetSecretFields
// (username). It does not serve RevealSecretField: the gateway hands the
// broker a reference and the broker reveals the key from the vault itself at
// redeem time, so the gateway never touches key material on this path.
type fakeSSHVault struct {
	vaultv1.VaultServiceClient

	secretTypeID string // defaults to "type-ssh-key" if empty
	targetID     string
	targetIDs    []string // #168: several attached targets; wins over targetID when set
	getSecretErr error    // simulate an upstream authz/read denial on GetSecret
}

func (f *fakeSSHVault) GetSecret(_ context.Context, req *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	if f.getSecretErr != nil {
		return nil, f.getSecretErr
	}
	typeID := f.secretTypeID
	if typeID == "" {
		typeID = "type-ssh-key"
	}
	sec := &vaultv1.Secret{Id: req.GetId(), TypeId: typeID}
	if f.targetID != "" {
		sec.TargetId = f.targetID
		sec.TargetIds = []string{f.targetID}
	}
	if len(f.targetIDs) > 0 {
		sec.TargetId = f.targetIDs[0]
		sec.TargetIds = f.targetIDs
	}
	return &vaultv1.GetSecretResponse{Secret: sec}, nil
}

func (f *fakeSSHVault) ListTargets(_ context.Context, _ *vaultv1.ListTargetsRequest, _ ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{
		{Id: "target-1", Hostname: "host.example.org", ConnectionId: "conn-1"},
		{Id: "target-2", Hostname: "host-2.example.org", ConnectionId: "conn-1"},
	}}, nil
}

func (f *fakeSSHVault) ListConnections(_ context.Context, _ *vaultv1.ListConnectionsRequest, _ ...grpc.CallOption) (*vaultv1.ListConnectionsResponse, error) {
	return &vaultv1.ListConnectionsResponse{Connections: []*vaultv1.Connection{
		{Id: "conn-1", Protocol: "ssh", Port: 22},
	}}, nil
}

func (f *fakeSSHVault) GetSecretFields(_ context.Context, _ *vaultv1.GetSecretFieldsRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretFieldsResponse, error) {
	return &vaultv1.GetSecretFieldsResponse{Fields: map[string]string{"username": "deploy"}}, nil
}

// fakeSSHBroker records whether CreateSession was called and what it was
// called with, so tests can assert the broker is never reached on a denied
// or invalid request, and that it receives a reference (not the key).
type fakeSSHBroker struct {
	sshbrokerv1.SSHBrokerServiceClient

	called  bool
	lastReq *sshbrokerv1.CreateSessionRequest
}

func (f *fakeSSHBroker) CreateSession(_ context.Context, req *sshbrokerv1.CreateSessionRequest, _ ...grpc.CallOption) (*sshbrokerv1.CreateSessionResponse, error) {
	f.called = true
	f.lastReq = req
	return &sshbrokerv1.CreateSessionResponse{
		SessionId:        "sess-1",
		Ticket:           "ticket-abc",
		WsUrl:            "ws://localhost:9096/ssh/session",
		ExpiresInSeconds: 30,
	}, nil
}

// newSSHClient wires the gqlgen handler over fake vault + sshbroker clients,
// injecting a fixed no-auth actor.
func newSSHClient(fv vaultv1.VaultServiceClient, fb sshbrokerv1.SSHBrokerServiceClient, actor string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, SSHBroker: fb}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	})
	return gqlclient.New(wrapped)
}

const openSSHSessionMutation = `mutation { openSshSession(secretId:"s1") { wsUrl ticket sessionId expiresInSeconds } }`

const openSSHSessionWithTargetMutation = `mutation($targetId: ID) { openSshSession(secretId:"s1", targetId: $targetId) { wsUrl ticket sessionId expiresInSeconds } }`

func TestSshSessionGetSecretDeniedDoesNotCallBroker(t *testing.T) {
	fv := &fakeSSHVault{targetID: "target-1", getSecretErr: fmt.Errorf("permission denied")}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	err := c.Post(openSSHSessionMutation, &resp)
	if err == nil {
		t.Fatalf("expected error, got none")
	}
	if fb.called {
		t.Fatalf("CreateSession must not be called when the secret read is denied")
	}
}

func TestSshSessionRejectsNonSSHSecret(t *testing.T) {
	fv := &fakeSSHVault{secretTypeID: "type-password", targetID: "target-1"}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	err := c.Post(openSSHSessionMutation, &resp)
	if err == nil {
		t.Fatalf("expected error for non-ssh-key secret, got none")
	}
	if fb.called {
		t.Fatalf("CreateSession must not be called for a non-ssh-key secret")
	}
}

// TestSshSessionForwardsReferenceNotKey proves the gateway resolves the
// non-sensitive endpoint/username and forwards a REFERENCE (secret id +
// actor) to the broker, and never fetches or forwards the key itself. The broker reveals the key from the vault at redeem time.
func TestSshSessionForwardsReferenceNotKey(t *testing.T) {
	fv := &fakeSSHVault{targetID: "target-1"}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	c.MustPost(openSSHSessionMutation, &resp)

	if !fb.called {
		t.Fatalf("expected CreateSession to be called")
	}
	req := fb.lastReq
	// No key material is forwarded.
	if req.GetPrivateKey() != "" || req.GetPassphrase() != "" {
		t.Fatalf("gateway must not forward key material; got private_key/passphrase set: %+v", req)
	}
	// The reference + actor are forwarded so the broker can reveal the key.
	if got := req.GetActor().GetUserId(); got != "user-morgan" {
		t.Fatalf("actor.user_id = %q, want user-morgan", got)
	}
	assertEndpoint(t, req)
	if req.GetActorUserId() != "user-morgan" || req.GetSecretId() != "s1" || req.GetTargetId() != "target-1" {
		t.Fatalf("actor/secret/target not forwarded correctly: %+v", req)
	}
	if req.GetTtlSeconds() != 30 {
		t.Fatalf("ttl = %d, want 30", req.GetTtlSeconds())
	}
}

// assertEndpoint checks the non-sensitive endpoint/username the gateway
// resolved and forwarded.
func assertEndpoint(t *testing.T, req *sshbrokerv1.CreateSessionRequest) {
	t.Helper()
	if req.GetHost() != "host.example.org" || req.GetPort() != 22 {
		t.Fatalf("resolved endpoint = %s:%d, want host.example.org:22", req.GetHost(), req.GetPort())
	}
	if req.GetUsername() != "deploy" {
		t.Fatalf("username = %q, want deploy", req.GetUsername())
	}
}

// TestSshSessionAllowsPasswordAccountSecret proves a Password Account (SSH)
// secret (type-unix-ssh) opens a session, with password_auth set so the
// broker knows to reveal the password, not a key.
func TestSshSessionAllowsPasswordAccountSecret(t *testing.T) {
	fv := &fakeSSHVault{secretTypeID: "type-unix-ssh", targetID: "target-1"}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	c.MustPost(openSSHSessionMutation, &resp)

	if !fb.called {
		t.Fatalf("expected CreateSession to be called for a Password Account (SSH) secret")
	}
	req := fb.lastReq
	if !req.GetPasswordAuth() {
		t.Fatalf("password_auth = false, want true for a type-unix-ssh secret")
	}
	if req.GetPrivateKey() != "" {
		t.Fatalf("gateway must not forward key material for a password secret: %+v", req)
	}
	assertEndpoint(t, req)
}

// A key secret must never set password_auth: the broker would otherwise try
// to reveal a "password" field the secret doesn't have.
func TestSshSessionKeySecretLeavesPasswordAuthFalse(t *testing.T) {
	fv := &fakeSSHVault{targetID: "target-1"} // defaults to type-ssh-key
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	c.MustPost(openSSHSessionMutation, &resp)

	if fb.lastReq.GetPasswordAuth() {
		t.Fatalf("password_auth = true, want false for a type-ssh-key secret")
	}
}

// TestSshSessionReturnsBrokerTicket proves the broker's ticket is surfaced back
// to the caller unchanged.
func TestSshSessionReturnsBrokerTicket(t *testing.T) {
	fv := &fakeSSHVault{targetID: "target-1"}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	c.MustPost(openSSHSessionMutation, &resp)

	got := resp.OpenSshSession
	if got.WsURL != "ws://localhost:9096/ssh/session" || got.Ticket != "ticket-abc" ||
		got.SessionID != "sess-1" || got.ExpiresInSeconds != 30 {
		t.Fatalf("ticket not surfaced correctly: %+v", got)
	}
}

// TestSshSessionDefaultsToTheOnlyTarget proves a secret with exactly one
// attached target opens on it without targetId being given (#168: required
// only when there's more than one).
func TestSshSessionDefaultsToTheOnlyTarget(t *testing.T) {
	fv := &fakeSSHVault{targetID: "target-1"}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	c.MustPost(openSSHSessionMutation, &resp)
	if fb.lastReq.GetTargetId() != "target-1" {
		t.Fatalf("target_id = %q, want target-1", fb.lastReq.GetTargetId())
	}
	if got := fb.lastReq.GetSecretTargetIds(); len(got) != 1 || got[0] != "target-1" {
		t.Fatalf("secret_target_ids = %v, want [target-1]", got)
	}
}

// TestSshSessionRequiresTargetIdWhenSeveralAreAttached proves a secret
// attached to more than one target refuses to pick one on its own.
func TestSshSessionRequiresTargetIdWhenSeveralAreAttached(t *testing.T) {
	fv := &fakeSSHVault{targetIDs: []string{"target-1", "target-2"}}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	err := c.Post(openSSHSessionMutation, &resp)
	if err == nil {
		t.Fatal("expected an error when targetId is omitted and the secret has several targets")
	}
	if fb.called {
		t.Fatal("CreateSession must not be called without a chosen target")
	}
}

// TestSshSessionOpensEachOfSeveralAttachedTargets is #168's "picking each":
// given an explicit targetId, the gateway opens on that one and carries the
// secret's full attached-target list to the broker, so the broker can check
// attachment independently.
func TestSshSessionOpensEachOfSeveralAttachedTargets(t *testing.T) {
	for _, targetID := range []string{"target-1", "target-2"} {
		t.Run(targetID, func(t *testing.T) {
			fv := &fakeSSHVault{targetIDs: []string{"target-1", "target-2"}}
			fb := &fakeSSHBroker{}
			c := newSSHClient(fv, fb, "user-morgan")

			var resp struct {
				OpenSshSession struct {
					WsURL, Ticket, SessionID string
					ExpiresInSeconds         int
				}
			}
			c.MustPost(openSSHSessionWithTargetMutation, &resp, gqlclient.Var("targetId", targetID))
			if fb.lastReq.GetTargetId() != targetID {
				t.Fatalf("target_id = %q, want %q", fb.lastReq.GetTargetId(), targetID)
			}
			if got := fb.lastReq.GetSecretTargetIds(); len(got) != 2 {
				t.Fatalf("secret_target_ids = %v, want both attached targets", got)
			}
		})
	}
}

// TestSshSessionRefusesATargetNotAttachedToTheSecret proves a targetId that
// isn't one of the secret's attached targets is refused by the gateway
// itself, with a clear error, before the broker is ever called.
func TestSshSessionRefusesATargetNotAttachedToTheSecret(t *testing.T) {
	fv := &fakeSSHVault{targetIDs: []string{"target-1", "target-2"}}
	fb := &fakeSSHBroker{}
	c := newSSHClient(fv, fb, "user-morgan")

	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	err := c.Post(openSSHSessionWithTargetMutation, &resp, gqlclient.Var("targetId", "target-not-attached"))
	if err == nil {
		t.Fatal("expected an error for a target not attached to the secret")
	}
	if fb.called {
		t.Fatal("CreateSession must not be called for a target not attached to the secret")
	}
}

// The broker refuses any principal but a person, so it must be told which kind
// the gateway authenticated, with the same numbers as the vault's enum.
func TestBrokerActorCarriesThePrincipalKind(t *testing.T) {
	cases := map[vaultv1.PrincipalKind]sshbrokerv1.PrincipalKind{
		vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN:           sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_HUMAN,
		vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT: sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT,
		vaultv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD:        sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_WORKLOAD,
		vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN:      sshbrokerv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN,
	}
	for in, want := range cases {
		got := brokerActor(&vaultv1.ActorContext{UserId: "u-1", IsSiteAdmin: true, GroupNames: []string{"ops"}, PrincipalKind: in})
		if got.GetPrincipalKind() != want || got.GetUserId() != "u-1" || !got.GetIsSiteAdmin() || len(got.GetGroupNames()) != 1 {
			t.Fatalf("%v: broker actor = %+v", in, got)
		}
	}
}

// hangingSSHBroker never answers CreateSession until the call's context ends.
type hangingSSHBroker struct {
	sshbrokerv1.SSHBrokerServiceClient
}

func (hangingSSHBroker) CreateSession(ctx context.Context, _ *sshbrokerv1.CreateSessionRequest, _ ...grpc.CallOption) (*sshbrokerv1.CreateSessionResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A broker (or vault) that never answers must not hold the terminal on
// "Opening session": the ticket request is bounded and names what stalled.
func TestSshSessionTicketIsBoundedWhenTheBrokerHangs(t *testing.T) {
	old := openSSHSessionTimeout
	openSSHSessionTimeout = 200 * time.Millisecond
	t.Cleanup(func() { openSSHSessionTimeout = old })

	c := newSSHClient(&fakeSSHVault{targetID: "target-1"}, hangingSSHBroker{}, "user-morgan")
	var resp struct {
		OpenSshSession struct{ Ticket string }
	}
	started := time.Now()
	err := c.Post(openSSHSessionMutation, &resp)
	if err == nil {
		t.Fatal("expected an error from a broker that never answers")
	}
	if took := time.Since(started); took > 3*time.Second {
		t.Fatalf("ticket request took %s, want it bounded", took)
	}
	if !strings.Contains(err.Error(), "the SSH broker didn't answer") {
		t.Fatalf("error = %v, want it to name the SSH broker", err)
	}
}

// recordedLine is one line a recordingLog took.
type recordedLine struct {
	level, msg string
	fields     map[string]any
}

// recordingLog is a log.Logger that keeps every line, with the fields
// added by With.
type recordingLog struct {
	lines *[]recordedLine
	base  []log.Field
}

func newRecordingLog() *recordingLog { return &recordingLog{lines: &[]recordedLine{}} }

func (l *recordingLog) add(level, msg string, fields []log.Field) {
	m := map[string]any{}
	for _, f := range append(append([]log.Field{}, l.base...), fields...) {
		m[f.Key] = f.Val
	}
	*l.lines = append(*l.lines, recordedLine{level: level, msg: msg, fields: m})
}

func (l *recordingLog) Debug(msg string, f ...log.Field) { l.add("debug", msg, f) }
func (l *recordingLog) Info(msg string, f ...log.Field)  { l.add("info", msg, f) }
func (l *recordingLog) Warn(msg string, f ...log.Field)  { l.add("warn", msg, f) }
func (l *recordingLog) Error(_ error, msg string, f ...log.Field) {
	l.add("error", msg, f)
}
func (l *recordingLog) Fatal(_ error, msg string, f ...log.Field) { l.add("fatal", msg, f) }
func (l *recordingLog) With(f ...log.Field) log.Logger {
	return &recordingLog{lines: l.lines, base: append(append([]log.Field{}, l.base...), f...)}
}
func (l *recordingLog) Ctx(context.Context) log.Logger { return l }

// want returns the line with msg, failing unless it has the level and the
// fields given.
func (l *recordingLog) want(t *testing.T, msg, level string, fields map[string]any) recordedLine {
	t.Helper()
	for _, line := range *l.lines {
		if line.msg != msg {
			continue
		}
		if line.level != level {
			t.Fatalf("%q logged at %s, want %s", msg, line.level, level)
		}
		for k, v := range fields {
			if line.fields[k] != v {
				t.Fatalf("%q field %s = %v, want %v (%+v)", msg, k, line.fields[k], v, line.fields)
			}
		}
		return line
	}
	t.Fatalf("no %q line in %+v", msg, *l.lines)
	return recordedLine{}
}

func newLoggedSSHClient(fv vaultv1.VaultServiceClient, fb sshbrokerv1.SSHBrokerServiceClient, lg log.Logger) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, SSHBroker: fb, Log: lg}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-morgan")))
	})
	return gqlclient.New(wrapped)
}

// A session open is logged at info level on the way in and when the ticket
// comes back, with who asked and for which target, and never a secret.
func TestSshSessionOpenIsLogged(t *testing.T) {
	lg := newRecordingLog()
	c := newLoggedSSHClient(&fakeSSHVault{targetID: "target-1"}, &fakeSSHBroker{}, lg)
	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	if err := c.Post(openSSHSessionMutation, &resp); err != nil {
		t.Fatalf("open: %v", err)
	}
	lg.want(t, "ssh session requested", "info", map[string]any{"actor_user_id": "user-morgan", "secret_id": "s1"})
	got := lg.want(t, "ssh session ticket issued", "info", map[string]any{
		"target_id": "target-1", "session_id": "sess-1", "host": "host.example.org", "port": 22,
	})
	if _, ok := got.fields["duration_ms"]; !ok {
		t.Fatalf("issued line has no duration: %+v", got)
	}
	for _, line := range *lg.lines {
		for k, v := range line.fields {
			if k == "ticket" || v == "ticket-abc" {
				t.Fatalf("the ticket reached the log: %+v", line)
			}
		}
	}
}

func TestSshSessionOpenFailureIsLogged(t *testing.T) {
	old := openSSHSessionTimeout
	openSSHSessionTimeout = 200 * time.Millisecond
	t.Cleanup(func() { openSSHSessionTimeout = old })

	lg := newRecordingLog()
	c := newLoggedSSHClient(&fakeSSHVault{targetID: "target-1"}, hangingSSHBroker{}, lg)
	var resp struct {
		OpenSshSession struct{ Ticket string }
	}
	if err := c.Post(openSSHSessionMutation, &resp); err == nil {
		t.Fatal("expected an error")
	}
	lg.want(t, "ssh session ticket failed", "warn", map[string]any{"step": "broker", "target_id": "target-1"})
}
