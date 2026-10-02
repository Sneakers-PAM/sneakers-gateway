// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
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
	getSecretErr error // simulate an upstream authz/read denial on GetSecret
}

func (f *fakeSSHVault) GetSecret(_ context.Context, req *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	if f.getSecretErr != nil {
		return nil, f.getSecretErr
	}
	typeID := f.secretTypeID
	if typeID == "" {
		typeID = "type-ssh-key"
	}
	return &vaultv1.GetSecretResponse{Secret: &vaultv1.Secret{
		Id:       req.GetId(),
		TypeId:   typeID,
		TargetId: f.targetID,
	}}, nil
}

func (f *fakeSSHVault) ListTargets(_ context.Context, _ *vaultv1.ListTargetsRequest, _ ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{
		{Id: "target-1", Hostname: "host.example.org", ConnectionId: "conn-1"},
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
