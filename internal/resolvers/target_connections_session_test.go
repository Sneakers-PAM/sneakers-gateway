// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// multiConnSSHVault is fakeSSHVault with a target that carries two
// connections (an ssh default and a non-default winrm one), for exercising
// session-start connection selection.
type multiConnSSHVault struct {
	fakeSSHVault
}

func (f *multiConnSSHVault) ListTargets(context.Context, *vaultv1.ListTargetsRequest, ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{{
		Id: "target-1", Hostname: "host.example.org", ConnectionId: "conn-ssh",
		Connections: []*vaultv1.TargetConnection{
			{ConnectionId: "conn-ssh", IsDefault: true},
			{ConnectionId: "conn-winrm", IsDefault: false},
		},
	}}}, nil
}

func (f *multiConnSSHVault) ListConnections(context.Context, *vaultv1.ListConnectionsRequest, ...grpc.CallOption) (*vaultv1.ListConnectionsResponse, error) {
	return &vaultv1.ListConnectionsResponse{Connections: []*vaultv1.Connection{
		{Id: "conn-ssh", Protocol: "ssh", Port: 22},
		{Id: "conn-winrm", Protocol: "winrm", Port: 5985},
	}}, nil
}

// A session start with no connectionId picks the target's default connection.
func TestSshSessionPicksDefaultConnectionWhenNoneNamed(t *testing.T) {
	fv := &multiConnSSHVault{fakeSSHVault: fakeSSHVault{targetID: "target-1"}}
	fb := &fakeSSHBroker{}
	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	newSSHClient(fv, fb, "user-morgan").MustPost(openSSHSessionMutation, &resp)
	if !fb.called || fb.lastReq.GetPort() != 22 {
		t.Fatalf("called=%v port=%d, want the default connection on 22", fb.called, fb.lastReq.GetPort())
	}
}

// Naming a connection outside the target's own list is refused, even if that
// connection exists elsewhere.
func TestSshSessionRejectsConnectionNotOnTarget(t *testing.T) {
	fv := &multiConnSSHVault{fakeSSHVault: fakeSSHVault{targetID: "target-1"}}
	fb := &fakeSSHBroker{}
	var resp struct {
		OpenSshSession struct{ WsURL, Ticket, SessionID string }
	}
	err := newSSHClient(fv, fb, "user-morgan").Post(
		`mutation { openSshSession(secretId:"s1", connectionId:"conn-other") { wsUrl } }`, &resp)
	if err == nil {
		t.Fatalf("expected an error naming a connection outside the target's list")
	}
	if fb.called {
		t.Fatalf("CreateSession must not be called for a rejected connection")
	}
}

// Naming the target's own non-default, non-ssh connection is refused with
// the existing "connection is not ssh" check, not silently ignored.
func TestSshSessionRejectsNamedNonSSHConnection(t *testing.T) {
	fv := &multiConnSSHVault{fakeSSHVault: fakeSSHVault{targetID: "target-1"}}
	fb := &fakeSSHBroker{}
	var resp struct {
		OpenSshSession struct{ WsURL, Ticket, SessionID string }
	}
	err := newSSHClient(fv, fb, "user-morgan").Post(
		`mutation { openSshSession(secretId:"s1", connectionId:"conn-winrm") { wsUrl } }`, &resp)
	if err == nil {
		t.Fatalf("expected an error naming the target's non-ssh connection")
	}
	if fb.called {
		t.Fatalf("CreateSession must not be called for a rejected connection")
	}
}
