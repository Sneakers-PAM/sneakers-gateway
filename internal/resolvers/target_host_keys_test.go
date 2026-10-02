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
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// The gateway never parses pins, so placeholders stand in for real keys.
var testPins = []string{"ssh-ed25519 pinned-host-key-1 app01", "ecdsa-sha2-nistp256 pinned-host-key-2"}

// pinnedSSHVault is fakeSSHVault with the target's host keys pinned.
type pinnedSSHVault struct {
	fakeSSHVault
	pins []string
}

func (f *pinnedSSHVault) ListTargets(_ context.Context, _ *vaultv1.ListTargetsRequest, _ ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{
		{Id: "target-1", Hostname: "host.example.org", ConnectionId: "conn-1", SshHostKeys: f.pins},
	}}, nil
}

func TestSshSessionPassesTargetHostKeys(t *testing.T) {
	fv := &pinnedSSHVault{fakeSSHVault: fakeSSHVault{targetID: "target-1"}, pins: testPins}
	fb := &fakeSSHBroker{}
	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	newSSHClient(fv, fb, "user-morgan").MustPost(openSSHSessionMutation, &resp)
	if got := fb.lastReq.GetHostKeys(); strings.Join(got, "|") != strings.Join(testPins, "|") {
		t.Fatalf("host_keys to the broker = %q, want %q", got, testPins)
	}
}

// An unpinned target still gets a ticket; the broker refuses the connection
// and tells the client why.
func TestSshSessionUnpinnedTargetSendsNoHostKeys(t *testing.T) {
	fv := &pinnedSSHVault{fakeSSHVault: fakeSSHVault{targetID: "target-1"}}
	fb := &fakeSSHBroker{}
	var resp struct {
		OpenSshSession struct {
			WsURL, Ticket, SessionID string
			ExpiresInSeconds         int
		}
	}
	newSSHClient(fv, fb, "user-morgan").MustPost(openSSHSessionMutation, &resp)
	if !fb.called || len(fb.lastReq.GetHostKeys()) != 0 {
		t.Fatalf("called=%v host_keys=%q", fb.called, fb.lastReq.GetHostKeys())
	}
}

// targetSaveVault records SaveTarget and serves one stored target.
type targetSaveVault struct {
	vaultv1.VaultServiceClient
	stored   *vaultv1.Target
	lastSave *vaultv1.SaveTargetRequest
	lists    int
}

func (f *targetSaveVault) ListTargets(context.Context, *vaultv1.ListTargetsRequest, ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	f.lists++
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{f.stored}}, nil
}

func (f *targetSaveVault) SaveTarget(_ context.Context, in *vaultv1.SaveTargetRequest, _ ...grpc.CallOption) (*vaultv1.SaveTargetResponse, error) {
	f.lastSave = in
	t := in.GetTarget()
	if t.GetId() == "" {
		t.Id = "t-new"
	}
	return &vaultv1.SaveTargetResponse{Target: t}, nil
}

func newTargetSaveClient(fv *targetSaveVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-admin")))
	}))
}

func TestTargetsQueryReturnsHostKeys(t *testing.T) {
	fv := &targetSaveVault{stored: &vaultv1.Target{Id: "t1", Name: "app01", Hostname: "app01.example.org", ConnectionId: "c1", SshHostKeys: testPins}}
	var resp struct {
		Targets []struct{ SSHHostKeys []string }
	}
	newTargetSaveClient(fv).MustPost(`{ targets { sshHostKeys } }`, &resp)
	if len(resp.Targets) != 1 || strings.Join(resp.Targets[0].SSHHostKeys, "|") != strings.Join(testPins, "|") {
		t.Fatalf("targets = %+v", resp)
	}
}

func TestSaveTargetSendsHostKeys(t *testing.T) {
	fv := &targetSaveVault{stored: &vaultv1.Target{Id: "t1"}}
	var resp struct {
		SaveTarget struct{ SSHHostKeys []string }
	}
	newTargetSaveClient(fv).MustPost(`mutation { saveTarget(input:{name:"app01", hostname:"app01.example.org", connectionId:"c1", sshHostKeys:["`+testPins[0]+`","`+testPins[1]+`"]}) { sshHostKeys } }`, &resp)
	if got := fv.lastSave.GetTarget().GetSshHostKeys(); strings.Join(got, "|") != strings.Join(testPins, "|") {
		t.Fatalf("sent host keys = %q", got)
	}
	if strings.Join(resp.SaveTarget.SSHHostKeys, "|") != strings.Join(testPins, "|") {
		t.Fatalf("returned host keys = %q", resp.SaveTarget.SSHHostKeys)
	}
}

// An edit that leaves sshHostKeys out keeps the target's pins (the vault
// replaces the list on every save); an explicit empty list clears them.
func TestSaveTargetOmittedHostKeysKeepsPins(t *testing.T) {
	fv := &targetSaveVault{stored: &vaultv1.Target{Id: "t1", Name: "app01", Hostname: "app01.example.org", ConnectionId: "c1", SshHostKeys: testPins}}
	c := newTargetSaveClient(fv)
	var resp struct{ SaveTarget struct{ ID string } }

	c.MustPost(`mutation { saveTarget(input:{id:"t1", name:"app01 renamed", hostname:"app01.example.org", connectionId:"c1"}) { id } }`, &resp)
	if got := fv.lastSave.GetTarget().GetSshHostKeys(); strings.Join(got, "|") != strings.Join(testPins, "|") {
		t.Fatalf("omitted sshHostKeys sent %q, want the stored pins", got)
	}

	fv.lists = 0
	c.MustPost(`mutation { saveTarget(input:{id:"t1", name:"app01", hostname:"app01.example.org", connectionId:"c1", sshHostKeys:[]}) { id } }`, &resp)
	if got := fv.lastSave.GetTarget().GetSshHostKeys(); len(got) != 0 || fv.lists != 0 {
		t.Fatalf("explicit [] sent %q after %d lookups, want none", got, fv.lists)
	}

	// A new target with no sshHostKeys needs no lookup.
	c.MustPost(`mutation { saveTarget(input:{name:"app02", hostname:"app02.example.org", connectionId:"c1"}) { id } }`, &resp)
	if fv.lists != 0 || len(fv.lastSave.GetTarget().GetSshHostKeys()) != 0 {
		t.Fatalf("create looked up %d times, sent %q", fv.lists, fv.lastSave.GetTarget().GetSshHostKeys())
	}
}
