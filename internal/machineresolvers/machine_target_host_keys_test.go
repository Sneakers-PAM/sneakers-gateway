// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

// The gateway never parses pins, so placeholders stand in for real keys.
var machinePins = []string{"ssh-ed25519 pinned-host-key-1 web-01", "ecdsa-sha2-nistp256 pinned-host-key-2"}

// pinnedTargetVault is targetVault with web-01 (t2) pinned.
type pinnedTargetVault struct {
	targetVault
	lists int
}

func (f *pinnedTargetVault) ListTargets(_ context.Context, in *vaultv1.ListTargetsRequest, _ ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	f.lists++
	f.lastListTargets = in
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{
		{Id: "t1", Name: "ad.example.org DCs", Hostname: "dc1.ad.example.org", ConnectionId: "conn-ldaps"},
		{Id: "t2", Name: "web-01", Hostname: "web-01.example.org", ConnectionId: "conn-ssh", OwnerUserId: "u-ada", SshHostKeys: machinePins},
	}}, nil
}

func newPinnedTargetClient(fv *pinnedTargetVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)))
	}))
}

func TestTargetsForPrincipalReturnsHostKeys(t *testing.T) {
	var resp struct {
		TargetsForPrincipal []struct {
			ID          string
			SSHHostKeys []string `json:"sshHostKeys"`
		}
	}
	newPinnedTargetClient(&pinnedTargetVault{}).MustPost(`{ targetsForPrincipal { id sshHostKeys } }`, &resp)
	got := map[string][]string{}
	for _, tg := range resp.TargetsForPrincipal {
		got[tg.ID] = tg.SSHHostKeys
	}
	if strings.Join(got["t2"], "|") != strings.Join(machinePins, "|") {
		t.Fatalf("pinned target sshHostKeys = %q", got["t2"])
	}
	if pins, ok := got["t1"]; !ok || pins == nil || len(pins) != 0 {
		t.Fatalf("unpinned target sshHostKeys = %#v, want []", pins)
	}
}

func TestSaveTargetForPrincipalSendsHostKeys(t *testing.T) {
	fv := &pinnedTargetVault{}
	var resp struct {
		SaveTargetForPrincipal struct {
			SSHHostKeys []string `json:"sshHostKeys"`
		}
	}
	newPinnedTargetClient(fv).MustPost(`mutation { saveTargetForPrincipal(input:{name:"web-02", hostname:"web-02.example.org", connectionId:"conn-ssh", sshHostKeys:["`+machinePins[0]+`"]}) { sshHostKeys } }`, &resp)
	if got := fv.lastSave.GetTarget().GetSshHostKeys(); len(got) != 1 || got[0] != machinePins[0] {
		t.Fatalf("sent host keys = %q", got)
	}
	if len(resp.SaveTargetForPrincipal.SSHHostKeys) != 1 {
		t.Fatalf("returned host keys = %q", resp.SaveTargetForPrincipal.SSHHostKeys)
	}
}

func TestSaveTargetForPrincipalOmittedHostKeysKeepsPins(t *testing.T) {
	fv := &pinnedTargetVault{}
	c := newPinnedTargetClient(fv)
	var resp struct{ SaveTargetForPrincipal struct{ ID string } }

	c.MustPost(`mutation { saveTargetForPrincipal(input:{id:"t2", name:"web-01", hostname:"web-01.example.org", connectionId:"conn-ssh", description:"edited"}) { id } }`, &resp)
	if got := fv.lastSave.GetTarget().GetSshHostKeys(); strings.Join(got, "|") != strings.Join(machinePins, "|") {
		t.Fatalf("omitted sshHostKeys sent %q, want the stored pins", got)
	}

	fv.lists = 0
	c.MustPost(`mutation { saveTargetForPrincipal(input:{id:"t2", name:"web-01", hostname:"web-01.example.org", connectionId:"conn-ssh", sshHostKeys:[]}) { id } }`, &resp)
	if len(fv.lastSave.GetTarget().GetSshHostKeys()) != 0 || fv.lists != 0 {
		t.Fatalf("explicit [] sent %q after %d lookups", fv.lastSave.GetTarget().GetSshHostKeys(), fv.lists)
	}
}
