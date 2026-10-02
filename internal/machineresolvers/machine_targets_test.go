// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

type targetVault struct {
	vaultv1.VaultServiceClient
	lastListTargets *vaultv1.ListTargetsRequest
	lastSave        *vaultv1.SaveTargetRequest
	lastSet         *vaultv1.SetSecretTargetForPrincipalRequest
	lastRequest     *vaultv1.RequestHeartbeatForPrincipalRequest
}

func (f *targetVault) ListConnections(context.Context, *vaultv1.ListConnectionsRequest, ...grpc.CallOption) (*vaultv1.ListConnectionsResponse, error) {
	return &vaultv1.ListConnectionsResponse{Connections: []*vaultv1.Connection{{Id: "conn-ldaps", Name: "AD LDAPS", Protocol: "ldap", Port: 636, UseTls: true, TargetCount: 2}}}, nil
}

func (f *targetVault) ListTargets(_ context.Context, in *vaultv1.ListTargetsRequest, _ ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	f.lastListTargets = in
	return &vaultv1.ListTargetsResponse{Targets: []*vaultv1.Target{
		{Id: "t1", Name: "ad.example.org DCs", Hostname: "dc1.ad.example.org", Kind: "windows", Domain: "ad.example.org", ConnectionId: "conn-ldaps", SecretCount: 1},
		{Id: "t2", Name: "web-01", Hostname: "web-01.example.org", Kind: "unix", ConnectionId: "conn-ssh", OwnerUserId: "u-ada"},
	}}, nil
}

func (f *targetVault) SaveTarget(_ context.Context, in *vaultv1.SaveTargetRequest, _ ...grpc.CallOption) (*vaultv1.SaveTargetResponse, error) {
	f.lastSave = in
	t := in.GetTarget()
	t.Id, t.OwnerUserId = "t9", "u-ada"
	return &vaultv1.SaveTargetResponse{Target: t}, nil
}

func (f *targetVault) SetSecretTargetForPrincipal(_ context.Context, in *vaultv1.SetSecretTargetForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.SetSecretTargetForPrincipalResponse, error) {
	f.lastSet = in
	return &vaultv1.SetSecretTargetForPrincipalResponse{Secret: &vaultv1.Secret{Id: in.GetSecretId(), Name: "morgan_da", TargetId: in.GetTargetId()}}, nil
}

func newTargetClient(fv *targetVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)))
	}))
}

func TestConnectionsForPrincipalListsConnections(t *testing.T) {
	var resp struct {
		ConnectionsForPrincipal []struct {
			ID, Name, Protocol string
			Port               int
			UseTLS             bool `json:"useTls"`
		}
	}
	newTargetClient(&targetVault{}).MustPost(`{ connectionsForPrincipal { id name protocol port useTls } }`, &resp)
	if len(resp.ConnectionsForPrincipal) != 1 || resp.ConnectionsForPrincipal[0].Port != 636 || !resp.ConnectionsForPrincipal[0].UseTLS {
		t.Fatalf("connections = %+v", resp)
	}
}

func TestTargetsForPrincipalFiltersByNameAndConnection(t *testing.T) {
	fv := &targetVault{}
	var resp struct{ TargetsForPrincipal []struct{ ID string } }
	newTargetClient(fv).MustPost(`{ targetsForPrincipal(query:"AD.EXAMPLE", connectionId:"conn-ldaps") { id } }`, &resp)
	if fv.lastListTargets.GetActor().GetTokenId() != "utok-1" || len(resp.TargetsForPrincipal) != 1 || resp.TargetsForPrincipal[0].ID != "t1" {
		t.Fatalf("list req = %+v resp = %+v", fv.lastListTargets, resp)
	}
}

func TestSaveTargetForPrincipalForwardsTheToken(t *testing.T) {
	fv := &targetVault{}
	var resp struct {
		SaveTargetForPrincipal struct{ ID, OwnerUserID string }
	}
	newTargetClient(fv).MustPost(`mutation { saveTargetForPrincipal(input:{name:"corp DCs", hostname:"dc1.corp.ad.example.org", kind:"windows", domain:"corp.ad.example.org", realm:"CORP.AD.EXAMPLE.ORG", connectionId:"conn-ldaps"}) { id ownerUserId } }`, &resp)
	s := fv.lastSave
	if s.GetActor().GetTokenId() != "utok-1" || s.GetTarget().GetDomain() != "corp.ad.example.org" || s.GetTarget().GetConnectionId() != "conn-ldaps" || resp.SaveTargetForPrincipal.ID != "t9" {
		t.Fatalf("save = %+v resp = %+v", s, resp)
	}
}

func TestSetSecretTargetForPrincipalAttachesAndDetaches(t *testing.T) {
	fv := &targetVault{}
	c := newTargetClient(fv)
	var resp struct{ SetSecretTargetForPrincipal struct{ ID, TargetID string } }
	c.MustPost(`mutation { setSecretTargetForPrincipal(secretId:"s1", targetId:"t1") { id targetId } }`, &resp)
	if fv.lastSet.GetSecretId() != "s1" || fv.lastSet.GetTargetId() != "t1" || resp.SetSecretTargetForPrincipal.TargetID != "t1" {
		t.Fatalf("set = %+v resp = %+v", fv.lastSet, resp)
	}
	c.MustPost(`mutation { setSecretTargetForPrincipal(secretId:"s1") { id } }`, &resp)
	if fv.lastSet.GetTargetId() != "" {
		t.Fatalf("detach sent target %q", fv.lastSet.GetTargetId())
	}
}
