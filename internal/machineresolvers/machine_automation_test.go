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
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

type automationVault struct {
	vaultv1.VaultServiceClient

	lastSet      *vaultv1.SetSecretAutomationForPrincipalRequest
	lastCreate   *vaultv1.CreateSecretForPrincipalRequest
	lastGenerate *vaultv1.GenerateSecretForPrincipalRequest
	err          error
}

func (f *automationVault) SetSecretAutomationForPrincipal(_ context.Context, in *vaultv1.SetSecretAutomationForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.SetSecretAutomationForPrincipalResponse, error) {
	f.lastSet = in
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.SetSecretAutomationForPrincipalResponse{Secret: &vaultv1.Secret{
		Id: in.GetSecretId(), Name: "svc-static", FolderId: "f1", TypeId: "type-ad",
		RotationOptOut: in.GetDisableRotation(), HeartbeatOptOut: in.GetDisableHeartbeat(),
	}}, nil
}

func (f *automationVault) CreateSecretForPrincipal(_ context.Context, in *vaultv1.CreateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.CreateSecretForPrincipalResponse, error) {
	f.lastCreate = in
	return &vaultv1.CreateSecretForPrincipalResponse{Secret: &vaultv1.Secret{
		Id: "s9", RotationOptOut: in.GetDisableRotation(), HeartbeatOptOut: in.GetDisableHeartbeat(),
	}}, nil
}

func (f *automationVault) GenerateSecretForPrincipal(_ context.Context, in *vaultv1.GenerateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.GenerateSecretForPrincipalResponse, error) {
	f.lastGenerate = in
	return &vaultv1.GenerateSecretForPrincipalResponse{Secret: &vaultv1.Secret{
		Id: "s9", RotationOptOut: in.GetDisableRotation(), HeartbeatOptOut: in.GetDisableHeartbeat(),
	}}, nil
}

// newAutomationClient serves the machine schema over fv directly: wrapping it in
// fakePrincipalVault would shadow its create/generate methods.
func newAutomationClient(fv *automationVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithMachineActor(r.Context(), "sa-7", nil)))
	}))
}

type optOutResp struct {
	ID              string
	RotationOptOut  bool
	HeartbeatOptOut bool
}

func TestSecretSummaryMapsOptOuts(t *testing.T) {
	got := summaryOf(&vaultv1.Secret{Id: "s1", RotationOptOut: true})
	if !got.RotationOptOut || got.HeartbeatOptOut {
		t.Fatalf("rotation-only = %+v", got)
	}
	got = summaryOf(&vaultv1.Secret{Id: "s1", HeartbeatOptOut: true})
	if got.RotationOptOut || !got.HeartbeatOptOut {
		t.Fatalf("heartbeat-only = %+v", got)
	}
}

func TestSetSecretAutomationForPrincipal_ForwardsActorAndFlags(t *testing.T) {
	for _, tc := range []struct{ rot, hb bool }{{true, false}, {false, true}, {true, true}, {false, false}} {
		fv := &automationVault{}
		c := newAutomationClient(fv)
		var resp struct{ SetSecretAutomationForPrincipal optOutResp }
		c.MustPost(`mutation($r: Boolean!, $h: Boolean!) { setSecretAutomationForPrincipal(secretId: "s1", disableRotation: $r, disableHeartbeat: $h) { id rotationOptOut heartbeatOptOut } }`,
			&resp, gqlclient.Var("r", tc.rot), gqlclient.Var("h", tc.hb))

		if fv.lastSet == nil {
			t.Fatal("vault.SetSecretAutomationForPrincipal was not called")
		}
		assertMachineActor(t, fv.lastSet.GetActor(), "sa-7")
		if fv.lastSet.GetSecretId() != "s1" || fv.lastSet.GetDisableRotation() != tc.rot || fv.lastSet.GetDisableHeartbeat() != tc.hb {
			t.Fatalf("%+v: args not forwarded: %+v", tc, fv.lastSet)
		}
		got := resp.SetSecretAutomationForPrincipal
		if got.ID != "s1" || got.RotationOptOut != tc.rot || got.HeartbeatOptOut != tc.hb {
			t.Fatalf("%+v: summary mapped wrong: %+v", tc, got)
		}
	}
}

func TestSetSecretAutomationForPrincipal_VaultErrorSurfaces(t *testing.T) {
	fv := &automationVault{err: status.Error(codes.PermissionDenied, "not permitted to change the automation of this secret")}
	c := newAutomationClient(fv)
	var resp struct{ SetSecretAutomationForPrincipal *optOutResp }
	err := c.Post(`mutation { setSecretAutomationForPrincipal(secretId: "s1", disableRotation: true, disableHeartbeat: false) { id } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("want the vault error surfaced, got %v", err)
	}
}

func TestCreateSecretForPrincipal_ForwardsAutomationOptOuts(t *testing.T) {
	fv := &automationVault{}
	c := newAutomationClient(fv)
	var resp struct{ CreateSecretForPrincipal optOutResp }
	c.MustPost(`mutation { createSecretForPrincipal(folderId: "f1", typeId: "type-ad", name: "svc-static", fields: [], disableRotation: true, disableHeartbeat: true) { id rotationOptOut heartbeatOptOut } }`, &resp)
	if !fv.lastCreate.GetDisableRotation() || !fv.lastCreate.GetDisableHeartbeat() {
		t.Fatalf("opt-outs not forwarded: %+v", fv.lastCreate)
	}
	if !resp.CreateSecretForPrincipal.RotationOptOut || !resp.CreateSecretForPrincipal.HeartbeatOptOut {
		t.Fatalf("summary mapped wrong: %+v", resp.CreateSecretForPrincipal)
	}

	c.MustPost(`mutation { createSecretForPrincipal(folderId: "f1", typeId: "type-ad", name: "svc", fields: []) { id } }`, &resp)
	if fv.lastCreate.GetDisableRotation() || fv.lastCreate.GetDisableHeartbeat() {
		t.Fatalf("omitted opt-outs must default to false: %+v", fv.lastCreate)
	}
}

func TestGenerateSecretForPrincipal_ForwardsAutomationOptOuts(t *testing.T) {
	fv := &automationVault{}
	c := newAutomationClient(fv)
	var resp struct {
		GenerateSecretForPrincipal struct{ Secret optOutResp }
	}
	c.MustPost(`mutation { generateSecretForPrincipal(folderId: "f1", typeId: "type-ad", name: "svc-static", fields: [], disableRotation: true, disableHeartbeat: false) { secret { id rotationOptOut heartbeatOptOut } } }`, &resp)
	if !fv.lastGenerate.GetDisableRotation() || fv.lastGenerate.GetDisableHeartbeat() {
		t.Fatalf("opt-outs not forwarded: %+v", fv.lastGenerate)
	}
	if got := resp.GenerateSecretForPrincipal.Secret; !got.RotationOptOut || got.HeartbeatOptOut {
		t.Fatalf("summary mapped wrong: %+v", got)
	}

	c.MustPost(`mutation { generateSecretForPrincipal(folderId: "f1", typeId: "type-ad", name: "svc", fields: []) { secret { id } } }`, &resp)
	if fv.lastGenerate.GetDisableRotation() || fv.lastGenerate.GetDisableHeartbeat() {
		t.Fatalf("omitted opt-outs must default to false: %+v", fv.lastGenerate)
	}
}
