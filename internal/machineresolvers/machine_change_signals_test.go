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
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type signalsVault struct {
	vaultv1.VaultServiceClient
	listReq *vaultv1.ListSecretsForPrincipalRequest
	getReq  *vaultv1.GetSecretForPrincipalRequest
	secret  *vaultv1.Secret
	denyGet bool
}

func (f *signalsVault) ListSecretsForPrincipal(_ context.Context, in *vaultv1.ListSecretsForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretsForPrincipalResponse, error) {
	f.listReq = in
	return &vaultv1.ListSecretsForPrincipalResponse{Secrets: []*vaultv1.Secret{f.secret}}, nil
}

func (f *signalsVault) GetSecretForPrincipal(_ context.Context, in *vaultv1.GetSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretForPrincipalResponse, error) {
	f.getReq = in
	if f.denyGet {
		return nil, status.Error(codes.PermissionDenied, "not permitted to read this secret")
	}
	return &vaultv1.GetSecretForPrincipalResponse{Secret: f.secret}, nil
}

func machineClient(fv vaultv1.VaultServiceClient) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithMachineActor(r.Context(), "sa-42", nil)))
	}))
}

func rotatingSecret() *vaultv1.Secret {
	return &vaultv1.Secret{
		Id: "s1", Name: "svc", FolderId: "f", TypeId: "type-windows-domain",
		ValueVersion: 4, ValueChangedAt: "2026-10-01T12:00:00Z",
		RotationEnabled: true, RotatesOnCheckin: true, HeartbeatEnabled: true,
		LastRotationResult: vaultv1.RotationState_ROTATION_STATE_OK, RotatedAt: "2026-10-01T12:00:00Z", NextRotationAt: "2026-10-31T12:00:00Z",
		LastHeartbeatResult: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK,
	}
}

type signalSummary struct {
	ID                  string
	ValueVersion        int
	ValueChangedAt      *string
	RotationEnabled     bool
	RotatesOnCheckin    bool
	HeartbeatEnabled    bool
	LastRotationResult  *string
	RotatedAt           *string
	NextRotationAt      *string
	LastHeartbeatResult *string
}

const signalFields = `id valueVersion valueChangedAt rotationEnabled rotatesOnCheckin heartbeatEnabled lastRotationResult rotatedAt nextRotationAt lastHeartbeatResult`

func checkSignals(t *testing.T, got signalSummary) {
	t.Helper()
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	if got.ValueVersion != 4 || str(got.ValueChangedAt) != "2026-10-01T12:00:00Z" || !got.RotationEnabled || !got.RotatesOnCheckin || !got.HeartbeatEnabled ||
		str(got.LastRotationResult) != "OK" || str(got.RotatedAt) != "2026-10-01T12:00:00Z" || str(got.NextRotationAt) != "2026-10-31T12:00:00Z" || str(got.LastHeartbeatResult) != "OK" {
		t.Fatalf("summary = %+v", got)
	}
}

func TestFindSecretsForPrincipal_ForwardsChangedSinceAndCarriesTheSignals(t *testing.T) {
	fv := &signalsVault{secret: rotatingSecret()}
	var resp struct{ FindSecretsForPrincipal []signalSummary }
	c := machineClient(fv)
	c.MustPost(`query { findSecretsForPrincipal(changedSince: "2026-10-01T00:00:00Z") { `+signalFields+` } }`, &resp)
	if fv.listReq.GetChangedSince() != "2026-10-01T00:00:00Z" || fv.listReq.GetActor().GetPrincipalId() != "sa-42" {
		t.Fatalf("vault request = %+v", fv.listReq)
	}
	if len(resp.FindSecretsForPrincipal) != 1 {
		t.Fatalf("got %d secrets", len(resp.FindSecretsForPrincipal))
	}
	checkSignals(t, resp.FindSecretsForPrincipal[0])
}

func TestUnsetSignalsAreNull(t *testing.T) {
	fv := &signalsVault{secret: &vaultv1.Secret{Id: "s1", Name: "svc", FolderId: "f", TypeId: "type-password"}}
	var resp struct{ FindSecretsForPrincipal []signalSummary }
	machineClient(fv).MustPost(`query { findSecretsForPrincipal { `+signalFields+` } }`, &resp)
	got := resp.FindSecretsForPrincipal[0]
	if got.ValueVersion != 0 || got.ValueChangedAt != nil || got.LastRotationResult != nil || got.RotatedAt != nil || got.NextRotationAt != nil || got.LastHeartbeatResult != nil {
		t.Fatalf("unset fields should be zero or null: %+v", got)
	}
}

func TestSecretForPrincipal(t *testing.T) {
	fv := &signalsVault{secret: rotatingSecret()}
	var resp struct{ SecretForPrincipal signalSummary }
	machineClient(fv).MustPost(`query { secretForPrincipal(id: "s1") { `+signalFields+` } }`, &resp)
	if fv.getReq.GetId() != "s1" || fv.getReq.GetActor().GetPrincipalId() != "sa-42" {
		t.Fatalf("vault request = %+v", fv.getReq)
	}
	checkSignals(t, resp.SecretForPrincipal)

	fv.denyGet = true
	if err := machineClient(fv).Post(`query { secretForPrincipal(id: "s1") { id } }`, &resp); err == nil {
		t.Fatal("a vault denial didn't surface")
	}
}
