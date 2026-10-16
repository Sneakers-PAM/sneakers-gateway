// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// heartbeatBlockedReason (sneakers-vault#162) isn't on vault's human
// GetSecret/ListSecretsInFolder responses (only the *ForPrincipal ones), so
// the resolver derives it from the secret type catalog and the target —
// this fake plays both.
type fakeHeartbeatVault struct {
	vaultv1.VaultServiceClient
	secret  *vaultv1.Secret
	types   []*vaultv1.SecretType
	targets []*vaultv1.Target
}

func (f *fakeHeartbeatVault) GetSecret(_ context.Context, _ *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	return &vaultv1.GetSecretResponse{Secret: f.secret}, nil
}

func (f *fakeHeartbeatVault) ListSecretTypes(_ context.Context, _ *vaultv1.ListSecretTypesRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretTypesResponse, error) {
	return &vaultv1.ListSecretTypesResponse{Types: f.types}, nil
}

func (f *fakeHeartbeatVault) ListTargets(_ context.Context, _ *vaultv1.ListTargetsRequest, _ ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: f.targets}, nil
}

func heartbeatClient(fv *fakeHeartbeatVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-morgan")))
	}))
}

func heartbeatCapableType() *vaultv1.SecretType {
	return &vaultv1.SecretType{Id: "type-ssh-key", Name: "SSH Key", Heartbeat: true}
}

func queryHeartbeatBlockedReason(t *testing.T, fv *fakeHeartbeatVault) *string {
	t.Helper()
	var resp struct {
		Secret struct{ HeartbeatBlockedReason *string }
	}
	heartbeatClient(fv).MustPost(`{ secret(id:"s1") { heartbeatBlockedReason } }`, &resp)
	return resp.Secret.HeartbeatBlockedReason
}

func TestHeartbeatBlockedReasonNoTarget(t *testing.T) {
	fv := &fakeHeartbeatVault{
		secret: &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key"},
		types:  []*vaultv1.SecretType{heartbeatCapableType()},
	}
	got := queryHeartbeatBlockedReason(t, fv)
	if got == nil || *got != "no target" {
		t.Fatalf("heartbeatBlockedReason = %v, want \"no target\"", got)
	}
}

func TestHeartbeatBlockedReasonNoConnection(t *testing.T) {
	fv := &fakeHeartbeatVault{
		secret:  &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key", TargetId: "t1"},
		types:   []*vaultv1.SecretType{heartbeatCapableType()},
		targets: []*vaultv1.Target{{Id: "t1", Name: "app01"}},
	}
	got := queryHeartbeatBlockedReason(t, fv)
	if got == nil || *got != "no connection" {
		t.Fatalf("heartbeatBlockedReason = %v, want \"no connection\"", got)
	}
}

func TestHeartbeatBlockedReasonNoPinnedHostKey(t *testing.T) {
	fv := &fakeHeartbeatVault{
		secret:  &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key", TargetId: "t1"},
		types:   []*vaultv1.SecretType{heartbeatCapableType()},
		targets: []*vaultv1.Target{{Id: "t1", Name: "app01", ConnectionId: "conn-ssh"}},
	}
	got := queryHeartbeatBlockedReason(t, fv)
	if got == nil || *got != "no pinned host key" {
		t.Fatalf("heartbeatBlockedReason = %v, want \"no pinned host key\"", got)
	}
}

func TestHeartbeatBlockedReasonEmptyWhenReady(t *testing.T) {
	fv := &fakeHeartbeatVault{
		secret: &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key", TargetId: "t1"},
		types:  []*vaultv1.SecretType{heartbeatCapableType()},
		targets: []*vaultv1.Target{
			{Id: "t1", Name: "app01", ConnectionId: "conn-ssh", SshHostKeys: []string{"ssh-ed25519 AAAA"}},
		},
	}
	got := queryHeartbeatBlockedReason(t, fv)
	if got != nil {
		t.Fatalf("heartbeatBlockedReason = %v, want nil (ready)", *got)
	}
}

func TestHeartbeatBlockedReasonEmptyWhenOptedOut(t *testing.T) {
	fv := &fakeHeartbeatVault{
		secret: &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key", HeartbeatOptOut: true},
		types:  []*vaultv1.SecretType{heartbeatCapableType()},
	}
	got := queryHeartbeatBlockedReason(t, fv)
	if got != nil {
		t.Fatalf("heartbeatBlockedReason = %v, want nil (opted out is a choice, not a block)", *got)
	}
}

func TestHeartbeatBlockedReasonEmptyWhenTypeHasNoHeartbeat(t *testing.T) {
	fv := &fakeHeartbeatVault{
		secret: &vaultv1.Secret{Id: "s1", TypeId: "type-password"},
		types:  []*vaultv1.SecretType{{Id: "type-password", Name: "Password", Heartbeat: false}},
	}
	got := queryHeartbeatBlockedReason(t, fv)
	if got != nil {
		t.Fatalf("heartbeatBlockedReason = %v, want nil (type isn't heartbeat-capable)", *got)
	}
}
