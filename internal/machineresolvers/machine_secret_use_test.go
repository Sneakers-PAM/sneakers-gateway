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
	"google.golang.org/protobuf/proto"
)

type useVault struct {
	vaultv1.VaultServiceClient

	lastPrepare *vaultv1.PrepareSecretUseRequest
	lastGet     *vaultv1.GetSecretUseRequest
	lastRedeem  *vaultv1.RedeemSecretUseRequest
	redeemErr   error
}

var preparedUse = &vaultv1.SecretUse{
	Id: "use-1", SecretId: "s1", SecretName: "router-admin", FieldKey: "password",
	Argv: []string{"ssh", "admin@router-01"}, State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, ExpiresAtUnix: 1790000600,
}

func (f *useVault) PrepareSecretUse(_ context.Context, in *vaultv1.PrepareSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.PrepareSecretUseResponse, error) {
	f.lastPrepare = in
	return &vaultv1.PrepareSecretUseResponse{Use: preparedUse}, nil
}

func (f *useVault) GetSecretUse(_ context.Context, in *vaultv1.GetSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretUseResponse, error) {
	f.lastGet = in
	return &vaultv1.GetSecretUseResponse{Use: preparedUse}, nil
}

func (f *useVault) RedeemSecretUse(_ context.Context, in *vaultv1.RedeemSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.RedeemSecretUseResponse, error) {
	f.lastRedeem = in
	if f.redeemErr != nil {
		return nil, f.redeemErr
	}
	used := proto.Clone(preparedUse).(*vaultv1.SecretUse)
	used.State = vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED
	return &vaultv1.RedeemSecretUseResponse{Use: used, Value: "s3cret"}, nil
}

func newUseClient(fv *useVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, PublicURL: "https://sneakers.example.org"}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", []string{"Infrastructure"})))
	}))
}

func TestPrepareSecretUseForwardsTheTokenAndReturnsTheApprovalPage(t *testing.T) {
	fv := &useVault{}
	var resp struct {
		PrepareSecretUse struct {
			ID, SecretName, State, ApprovalURL string
			Argv                               []string
		}
	}
	newUseClient(fv).MustPost(`mutation { prepareSecretUse(secretId:"s1", fieldKey:"password", argv:["ssh","admin@router-01"], clientLabel:"laptop") { id secretName state approvalUrl argv } }`, &resp)

	r := fv.lastPrepare
	if r.GetActor().GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN || r.GetActor().GetTokenId() != "utok-1" ||
		r.GetSecretId() != "s1" || r.GetFieldKey() != "password" || len(r.GetArgv()) != 2 || r.GetClientLabel() != "laptop" {
		t.Fatalf("prepare request = %+v", r)
	}
	got := resp.PrepareSecretUse
	if got.ID != "use-1" || got.State != "PENDING" || got.ApprovalURL != "https://sneakers.example.org/approvals" || got.SecretName != "router-admin" {
		t.Fatalf("prepared use = %+v", got)
	}
}

func TestSecretUsePollsTheState(t *testing.T) {
	fv := &useVault{}
	var resp struct{ SecretUse struct{ State string } }
	newUseClient(fv).MustPost(`query { secretUse(id:"use-1") { state } }`, &resp)
	if fv.lastGet.GetUseId() != "use-1" || fv.lastGet.GetActor().GetTokenId() != "utok-1" || resp.SecretUse.State != "PENDING" {
		t.Fatalf("get = %+v resp = %+v", fv.lastGet, resp)
	}
}

func TestRedeemSecretUseReturnsTheValueAndTheBoundCommand(t *testing.T) {
	fv := &useVault{}
	var resp struct {
		RedeemSecretUse struct {
			Value string
			Use   struct {
				State string
				Argv  []string
			}
		}
	}
	newUseClient(fv).MustPost(`mutation { redeemSecretUse(id:"use-1") { value use { state argv } } }`, &resp)
	if fv.lastRedeem.GetActor().GetTokenId() != "utok-1" || resp.RedeemSecretUse.Value != "s3cret" || resp.RedeemSecretUse.Use.State != "REDEEMED" {
		t.Fatalf("redeem = %+v resp = %+v", fv.lastRedeem, resp)
	}
}

func TestRedeemSecretUsePassesVaultsRefusalThrough(t *testing.T) {
	fv := &useVault{redeemErr: status.Error(codes.FailedPrecondition, "secret use is SECRET_USE_STATE_PENDING")}
	var resp map[string]any
	if err := newUseClient(fv).Post(`mutation { redeemSecretUse(id:"use-1") { value } }`, &resp); err == nil {
		t.Fatal("an unapproved use must not redeem")
	}
}
