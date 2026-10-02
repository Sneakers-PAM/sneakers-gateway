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
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

var (
	totpOK          bool
	lastTotpReq     *identityv1.VerifyTotpRequest
	lastEmailOtpReq *identityv1.SendEmailOtpRequest
)

func (f *fakeIdentity) VerifyTotp(_ context.Context, in *identityv1.VerifyTotpRequest, _ ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error) {
	lastTotpReq = in
	return &identityv1.VerifyTotpResponse{Ok: totpOK}, nil
}

func (f *fakeIdentity) SendEmailOtp(_ context.Context, in *identityv1.SendEmailOtpRequest, _ ...grpc.CallOption) (*identityv1.SendEmailOtpResponse, error) {
	lastEmailOtpReq = in
	return &identityv1.SendEmailOtpResponse{}, nil
}

type useAdminVault struct {
	vaultv1.VaultServiceClient
	lastList     *vaultv1.ListPendingSecretUsesRequest
	lastDecide   *vaultv1.DecideSecretUseRequest
	lastCreate   *vaultv1.CreateUseGrantRequest
	lastRevoke   *vaultv1.RevokeUseGrantRequest
	lastApproval *vaultv1.SetSecretTokenApprovalRequest
}

func (f *useAdminVault) ListPendingSecretUses(_ context.Context, in *vaultv1.ListPendingSecretUsesRequest, _ ...grpc.CallOption) (*vaultv1.ListPendingSecretUsesResponse, error) {
	f.lastList = in
	return &vaultv1.ListPendingSecretUsesResponse{Uses: []*vaultv1.SecretUse{{
		Id: "use-1", SecretName: "router-admin", FieldKey: "password", Argv: []string{"ssh", "admin@router-01"},
		ClientLabel: "laptop", State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, ExpiresAtUnix: 1790000600,
	}}}, nil
}

func (f *useAdminVault) DecideSecretUse(_ context.Context, in *vaultv1.DecideSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.DecideSecretUseResponse, error) {
	f.lastDecide = in
	state := vaultv1.SecretUseState_SECRET_USE_STATE_DENIED
	if in.GetApprove() {
		state = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
	}
	return &vaultv1.DecideSecretUseResponse{Use: &vaultv1.SecretUse{Id: in.GetUseId(), State: state}}, nil
}

func (f *useAdminVault) CreateUseGrant(_ context.Context, in *vaultv1.CreateUseGrantRequest, _ ...grpc.CallOption) (*vaultv1.CreateUseGrantResponse, error) {
	f.lastCreate = in
	g := in.GetGrant()
	g.Id = "g-1"
	return &vaultv1.CreateUseGrantResponse{Grant: g}, nil
}

func (f *useAdminVault) RevokeUseGrant(_ context.Context, in *vaultv1.RevokeUseGrantRequest, _ ...grpc.CallOption) (*vaultv1.RevokeUseGrantResponse, error) {
	f.lastRevoke = in
	return &vaultv1.RevokeUseGrantResponse{Grant: &vaultv1.UseGrant{Id: in.GetGrantId(), RevokedAtUnix: 1790000700}}, nil
}

func newUseAdminClient(fv *useAdminVault, actor string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Identity: &fakeIdentity{}}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActorInfo(WithActor(r.Context(), actor), false, false, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func TestPendingSecretUsesListsTheCallersUses(t *testing.T) {
	fv := &useAdminVault{}
	var resp struct {
		PendingSecretUses []struct {
			ID, SecretName, ClientLabel string
			Argv                        []string
		}
	}
	newUseAdminClient(fv, "u-ada").MustPost(`query { pendingSecretUses { id secretName clientLabel argv } }`, &resp)
	if fv.lastList.GetActor().GetUserId() != "u-ada" || len(resp.PendingSecretUses) != 1 || resp.PendingSecretUses[0].ClientLabel != "laptop" {
		t.Fatalf("list = %+v resp = %+v", fv.lastList, resp)
	}
}

func TestApprovingASecretUseNeedsAFreshSecondFactor(t *testing.T) {
	fv := &useAdminVault{}
	c := newUseAdminClient(fv, "u-ada")
	var resp map[string]any
	if err := c.Post(`mutation { decideSecretUse(id:"use-1", approve:true) { state } }`, &resp); err == nil || fv.lastDecide != nil {
		t.Fatal("approving without a second factor must be refused before vault is asked")
	}
	totpOK = false
	if err := c.Post(`mutation { decideSecretUse(id:"use-1", approve:true, factor:{kind:"totp", code:"000000"}) { state } }`, &resp); err == nil || fv.lastDecide != nil {
		t.Fatal("a wrong code must be refused before vault is asked")
	}
	totpOK = true
	var ok struct{ DecideSecretUse struct{ State string } }
	c.MustPost(`mutation { decideSecretUse(id:"use-1", approve:true, factor:{kind:"totp", code:"123456"}) { state } }`, &ok)
	if !fv.lastDecide.GetApprove() || fv.lastDecide.GetActor().GetUserId() != "u-ada" || lastTotpReq.GetUserId() != "u-ada" || ok.DecideSecretUse.State != "APPROVED" {
		t.Fatalf("decide = %+v totp = %+v resp = %+v", fv.lastDecide, lastTotpReq, ok)
	}
}

func TestDenyingASecretUseNeedsNoSecondFactor(t *testing.T) {
	fv := &useAdminVault{}
	var resp struct{ DecideSecretUse struct{ State string } }
	newUseAdminClient(fv, "u-ada").MustPost(`mutation { decideSecretUse(id:"use-1", approve:false) { state } }`, &resp)
	if fv.lastDecide.GetApprove() || resp.DecideSecretUse.State != "DENIED" {
		t.Fatalf("deny = %+v resp = %+v", fv.lastDecide, resp)
	}
}

func TestCreatingAUseGrantNeedsAFactorAndTheCallersOwnToken(t *testing.T) {
	fv := &useAdminVault{}
	c := newUseAdminClient(fv, "u-ada")
	totpOK = true
	var resp map[string]any
	input := `input:{tokenId:"utok-other", secretIds:["s1"], programs:[{program:"ssh", argPattern:"admin@router-*"}], expiresAtUnix:1790028800}`
	if err := c.Post(`mutation { createUseGrant(`+input+`, factor:{kind:"totp", code:"123456"}) { id } }`, &resp); err == nil || fv.lastCreate != nil {
		t.Fatal("a grant for a token the caller doesn't own must be refused")
	}
	own := `input:{tokenId:"utok-1", secretIds:["s1"], programs:[{program:"ssh", argPattern:"admin@router-*"}], expiresAtUnix:1790028800, maxUses:3}`
	totpOK = false
	if err := c.Post(`mutation { createUseGrant(`+own+`, factor:{kind:"totp", code:"000000"}) { id } }`, &resp); err == nil || fv.lastCreate != nil {
		t.Fatal("a grant needs a valid second factor")
	}
	totpOK = true
	var ok struct{ CreateUseGrant struct{ ID string } }
	c.MustPost(`mutation { createUseGrant(`+own+`, factor:{kind:"totp", code:"123456"}) { id } }`, &ok)
	g := fv.lastCreate.GetGrant()
	if fv.lastCreate.GetActor().GetUserId() != "u-ada" || g.GetTokenId() != "utok-1" || g.GetMaxUses() != 3 ||
		len(g.GetPrograms()) != 1 || g.GetPrograms()[0].GetArgPattern() != "admin@router-*" || ok.CreateUseGrant.ID != "g-1" {
		t.Fatalf("create = %+v resp = %+v", fv.lastCreate, ok)
	}
}

func TestRevokeUseGrantAndEmailCode(t *testing.T) {
	fv := &useAdminVault{}
	c := newUseAdminClient(fv, "u-ada")
	var rev struct{ RevokeUseGrant struct{ RevokedAtUnix int } }
	c.MustPost(`mutation { revokeUseGrant(id:"g-1") { revokedAtUnix } }`, &rev)
	if fv.lastRevoke.GetGrantId() != "g-1" || rev.RevokeUseGrant.RevokedAtUnix == 0 {
		t.Fatalf("revoke = %+v resp = %+v", fv.lastRevoke, rev)
	}
	var sent struct{ SendMfaEmailCode bool }
	c.MustPost(`mutation { sendMfaEmailCode }`, &sent)
	if !sent.SendMfaEmailCode || lastEmailOtpReq.GetUserId() != "u-ada" || lastEmailOtpReq.GetPurpose() != "login" {
		t.Fatalf("email code = %+v", lastEmailOtpReq)
	}
}
