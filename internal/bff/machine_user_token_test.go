// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

func (f *fakeIdentity) VerifyUserToken(_ context.Context, in *identityv1.VerifyUserTokenRequest, _ ...grpc.CallOption) (*identityv1.VerifyUserTokenResponse, error) {
	f.verifyUserTokenReq = in
	if f.verifyUserTokenResp != nil {
		return f.verifyUserTokenResp, nil
	}
	return &identityv1.VerifyUserTokenResponse{}, nil
}

func serveMachine(h *Handler, bearer string) (*vaultv1.ActorContext, bool, int) {
	var actor *vaultv1.ActorContext
	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		actor = resolvers.MachineActorOf(r.Context())
	})
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)
	return actor, ran, rec.Code
}

func TestMachineActor_UserTokenActsAsItsOwnerWithLiveGroups(t *testing.T) {
	fid := &fakeIdentity{verifyUserTokenResp: &identityv1.VerifyUserTokenResponse{
		Valid: true, TokenId: "utok-1",
		User:       &identityv1.User{Id: "u-ada", Roles: []string{"site-admin"}, IsRoot: true},
		GroupNames: []string{"Help Desk", "Infrastructure"},
	}}
	actor, ran, code := serveMachine(&Handler{Identity: fid}, "snk_u_abc")

	if !ran || code != http.StatusOK {
		t.Fatalf("ran=%v status=%d", ran, code)
	}
	if fid.verifyUserTokenReq.GetToken() != "snk_u_abc" || fid.verifyApiTokenReq != nil {
		t.Fatalf("user token must go to VerifyUserToken only (user=%v sa=%v)", fid.verifyUserTokenReq, fid.verifyApiTokenReq)
	}
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN || actor.GetUserId() != "u-ada" ||
		actor.GetTokenId() != "utok-1" || len(actor.GetGroupNames()) != 2 || actor.GetGroupNames()[0] != "Help Desk" {
		t.Fatalf("actor = %+v", actor)
	}
	if actor.GetIsSiteAdmin() || actor.GetIsRoot() {
		t.Fatalf("a user token must never carry admin or root authority: %+v", actor)
	}
}

func TestMachineActor_InvalidUserTokenIs401(t *testing.T) {
	fid := &fakeIdentity{}
	_, ran, code := serveMachine(&Handler{Identity: fid}, "snk_u_revoked")
	if ran || code != http.StatusUnauthorized {
		t.Fatalf("invalid user token: ran=%v status=%d", ran, code)
	}
}
