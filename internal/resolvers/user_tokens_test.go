// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc"
)

var (
	lastListUserTokensReq  *identityv1.ListUserTokensRequest
	lastRevokeUserTokenReq *identityv1.RevokeUserTokenRequest
)

func (f *fakeIdentity) ListUserTokens(_ context.Context, in *identityv1.ListUserTokensRequest, _ ...grpc.CallOption) (*identityv1.ListUserTokensResponse, error) {
	lastListUserTokensReq = in
	return &identityv1.ListUserTokensResponse{Tokens: []*identityv1.UserToken{{
		Id: "utok-1", UserId: in.GetUserId(), Label: "laptop", ClientName: "Example CLI",
		CreatedAtUnix: 1790000000, LastUsedAtUnix: 1790000100,
	}}}, nil
}

func (f *fakeIdentity) RevokeUserToken(_ context.Context, in *identityv1.RevokeUserTokenRequest, _ ...grpc.CallOption) (*identityv1.RevokeUserTokenResponse, error) {
	lastRevokeUserTokenReq = in
	return &identityv1.RevokeUserTokenResponse{Meta: &identityv1.UserToken{Id: in.GetId(), UserId: in.GetUserId(), RevokedAtUnix: 1790000200}}, nil
}

func resetTokenStubs() { lastListUserTokensReq, lastRevokeUserTokenReq = nil, nil }

func TestMyTokensListsOnlyTheCallersTokens(t *testing.T) {
	resetTokenStubs()
	c := newIdentityClient(&fakeIdentity{}, "u-ada", false)
	var resp struct {
		MyTokens []struct {
			ID, Label, ClientName string
			LastUsedAtUnix        int64
			RevokedAtUnix         int64
		}
	}
	c.MustPost(`query { myTokens { id label clientName lastUsedAtUnix revokedAtUnix } }`, &resp)
	if lastListUserTokensReq.GetUserId() != "u-ada" {
		t.Fatalf("listed tokens of %q, want the caller u-ada", lastListUserTokensReq.GetUserId())
	}
	if len(resp.MyTokens) != 1 || resp.MyTokens[0].ID != "utok-1" || resp.MyTokens[0].Label != "laptop" ||
		resp.MyTokens[0].LastUsedAtUnix != 1790000100 || resp.MyTokens[0].RevokedAtUnix != 0 {
		t.Fatalf("myTokens = %+v", resp.MyTokens)
	}
}

func TestRevokeMyTokenRevokesAsTheCaller(t *testing.T) {
	resetTokenStubs()
	c := newIdentityClient(&fakeIdentity{}, "u-ada", false)
	var resp struct{ RevokeMyToken struct{ RevokedAtUnix int64 } }
	c.MustPost(`mutation { revokeMyToken(id:"utok-1") { revokedAtUnix } }`, &resp)
	if lastRevokeUserTokenReq.GetId() != "utok-1" || lastRevokeUserTokenReq.GetUserId() != "u-ada" || resp.RevokeMyToken.RevokedAtUnix == 0 {
		t.Fatalf("revoke = %+v, resp = %+v", lastRevokeUserTokenReq, resp)
	}
}

func TestAdminTokenOpsRequireSiteAdmin(t *testing.T) {
	resetTokenStubs()
	c := newIdentityClient(&fakeIdentity{}, "u-ada", false)
	var resp map[string]any
	if err := c.Post(`query { userTokens(userId:"u-bob") { id } }`, &resp); err == nil {
		t.Fatal("a non-admin must not list another user's tokens")
	}
	if err := c.Post(`mutation { revokeUserToken(userId:"u-bob", id:"utok-9") { id } }`, &resp); err == nil {
		t.Fatal("a non-admin must not revoke another user's token")
	}
	if lastListUserTokensReq != nil || lastRevokeUserTokenReq != nil {
		t.Fatal("identity must not be called for a non-admin")
	}
}

func TestAdminCanListAndRevokeAUsersTokens(t *testing.T) {
	resetTokenStubs()
	c := newIdentityClient(&fakeIdentity{}, "user-admin", true)
	var list struct{ UserTokens []struct{ ID string } }
	c.MustPost(`query { userTokens(userId:"u-bob") { id } }`, &list)
	if lastListUserTokensReq.GetUserId() != "u-bob" || len(list.UserTokens) != 1 {
		t.Fatalf("admin list = %+v (req %+v)", list, lastListUserTokensReq)
	}
	var rev struct{ RevokeUserToken struct{ ID string } }
	c.MustPost(`mutation { revokeUserToken(userId:"u-bob", id:"utok-9") { id } }`, &rev)
	if lastRevokeUserTokenReq.GetUserId() != "u-bob" || lastRevokeUserTokenReq.GetId() != "utok-9" {
		t.Fatalf("admin revoke req = %+v", lastRevokeUserTokenReq)
	}
}
