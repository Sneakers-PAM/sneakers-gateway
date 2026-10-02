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
	"google.golang.org/grpc"
)

// actingIdentity records the acting_user_id of each admin call it serves.
type actingIdentity struct {
	identityv1.IdentityServiceClient
	acting map[string]string
}

type actingRequest interface{ GetActingUserId() string }

func (f *actingIdentity) seen(rpc string, req actingRequest) {
	if f.acting == nil {
		f.acting = map[string]string{}
	}
	f.acting[rpc] = req.GetActingUserId()
}

func (f *actingIdentity) AddGroupMember(_ context.Context, in *identityv1.AddGroupMemberRequest, _ ...grpc.CallOption) (*identityv1.AddGroupMemberResponse, error) {
	f.seen("AddGroupMember", in)
	return &identityv1.AddGroupMemberResponse{}, nil
}

func (f *actingIdentity) RemoveGroupMember(_ context.Context, in *identityv1.RemoveGroupMemberRequest, _ ...grpc.CallOption) (*identityv1.RemoveGroupMemberResponse, error) {
	f.seen("RemoveGroupMember", in)
	return &identityv1.RemoveGroupMemberResponse{}, nil
}

func (f *actingIdentity) CreateGroup(_ context.Context, in *identityv1.CreateGroupRequest, _ ...grpc.CallOption) (*identityv1.CreateGroupResponse, error) {
	f.seen("CreateGroup", in)
	return &identityv1.CreateGroupResponse{Group: &identityv1.Group{Id: "g-1", Name: in.GetName()}}, nil
}

func (f *actingIdentity) CreateLocalUser(_ context.Context, in *identityv1.CreateLocalUserRequest, _ ...grpc.CallOption) (*identityv1.CreateLocalUserResponse, error) {
	f.seen("CreateLocalUser", in)
	return &identityv1.CreateLocalUserResponse{User: &identityv1.User{Id: "u-new"}}, nil
}

func (f *actingIdentity) SetUserRoles(_ context.Context, in *identityv1.SetUserRolesRequest, _ ...grpc.CallOption) (*identityv1.SetUserRolesResponse, error) {
	f.seen("SetUserRoles", in)
	return &identityv1.SetUserRolesResponse{User: &identityv1.User{Id: in.GetUserId()}}, nil
}

func (f *actingIdentity) SetUserDisabled(_ context.Context, in *identityv1.SetUserDisabledRequest, _ ...grpc.CallOption) (*identityv1.SetUserDisabledResponse, error) {
	f.seen("SetUserDisabled", in)
	return &identityv1.SetUserDisabledResponse{User: &identityv1.User{Id: in.GetUserId()}}, nil
}

func (f *actingIdentity) RevokeUserToken(_ context.Context, in *identityv1.RevokeUserTokenRequest, _ ...grpc.CallOption) (*identityv1.RevokeUserTokenResponse, error) {
	f.seen("RevokeUserToken:"+in.GetUserId(), in)
	return &identityv1.RevokeUserTokenResponse{Meta: &identityv1.UserToken{Id: in.GetId(), UserId: in.GetUserId()}}, nil
}

func (f *actingIdentity) UpdateUser(_ context.Context, in *identityv1.UpdateUserRequest, _ ...grpc.CallOption) (*identityv1.UpdateUserResponse, error) {
	f.seen("UpdateUser", in)
	return &identityv1.UpdateUserResponse{User: &identityv1.User{Id: in.GetUserId()}}, nil
}

func (f *actingIdentity) DisableServiceAccount(_ context.Context, in *identityv1.DisableServiceAccountRequest, _ ...grpc.CallOption) (*identityv1.DisableServiceAccountResponse, error) {
	f.seen("DisableServiceAccount", in)
	return &identityv1.DisableServiceAccountResponse{ServiceAccount: &identityv1.ServiceAccount{Id: in.GetId()}}, nil
}

func (f *actingIdentity) RevokeApiToken(_ context.Context, in *identityv1.RevokeApiTokenRequest, _ ...grpc.CallOption) (*identityv1.RevokeApiTokenResponse, error) {
	f.seen("RevokeApiToken", in)
	return &identityv1.RevokeApiTokenResponse{Meta: &identityv1.ApiToken{Id: in.GetId()}}, nil
}

// Every identity admin call names the signed-in user as acting_user_id, so the
// audit event identity records has an actor.
func TestIdentityAdminCallsSendTheActingUser(t *testing.T) {
	fid := &actingIdentity{}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: fid}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActorInfo(WithActor(r.Context(), "u-admin"), true, false, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	var resp map[string]any
	for _, m := range []string{
		`mutation { addGroupMember(userId: "u-2", groupId: "g-1") }`,
		`mutation { removeGroupMember(userId: "u-2", groupId: "g-1") }`,
		`mutation { createGroup(name: "Ops") { id } }`,
		`mutation { createLocalUser(username: "u", email: "u@example.org", name: "U", password: "p") { id } }`,
		`mutation { setUserRoles(userId: "u-2", roles: ["site-admin"]) { id } }`,
		`mutation { setUserDisabled(userId: "u-2", disabled: true) { id } }`,
		`mutation { revokeMyToken(id: "t-1") { id } }`,
		`mutation { revokeUserToken(userId: "u-2", id: "t-2") { id } }`,
		`mutation { updateUser(userId: "u-2", name: "U", email: "u@example.org", username: "u") { id } }`,
		`mutation { disableServiceAccount(id: "sa-1") { id } }`,
		`mutation { revokeApiToken(id: "at-1") { id } }`,
	} {
		c.MustPost(m, &resp)
	}
	for _, rpc := range []string{
		"AddGroupMember", "RemoveGroupMember", "CreateGroup", "CreateLocalUser", "SetUserRoles", "SetUserDisabled",
		"RevokeUserToken:u-admin", "RevokeUserToken:u-2", "UpdateUser", "DisableServiceAccount", "RevokeApiToken",
	} {
		got, ok := fid.acting[rpc]
		if !ok {
			t.Fatalf("%s was not called", rpc)
		}
		if got != "u-admin" {
			t.Fatalf("%s acting_user_id = %q, want u-admin", rpc, got)
		}
	}
}
