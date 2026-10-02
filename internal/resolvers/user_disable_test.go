// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc"
)

var lastSetDisabledReq *identityv1.SetUserDisabledRequest

func (f *fakeIdentity) SetUserDisabled(_ context.Context, in *identityv1.SetUserDisabledRequest, _ ...grpc.CallOption) (*identityv1.SetUserDisabledResponse, error) {
	lastSetDisabledReq = in
	var at int64
	if in.GetDisabled() {
		at = 1790000000
	}
	return &identityv1.SetUserDisabledResponse{User: &identityv1.User{Id: in.GetUserId(), Name: "Ada", DisabledAtUnix: at}}, nil
}

func TestSetUserDisabledRequiresSiteAdmin(t *testing.T) {
	lastSetDisabledReq = nil
	c := newIdentityClient(&fakeIdentity{}, "user-plain", false)
	var resp map[string]any
	if err := c.Post(`mutation { setUserDisabled(userId:"u-ada", disabled:true) { id } }`, &resp); err == nil {
		t.Fatal("a non-site-admin must not disable users")
	}
	if lastSetDisabledReq != nil {
		t.Fatal("identity must not be called for a non-site-admin")
	}
}

func TestSetUserDisabledForwardsAndReportsTheState(t *testing.T) {
	lastSetDisabledReq = nil
	c := newIdentityClient(&fakeIdentity{}, "user-admin", true)
	var resp struct {
		SetUserDisabled struct {
			ID       string
			Disabled bool
		}
	}
	c.MustPost(`mutation { setUserDisabled(userId:"u-ada", disabled:true) { id disabled } }`, &resp)
	if lastSetDisabledReq.GetUserId() != "u-ada" || !lastSetDisabledReq.GetDisabled() {
		t.Fatalf("request = %+v", lastSetDisabledReq)
	}
	if resp.SetUserDisabled.ID != "u-ada" || !resp.SetUserDisabled.Disabled {
		t.Fatalf("response = %+v", resp.SetUserDisabled)
	}
}

func TestSetUserDisabledRefusesTheCallersOwnAccount(t *testing.T) {
	lastSetDisabledReq = nil
	c := newIdentityClient(&fakeIdentity{}, "user-admin", true)
	var resp map[string]any
	if err := c.Post(`mutation { setUserDisabled(userId:"user-admin", disabled:true) { id } }`, &resp); err == nil {
		t.Fatal("an admin must not be able to lock themselves out")
	}
	if lastSetDisabledReq != nil {
		t.Fatal("identity must not be called for a self-disable")
	}
}
