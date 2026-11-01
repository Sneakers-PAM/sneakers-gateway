// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"net/http"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

// The flag follows the owner identity reports for this token, on every call.
func TestMachineActor_MarksATokenWhoseOwnerIsASiteAdmin(t *testing.T) {
	for name, tc := range map[string]struct {
		user *identityv1.User
		want bool
	}{
		"site-admin role": {&identityv1.User{Id: "u-ada", Roles: []string{"site-admin"}}, true},
		"admin role":      {&identityv1.User{Id: "u-ada", Roles: []string{"admin"}}, true},
		"root":            {&identityv1.User{Id: "u-ada", IsRoot: true}, true},
		"plain user":      {&identityv1.User{Id: "u-bob", Roles: []string{"user"}}, false},
		"recovery only":   {&identityv1.User{Id: "u-bob", Roles: []string{"recovery"}}, false},
		"no roles":        {&identityv1.User{Id: "u-bob"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			fid := &fakeIdentity{verifyUserTokenResp: &identityv1.VerifyUserTokenResponse{Valid: true, TokenId: "utok-1", User: tc.user}}
			actor, ran, code := serveMachine(&Handler{Identity: fid}, "snk_u_abc")
			if !ran || code != http.StatusOK {
				t.Fatalf("ran=%v status=%d", ran, code)
			}
			if actor.GetTokenOwnerIsSiteAdmin() != tc.want {
				t.Fatalf("token_owner_is_site_admin = %v, want %v", actor.GetTokenOwnerIsSiteAdmin(), tc.want)
			}
			if actor.GetIsSiteAdmin() || actor.GetIsRoot() {
				t.Fatalf("a user token must never carry admin or root authority: %+v", actor)
			}
		})
	}
}

// The kind comes from what identity recorded for the token; nothing the
// client sends can set it.
func TestMachineActor_CarriesTheTokensClientKind(t *testing.T) {
	for _, kind := range []string{ClientKindMCP, "cli", ""} {
		fid := &fakeIdentity{verifyUserTokenResp: &identityv1.VerifyUserTokenResponse{
			Valid: true, TokenId: "utok-1", ClientKind: kind, User: &identityv1.User{Id: "u-ada"},
		}}
		actor, ran, _ := serveMachine(&Handler{Identity: fid}, "snk_u_abc")
		if !ran || actor.GetTokenClientKind() != kind {
			t.Fatalf("kind %q: ran=%v actor=%+v", kind, ran, actor)
		}
	}
}
