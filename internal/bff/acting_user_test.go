// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

// Removing your own factor names you as the acting user.
func TestMfaRemove_SendsTheActingUser(t *testing.T) {
	fid := &fakeIdentity{}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := enrolledSession(t, h, "usr-42")
	if rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, nil); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if got := fid.removeFactorReq.GetActingUserId(); got != "usr-42" {
		t.Fatalf("acting_user_id = %q", got)
	}
}

// An admin removing another user's factor is the acting user, not the target.
func TestMfaAdminRemoveTotp_SendsTheAdminAsActingUser(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User:  &identityv1.User{Id: "usr-admin"},
		Roles: []string{"user", "site-admin"},
	}}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := adminSession(t, h, "usr-admin", "sub-admin-1")
	if rec := authedPost(h.MfaAdminRemoveTotp, "/auth/mfa/admin/remove-totp", sid, csrf, map[string]string{"userId": "usr-locked-out"}); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.removeFactorReq.GetUserId() != "usr-locked-out" || fid.removeFactorReq.GetActingUserId() != "usr-admin" {
		t.Fatalf("RemoveFactor = %+v", fid.removeFactorReq)
	}
}

func TestActorAttrs_MapsGroupIDs(t *testing.T) {
	got, err := actorAttrsFrom(&identityv1.ResolveUserContextResponse{
		User:       &identityv1.User{Id: "usr-42"},
		GroupNames: []string{"Ops", "Help Desk"},
		GroupIds:   []string{"g-ops", "g-help"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.groupIDs) != 2 || got.groupIDs[0] != "g-ops" || got.groupIDs[1] != "g-help" {
		t.Fatalf("groupIDs = %v", got.groupIDs)
	}
}

// The request gate puts the group ids on the vault actor, so a rule that names
// a group by id matches.
func TestSessionActor_CarriesGroupIDs(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User: &identityv1.User{Id: "usr-42"}, GroupNames: []string{"Ops"}, GroupIds: []string{"g-ops"},
	}}
	h := stepUpHandler(fid)
	seedSession(t, h, Session{AccessToken: "tok", UserID: "usr-42", Subject: "sub-1", CSRFToken: "csrf-1", MFAVerified: true})
	var ids []string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ids = resolvers.ActorGroupIDs(r.Context()) })
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid-1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	h.SessionActor(next).ServeHTTP(httptest.NewRecorder(), req)
	if len(ids) != 1 || ids[0] != "g-ops" {
		t.Fatalf("group ids on the context = %v", ids)
	}
}

func TestUserToken_CarriesGroupIDs(t *testing.T) {
	fid := &fakeIdentity{verifyUserTokenResp: &identityv1.VerifyUserTokenResponse{
		Valid: true, User: &identityv1.User{Id: "usr-42"}, TokenId: "ut-1", GroupNames: []string{"Ops"}, GroupIds: []string{"g-ops"},
	}}
	h := &Handler{Identity: fid}
	var actor *vaultv1.ActorContext
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { actor = resolvers.MachineActorOf(r.Context()) })
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer snk_u_example")
	h.MachineActor(next).ServeHTTP(httptest.NewRecorder(), req)
	if actor == nil || len(actor.GetGroupIds()) != 1 || actor.GetGroupIds()[0] != "g-ops" || len(actor.GetGroupNames()) != 1 {
		t.Fatalf("machine actor = %+v", actor)
	}
}
