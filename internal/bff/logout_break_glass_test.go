// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

type logoutBreakGlass struct {
	get      *vaultv1.GetBreakGlassSessionRequest
	closeReq *vaultv1.CloseBreakGlassSessionRequest
	open     bool
}

func (f *logoutBreakGlass) GetBreakGlassSession(_ context.Context, in *vaultv1.GetBreakGlassSessionRequest, _ ...grpc.CallOption) (*vaultv1.GetBreakGlassSessionResponse, error) {
	f.get = in
	if !f.open {
		return &vaultv1.GetBreakGlassSessionResponse{}, nil
	}
	return &vaultv1.GetBreakGlassSessionResponse{Session: &vaultv1.BreakGlassSession{Id: "bgs-1"}}, nil
}

func (f *logoutBreakGlass) CloseBreakGlassSession(_ context.Context, in *vaultv1.CloseBreakGlassSessionRequest, _ ...grpc.CallOption) (*vaultv1.CloseBreakGlassSessionResponse, error) {
	f.closeReq = in
	return &vaultv1.CloseBreakGlassSessionResponse{Session: &vaultv1.BreakGlassSession{Id: in.GetSessionId()}}, nil
}

// Break-glass belongs to the web session that opened it: signing out ends it
// there and then, not when its timer runs out.
func TestLogoutEndsTheSessionsBreakGlass(t *testing.T) {
	for _, open := range []bool{true, false} {
		fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
			User: &identityv1.User{Id: "usr-admin"}, Roles: []string{"user", "site-admin"},
		}}
		h, _ := mfaLoginHandler(t, fid)
		bg := &logoutBreakGlass{open: open}
		h.BreakGlass = bg
		sid, csrf := adminSession(t, h, "usr-admin", "sub-admin-1")
		if rec := authedPost(h.Logout, "/auth/logout", sid, csrf, nil); rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		a := bg.get.GetActor()
		if a.GetUserId() != "usr-admin" || !a.GetIsSiteAdmin() || a.GetSessionRef() != sessionRefOf(sid) {
			t.Fatalf("open %v: get actor = %+v", open, a)
		}
		switch {
		case open && (bg.closeReq.GetSessionId() != "bgs-1" || bg.closeReq.GetActor().GetSessionRef() != sessionRefOf(sid)):
			t.Fatalf("close = %+v", bg.closeReq)
		case !open && bg.closeReq != nil:
			t.Fatalf("nothing open, yet close = %+v", bg.closeReq)
		}
		if _, ok, _ := h.Store.Get(context.Background(), sid); ok {
			t.Fatal("the web session must be gone")
		}
	}
}
