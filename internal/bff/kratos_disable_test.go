// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

func hasSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName && c.Value != "" {
			return true
		}
	}
	return false
}

func TestLogin_DisabledUserGetsNoSession(t *testing.T) {
	var submitted string
	kratos := identifierKratos(t, "ada@example.org", "pw", &submitted)
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-ada", DisabledAtUnix: 1790000000}}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL)}

	rec := postLogin(h, "ada@example.org", "pw")
	if rec.Code != http.StatusForbidden || hasSessionCookie(rec) {
		t.Fatalf("disabled user: status=%d cookie=%v body=%s", rec.Code, hasSessionCookie(rec), rec.Body)
	}
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["error"] != "account_disabled" {
		t.Fatalf("error = %q, want account_disabled", out["error"])
	}
}

func TestSessionActor_DisabledUserIsSignedOutOnTheNextRequest(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User: &identityv1.User{Id: "usr-ada", DisabledAtUnix: 1790000000},
	}}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour}
	sess := Session{AccessToken: "opaque", ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf-1", UserID: "usr-ada", Subject: "kid-ada", MFAVerified: true}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	ran := false
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rec := httptest.NewRecorder()
	h.SessionActor(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })).ServeHTTP(rec, req)

	if ran || rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled user's session: handler ran=%v status=%d", ran, rec.Code)
	}
	if _, ok, _ := h.Store.Get(context.Background(), "sid1"); ok {
		t.Fatal("a disabled user's session must be deleted")
	}
}
