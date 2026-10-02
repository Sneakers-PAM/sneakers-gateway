// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

func TestLogin_KratosBackend_AdoptsFederatedUserAndStoresSession(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-42"}}
	h := &Handler{
		Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour,
		Auth: NewKratosClient(kratos.URL, kratos.URL), Backend: backendKratos,
	}

	body, _ := json.Marshal(map[string]string{"username": cfg.email, "password": cfg.goodPassword})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.adoptReq == nil || fid.adoptReq.GetKeycloakSubject() != cfg.identityID || fid.adoptReq.GetEmail() != cfg.email {
		t.Fatalf("adopt request wrong: %+v", fid.adoptReq)
	}
	// Kratos never supplies a username/name; adoption must not invent one.
	if fid.adoptReq.GetKeycloakUsername() != "" || fid.adoptReq.GetName() != "" {
		t.Fatalf("kratos adopt request should carry no username/name, got %+v", fid.adoptReq)
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			sid = c.Value
		}
	}
	sess, ok, _ := h.Store.Get(context.Background(), sid)
	if !ok || sess.UserID != "usr-42" || sess.KeycloakSubject != cfg.identityID {
		t.Fatalf("session not stored with identity id/subject: %+v ok=%v", sess, ok)
	}
}

func TestLogin_KratosBackend_WrongPasswordIs401(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	h := &Handler{Store: NewMemStore(time.Hour), Identity: &fakeIdentity{}, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL), Backend: backendKratos}

	body, _ := json.Marshal(map[string]string{"username": cfg.email, "password": "wrong"})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d body=%s", rec.Code, rec.Body)
	}
}

func TestResolveSessionActor_KratosBackend_TrustsStoredSubjectWithoutJWTVerify(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User: &identityv1.User{Id: "usr-42"}, Roles: []string{"user"},
	}}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour, Backend: backendKratos}
	// AccessToken is an OPAQUE Kratos session_token — NOT a JWT. If
	// resolveSessionActor tried to JWKS-verify it (the Keycloak path's
	// behavior), this would fail; under Backend=kratos it must not even try.
	sess := Session{AccessToken: "opaque-session-token", ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf-1", UserID: "usr-42", KeycloakSubject: "identity-1"}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	ran := false
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rec := httptest.NewRecorder()
	h.SessionActor(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !ran {
		t.Fatalf("expected authed pass-through 200, got %d ran=%v body=%s", rec.Code, ran, rec.Body)
	}
	if fid.resolveReq == nil || fid.resolveReq.GetKeycloakSubject() != "identity-1" {
		t.Fatalf("ResolveUserContext not called with the stored subject: %+v", fid.resolveReq)
	}
}

func TestResolveSessionActor_KratosBackend_RefreshUpdatesSubjectAndExpiry(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour, Backend: backendKratos, Auth: NewKratosClient(kratos.URL, kratos.URL)}
	// ExpiresAt is inside the 30s refresh window — resolveSessionActor must
	// call auth().Refresh(ctx, backendToken(sess)) == Refresh(ctx, AccessToken).
	sess := Session{AccessToken: cfg.sessionToken, ExpiresAt: time.Now().Add(10 * time.Second), CSRFToken: "csrf-1", UserID: "usr-42", KeycloakSubject: cfg.identityID}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rec := httptest.NewRecorder()
	h.SessionActor(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body)
	}
	refreshed, ok, _ := h.Store.Get(context.Background(), "sid1")
	if !ok || time.Until(refreshed.ExpiresAt) < 30*time.Second {
		t.Fatalf("expected ExpiresAt to be pushed out by the whoami refresh, got %+v", refreshed)
	}
}
