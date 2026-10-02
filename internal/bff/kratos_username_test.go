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

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc"
)

func (f *fakeIdentity) SearchUsers(_ context.Context, in *identityv1.SearchUsersRequest, _ ...grpc.CallOption) (*identityv1.SearchUsersResponse, error) {
	f.searchReq = in
	return &identityv1.SearchUsersResponse{Users: f.searchUsers}, nil
}

// identifierKratos accepts one email/password pair and records the identifier
// each login attempt submitted.
func identifierKratos(t *testing.T, email, password string, got *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/self-service/login/api", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "flow-1"})
	})
	mux.HandleFunc("/self-service/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Identifier, Password string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		*got = body.Identifier
		if body.Identifier != email || body.Password != password {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session_token": "tok-1",
			"session": map[string]any{
				"active": true, "expires_at": time.Now().Add(time.Hour),
				"identity": map[string]any{"id": "kid-ada", "traits": map[string]any{"email": email}},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func postLogin(h *Handler, username, password string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	return rec
}

// Kratos identifies users by email; people who sign in with their username
// must still be able to sign in.
func TestLogin_KratosBackend_UsernameIsResolvedToTheUsersEmail(t *testing.T) {
	var submitted string
	kratos := identifierKratos(t, "ada@example.org", "pw", &submitted)
	fid := &fakeIdentity{
		adoptUser:   &identityv1.User{Id: "usr-ada"},
		searchUsers: []*identityv1.User{{Id: "usr-adam", Username: "adam", Email: "adam@example.org"}, {Id: "usr-ada", Username: "ada", Email: "ada@example.org"}},
	}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL), Backend: backendKratos}

	rec := postLogin(h, "Ada", "pw")
	if rec.Code != http.StatusOK || submitted != "ada@example.org" {
		t.Fatalf("status=%d submitted identifier=%q body=%s", rec.Code, submitted, rec.Body)
	}
}

func TestLogin_KratosBackend_EmailIsSubmittedAsIs(t *testing.T) {
	var submitted string
	kratos := identifierKratos(t, "ada@example.org", "pw", &submitted)
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-ada"}}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL), Backend: backendKratos}

	if rec := postLogin(h, "ada@example.org", "pw"); rec.Code != http.StatusOK || submitted != "ada@example.org" {
		t.Fatalf("status=%d submitted=%q", rec.Code, submitted)
	}
	if fid.searchReq != nil {
		t.Fatal("an email identifier must not trigger a username lookup")
	}
}
