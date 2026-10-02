// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	apperr "github.com/Bugs5382/go-apperr"
)

func newPolisServer(t *testing.T, goodCode, accessToken, email string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != goodCode || r.Form.Get("grant_type") != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": accessToken, "token_type": "bearer", "expires_in": 300})
	})
	mux.HandleFunc("/api/oauth/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+accessToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "idp-1", "email": email, "firstName": "Ada", "lastName": "Lovelace"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestPolisClient_AuthorizeURL_SingleTenantProduct(t *testing.T) {
	c := NewPolisClient("https://sneakers.example.org/sso", "http://sneakers-polis:5225", "sneakers", "example.org")
	got := c.AuthorizeURL("https://sneakers.example.org/auth/sso/callback", "state-xyz")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !strings.HasPrefix(got, "https://sneakers.example.org/sso/api/oauth/authorize?") {
		t.Fatalf("wrong base: %s", got)
	}
	q := u.Query()
	if q.Get("response_type") != "code" || q.Get("scope") != "openid" {
		t.Fatalf("wrong oauth params: %v", q)
	}
	if q.Get("product") != "sneakers" || q.Get("tenant") != "example.org" {
		t.Fatalf("tenant/product not baked in: %v", q)
	}
	if q.Get("state") != "state-xyz" || q.Get("redirect_uri") != "https://sneakers.example.org/auth/sso/callback" {
		t.Fatalf("wrong state/redirect: %v", q)
	}
}

func TestPolisClient_CodeExchange_And_UserInfo(t *testing.T) {
	srv := newPolisServer(t, "code-1", "polis-at-1", "ada@example.org")
	c := NewPolisClient(srv.URL, srv.URL, "sneakers", "example.org")

	tok, err := c.CodeExchange(context.Background(), "code-1", "https://x/callback")
	if err != nil {
		t.Fatalf("CodeExchange: %v", err)
	}
	if tok.AccessToken != "polis-at-1" {
		t.Fatalf("wrong token: %+v", tok)
	}
	prof, err := c.UserInfo(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if prof.Email != "ada@example.org" || prof.FirstName != "Ada" {
		t.Fatalf("wrong profile: %+v", prof)
	}
}

func TestPolisClient_CodeExchange_BadCodeIsCoded2216(t *testing.T) {
	srv := newPolisServer(t, "code-1", "polis-at-1", "ada@example.org")
	c := NewPolisClient(srv.URL, srv.URL, "sneakers", "example.org")

	_, err := c.CodeExchange(context.Background(), "wrong-code", "https://x/callback")
	code, ok := apperr.Code(err)
	if !ok || code != 2216 {
		t.Fatalf("expected coded 2216, got code=%d ok=%v err=%v", code, ok, err)
	}
}

func TestPolisClient_UserInfo_MissingEmailIsCoded2217(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "idp-1", "email": ""})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := NewPolisClient(srv.URL, srv.URL, "sneakers", "example.org")

	_, err := c.UserInfo(context.Background(), "anything")
	code, ok := apperr.Code(err)
	if !ok || code != 2217 {
		t.Fatalf("expected coded 2217, got code=%d ok=%v err=%v", code, ok, err)
	}
}
