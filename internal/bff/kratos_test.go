// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
)

// kratosLoginServerConfig tunes the fake Kratos login API this file's tests
// drive: GET .../login/api then POST .../login?flow=...
type kratosLoginServerConfig struct {
	goodPassword string
	sessionToken string
	identityID   string
	email        string
	expiresAt    time.Time
	whoamiActive bool
}

func newKratosLoginServer(t *testing.T, cfg kratosLoginServerConfig) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/self-service/login/api", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "loginflow-1"})
	})
	mux.HandleFunc("/self-service/login", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("flow") != "loginflow-1" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var body struct {
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Password != cfg.goodPassword {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"session_token": cfg.sessionToken,
			"session": map[string]any{
				"active": true, "expires_at": cfg.expiresAt,
				"identity": map[string]any{"id": cfg.identityID, "traits": map[string]any{"email": cfg.email}},
			},
		})
	})
	mux.HandleFunc("/sessions/whoami", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+cfg.sessionToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !cfg.whoamiActive {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true, "expires_at": cfg.expiresAt,
			"identity": map[string]any{"id": cfg.identityID, "traits": map[string]any{"email": cfg.email}},
		})
	})
	mux.HandleFunc("/self-service/logout/api", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func defaultKratosLoginConfig() kratosLoginServerConfig {
	return kratosLoginServerConfig{
		goodPassword: "good", sessionToken: "sess-tok-1", identityID: "identity-1",
		email: "alice@example.org", expiresAt: time.Now().Add(time.Hour), whoamiActive: true,
	}
}

func TestKratosClient_VerifyPassword_Valid(t *testing.T) {
	srv := newKratosLoginServer(t, defaultKratosLoginConfig())
	c := NewKratosClient(srv.URL, srv.URL)

	ar, err := c.VerifyPassword(context.Background(), "alice@example.org", "good")
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if ar.AccessToken != "sess-tok-1" || ar.RefreshToken != "" || ar.Subject != "identity-1" || ar.Email != "alice@example.org" {
		t.Fatalf("wrong AuthResult: %+v", ar)
	}
}

func TestKratosClient_VerifyPassword_WrongPassword(t *testing.T) {
	srv := newKratosLoginServer(t, defaultKratosLoginConfig())
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.VerifyPassword(context.Background(), "alice@example.org", "wrong")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
	if _, coded := apperr.Code(err); coded {
		t.Fatal("a wrong password must never be a coded internal error")
	}
}

func TestKratosClient_VerifyPassword_Unreachable(t *testing.T) {
	c := NewKratosClient("http://127.0.0.1:0", "http://127.0.0.1:0")
	_, err := c.VerifyPassword(context.Background(), "alice@example.org", "good")
	code, coded := apperr.Code(err)
	if !coded || code != 2212 {
		t.Fatalf("expected coded 2212, got code=%d coded=%v err=%v", code, coded, err)
	}
}

func TestKratosClient_Refresh_ActiveSessionReturnsSameToken(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	srv := newKratosLoginServer(t, cfg)
	c := NewKratosClient(srv.URL, srv.URL)

	ar, err := c.Refresh(context.Background(), cfg.sessionToken)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if ar.AccessToken != cfg.sessionToken || ar.Subject != cfg.identityID {
		t.Fatalf("Refresh should return the SAME token + resolved identity, got %+v", ar)
	}
}

func TestKratosClient_Refresh_InactiveSessionFailsClosed(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	cfg.whoamiActive = false
	srv := newKratosLoginServer(t, cfg)
	c := NewKratosClient(srv.URL, srv.URL)

	_, err := c.Refresh(context.Background(), cfg.sessionToken)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for an inactive session, got %v", err)
	}
}

func TestKratosClient_Logout_BestEffort(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	srv := newKratosLoginServer(t, cfg)
	c := NewKratosClient(srv.URL, srv.URL)
	if err := c.Logout(context.Background(), cfg.sessionToken); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if err := c.Logout(context.Background(), ""); err != nil {
		t.Fatalf("Logout with empty token should be a no-op, got %v", err)
	}
}

// TestKratosClient_SatisfiesAuthClient is a compile-time proof.
func TestKratosClient_SatisfiesAuthClient(t *testing.T) {
	var _ authClient = (*KratosClient)(nil)
}
