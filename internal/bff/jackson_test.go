// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestJacksonProvisioner_EnsureConnection_PostsSingleConnection(t *testing.T) {
	var gotForm url.Values
	var authHeader string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sso", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		_ = r.ParseForm()
		gotForm = r.Form
		authHeader = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"clientID":"cid-1","clientSecret":"csec-1"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p := NewJacksonProvisioner(srv.URL, "api-key-1", "sneakers", "example.org",
		"https://gw.example.org", "https://idp.example.org/metadata")
	if err := p.EnsureConnection(context.Background()); err != nil {
		t.Fatalf("EnsureConnection: %v", err)
	}
	if authHeader != "Api-Key api-key-1" {
		t.Fatalf("auth header = %q", authHeader)
	}
	if gotForm.Get("tenant") != "example.org" || gotForm.Get("product") != "sneakers" {
		t.Fatalf("tenant/product wrong: %v", gotForm)
	}
	if gotForm.Get("defaultRedirectUrl") != "https://gw.example.org/auth/sso/callback" {
		t.Fatalf("defaultRedirectUrl wrong: %q", gotForm.Get("defaultRedirectUrl"))
	}
	if gotForm.Get("metadataUrl") != "https://idp.example.org/metadata" {
		t.Fatalf("metadataUrl wrong: %q", gotForm.Get("metadataUrl"))
	}
}

func TestJacksonProvisioner_EnsureConnection_Non2xxIsCoded2215(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sso", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p := NewJacksonProvisioner(srv.URL, "k", "sneakers", "example.org", "https://gw", "https://idp/md")
	err := p.EnsureConnection(context.Background())
	if err == nil {
		t.Fatal("expected error on 500")
	}
}
