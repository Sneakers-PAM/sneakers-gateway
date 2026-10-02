// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsRequest(t *testing.T, p *corsPolicy, method, origin string) *httptest.ResponseRecorder {
	t.Helper()
	called := false
	h := p.wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(method, "/graphql", nil)
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if method != http.MethodOptions && !called {
		t.Fatalf("%s from %q: the wrapped handler did not run", method, origin)
	}
	return rec
}

func TestCORSAllowListedOriginGetsCredentialedHeaders(t *testing.T) {
	p, err := newCORSPolicy("real", "https://ui.example.org, https://admin.example.org:8443")
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"https://ui.example.org", "https://admin.example.org:8443"} {
		rec := corsRequest(t, p, http.MethodPost, origin)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("Allow-Origin for %q = %q", origin, got)
		}
		if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
			t.Fatalf("Allow-Credentials for %q = %q", origin, got)
		}
		if got := rec.Header().Get("Vary"); got != "Origin" {
			t.Fatalf("Vary = %q", got)
		}
	}
}

func TestCORSUnknownOriginGetsNoHeaders(t *testing.T) {
	p, err := newCORSPolicy("real", "https://ui.example.org")
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"https://evil.example.net", "http://ui.example.org", "https://ui.example.org:444", "null"} {
		rec := corsRequest(t, p, http.MethodPost, origin)
		for _, h := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"} {
			if got := rec.Header().Get(h); got != "" {
				t.Fatalf("%s for %q = %q, want none", h, origin, got)
			}
		}
		if got := rec.Header().Get("Vary"); got != "Origin" {
			t.Fatalf("Vary for %q = %q", origin, got)
		}
	}
}

func TestCORSUnknownOriginPreflightRefused(t *testing.T) {
	p, err := newCORSPolicy("real", "https://ui.example.org")
	if err != nil {
		t.Fatal(err)
	}
	rec := corsRequest(t, p, http.MethodOptions, "https://evil.example.net")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "" {
		t.Fatalf("Allow-Methods = %q, want none", got)
	}
}

func TestCORSAllowedPreflight(t *testing.T) {
	p, err := newCORSPolicy("real", "https://ui.example.org")
	if err != nil {
		t.Fatal(err)
	}
	rec := corsRequest(t, p, http.MethodOptions, "https://ui.example.org")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type,X-Dev-User,X-CSRF-Token,Authorization" {
		t.Fatalf("Allow-Headers = %q", got)
	}
}

func TestCORSNoOriginGetsNoHeaders(t *testing.T) {
	p, err := newCORSPolicy("real", "https://ui.example.org")
	if err != nil {
		t.Fatal(err)
	}
	rec := corsRequest(t, p, http.MethodPost, "")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q, want none", got)
	}
}

func TestCORSRealModeWithoutListAllowsNoCrossOrigin(t *testing.T) {
	p, err := newCORSPolicy("real", "")
	if err != nil {
		t.Fatal(err)
	}
	rec := corsRequest(t, p, http.MethodPost, "https://ui.example.org")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q, want none", got)
	}
}

func TestCORSNoauthWithoutListReflectsForLocalDev(t *testing.T) {
	p, err := newCORSPolicy("noauth", "")
	if err != nil {
		t.Fatal(err)
	}
	rec := corsRequest(t, p, http.MethodPost, "http://localhost:5173")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("Allow-Origin = %q", got)
	}
}

func TestCORSNoauthWithListUsesList(t *testing.T) {
	p, err := newCORSPolicy("noauth", "http://localhost:5173")
	if err != nil {
		t.Fatal(err)
	}
	rec := corsRequest(t, p, http.MethodPost, "http://localhost:3000")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("Allow-Origin = %q, want none", got)
	}
}

func TestCORSBadEntriesRefused(t *testing.T) {
	for _, raw := range []string{
		"*",
		"https://ui.example.org,*",
		"ui.example.org",
		"ftp://ui.example.org",
		"https://ui.example.org/app",
		"https://",
		"https://ui.example.org?x=1",
		"https://user@ui.example.org",
	} {
		if _, err := newCORSPolicy("real", raw); err == nil {
			t.Fatalf("newCORSPolicy(%q): want an error", raw)
		}
	}
}

func TestCORSTrailingSlashAndCaseNormalised(t *testing.T) {
	p, err := newCORSPolicy("real", "HTTPS://UI.Example.org/")
	if err != nil {
		t.Fatal(err)
	}
	rec := corsRequest(t, p, http.MethodPost, "https://ui.example.org")
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example.org" {
		t.Fatalf("Allow-Origin = %q", got)
	}
}
