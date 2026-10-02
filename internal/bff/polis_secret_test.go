// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The code exchange sends the configured client secret (Polis checks it against
// its CLIENT_SECRET_VERIFIER), not the development value.
func TestPolisClient_CodeExchangeSendsTheConfiguredSecret(t *testing.T) {
	var got string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.Form.Get("client_secret")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "bearer", "expires_in": 300})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := NewPolisClient(srv.URL, srv.URL, "sneakers", "example.org")
	c.ClientSecret = "verifier-from-a-secret"
	if _, err := c.CodeExchange(context.Background(), "code-1", "https://x/callback"); err != nil {
		t.Fatal(err)
	}
	if got != "verifier-from-a-secret" {
		t.Fatalf("client_secret = %q", got)
	}
}
