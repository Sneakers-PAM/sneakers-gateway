// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

// In no-auth dev the X-Dev-User persona stands in for a web session, so its
// vault calls carry a session reference like a real login's.
func TestNoAuthDevPersonaHasASessionRef(t *testing.T) {
	for user, want := range map[string]string{"u-dev": "dev:u-dev", "": ""} {
		var got string
		h := withActor(nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = resolvers.SessionRef(r.Context())
		}))
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		if user != "" {
			req.Header.Set("X-Dev-User", user)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		if got != want {
			t.Fatalf("user %q: session ref = %q, want %q", user, got, want)
		}
	}
}
