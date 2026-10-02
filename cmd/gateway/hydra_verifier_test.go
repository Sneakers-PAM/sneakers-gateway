// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

// newHydraVerifier must stay inert by construction even when a deployment
// sets HYDRA_ISSUER/HYDRA_JWKS_URL/HYDRA_AUDIENCE in every environment while
// hydra.enabled is false, so gating on issuer-presence alone would never
// actually be inert once deployed. Gating on HYDRA_ENABLED (default off)
// handles that: these tests prove BOTH the pure gating logic and the end-to-end effect on
// MachineActor, including that no JWKS network fetch is even attempted while
// disabled.

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/bff"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
)

func TestNewHydraVerifier_DisabledByDefaultEvenWithIssuerAndJWKSURLSet(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "http://sneakers-hydra:4444/")
	t.Setenv("HYDRA_JWKS_URL", "http://sneakers-hydra:4444/.well-known/jwks.json")
	t.Setenv("HYDRA_AUDIENCE", "sneakers-mcp")
	// HYDRA_ENABLED deliberately left unset — configured but not activated.

	verifier, issuer := newHydraVerifier(zerolog.Nop())
	if verifier != nil {
		t.Fatalf("expected a nil verifier while HYDRA_ENABLED is unset, even with HYDRA_ISSUER/HYDRA_JWKS_URL set, got %+v", verifier)
	}
	if issuer != "http://sneakers-hydra:4444/" {
		t.Fatalf("issuer = %q, want the configured HYDRA_ISSUER (still surfaced for the admin linkOidcClient mutation)", issuer)
	}
}

func TestNewHydraVerifier_EnabledBuildsAVerifier(t *testing.T) {
	t.Setenv("HYDRA_ISSUER", "http://sneakers-hydra:4444/")
	t.Setenv("HYDRA_JWKS_URL", "http://sneakers-hydra:4444/.well-known/jwks.json")
	t.Setenv("HYDRA_AUDIENCE", "sneakers-mcp")
	t.Setenv("HYDRA_ENABLED", "true")

	verifier, issuer := newHydraVerifier(zerolog.Nop())
	if verifier == nil {
		t.Fatal("expected a non-nil verifier once HYDRA_ENABLED=true")
	}
	if issuer != "http://sneakers-hydra:4444/" {
		t.Fatalf("issuer = %q, want http://sneakers-hydra:4444/", issuer)
	}
}

// TestNewHydraVerifier_EnabledWithEmptyIssuerFailsFast: HYDRA_ENABLED=
// true with an empty HYDRA_ISSUER must never silently build a verifier with
// issuer validation disabled (jwt.WithIssuer is only added when the issuer is
// non-empty) — it must Fatal at boot instead. This drives the REAL
// newHydraVerifier code path (not an extracted predicate) by swapping in
// zerolog.FatalExitFunc so the process doesn't actually exit mid-test-run.
func TestNewHydraVerifier_EnabledWithEmptyIssuerFailsFast(t *testing.T) {
	t.Setenv("HYDRA_ENABLED", "true")
	t.Setenv("HYDRA_ISSUER", "")
	t.Setenv("HYDRA_JWKS_URL", "http://sneakers-hydra:4444/.well-known/jwks.json")
	t.Setenv("HYDRA_AUDIENCE", "sneakers-mcp")

	origExit := zerolog.FatalExitFunc
	defer func() { zerolog.FatalExitFunc = origExit }()
	exited := false
	zerolog.FatalExitFunc = func() { exited = true; panic("newHydraVerifier: fatal exit (test double)") }

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected newHydraVerifier to Fatal when HYDRA_ENABLED=true and HYDRA_ISSUER is empty")
			}
		}()
		newHydraVerifier(zerolog.Nop())
	}()

	if !exited {
		t.Fatal("expected the test's FatalExitFunc to run")
	}
}

func TestEnvTrue(t *testing.T) {
	t.Run("unset is false", func(t *testing.T) {
		if envTrue("HYDRA_ENABLED_UNSET_PROBE") {
			t.Fatal("expected false for an unset env var")
		}
	})
	t.Run("false is false", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "false")
		if envTrue("HYDRA_ENABLED") {
			t.Fatal("expected false for \"false\"")
		}
	})
	t.Run("0 is false", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "0")
		if envTrue("HYDRA_ENABLED") {
			t.Fatal("expected false for \"0\"")
		}
	})
	t.Run("empty is false", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "")
		if envTrue("HYDRA_ENABLED") {
			t.Fatal("expected false for \"\"")
		}
	})
	t.Run("junk is false", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "yes")
		if envTrue("HYDRA_ENABLED") {
			t.Fatal("expected false for \"yes\" (strictly opt-in, not a generic truthy parse)")
		}
	})
	t.Run("true is true", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "true")
		if !envTrue("HYDRA_ENABLED") {
			t.Fatal("expected true for \"true\"")
		}
	})
	t.Run("True is true (case-insensitive)", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "True")
		if !envTrue("HYDRA_ENABLED") {
			t.Fatal("expected true for \"True\"")
		}
	})
	t.Run("TRUE is true (case-insensitive)", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "TRUE")
		if !envTrue("HYDRA_ENABLED") {
			t.Fatal("expected true for \"TRUE\"")
		}
	})
	t.Run("padded true is true (trimmed)", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "  true  ")
		if !envTrue("HYDRA_ENABLED") {
			t.Fatal("expected true for \"  true  \"")
		}
	})
	t.Run("1 is true", func(t *testing.T) {
		t.Setenv("HYDRA_ENABLED", "1")
		if !envTrue("HYDRA_ENABLED") {
			t.Fatal("expected true for \"1\"")
		}
	})
}

// TestMachineActor_ShippedHydraEnvWithoutActivation_401sWithNoJWKSFetch is the
// end-to-end pin: with HYDRA_ISSUER and HYDRA_JWKS_URL BOTH set (configured
// but not activated) and HYDRA_ENABLED unset, a JWT-shaped bearer against the
// resulting Handler must 401, next must not run, and — the specific failure
// this guards against — the JWKS endpoint must receive
// ZERO requests: constructing no verifier means oidcVerifier.verify is never
// even reached, so bff.Verifier's lazy JWKS cache never fires.
func TestMachineActor_ShippedHydraEnvWithoutActivation_401sWithNoJWKSFetch(t *testing.T) {
	var jwksHits int
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jwksHits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer jwksSrv.Close()

	t.Setenv("HYDRA_ISSUER", "http://sneakers-hydra:4444/")
	t.Setenv("HYDRA_JWKS_URL", jwksSrv.URL)
	t.Setenv("HYDRA_AUDIENCE", "sneakers-mcp")
	// HYDRA_ENABLED deliberately unset.

	verifier, issuer := newHydraVerifier(zerolog.Nop())
	h := &bff.Handler{MachineOidcVerifier: verifier, MachineOidcIssuer: issuer}

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	// A real, well-formed, validly-SIGNED JWT with a kid absent from every
	// JWKS (jwksSrv above serves an empty key set) — NOT the placeholder
	// "aaa.bbb.ccc", which fails header/segment parsing before keyFunc (and
	// hence any JWKS fetch) is ever reached, so the jwksHits==0 assertion
	// below would pass even under the failure it claims to guard.
	req.Header.Set("Authorization", "Bearer "+signUnknownKidJWT(t))
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)

	if ran {
		t.Fatal("next must NOT run for a JWT bearer while Hydra is not activated")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if jwksHits != 0 {
		t.Fatalf("expected ZERO JWKS fetch attempts while HYDRA_ENABLED is unset, got %d", jwksHits)
	}
}

// signUnknownKidJWT mints a well-formed, validly-signed RS256 JWT whose kid
// matches no key in any JWKS (the test server above always serves an empty
// key set) — a genuine JWT-shaped bearer that reaches keyFunc, unlike
// "aaa.bbb.ccc" (which fails jwt.Parse's header/segment decoding before
// keyFunc, and hence before any JWKS fetch, is ever reached).
func signUnknownKidJWT(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "http://sneakers-hydra:4444/", "aud": "sneakers-mcp", "sub": "hydra-client-abc",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	})
	tok.Header["kid"] = "unknown-kid-not-in-jwks"
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}
