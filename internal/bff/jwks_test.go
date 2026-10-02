// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksServer serves a single RSA signing key and returns the key + a token
// factory bound to it.
func jwksServer(t *testing.T, kid string) (*httptest.Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	jwks := map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(srv.Close)
	return srv, key
}

func sign(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

const (
	testIssuer = "http://kc.example.org/realms/sneakers"
	testClient = "sneakers-gateway"
)

func newTestVerifier(jwksURL string) *Verifier {
	return NewVerifier(jwksURL, testIssuer, testClient, testClient, time.Minute, 30*time.Second)
}

func goodClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": testIssuer, "azp": testClient, "sub": "kc-abc-123",
		"preferred_username": "alice@dev", "sid": "sess-1",
		"exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix(),
	}
}

func TestVerifyValidToken(t *testing.T) {
	srv, key := jwksServer(t, "k1")
	v := newTestVerifier(srv.URL)
	vc, err := v.Verify(sign(t, key, "k1", goodClaims()))
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if vc.Username != "alice@dev" || vc.Subject != "kc-abc-123" || vc.SID != "sess-1" {
		t.Fatalf("wrong claims: %+v", vc)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	srv, key := jwksServer(t, "k1")
	v := newTestVerifier(srv.URL)
	tok := sign(t, key, "k1", goodClaims())
	// Flip a char at the START of the signature segment. (Flipping the LAST
	// char can land on unused padding bits of a 2048-bit RSA signature and
	// leave the decoded bytes — and thus validity — unchanged.)
	dot := strings.LastIndexByte(tok, '.')
	b := []byte(tok)
	i := dot + 1
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := v.Verify(string(b)); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestVerifyRejectsWrongIssuer(t *testing.T) {
	srv, key := jwksServer(t, "k1")
	v := newTestVerifier(srv.URL)
	c := goodClaims()
	c["iss"] = "http://evil/realms/sneakers"
	if _, err := v.Verify(sign(t, key, "k1", c)); err == nil {
		t.Fatal("wrong-issuer token accepted")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	srv, key := jwksServer(t, "k1")
	v := newTestVerifier(srv.URL)
	c := goodClaims()
	c["azp"] = "some-other-client"
	c["aud"] = "account" // neither azp==client nor aud-contains(client)
	if _, err := v.Verify(sign(t, key, "k1", c)); err == nil {
		t.Fatal("wrong-audience token accepted")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	srv, key := jwksServer(t, "k1")
	v := newTestVerifier(srv.URL)
	c := goodClaims()
	c["exp"] = time.Now().Add(-time.Hour).Unix() // well beyond leeway
	if _, err := v.Verify(sign(t, key, "k1", c)); err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestVerifyAcceptsAudienceViaAudList(t *testing.T) {
	srv, key := jwksServer(t, "k1")
	v := newTestVerifier(srv.URL)
	c := goodClaims()
	delete(c, "azp")
	c["aud"] = []any{"account", testClient} // accepted via aud list
	if _, err := v.Verify(sign(t, key, "k1", c)); err != nil {
		t.Fatalf("aud-list token rejected: %v", err)
	}
}

// TestScopeClaim exercises scopeClaim's shape tolerance directly: the
// standard OAuth2 `scope` string, Hydra's (fosite JWTScopeFieldList) `scp`
// array, and hostile/malformed input that must degrade to "" (or to just the
// valid entries) without ever panicking.
func TestScopeClaim(t *testing.T) {
	cases := []struct {
		name string
		mc   jwt.MapClaims
		want string
	}{
		{"scope string", jwt.MapClaims{"scope": "a b c"}, "a b c"},
		{"scp array", jwt.MapClaims{"scp": []any{"a", "b", "c"}}, "a b c"},
		{"missing", jwt.MapClaims{}, ""},
		{"scope wrong type", jwt.MapClaims{"scope": 123}, ""},
		{"scp not array", jwt.MapClaims{"scp": "a b"}, ""},
		{"scp array with non-string entries", jwt.MapClaims{"scp": []any{"a", 1, nil, "b"}}, "a b"},
		{"scp nested object", jwt.MapClaims{"scp": map[string]any{"a": "b"}}, ""},
		{"scope and scp both present prefers scope", jwt.MapClaims{"scope": "x", "scp": []any{"y"}}, "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scopeClaim(tc.mc); got != tc.want {
				t.Fatalf("scopeClaim(%+v) = %q, want %q", tc.mc, got, tc.want)
			}
		})
	}
}
