// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

// Real Keycloak access-token verification for AUTH_MODE=real, kept
// self-contained here (no identity-service round-trip). The actor is trusted
// only after the token's signature, issuer, audience and time claims are
// cryptographically verified.
//
// Besides the signature and time claims this checks `iss` and `aud`/`azp`
// with a configurable clock-skew leeway.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VerifiedClaims is the trustworthy subset extracted from a verified token.
type VerifiedClaims struct {
	Subject  string // sub
	Username string // preferred_username (falls back to sub)
	Email    string // email (used to adopt a pre-created local user by match)
	Name     string // name / full name (falls back to preferred_username)
	SID      string // Keycloak session id (sid), for session recording
	// Scope is the OAuth2 granted scope: for a Hydra
	// client-credentials token this is the client's granted scope,
	// normalised to a space-delimited string exactly like an opaque
	// service-account API token's Scope — both are resolved to RACI group
	// names by identity's scope grammar. Hydra (fosite) can emit this
	// as either the standard OAuth2 `scope` claim (a space-delimited
	// string) or, with JWTScopeFieldList (the v2.x default), as `scp` (a
	// JSON array of strings) — scopeClaim below accepts either shape.
	// Absent/empty for tokens that don't carry it (e.g. Keycloak human
	// tokens); harmless there, since the human path never reads it.
	Scope string
}

// Verifier validates Keycloak JWTs against a cached JWKS.
type Verifier struct {
	cache    *jwksCache
	issuer   string // expected iss (empty = skip)
	audience string // expected aud entry (matched against aud[] or azp)
	clientID string // expected azp (Keycloak sets azp = the client id)
	leeway   time.Duration
}

// NewVerifier builds a Verifier. jwksURL is the realm certs endpoint; issuer is
// the expected token issuer; audience/clientID gate the audience (a token is
// accepted when its aud contains `audience` OR its azp equals `clientID` —
// Keycloak's default aud is "account" with azp = the client).
func NewVerifier(jwksURL, issuer, audience, clientID string, ttl, leeway time.Duration) *Verifier {
	return &Verifier{
		cache:    newJWKSCache(jwksURL, ttl),
		issuer:   issuer,
		audience: audience,
		clientID: clientID,
		leeway:   leeway,
	}
}

var validSigningMethods = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

func (v *Verifier) parserOpts() []jwt.ParserOption {
	opts := []jwt.ParserOption{jwt.WithValidMethods(validSigningMethods), jwt.WithLeeway(v.leeway)}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	return opts
}

// keyFunc resolves the signing key for a token's kid and enforces that the key
// type matches the token's signing method. forceRefresh re-fetches the JWKS.
func (v *Verifier) keyFunc(forceRefresh bool) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("jwt: missing kid header")
		}
		key, err := v.cache.key(kid, forceRefresh)
		if err != nil {
			return nil, err
		}
		if err := keyMatchesMethod(key, t.Method, kid); err != nil {
			return nil, err
		}
		return key, nil
	}
}

func keyMatchesMethod(key crypto.PublicKey, m jwt.SigningMethod, kid string) error {
	switch m.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodRSAPSS:
		if _, ok := key.(*rsa.PublicKey); !ok {
			return fmt.Errorf("jwt: key for kid %q is not RSA", kid)
		}
	case *jwt.SigningMethodECDSA:
		if _, ok := key.(*ecdsa.PublicKey); !ok {
			return fmt.Errorf("jwt: key for kid %q is not ECDSA", kid)
		}
	default:
		return fmt.Errorf("jwt: unsupported signing method %v", m)
	}
	return nil
}

// retryableKid reports whether a parse error warrants one JWKS refresh + retry
// (unknown kid = likely key rotation).
func retryableKid(err error) bool {
	return strings.Contains(err.Error(), "kid") || errors.Is(err, jwt.ErrTokenUnverifiable)
}

func (v *Verifier) claimsFrom(parsed *jwt.Token) (VerifiedClaims, error) {
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return VerifiedClaims{}, fmt.Errorf("jwt: unexpected claims type %T", parsed.Claims)
	}
	if err := v.checkAudience(mc); err != nil {
		return VerifiedClaims{}, err
	}
	sub, _ := mc["sub"].(string)
	if sub == "" {
		return VerifiedClaims{}, fmt.Errorf("jwt: missing sub")
	}
	username, _ := mc["preferred_username"].(string)
	if username == "" {
		username = sub
	}
	email, _ := mc["email"].(string)
	name, _ := mc["name"].(string)
	if name == "" {
		name = username
	}
	sid, _ := mc["sid"].(string)
	scope := scopeClaim(mc)
	return VerifiedClaims{Subject: sub, Username: username, Email: email, Name: name, SID: sid, Scope: scope}, nil
}

// Verify validates the token (signature + iss + aud/azp + time) and returns its
// trustworthy claims, or an error (fail-closed — the caller responds 401).
func (v *Verifier) Verify(raw string) (VerifiedClaims, error) {
	opts := v.parserOpts()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		parsed, err := jwt.Parse(raw, v.keyFunc(attempt == 1), opts...)
		if err != nil {
			lastErr = err
			if attempt == 0 && retryableKid(err) { // refresh JWKS once, retry
				continue
			}
			return VerifiedClaims{}, fmt.Errorf("jwt: parse: %w", err)
		}
		return v.claimsFrom(parsed)
	}
	return VerifiedClaims{}, fmt.Errorf("jwt: parse: %w", lastErr)
}

// checkAudience accepts the token when its azp equals the expected client id OR
// its aud contains the expected audience. Keycloak's default access-token aud
// is "account" with azp set to the authorized client, so azp is the reliable
// binding to this gateway's confidential client.
func (v *Verifier) checkAudience(mc jwt.MapClaims) error {
	if v.audience == "" && v.clientID == "" {
		return nil
	}
	if azp, _ := mc["azp"].(string); azp != "" && v.clientID != "" && azp == v.clientID {
		return nil
	}
	for _, a := range audienceList(mc["aud"]) {
		if v.audience != "" && a == v.audience {
			return nil
		}
	}
	return fmt.Errorf("jwt: audience/azp does not include %q", firstNonEmpty(v.audience, v.clientID))
}

func audienceList(v any) []string {
	switch a := v.(type) {
	case string:
		return []string{a}
	case []any:
		out := make([]string, 0, len(a))
		for _, e := range a {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// scopeClaim extracts the granted-scope claim in whichever shape the issuer
// used, normalising to the single space-delimited string that is forwarded
// to identity.ResolveServiceAccountByOidc: Keycloak/plain-OAuth2 issuers send `scope`
// as a space-delimited string; Hydra (fosite) with JWTScopeFieldList — the
// v2.x default — sends `scp` as a JSON array of strings instead. Mirrors
// audienceList's shape tolerance above. Attacker-influenced input: a missing
// claim, a non-string/non-array, an array containing non-string entries, or
// a nested object all degrade to "" (or to just the valid array entries),
// never panic.
func scopeClaim(mc jwt.MapClaims) string {
	if s, ok := mc["scope"].(string); ok {
		return s
	}
	if arr, ok := mc["scp"].([]any); ok {
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return strings.Join(out, " ")
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- JWKS cache (RSA + EC only; oct rejected) -------------------------------

type jwksCache struct {
	url    string
	ttl    time.Duration
	client *http.Client

	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	expiresAt time.Time
}

func newJWKSCache(url string, ttl time.Duration) *jwksCache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &jwksCache{url: url, ttl: ttl, client: &http.Client{Timeout: 10 * time.Second}, keys: map[string]crypto.PublicKey{}}
}

func (j *jwksCache) key(kid string, forceRefresh bool) (crypto.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !forceRefresh {
		if k, ok := j.keys[kid]; ok && time.Now().Before(j.expiresAt) {
			return k, nil
		}
	}
	if err := j.fetchLocked(); err != nil {
		if k, ok := j.keys[kid]; ok { // keep stale keys on transient fetch failure
			return k, nil
		}
		return nil, err
	}
	k, ok := j.keys[kid]
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not present", kid)
	}
	return k, nil
}

func (j *jwksCache) fetchLocked() error {
	resp, err := j.client.Get(j.url) // #nosec G704 -- j.url is the operator-configured JWKS URL, never request input
	if err != nil {
		return fmt.Errorf("jwks: fetch %s: %w", j.url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: fetch %s: status %d", j.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("jwks: read body: %w", err)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}
	j.keys = keys
	j.expiresAt = time.Now().Add(j.ttl)
	return nil
}

func parseJWKS(raw []byte) (map[string]crypto.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Alg string
			N, E               string // RSA
			Crv, X, Y          string // EC
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("jwks: parse: %w", err)
	}
	out := make(map[string]crypto.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			pub, err := rsaPublicFromJWK(k.N, k.E)
			if err != nil {
				return nil, fmt.Errorf("jwks: kid %q: %w", k.Kid, err)
			}
			out[k.Kid] = pub
		case "EC":
			pub, err := ecdsaPublicFromJWK(k.Crv, k.X, k.Y)
			if err != nil {
				return nil, fmt.Errorf("jwks: kid %q: %w", k.Kid, err)
			}
			out[k.Kid] = pub
		}
	}
	return out, nil
}

func b64uBig(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

func rsaPublicFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	n, err := b64uBig(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	e, err := b64uBig(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	if !e.IsInt64() {
		return nil, fmt.Errorf("rsa exponent too large")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func ecdsaPublicFromJWK(crv, xB64, yB64 string) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
	x, err := b64uBig(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	y, err := b64uBig(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
