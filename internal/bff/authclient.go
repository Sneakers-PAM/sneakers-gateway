// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"time"
)

// AuthResult is the backend-agnostic outcome of a password verification,
// refresh, or session-liveness check. It carries Username/Name because
// Sneakers' AdoptOrProvisionFederatedUser keys adoption on the login handle
// (Keycloak preferred_username / LDAP uid) before falling back to email.
//
//   - AccessToken is the bearer the gateway stores in the session: Keycloak's
//     OIDC access token, or Kratos's opaque session_token.
//   - RefreshToken is only meaningful for Keycloak's OAuth2 rotation; Kratos
//     has none (Refresh re-validates/extends the SAME session_token via
//     whoami instead), so this is always "" on a Kratos AuthResult.
//   - Username/Name are populated by the Keycloak backend (from the verified
//     JWT's preferred_username/name claims) and left empty by Kratos (whose
//     identity schema — traits email/first_name/last_name — carries no
//     separate username; email IS the login identifier).
type AuthResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Subject      string
	Email        string
	Username     string
	Name         string
}

// backendKeycloak/backendKratos are the AUTH_BACKEND env values (see
// cmd/gateway/main.go). Handler.Backend carries one of these;
// backendToken branches on it.
const (
	backendKeycloak = "keycloak"
	backendKratos   = "kratos"
)

// authClient is the narrow local-login password-backend contract Login,
// session refresh, and Logout depend on. *kcVerifiedAuth (this file) and
// *KratosClient (kratos.go) both satisfy it.
type authClient interface {
	// VerifyPassword checks a username/password. On success it returns the
	// resulting AuthResult; on a bad credential it returns the
	// ErrInvalidCredentials sentinel — never a coded internal error. The
	// Keycloak implementation (kcVerifiedAuth) has one more failure mode with
	// no Kratos equivalent: a correct password whose freshly-issued access
	// token fails JWKS verification returns the distinct ErrTokenVerifyFailed
	// sentinel instead, so Login (http.go) can tell that apart from a bad
	// password.
	VerifyPassword(ctx context.Context, username, password string) (AuthResult, error)
	// Refresh validates/rotates the caller's credential and returns an
	// updated AuthResult. An inactive/expired/rejected credential returns
	// ErrInvalidCredentials so the caller fails closed exactly as a bad
	// password would.
	Refresh(ctx context.Context, token string) (AuthResult, error)
	// Logout best-effort revokes the backend-side session/token.
	Logout(ctx context.Context, token string) error
}

// auth resolves the effective local-login backend: the explicit Auth field
// when set, else a kcVerifiedAuth wrapping KC+Verifier — so a plain
// Handler{KC: ..., Verifier: ...} construction (as most tests in this
// package use) runs the Keycloak path with no extra wiring; only main.go
// under AUTH_BACKEND=kratos sets Auth explicitly.
func (h *Handler) auth() authClient {
	if h.Auth != nil {
		return h.Auth
	}
	return &kcVerifiedAuth{kc: h.KC, verifier: h.Verifier}
}

// backendToken picks which stored credential Refresh/Logout present to the
// backend: Keycloak rotates via RefreshToken; Kratos has none — Refresh
// re-validates the SAME AccessToken (session_token) via whoami instead.
func (h *Handler) backendToken(sess Session) string {
	if h.Backend == backendKratos {
		return sess.AccessToken
	}
	return sess.RefreshToken
}

// asTokens adapts an AuthResult into the Tokens shape that beginStepUp
// (mfa.go) parks for pending auth. ExpiresIn is derived from ExpiresAt — a round trip through Tokens'
// relative-seconds shape — losing at most sub-second precision, which
// beginStepUp/Pending immediately convert back to an absolute instant on
// promotion anyway.
func asTokens(ar AuthResult) Tokens {
	return Tokens{
		AccessToken:  ar.AccessToken,
		RefreshToken: ar.RefreshToken,
		ExpiresIn:    int(time.Until(ar.ExpiresAt).Seconds()),
	}
}

// kcVerifiedAuth adapts *KCClient + *Verifier into authClient. Rather than
// trusting the access token's claims because it came straight from
// Keycloak's own token endpoint, it keeps defense-in-depth: every
// Keycloak-issued access token is cryptographically verified (signature +
// iss + aud/azp + leeway) via JWKS before its claims are trusted.
type kcVerifiedAuth struct {
	kc       *KCClient
	verifier *Verifier
}

func (a *kcVerifiedAuth) VerifyPassword(ctx context.Context, username, password string) (AuthResult, error) {
	tok, err := a.kc.PasswordGrant(ctx, username, password)
	if err != nil {
		return AuthResult{}, err
	}
	vc, verr := a.verifier.Verify(tok.AccessToken)
	if verr != nil {
		// Fail closed: a token straight from Keycloak's own token endpoint that
		// still fails signature/iss/aud verification is never trusted. This is
		// NOT a bad-credential outcome — the password grant already succeeded —
		// so it returns the distinct ErrTokenVerifyFailed sentinel rather than
		// folding into ErrInvalidCredentials, letting Login (http.go) tell a
		// JWKS/issuer misconfig or key-rotation glitch apart from a wrong
		// password.
		return AuthResult{}, ErrTokenVerifyFailed
	}
	return AuthResult{
		AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken,
		ExpiresAt: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
		Subject:   vc.Subject, Email: vc.Email, Username: vc.Username, Name: vc.Name,
	}, nil
}

// Refresh wraps KCClient.Refresh WITHOUT re-verifying the rotated token here
// — resolveSessionActor (http.go) re-verifies the (possibly refreshed)
// access token itself on EVERY request for the Keycloak backend, so
// Subject/Email are intentionally left empty.
func (a *kcVerifiedAuth) Refresh(ctx context.Context, refreshToken string) (AuthResult, error) {
	tok, err := a.kc.Refresh(ctx, refreshToken)
	if err != nil {
		return AuthResult{}, err
	}
	return AuthResult{
		AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken,
		ExpiresAt: time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
	}, nil
}

func (a *kcVerifiedAuth) Logout(ctx context.Context, refreshToken string) error {
	return a.kc.Logout(ctx, refreshToken)
}
