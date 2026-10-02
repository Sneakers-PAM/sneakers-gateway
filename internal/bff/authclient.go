// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"errors"
	"time"
)

// ErrInvalidCredentials is the sentinel a password backend returns for a
// rejected username/password, kept apart from coded internal errors so Login
// can answer 401 rather than 502.
var ErrInvalidCredentials = errors.New("invalid credentials")

// AuthResult is the outcome of a password verification, refresh, or
// session-liveness check against Ory Kratos.
//
//   - AccessToken is the Kratos session_token the gateway stores in the
//     session. Refresh re-validates and extends the SAME token via whoami.
//   - Subject is the Kratos identity id; Email is the identity's email trait,
//     which is also the login identifier.
type AuthResult struct {
	AccessToken string
	ExpiresAt   time.Time
	Subject     string
	Email       string
}

// authClient is the narrow local-login password-backend contract Login,
// session refresh, and Logout depend on. *KratosClient (kratos.go) satisfies
// it.
type authClient interface {
	// VerifyPassword checks a username/password. On success it returns the
	// resulting AuthResult; on a bad credential it returns the
	// ErrInvalidCredentials sentinel — never a coded internal error.
	VerifyPassword(ctx context.Context, username, password string) (AuthResult, error)
	// Refresh validates the caller's credential and returns an updated
	// AuthResult. An inactive/expired/rejected credential returns
	// ErrInvalidCredentials so the caller fails closed exactly as a bad
	// password would.
	Refresh(ctx context.Context, token string) (AuthResult, error)
	// Logout best-effort revokes the backend-side session/token.
	Logout(ctx context.Context, token string) error
}

// asTokens adapts an AuthResult into the Tokens shape that beginStepUp
// (mfa.go) parks for pending auth. ExpiresIn is derived from ExpiresAt — a round trip through Tokens'
// relative-seconds shape — losing at most sub-second precision, which
// beginStepUp/Pending immediately convert back to an absolute instant on
// promotion anyway.
func asTokens(ar AuthResult) Tokens {
	return Tokens{
		AccessToken: ar.AccessToken,
		ExpiresIn:   int(time.Until(ar.ExpiresAt).Seconds()),
	}
}
