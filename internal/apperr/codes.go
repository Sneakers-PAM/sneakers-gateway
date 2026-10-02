// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package apperr holds the gateway's error-code table. The coded-error
// helpers (Coded, Code) come from github.com/Bugs5382/go-apperr; this package
// keeps only the codes, each a stable numeric code operators can map from a
// log line straight to the failure class in docs/error-codes.md.
//
// # Registry convention
//
// Codes are namespaced by service: the first digit identifies the owning
// service, the remaining digits identify the failure within it.
//
//   - The gateway owns the 2xxx range. Another service adopting apperr MUST
//     pick a different first digit (3, 4, ...) — do not reuse 2.
//   - 2000: default/unclassified internal error (the presenter's fallback
//     when an error carries no apperr code at all).
//   - 2001: sample code exercised by this package's own tests.
//   - 2210-2214 and 2221-2224: Kratos auth-backend band —
//     *bff.KratosClient login (2210-2214) and admin recovery (2221-2224)
//     failures. Invalid credentials and invalid/expired recovery codes are
//     NOT in this band: those stay the ErrInvalidCredentials /
//     ErrInvalidRecoveryCode sentinels (a plain 401/400 to the client), never
//     a coded internal error.
//   - 2215-2218: SSO via Polis (SAML).
//   - 2219-2220: reserved — do not reuse.
//
// New gateway codes should be added to the Registry map below (and mirrored
// in docs/error-codes.md) as they are introduced; nothing else in this file
// needs to change to add one.
package apperr

// DefaultCode is the fallback code for an error that carries no apperr code.
const DefaultCode = 2000

// Registry maps every gateway (2xxx) code this package knows about to a short
// human-readable description. Single source of truth mirrored by
// docs/error-codes.md.
var Registry = map[int]string{
	DefaultCode: "unclassified internal error",
	2001:        "sample coded error (apperr package tests)",

	// Ory Kratos local-login backend (internal/bff/kratos.go), behind
	// AUTH_BACKEND=kratos.
	2210: "Kratos login-flow init failed (GET self-service/login/api)",
	2211: "Kratos password verify failed, non-credential (POST self-service/login)",
	2212: "Kratos unreachable (transport-level failure)",
	2213: "Kratos whoami/session-refresh failed (GET sessions/whoami)",
	2214: "Kratos logout failed (POST self-service/logout/api) — best-effort, never blocks logout",

	// Polis single-domain SAML SSO (internal/bff/sso.go, internal/bff/polis.go).
	// 2219-2220 are reserved.
	2215: "Polis SSO flow state invalid (missing/mismatched state or redirect build failure)",
	2216: "Polis code-exchange failed (POST /api/oauth/token)",
	2217: "Polis userinfo failed (GET /api/oauth/userinfo) or userinfo carried no email",
	2218: "SSO login rejected — no platform user for federated email (no-JIT)",

	// Kratos-admin self-service password reset (internal/bff/kratos.go).
	2221: "Kratos admin identity lookup failed (GET admin/identities)",
	2222: "Kratos admin recovery-code creation failed (POST admin/recovery/code)",
	2223: "Kratos self-service recovery flow failed (self-service/recovery), non-credential",
	2224: "Kratos self-service settings flow failed (self-service/settings), non-credential",
}
