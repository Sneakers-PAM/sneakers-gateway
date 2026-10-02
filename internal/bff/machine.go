// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Machine bearer-auth path: non-human callers authenticate WITHOUT a cookie,
// presenting either an opaque service-account API token (verified via
// identity.VerifyApiToken) or, when Hydra is configured, a Hydra-issued
// OIDC/OAuth2 JWT (verified via bff.Verifier +
// identity.ResolveServiceAccountByOidc — see oidc_machine.go). Either path
// lands on the SAME machine ActorContext (principal_kind=SERVICE_ACCOUNT,
// principal_id=the service-account id) placed on the request context, mirroring
// SessionActor's request-gate shape but with none of the human-session
// concerns: no cookie, no CSRF double-submit, no MFA enforcement gate. Fails
// closed: any absent/malformed header, invalid token, or identity error is a
// 401 and next is never called.
package bff

import (
	"net/http"
	"strings"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

const bearerPrefix = "Bearer "

// bearerToken extracts the token from an `Authorization: Bearer <token>`
// header. Returns ok=false for a missing header, a non-Bearer scheme, or an
// empty token (including a bare "Bearer" with no trailing token).
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) <= len(bearerPrefix) || !strings.EqualFold(h[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}
	t := strings.TrimSpace(h[len(bearerPrefix):])
	if t == "" {
		return "", false
	}
	return t, true
}

// MachineActor is the machine-path request gate: it resolves an Authorization:
// Bearer token to its principal — via identity.VerifyApiToken for an opaque
// service-account API token, or via bff.Verifier +
// identity.ResolveServiceAccountByOidc for a Hydra-issued OIDC JWT (dispatched
// purely on the bearer's own shape: looksLikeJWT) — and places a machine
// ActorContext on the request context. It fails CLOSED on any absent/malformed
// bearer, a JWT-shaped bearer when no OIDC verifier is wired (Hydra not
// configured), an identity error, or a valid=false response from either
// verifier (identity deliberately does not distinguish
// unknown/expired/revoked/disabled to the caller) — 401, and next is never
// invoked. Deliberately does NOT check a session cookie, CSRF header, or MFA
// posture: those are human-session concerns that don't apply to a bearer-token
// caller.
func (h *Handler) MachineActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if strings.HasPrefix(token, userTokenPrefix) {
			h.serveUserToken(w, r, next, token)
			return
		}
		var mv machineVerifier = saTokenVerifier{identity: h.Identity}
		if looksLikeJWT(token) {
			if h.MachineOidcVerifier == nil {
				// Inert: Hydra not enabled (HYDRA_ENABLED unset/false).
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			mv = oidcVerifier{jwt: h.MachineOidcVerifier, identity: h.Identity, issuer: h.MachineOidcIssuer}
		}
		p, ok := mv.verify(r.Context(), token)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := resolvers.WithMachineActor(r.Context(), p.id, p.groupNames)
		ctx = resolvers.WithMachineGroupIDs(ctx, p.groupIDs)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

const userTokenPrefix = "snk_u_"

// serveUserToken admits a personal token as its owner. Identity resolves the
// owner's current groups on every call, so nothing is cached here and a
// permission change or revocation applies to the very next request.
func (h *Handler) serveUserToken(w http.ResponseWriter, r *http.Request, next http.Handler, token string) {
	resp, err := h.Identity.VerifyUserToken(r.Context(), &identityv1.VerifyUserTokenRequest{Token: token})
	if err != nil || !resp.GetValid() || resp.GetUser().GetId() == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ctx := resolvers.WithUserTokenActor(r.Context(), resp.GetUser().GetId(), resp.GetTokenId(), resp.GetGroupNames())
	ctx = resolvers.WithMachineGroupIDs(ctx, resp.GetGroupIds())
	next.ServeHTTP(w, r.WithContext(ctx))
}
