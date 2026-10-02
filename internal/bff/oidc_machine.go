// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// OIDC machine-auth verifier: a second way for a non-human caller to arrive at
// MachineActor's ActorContext, alongside the opaque service-account API token
// verified by identity.VerifyApiToken. Here the caller presents a Hydra-issued
// OIDC/OAuth2 JWT (client-credentials); bff.Verifier (reused, no new JWT/JWKS
// dependency) checks its signature/iss/aud, and the verified `sub` (the OAuth2
// client_id) is resolved to a service account via
// identity.ResolveServiceAccountByOidc. Both machineVerifier implementations
// fail closed identically — MachineActor never learns WHY a token was rejected,
// only that it was.
package bff

import (
	"context"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

// machineVerifier resolves a machine-path bearer token to its principal and
// the RACI group names it holds. MachineActor picks the implementation by the
// bearer's own shape (opaque vs. JWT-looking) — never by which verifiers
// happen to be configured — and treats ok=false as the ONE fail-closed
// outcome regardless of cause.
//
// groupNames always comes from identity's scope resolution (a scope token
// matches a directory group by ID or by name slug; collisions fail closed),
// never from splitting a raw scope string here: identity owns the groups
// table and the admin bounds, and names may contain spaces.
type machineVerifier interface {
	verify(ctx context.Context, token string) (p machinePrincipal, ok bool)
}

// machinePrincipal is a verified service account and the groups identity
// resolved for it: names and ids of the same groups, in the same order.
type machinePrincipal struct {
	id         string
	groupNames []string
	groupIDs   []string
}

// saTokenVerifier is the opaque service-account API token path:
// identity.VerifyApiToken. The admin's mint-time scope is the bound; identity
// validated it at mint and resolves it to group_names on every verify.
type saTokenVerifier struct {
	identity IdentityClient
}

func (s saTokenVerifier) verify(ctx context.Context, token string) (machinePrincipal, bool) {
	resp, err := s.identity.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{Token: token})
	if err != nil || !resp.GetValid() {
		return machinePrincipal{}, false
	}
	return machinePrincipal{id: resp.GetServiceAccountId(), groupNames: resp.GetGroupNames(), groupIDs: resp.GetGroupIds()}, true
}

// oidcVerifier resolves a Hydra-issued OIDC/OAuth2 JWT: jwt.Verify checks the
// token's signature, issuer and audience (bff.Verifier); the verified `sub` is then
// the OAuth2 client_id, resolved against issuer via
// identity.ResolveServiceAccountByOidc. Fails closed on a verify error, an
// identity error, or valid=false — indistinguishably, like saTokenVerifier.
//
// The JWT's OWN `scope` claim (claims.Scope, space-delimited) is forwarded to
// identity, which resolves it by the scope grammar and bounds it by the
// linkage's admin-set allowed_groups (trust model: whoever administers Hydra
// clients controls the scope claim, so it is never trusted on its own). The
// client holds exactly the returned group_names: JWT scope groups INTERSECT
// allowed_groups. Empty allowed_groups grants no groups.
type oidcVerifier struct {
	jwt      *Verifier
	identity IdentityClient
	issuer   string
}

func (o oidcVerifier) verify(ctx context.Context, raw string) (machinePrincipal, bool) {
	claims, err := o.jwt.Verify(raw)
	if err != nil {
		return machinePrincipal{}, false
	}
	resp, err := o.identity.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
		OidcIssuer: o.issuer, OidcSubject: claims.Subject, Scope: claims.Scope,
	})
	if err != nil || !resp.GetValid() {
		return machinePrincipal{}, false
	}
	return machinePrincipal{id: resp.GetServiceAccountId(), groupNames: resp.GetGroupNames(), groupIDs: resp.GetGroupIds()}, true
}

// looksLikeJWT reports whether token has the three dot-separated segments of
// a JWT (header.payload.signature). An opaque service-account API token never
// contains a dot, so this cheaply and reliably dispatches MachineActor to the
// right machineVerifier without attempting a parse.
func looksLikeJWT(token string) bool {
	dots := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			dots++
		}
	}
	return dots == 2
}
