// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Machine scope grammar: the gateway never turns a raw scope string into
// RACI groups itself. identity resolves every scope token (group ID or name
// slug; collisions fail closed) and returns the resulting group names:
// VerifyApiTokenResponse.group_names for an opaque API token (bounded by the
// admin's mint-time scope), ResolveServiceAccountByOidcResponse.group_names
// for a Hydra JWT (bounded by the linkage's allowed_groups). MachineActor
// uses those names verbatim, so a group name containing spaces ("Help Desk")
// survives intact, and an older identity that leaves group_names empty
// grants no groups (fail closed).
package bff

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

// runMachine drives MachineActor with bearer against h and returns the HTTP
// code and the machine actor's group names.
func runMachine(t *testing.T, h *Handler, bearer string) (int, []string) {
	t.Helper()
	var groups []string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		groups = resolvers.MachineActorOf(r.Context()).GetGroupNames()
	})
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)
	return rec.Code, groups
}

// runOidcMachine signs a Hydra-shaped JWT carrying scope and resolves it
// against a fake identity returning resp.
func runOidcMachine(t *testing.T, scope string, resp *identityv1.ResolveServiceAccountByOidcResponse) (int, []string, *fakeIdentity) {
	t.Helper()
	srv, key := jwksServer(t, "hk1")
	fid := &fakeIdentity{resolveOidcResp: resp}
	h := &Handler{Identity: fid, MachineOidcVerifier: newOidcTestVerifier(srv.URL), MachineOidcIssuer: oidcTestIssuer}
	code, groups := runMachine(t, h, sign(t, key, "hk1", oidcGoodClaims("hydra-client-abc", scope)))
	return code, groups, fid
}

// TestMachineActor_JWTBearer_ForwardsScopeAndUsesIdentityGroupNames: the
// verified JWT scope claim is forwarded to identity unchanged, and the actor
// holds exactly identity's group_names, spaces and all.
func TestMachineActor_JWTBearer_ForwardsScopeAndUsesIdentityGroupNames(t *testing.T) {
	code, groups, fid := runOidcMachine(t, "help-desk group-infra example-admins", &identityv1.ResolveServiceAccountByOidcResponse{
		Valid: true, ServiceAccountId: "sa-mcp-1",
		AllowedGroups: []string{"group-helpdesk", "group-infra"},
		GroupNames:    []string{"Help Desk", "Infrastructure"},
	})
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if got := fid.resolveOidcReq.GetScope(); got != "help-desk group-infra example-admins" {
		t.Fatalf("scope forwarded to identity = %q", got)
	}
	if want := []string{"Help Desk", "Infrastructure"}; !reflect.DeepEqual(groups, want) {
		t.Fatalf("group_names = %q, want %q", groups, want)
	}
}

// TestMachineActor_JWTBearer_RawScopeNeverGrants: allowed_groups and the JWT
// scope overlap byte for byte, but identity returned no group_names (an older
// identity, or nothing resolved): the gateway must NOT fall back to
// intersecting the raw strings itself.
func TestMachineActor_JWTBearer_RawScopeNeverGrants(t *testing.T) {
	code, groups, _ := runOidcMachine(t, "sneakers-secrets mcp-agents", &identityv1.ResolveServiceAccountByOidcResponse{
		Valid: true, ServiceAccountId: "sa-mcp-1", AllowedGroups: []string{"sneakers-secrets", "mcp-agents"},
		Scope: "sneakers-secrets mcp-agents",
	})
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if len(groups) != 0 {
		t.Fatalf("group_names = %q, want none", groups)
	}
}

// TestMachineActor_APIToken_UsesIdentityGroupNames: the opaque API-token path
// holds identity's resolved group_names, never a whitespace split of the raw
// stored scope (which is canonical group IDs).
func TestMachineActor_APIToken_UsesIdentityGroupNames(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{
		Valid: true, ServiceAccountId: "sa-42", Scope: "group-helpdesk group-infra",
		GroupNames: []string{"Help Desk", "Infrastructure"},
	}}
	code, groups := runMachine(t, &Handler{Identity: fid}, "sa-token-plaintext")
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if want := []string{"Help Desk", "Infrastructure"}; !reflect.DeepEqual(groups, want) {
		t.Fatalf("group_names = %q, want %q", groups, want)
	}
}

// TestMachineActor_APIToken_RawScopeNeverGrants: a raw scope string with
// no resolved group_names grants nothing.
func TestMachineActor_APIToken_RawScopeNeverGrants(t *testing.T) {
	fid := &fakeIdentity{verifyApiTokenResp: &identityv1.VerifyApiTokenResponse{
		Valid: true, ServiceAccountId: "sa-42", Scope: "Infrastructure sneakers-secrets",
	}}
	code, groups := runMachine(t, &Handler{Identity: fid}, "sa-token-plaintext")
	if code != http.StatusOK {
		t.Fatalf("code = %d, want 200", code)
	}
	if len(groups) != 0 {
		t.Fatalf("group_names = %q, want none", groups)
	}
}
