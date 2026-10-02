// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

// linkOidcClient/unlinkOidcClient admin GraphQL: site-admin-only
// management of a service account's OIDC client linkage, on the HUMAN
// /graphql schema — the machine /machine/graphql resolve path
// (ResolveServiceAccountByOidc) is a separate concern in bff.oidcVerifier.
// The non-site-admin deny case for both mutations is covered alongside the
// rest of the SA/token admin surface in
// TestServiceAccountAdminOpsDenyNonSiteAdmin (identity_admin_test.go).

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

// newIdentityClientWithHydra mirrors newIdentityClient but also sets
// Resolver.HydraIssuer, since LinkOidcClient's issuer comes from there, not
// the caller.
func newIdentityClientWithHydra(fi *fakeIdentity, actor string, siteAdmin bool, hydraIssuer string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: fi, HydraIssuer: hydraIssuer}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActor(r.Context(), actor)
		ctx = WithActorInfo(ctx, siteAdmin, false, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
	return gqlclient.New(wrapped)
}

func TestLinkOidcClientUsesServerSideHydraIssuerNotCallerSupplied(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClientWithHydra(fi, "user-admin", true, "http://sneakers-hydra:4444/")
	var resp struct {
		LinkOidcClient struct{ ID string }
	}
	c.MustPost(`mutation { linkOidcClient(serviceAccountId:"sa-1", oidcSubject:"hydra-client-abc", allowedGroups:["ci-bots"]) { id } }`, &resp)

	if fi.lastLinkReq.GetServiceAccountId() != "sa-1" {
		t.Fatalf("serviceAccountId = %q, want sa-1", fi.lastLinkReq.GetServiceAccountId())
	}
	if fi.lastLinkReq.GetOidcSubject() != "hydra-client-abc" {
		t.Fatalf("oidcSubject = %q, want hydra-client-abc", fi.lastLinkReq.GetOidcSubject())
	}
	if fi.lastLinkReq.GetOidcIssuer() != "http://sneakers-hydra:4444/" {
		t.Fatalf("oidcIssuer = %q, want the server-side HydraIssuer (not caller-supplied)", fi.lastLinkReq.GetOidcIssuer())
	}
	if fi.lastLinkReq.GetActingAdmin() != "user-admin" {
		t.Fatalf("actingAdmin = %q, want user-admin", fi.lastLinkReq.GetActingAdmin())
	}
	if resp.LinkOidcClient.ID != "sa-1" {
		t.Fatalf("id = %q, want sa-1", resp.LinkOidcClient.ID)
	}
}

func TestUnlinkOidcClientForwardsServiceAccountAndActor(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClientWithHydra(fi, "user-admin", true, "http://sneakers-hydra:4444/")
	var resp struct {
		UnlinkOidcClient struct{ ID string }
	}
	c.MustPost(`mutation { unlinkOidcClient(serviceAccountId:"sa-1") { id } }`, &resp)

	if fi.lastUnlinkReq.GetServiceAccountId() != "sa-1" {
		t.Fatalf("serviceAccountId = %q, want sa-1", fi.lastUnlinkReq.GetServiceAccountId())
	}
	if fi.lastUnlinkReq.GetActingAdmin() != "user-admin" {
		t.Fatalf("actingAdmin = %q, want user-admin", fi.lastUnlinkReq.GetActingAdmin())
	}
	if resp.UnlinkOidcClient.ID != "sa-1" {
		t.Fatalf("id = %q, want sa-1", resp.UnlinkOidcClient.ID)
	}
}

func TestOidcClientAdminOpsPropagateIdentityErrors(t *testing.T) {
	fi := &fakeIdentity{linkErr: errors.New("identity: down")}
	c := newIdentityClientWithHydra(fi, "user-admin", true, "http://sneakers-hydra:4444/")
	var resp struct {
		LinkOidcClient struct{ ID string }
	}
	if err := c.Post(`mutation { linkOidcClient(serviceAccountId:"sa-1", oidcSubject:"client-1", allowedGroups:[]) { id } }`, &resp); err == nil {
		t.Fatal("expected identity error to propagate, got nil")
	}

	// unlinkOidcClient must independently propagate ITS OWN identity error
	// too, so the unlink path is driven separately from the link error.
	fi2 := &fakeIdentity{unlinkErr: errors.New("identity: down")}
	c2 := newIdentityClientWithHydra(fi2, "user-admin", true, "http://sneakers-hydra:4444/")
	var unlinkResp struct {
		UnlinkOidcClient struct{ ID string }
	}
	if err := c2.Post(`mutation { unlinkOidcClient(serviceAccountId:"sa-1") { id } }`, &unlinkResp); err == nil {
		t.Fatal("expected identity error to propagate from unlinkOidcClient, got nil")
	}
}

// TestGqlServiceAccount_OidcLinkageSurfacedOnlyWhenLinked: identity returns
// oidc_issuer/oidc_subject on the ServiceAccount proto, and gqlServiceAccount
// must surface them so admins can see which service accounts are OIDC-linked
// and to what. Exercises the
// serviceAccounts query with one linked and one unlinked account and asserts
// the linked one surfaces both fields while the unlinked one surfaces null
// for both (most SAs are unlinked, so this must stay the common case).
func TestGqlServiceAccount_OidcLinkageSurfacedOnlyWhenLinked(t *testing.T) {
	fi := &fakeIdentity{listSAResp: &identityv1.ListServiceAccountsResponse{ServiceAccounts: []*identityv1.ServiceAccount{
		{Id: "sa-linked", Name: "ci-bot", OidcIssuer: "http://sneakers-hydra:4444/", OidcSubject: "hydra-client-abc"},
		{Id: "sa-unlinked", Name: "unlinked-bot"},
	}}}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		ServiceAccounts []struct {
			ID          string
			OidcIssuer  *string
			OidcSubject *string
		}
	}
	c.MustPost(`query { serviceAccounts { id oidcIssuer oidcSubject } }`, &resp)

	if len(resp.ServiceAccounts) != 2 {
		t.Fatalf("got %d service accounts, want 2", len(resp.ServiceAccounts))
	}
	linked, unlinked := resp.ServiceAccounts[0], resp.ServiceAccounts[1]
	if linked.ID != "sa-linked" || linked.OidcIssuer == nil || *linked.OidcIssuer != "http://sneakers-hydra:4444/" {
		t.Fatalf("linked SA oidcIssuer = %+v, want http://sneakers-hydra:4444/", linked.OidcIssuer)
	}
	if linked.OidcSubject == nil || *linked.OidcSubject != "hydra-client-abc" {
		t.Fatalf("linked SA oidcSubject = %+v, want hydra-client-abc", linked.OidcSubject)
	}
	if unlinked.ID != "sa-unlinked" || unlinked.OidcIssuer != nil || unlinked.OidcSubject != nil {
		t.Fatalf("unlinked SA oidcIssuer/oidcSubject = %+v/%+v, want nil/nil", unlinked.OidcIssuer, unlinked.OidcSubject)
	}
}

// TestLinkOidcClientForwardsAllowedGroups: the site-admin-set allowed-groups
// bound reaches identity verbatim (identity normalizes it), including an
// explicit empty list, which links the client but grants it no groups.
func TestLinkOidcClientForwardsAllowedGroups(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want []string
	}{
		{`["sneakers-secrets","mcp-agents"]`, []string{"sneakers-secrets", "mcp-agents"}},
		{`[]`, nil},
	} {
		fi := &fakeIdentity{}
		c := newIdentityClientWithHydra(fi, "user-admin", true, "http://sneakers-hydra:4444/")
		var resp struct{ LinkOidcClient struct{ ID string } }
		c.MustPost(`mutation { linkOidcClient(serviceAccountId:"sa-1", oidcSubject:"c", allowedGroups:`+tc.arg+`) { id } }`, &resp)
		if got := fi.lastLinkReq.GetAllowedGroups(); len(got) != len(tc.want) || (len(got) > 0 && !reflect.DeepEqual(got, tc.want)) {
			t.Fatalf("allowedGroups %s: forwarded %q, want %q", tc.arg, got, tc.want)
		}
	}
}

// TestLinkOidcClientRequiresAllowedGroups: allowedGroups is a required
// argument, so an admin must state the bound explicitly; omitting it is a
// validation error and identity is never called.
func TestLinkOidcClientRequiresAllowedGroups(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClientWithHydra(fi, "user-admin", true, "http://sneakers-hydra:4444/")
	var resp struct{ LinkOidcClient struct{ ID string } }
	if err := c.Post(`mutation { linkOidcClient(serviceAccountId:"sa-1", oidcSubject:"c") { id } }`, &resp); err == nil {
		t.Fatal("expected a validation error when allowedGroups is omitted")
	}
	if fi.lastLinkReq != nil {
		t.Fatal("identity LinkOidcClient must not be called without allowedGroups")
	}
}

// TestGqlServiceAccount_OidcAllowedGroupsSurfaced: the bound is observable on
// ServiceAccount, and an unlinked account reports an empty list (not null).
func TestGqlServiceAccount_OidcAllowedGroupsSurfaced(t *testing.T) {
	fi := &fakeIdentity{listSAResp: &identityv1.ListServiceAccountsResponse{ServiceAccounts: []*identityv1.ServiceAccount{
		{Id: "sa-linked", OidcIssuer: "http://sneakers-hydra:4444/", OidcSubject: "c", OidcAllowedGroups: []string{"ci-bots"}},
		{Id: "sa-unlinked"},
	}}}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		ServiceAccounts []struct {
			ID                string
			OidcAllowedGroups []string
		}
	}
	c.MustPost(`query { serviceAccounts { id oidcAllowedGroups } }`, &resp)
	if len(resp.ServiceAccounts) != 2 {
		t.Fatalf("got %d service accounts, want 2", len(resp.ServiceAccounts))
	}
	if got := resp.ServiceAccounts[0].OidcAllowedGroups; !reflect.DeepEqual(got, []string{"ci-bots"}) {
		t.Fatalf("linked oidcAllowedGroups = %q, want [ci-bots]", got)
	}
	if got := resp.ServiceAccounts[1].OidcAllowedGroups; got == nil || len(got) != 0 {
		t.Fatalf("unlinked oidcAllowedGroups = %#v, want empty non-null list", got)
	}
}
