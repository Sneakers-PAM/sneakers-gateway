// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

// Service-account + API-token admin GraphQL:
// site-admin-only management of machine principals on the HUMAN /graphql
// schema, distinct from the machine /machine/graphql reveal endpoint. Every
// resolver here must fail closed for a non-site-admin caller, and the
// GraphQL ApiToken type must never carry a token value (only
// MintApiTokenResult does, once, at mint time).

import (
	"context"
	"errors"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc"
)

// fakeIdentity embeds the (nil) full generated client interface so it
// satisfies identityv1.IdentityServiceClient; only the SA/token methods a
// test exercises are overridden. Any other call would panic — fine, these
// tests don't make them.
type fakeIdentity struct {
	identityv1.IdentityServiceClient

	lastCreateReq  *identityv1.CreateServiceAccountRequest
	createResp     *identityv1.CreateServiceAccountResponse
	createErr      error
	listSAResp     *identityv1.ListServiceAccountsResponse
	listSAErr      error
	lastDisableReq *identityv1.DisableServiceAccountRequest
	disableResp    *identityv1.DisableServiceAccountResponse
	disableErr     error
	lastMintReq    *identityv1.MintApiTokenRequest
	mintResp       *identityv1.MintApiTokenResponse
	mintErr        error
	lastListReq    *identityv1.ListApiTokensRequest
	listTokResp    *identityv1.ListApiTokensResponse
	listTokErr     error
	lastRevokeReq  *identityv1.RevokeApiTokenRequest
	revokeResp     *identityv1.RevokeApiTokenResponse
	revokeErr      error

	// OIDC client-link admin stubs.
	lastLinkReq   *identityv1.LinkOidcClientRequest
	linkResp      *identityv1.LinkOidcClientResponse
	linkErr       error
	lastUnlinkReq *identityv1.UnlinkOidcClientRequest
	unlinkResp    *identityv1.UnlinkOidcClientResponse
	unlinkErr     error
}

func (f *fakeIdentity) CreateServiceAccount(_ context.Context, in *identityv1.CreateServiceAccountRequest, _ ...grpc.CallOption) (*identityv1.CreateServiceAccountResponse, error) {
	f.lastCreateReq = in
	if f.createErr != nil {
		return nil, f.createErr
	}
	if f.createResp != nil {
		return f.createResp, nil
	}
	return &identityv1.CreateServiceAccountResponse{ServiceAccount: &identityv1.ServiceAccount{Id: "sa-1", Name: in.GetName(), Description: in.GetDescription(), CreatedBy: in.GetCreatedBy()}}, nil
}

func (f *fakeIdentity) ListServiceAccounts(_ context.Context, _ *identityv1.ListServiceAccountsRequest, _ ...grpc.CallOption) (*identityv1.ListServiceAccountsResponse, error) {
	if f.listSAErr != nil {
		return nil, f.listSAErr
	}
	if f.listSAResp != nil {
		return f.listSAResp, nil
	}
	return &identityv1.ListServiceAccountsResponse{ServiceAccounts: []*identityv1.ServiceAccount{
		{Id: "sa-1", Name: "ci-bot", Description: "CI automation", CreatedBy: "user-admin", CreatedAtUnix: 1700000000},
	}}, nil
}

func (f *fakeIdentity) DisableServiceAccount(_ context.Context, in *identityv1.DisableServiceAccountRequest, _ ...grpc.CallOption) (*identityv1.DisableServiceAccountResponse, error) {
	f.lastDisableReq = in
	if f.disableErr != nil {
		return nil, f.disableErr
	}
	if f.disableResp != nil {
		return f.disableResp, nil
	}
	return &identityv1.DisableServiceAccountResponse{ServiceAccount: &identityv1.ServiceAccount{Id: in.GetId(), Name: "ci-bot", Disabled: true}}, nil
}

func (f *fakeIdentity) MintApiToken(_ context.Context, in *identityv1.MintApiTokenRequest, _ ...grpc.CallOption) (*identityv1.MintApiTokenResponse, error) {
	f.lastMintReq = in
	if f.mintErr != nil {
		return nil, f.mintErr
	}
	if f.mintResp != nil {
		return f.mintResp, nil
	}
	return &identityv1.MintApiTokenResponse{
		Token: "plaintext-token-abc123",
		Meta: &identityv1.ApiToken{
			Id: "tok-1", ServiceAccountId: in.GetServiceAccountId(), Scope: in.GetScope(),
			ExpiresAtUnix: in.GetExpiresAtUnix(), CreatedBy: in.GetCreatedBy(),
		},
	}, nil
}

func (f *fakeIdentity) ListApiTokens(_ context.Context, in *identityv1.ListApiTokensRequest, _ ...grpc.CallOption) (*identityv1.ListApiTokensResponse, error) {
	f.lastListReq = in
	if f.listTokErr != nil {
		return nil, f.listTokErr
	}
	if f.listTokResp != nil {
		return f.listTokResp, nil
	}
	return &identityv1.ListApiTokensResponse{Tokens: []*identityv1.ApiToken{
		{Id: "tok-1", ServiceAccountId: in.GetServiceAccountId(), Scope: "secrets-ci", ExpiresAtUnix: 1800000000, CreatedBy: "user-admin"},
	}}, nil
}

func (f *fakeIdentity) RevokeApiToken(_ context.Context, in *identityv1.RevokeApiTokenRequest, _ ...grpc.CallOption) (*identityv1.RevokeApiTokenResponse, error) {
	f.lastRevokeReq = in
	if f.revokeErr != nil {
		return nil, f.revokeErr
	}
	if f.revokeResp != nil {
		return f.revokeResp, nil
	}
	return &identityv1.RevokeApiTokenResponse{Meta: &identityv1.ApiToken{Id: in.GetId(), RevokedAtUnix: 1700000100}}, nil
}

func (f *fakeIdentity) LinkOidcClient(_ context.Context, in *identityv1.LinkOidcClientRequest, _ ...grpc.CallOption) (*identityv1.LinkOidcClientResponse, error) {
	f.lastLinkReq = in
	if f.linkErr != nil {
		return nil, f.linkErr
	}
	if f.linkResp != nil {
		return f.linkResp, nil
	}
	return &identityv1.LinkOidcClientResponse{ServiceAccount: &identityv1.ServiceAccount{
		Id: in.GetServiceAccountId(), Name: "ci-bot", OidcIssuer: in.GetOidcIssuer(), OidcSubject: in.GetOidcSubject(),
	}}, nil
}

func (f *fakeIdentity) UnlinkOidcClient(_ context.Context, in *identityv1.UnlinkOidcClientRequest, _ ...grpc.CallOption) (*identityv1.UnlinkOidcClientResponse, error) {
	f.lastUnlinkReq = in
	if f.unlinkErr != nil {
		return nil, f.unlinkErr
	}
	if f.unlinkResp != nil {
		return f.unlinkResp, nil
	}
	return &identityv1.UnlinkOidcClientResponse{ServiceAccount: &identityv1.ServiceAccount{Id: in.GetServiceAccountId(), Name: "ci-bot"}}, nil
}

// newIdentityClient wires the gqlgen handler over a fake identity client,
// injecting a fixed actor and (optionally) site-admin authz — mirroring
// newClient/newSSHClient but also setting WithActorInfo, since these
// resolvers gate on requireAdmin (site-admin/root), not just an acting user.
func newIdentityClient(fi *fakeIdentity, actor string, siteAdmin bool) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: fi}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActor(r.Context(), actor)
		ctx = WithActorInfo(ctx, siteAdmin, false, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
	return gqlclient.New(wrapped)
}

func mustDenied(t *testing.T, err error, op string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected permission-denied error for non-site-admin caller, got nil", op)
	}
}

func TestServiceAccountAdminOpsDenyNonSiteAdmin(t *testing.T) {
	fi := &fakeIdentity{}

	cases := []struct {
		name  string
		query string
	}{
		{"serviceAccounts", `{ serviceAccounts { id } }`},
		{"apiTokens", `{ apiTokens(serviceAccountId:"sa-1") { id } }`},
		{"createServiceAccount", `mutation { createServiceAccount(name:"bot", description:"d") { id } }`},
		{"disableServiceAccount", `mutation { disableServiceAccount(id:"sa-1") { id } }`},
		{"mintApiToken", `mutation { mintApiToken(serviceAccountId:"sa-1", scope:"s") { token apiToken { id } } }`},
		{"revokeApiToken", `mutation { revokeApiToken(id:"tok-1") { id } }`},
		{"linkOidcClient", `mutation { linkOidcClient(serviceAccountId:"sa-1", oidcSubject:"client-1", allowedGroups:["g"]) { id } }`},
		{"unlinkOidcClient", `mutation { unlinkOidcClient(serviceAccountId:"sa-1") { id } }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newIdentityClient(fi, "user-nobody", false)
			var resp map[string]any
			err := c.Post(tc.query, &resp)
			mustDenied(t, err, tc.name)
		})
	}
}

func TestServiceAccountsListsForSiteAdmin(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		ServiceAccounts []struct {
			ID, Name, Description, CreatedBy string
			Disabled                         bool
			CreatedAtUnix                    int
		}
	}
	c.MustPost(`{ serviceAccounts { id name description disabled createdBy createdAtUnix } }`, &resp)
	if len(resp.ServiceAccounts) != 1 || resp.ServiceAccounts[0].ID != "sa-1" {
		t.Fatalf("serviceAccounts = %+v, want one sa-1", resp.ServiceAccounts)
	}
}

func TestCreateServiceAccountForwardsActorAsCreatedBy(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		CreateServiceAccount struct{ ID, Name, Description string }
	}
	c.MustPost(`mutation { createServiceAccount(name:"ci-bot", description:"CI automation") { id name description } }`, &resp)
	if fi.lastCreateReq.GetCreatedBy() != "user-admin" {
		t.Fatalf("createdBy = %q, want user-admin", fi.lastCreateReq.GetCreatedBy())
	}
	if resp.CreateServiceAccount.Name != "ci-bot" {
		t.Fatalf("name = %q, want ci-bot", resp.CreateServiceAccount.Name)
	}
}

func TestDisableServiceAccountReturnsUpdatedAccount(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		DisableServiceAccount struct {
			ID       string
			Disabled bool
		}
	}
	c.MustPost(`mutation { disableServiceAccount(id:"sa-1") { id disabled } }`, &resp)
	if fi.lastDisableReq.GetId() != "sa-1" {
		t.Fatalf("disable id = %q, want sa-1", fi.lastDisableReq.GetId())
	}
	if !resp.DisableServiceAccount.Disabled {
		t.Fatal("disabled = false, want true")
	}
}

func TestMintApiTokenReturnsTokenOnceAndMetadata(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		MintApiToken struct {
			Token    string
			ApiToken struct {
				ID               string
				ServiceAccountID string
				Scope            string
			}
		}
	}
	c.MustPost(`mutation { mintApiToken(serviceAccountId:"sa-1", scope:"secrets-ci") { token apiToken { id serviceAccountId scope } } }`, &resp)
	if resp.MintApiToken.Token == "" {
		t.Fatal("token = empty, want a non-empty plaintext token")
	}
	if resp.MintApiToken.ApiToken.ID == "" || resp.MintApiToken.ApiToken.ServiceAccountID != "sa-1" || resp.MintApiToken.ApiToken.Scope != "secrets-ci" {
		t.Fatalf("apiToken metadata = %+v, want populated sa-1/secrets-ci", resp.MintApiToken.ApiToken)
	}
	if fi.lastMintReq.GetCreatedBy() != "user-admin" {
		t.Fatalf("createdBy = %q, want user-admin", fi.lastMintReq.GetCreatedBy())
	}
}

// TestApiTokenTypeHasNoTokenField proves the GraphQL ApiToken type never
// exposes a token value: selecting a `token` field on it must be a schema
// validation error, not a runtime nil/empty value that could later leak.
func TestApiTokenTypeHasNoTokenField(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClient(fi, "user-admin", true)
	var resp map[string]any
	err := c.Post(`{ apiTokens(serviceAccountId:"sa-1") { id token } }`, &resp)
	if err == nil {
		t.Fatal("expected a schema validation error selecting ApiToken.token, got nil (ApiToken must not expose a token field)")
	}
}

func TestApiTokensListsMetadataOnly(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		APITokens []struct {
			ID, ServiceAccountID, Scope, CreatedBy       string
			ExpiresAtUnix, RevokedAtUnix, LastUsedAtUnix int
		}
	}
	c.MustPost(`{ apiTokens(serviceAccountId:"sa-1") { id serviceAccountId scope expiresAtUnix revokedAtUnix lastUsedAtUnix createdBy } }`, &resp)
	if len(resp.APITokens) != 1 || resp.APITokens[0].ID != "tok-1" {
		t.Fatalf("apiTokens = %+v, want one tok-1", resp.APITokens)
	}
	if fi.lastListReq.GetServiceAccountId() != "sa-1" {
		t.Fatalf("serviceAccountId forwarded = %q, want sa-1", fi.lastListReq.GetServiceAccountId())
	}
}

func TestRevokeApiTokenReturnsUpdatedMetadata(t *testing.T) {
	fi := &fakeIdentity{}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		RevokeApiToken struct {
			ID            string
			RevokedAtUnix int
		}
	}
	c.MustPost(`mutation { revokeApiToken(id:"tok-1") { id revokedAtUnix } }`, &resp)
	if fi.lastRevokeReq.GetId() != "tok-1" {
		t.Fatalf("revoke id = %q, want tok-1", fi.lastRevokeReq.GetId())
	}
	if resp.RevokeApiToken.RevokedAtUnix == 0 {
		t.Fatal("revokedAtUnix = 0, want a non-zero revocation timestamp")
	}
}

func TestServiceAccountAdminOpsPropagateIdentityErrors(t *testing.T) {
	fi := &fakeIdentity{createErr: errors.New("identity: down")}
	c := newIdentityClient(fi, "user-admin", true)
	var resp struct {
		CreateServiceAccount struct{ ID string }
	}
	if err := c.Post(`mutation { createServiceAccount(name:"bot", description:"d") { id } }`, &resp); err == nil {
		t.Fatal("expected identity error to propagate, got nil")
	}
}

// TestRootCanManageServiceAccounts proves requireAdmin's "or root" branch also
// grants these ops (root confers the same authority as site-admin).
func TestRootCanManageServiceAccounts(t *testing.T) {
	fi := &fakeIdentity{}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: fi}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActor(r.Context(), "user-root")
		ctx = WithActorInfo(ctx, false, true, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
	c := gqlclient.New(wrapped)
	var resp struct {
		ServiceAccounts []struct{ ID string }
	}
	c.MustPost(`{ serviceAccounts { id } }`, &resp)
	if len(resp.ServiceAccounts) != 1 {
		t.Fatalf("serviceAccounts = %+v, want one result for root caller", resp.ServiceAccounts)
	}
}
