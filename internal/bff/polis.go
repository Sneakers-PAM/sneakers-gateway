// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Polis (BoxyHQ SAML Jackson) OAuth-façade client for single-domain SSO over
// ONE static connection: tenant and product are baked into the client at
// construction, not passed per authorize call. Jackson exposes SAML behind an OAuth2/OIDC
// code flow with a fixed dummy client id/secret (CLIENT_SECRET_VERIFIER=dummy
// on the Jackson side); connection selection is by tenant+product only.
package bff

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
)

const polisDummy = "dummy"

const (
	codePolisState        = 2215
	codePolisCodeExchange = 2216
	codePolisUserInfo     = 2217
)

// PolisProfile is the subset of Jackson's /api/oauth/userinfo response we use.
type PolisProfile struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
}

// PolisClient talks to a single static Jackson SAML connection.
//   - publicURL: browser-facing base incl. any /sso path prefix (POLIS_PUBLIC_URL).
//   - issuerURL: in-cluster base for token/userinfo (POLIS_ISSUER_URL).
//   - product/tenant: the ONE fixed connection selector.
type PolisClient struct {
	publicURL string
	issuerURL string
	product   string
	tenant    string
	http      *http.Client
}

func NewPolisClient(publicURL, issuerURL, product, tenant string) *PolisClient {
	return &PolisClient{
		publicURL: strings.TrimRight(publicURL, "/"),
		issuerURL: strings.TrimRight(issuerURL, "/"),
		product:   product,
		tenant:    tenant,
		http:      &http.Client{Timeout: 10 * time.Second},
	}
}

// AuthorizeURL builds the browser redirect to Jackson's authorize endpoint for
// the single fixed tenant+product. No PKCE (Jackson's SAML flow does not use it).
func (c *PolisClient) AuthorizeURL(redirectURI, state string) string {
	q := url.Values{
		"response_type": {"code"},
		"client_id":     {polisDummy},
		"redirect_uri":  {redirectURI},
		"state":         {state},
		"scope":         {"openid"},
		"product":       {c.product},
		"tenant":        {c.tenant},
	}
	return c.publicURL + "/api/oauth/authorize?" + q.Encode()
}

// CodeExchange swaps the authorization code for an opaque access token.
func (c *PolisClient) CodeExchange(ctx context.Context, code, redirectURI string) (Tokens, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {polisDummy},
		"client_secret": {polisDummy},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.issuerURL+"/api/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, apperr.Coded(codePolisCodeExchange, fmt.Errorf("polis: build token request: %w", err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return Tokens{}, apperr.Coded(codePolisCodeExchange, fmt.Errorf("polis: token request: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return Tokens{}, apperr.Coded(codePolisCodeExchange, fmt.Errorf("polis: token status %d: %s", res.StatusCode, body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil || out.AccessToken == "" {
		return Tokens{}, apperr.Coded(codePolisCodeExchange, fmt.Errorf("polis: decode token: %w", err))
	}
	return Tokens{AccessToken: out.AccessToken, ExpiresIn: out.ExpiresIn}, nil
}

// UserInfo fetches the federated profile. A missing email is fatal (2217): the
// callback resolves the platform user by email, so no email means no login.
func (c *PolisClient) UserInfo(ctx context.Context, accessToken string) (PolisProfile, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.issuerURL+"/api/oauth/userinfo", nil)
	if err != nil {
		return PolisProfile{}, apperr.Coded(codePolisUserInfo, fmt.Errorf("polis: build userinfo request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return PolisProfile{}, apperr.Coded(codePolisUserInfo, fmt.Errorf("polis: userinfo request: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return PolisProfile{}, apperr.Coded(codePolisUserInfo, fmt.Errorf("polis: userinfo status %d", res.StatusCode))
	}
	var p PolisProfile
	if err := json.NewDecoder(res.Body).Decode(&p); err != nil {
		return PolisProfile{}, apperr.Coded(codePolisUserInfo, fmt.Errorf("polis: decode userinfo: %w", err))
	}
	if p.Email == "" {
		return PolisProfile{}, apperr.Coded(codePolisUserInfo, fmt.Errorf("polis: userinfo carried no email"))
	}
	return p, nil
}
