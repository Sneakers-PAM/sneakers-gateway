// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrTokenVerifyFailed is returned by kcVerifiedAuth.VerifyPassword (see
// authclient.go) when Keycloak's password grant itself succeeded (so the
// credentials were correct) but the freshly-issued access token fails
// cryptographic JWKS verification (signature/iss/aud/time) — a JWKS/issuer
// misconfig or a key-rotation glitch, never a bad password. Login (http.go)
// maps this to its own distinct 401 {"error": "token_verify"}, kept separate
// from ErrInvalidCredentials's {"error": "invalid_credentials"} so an operator
// can tell "wrong password" from "Keycloak trust chain is broken" — the same
// distinction resolveSessionActor already preserves per-request via its own
// "token_verify" sentinel.
var ErrTokenVerifyFailed = errors.New("token_verify")

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	SessionState string `json:"session_state"`
}

type KCClient struct {
	tokenURL, logoutURL, clientID, clientSecret string
	http                                        *http.Client
}

func NewKCClient(tokenURL, logoutURL, clientID, clientSecret string) *KCClient {
	return &KCClient{tokenURL: tokenURL, logoutURL: logoutURL, clientID: clientID, clientSecret: clientSecret,
		http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *KCClient) post(ctx context.Context, endpoint string, form url.Values) (*http.Response, error) {
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode())) // #nosec G704 -- endpoint is the operator-configured Keycloak token/logout URL, never request input
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.http.Do(req) // #nosec G704 -- req targets the operator-configured Keycloak URL (see above)
}

func (c *KCClient) grant(ctx context.Context, form url.Values) (Tokens, error) {
	res, err := c.post(ctx, c.tokenURL, form)
	if err != nil {
		return Tokens{}, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusBadRequest {
		return Tokens{}, ErrInvalidCredentials
	}
	if res.StatusCode != http.StatusOK {
		return Tokens{}, fmt.Errorf("keycloak: unexpected status %d", res.StatusCode)
	}
	var t Tokens
	if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
		return Tokens{}, err
	}
	return t, nil
}

func (c *KCClient) PasswordGrant(ctx context.Context, username, password string) (Tokens, error) {
	// preferred_username (the login handle used to adopt the identity user) and
	// email come from the client's DEFAULT scopes (profile/email), so a plain
	// openid grant carries them — no explicit scope request (which requires the
	// scopes be assigned to the client and 400s with invalid_scope otherwise).
	return c.grant(ctx, url.Values{"grant_type": {"password"}, "username": {username}, "password": {password}, "scope": {"openid"}})
}

func (c *KCClient) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	return c.grant(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

func (c *KCClient) Logout(ctx context.Context, refreshToken string) error {
	res, err := c.post(ctx, c.logoutURL, url.Values{"refresh_token": {refreshToken}})
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode >= 300 {
		return fmt.Errorf("keycloak logout: status %d", res.StatusCode)
	}
	return nil
}
