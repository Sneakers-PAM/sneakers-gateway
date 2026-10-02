// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Ory Kratos local-login backend.
// Kratos runs HEADLESS here: the browser never talks to it directly — the
// gateway BFF drives the API (not browser) login flow server-to-server,
// exactly the same shape as KCClient's Keycloak ROPC grant, and hands back
// the same backend-agnostic AuthResult. Selected behind AUTH_BACKEND=kratos
// (cmd/server/main.go); Keycloak stays the unconditional default.
package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
)

// Kratos login coded-error band (gateway 2xxx, auth sub-band 22xx). See
// internal/apperr/codes.go for the registry these mirror. Invalid credentials
// are deliberately NOT one of these — that stays ErrInvalidCredentials.
const (
	codeKratosLoginFlowInit = 2210
	codeKratosVerifyFailed  = 2211
	codeKratosUnreachable   = 2212
	codeKratosWhoamiFailed  = 2213
	codeKratosLogoutFailed  = 2214
)

// kratosLoginFlow is the subset of Ory Kratos's login Flow object
// (GET /self-service/login/api) this client needs.
type kratosLoginFlow struct {
	ID string `json:"id"`
}

// kratosIdentity is the subset of a Kratos Identity object this client
// needs: the identity id and its email trait (the Kratos identity schema
// carries email/first_name/last_name traits).
type kratosIdentity struct {
	ID     string `json:"id"`
	Traits struct {
		Email string `json:"email"`
	} `json:"traits"`
}

// kratosSession is the subset of a Kratos Session object this client needs,
// shared by the login response's embedded session and /sessions/whoami.
type kratosSession struct {
	Active    bool           `json:"active"`
	ExpiresAt time.Time      `json:"expires_at"`
	Identity  kratosIdentity `json:"identity"`
}

// kratosLoginResponse is Kratos's SuccessfulNativeLogin response
// (POST /self-service/login?flow=... on a 200).
type kratosLoginResponse struct {
	SessionToken string        `json:"session_token"`
	Session      kratosSession `json:"session"`
}

// KratosClient implements authClient against Ory Kratos's API (not browser)
// login flow. No cookies are ever set or read — session_token is a bearer the
// caller stores itself (inside the existing sneakers_sid Redis session).
type KratosClient struct {
	publicURL, adminURL string
	http                *http.Client
}

// NewKratosClient constructs a KratosClient against Kratos's public API
// (login/whoami/logout) and admin API (recovery).
func NewKratosClient(publicURL, adminURL string) *KratosClient {
	return &KratosClient{publicURL: publicURL, adminURL: adminURL, http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *KratosClient) get(ctx context.Context, endpoint, bearer string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) // #nosec G704 -- endpoint is the operator-configured Kratos public/admin URL plus a fixed path, never request input
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.http.Do(req) // #nosec G704 -- req targets the operator-configured Kratos URL (see above)
}

func (c *KratosClient) postJSON(ctx context.Context, endpoint string, body any) (*http.Response, error) {
	return c.postJSONAuth(ctx, endpoint, "", body)
}

func (c *KratosClient) postJSONAuth(ctx context.Context, endpoint, bearer string, body any) (*http.Response, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b)) // #nosec G704 -- endpoint is the operator-configured Kratos public/admin URL plus a fixed path, never request input
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.http.Do(req) // #nosec G704 -- req targets the operator-configured Kratos URL (see above)
}

func sessionToAuthResult(sessionToken string, sess kratosSession) AuthResult {
	return AuthResult{
		AccessToken: sessionToken,
		ExpiresAt:   sess.ExpiresAt,
		Subject:     sess.Identity.ID,
		Email:       sess.Identity.Traits.Email,
	}
}

// VerifyPassword runs Kratos's headless API login flow: init the flow, then
// submit the password method. A 400 submitting the password is treated as a
// rejected credential (ErrInvalidCredentials); anything else non-2xx, or a
// response this client cannot parse, is a coded internal error.
func (c *KratosClient) VerifyPassword(ctx context.Context, identifier, password string) (AuthResult, error) {
	initRes, err := c.get(ctx, c.publicURL+"/self-service/login/api", "")
	if err != nil {
		return AuthResult{}, apperr.Coded(codeKratosUnreachable, fmt.Errorf("kratos: init login flow: %w", err))
	}
	defer func() { _ = initRes.Body.Close() }()
	if initRes.StatusCode != http.StatusOK {
		return AuthResult{}, apperr.Coded(codeKratosLoginFlowInit, fmt.Errorf("kratos: init login flow: unexpected status %d", initRes.StatusCode))
	}
	var flow kratosLoginFlow
	if err := json.NewDecoder(initRes.Body).Decode(&flow); err != nil || flow.ID == "" {
		return AuthResult{}, apperr.Coded(codeKratosLoginFlowInit, fmt.Errorf("kratos: decode login flow: %w", err))
	}

	submitURL := c.publicURL + "/self-service/login?flow=" + url.QueryEscape(flow.ID)
	subRes, err := c.postJSON(ctx, submitURL, map[string]string{
		"method": "password", "identifier": identifier, "password": password,
	})
	if err != nil {
		return AuthResult{}, apperr.Coded(codeKratosUnreachable, fmt.Errorf("kratos: submit login: %w", err))
	}
	defer func() { _ = subRes.Body.Close() }()

	if subRes.StatusCode == http.StatusBadRequest {
		return AuthResult{}, ErrInvalidCredentials
	}
	if subRes.StatusCode != http.StatusOK {
		return AuthResult{}, apperr.Coded(codeKratosVerifyFailed, fmt.Errorf("kratos: submit login: unexpected status %d", subRes.StatusCode))
	}
	var lr kratosLoginResponse
	if err := json.NewDecoder(subRes.Body).Decode(&lr); err != nil || lr.SessionToken == "" {
		return AuthResult{}, apperr.Coded(codeKratosVerifyFailed, fmt.Errorf("kratos: decode login response: %w", err))
	}
	return sessionToAuthResult(lr.SessionToken, lr.Session), nil
}

// Refresh validates/extends a Kratos session via /sessions/whoami — Kratos has
// no OAuth refresh grant. An active session returns a fresh AuthResult
// carrying the SAME token with an updated ExpiresAt. An inactive/expired/
// unknown session returns ErrInvalidCredentials.
func (c *KratosClient) Refresh(ctx context.Context, sessionToken string) (AuthResult, error) {
	res, err := c.get(ctx, c.publicURL+"/sessions/whoami", sessionToken)
	if err != nil {
		return AuthResult{}, apperr.Coded(codeKratosUnreachable, fmt.Errorf("kratos: whoami: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return AuthResult{}, ErrInvalidCredentials
	}
	if res.StatusCode != http.StatusOK {
		return AuthResult{}, apperr.Coded(codeKratosWhoamiFailed, fmt.Errorf("kratos: whoami: unexpected status %d", res.StatusCode))
	}
	var sess kratosSession
	if err := json.NewDecoder(res.Body).Decode(&sess); err != nil {
		return AuthResult{}, apperr.Coded(codeKratosWhoamiFailed, fmt.Errorf("kratos: decode whoami: %w", err))
	}
	if !sess.Active {
		return AuthResult{}, ErrInvalidCredentials
	}
	return sessionToAuthResult(sessionToken, sess), nil
}

// Logout best-effort revokes the Kratos session. Every existing caller
// already swallows this error and drops the local session regardless, so a
// failure here is diagnostic only.
func (c *KratosClient) Logout(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return nil
	}
	res, err := c.postJSON(ctx, c.publicURL+"/self-service/logout/api", map[string]string{"session_token": sessionToken})
	if err != nil {
		return apperr.Coded(codeKratosUnreachable, fmt.Errorf("kratos: logout: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode >= 300 {
		return apperr.Coded(codeKratosLogoutFailed, fmt.Errorf("kratos: logout: unexpected status %d", res.StatusCode))
	}
	return nil
}
