// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package bff: single static Polis SAML connection provisioner. ONE
// connection driven from config: no per-org CreateConnection/DeleteConnection
// surface, no domain-verify. Called at /setup day-0 (idempotent) so SSO works
// from first boot.
package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	apperr "github.com/Bugs5382/go-apperr"
)

const jacksonSSOPath = "/api/v1/sso"

// JacksonProvisioner ensures the ONE static SAML connection exists in Jackson.
type JacksonProvisioner struct {
	adminURL        string
	apiKey          string
	product         string
	tenant          string
	gatewayBaseURL  string
	samlMetadataURL string
	http            *http.Client
}

// NewJacksonProvisioner builds a JacksonProvisioner from the single-connection
// config (admin API URL/key, product/tenant, gateway base URL, and the IdP's
// SAML metadata URL).
func NewJacksonProvisioner(adminURL, apiKey, product, tenant, gatewayBaseURL, samlMetadataURL string) *JacksonProvisioner {
	return &JacksonProvisioner{
		adminURL: adminURL, apiKey: apiKey, product: product, tenant: tenant,
		gatewayBaseURL: gatewayBaseURL, samlMetadataURL: samlMetadataURL,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// EnsureConnection POSTs the single connection to Jackson's admin API. Jackson
// upserts a connection keyed by (tenant, product), so re-running at every
// /setup is idempotent.
func (p *JacksonProvisioner) EnsureConnection(ctx context.Context) error {
	redirectAllow, _ := json.Marshal([]string{p.gatewayBaseURL + "/*"})
	form := url.Values{
		"tenant":             {p.tenant},
		"product":            {p.product},
		"name":               {"Sneakers SSO"},
		"description":        {"Sneakers single-domain SAML SSO for " + p.tenant},
		"defaultRedirectUrl": {p.gatewayBaseURL + "/auth/sso/callback"},
		"redirectUrl":        {string(redirectAllow)},
		"metadataUrl":        {p.samlMetadataURL},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.adminURL+jacksonSSOPath, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return apperr.Coded(codePolisState, fmt.Errorf("jackson: build request: %w", err))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Api-Key "+p.apiKey)
	res, err := p.http.Do(req)
	if err != nil {
		return apperr.Coded(codePolisState, fmt.Errorf("jackson: request: %w", err))
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return apperr.Coded(codePolisState, fmt.Errorf("jackson: create connection status %d: %s", res.StatusCode, body))
	}
	return nil
}
