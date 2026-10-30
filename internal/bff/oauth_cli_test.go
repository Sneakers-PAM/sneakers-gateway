// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func (fx *oauthFixture) registerAs(t *testing.T, softwareID string) string {
	t.Helper()
	in := map[string]any{"client_name": "sneakers-put", "redirect_uris": []string{loopback}}
	if softwareID != "" {
		in["software_id"] = softwareID
	}
	body, _ := json.Marshal(in)
	rec := fx.do(t, http.MethodPost, "/oauth2/register", body, nil, false)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register %q: status=%d body=%s", softwareID, rec.Code, rec.Body)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ClientID
}

func TestOAuthMintsACLITokenForAClientThatSaysItIsTheCLI(t *testing.T) {
	fx := newOAuthFixture(t)
	clientID := fx.registerAs(t, CLISoftwareID)
	code := fx.approve(t, fx.authorize(t, clientID))
	if rec := fx.token(t, clientID, code, verifier, loopback); rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", rec.Code, rec.Body)
	}
	if got := fx.fid.mintUserTokenReq.GetClientKind(); got != ClientKindCLI {
		t.Fatalf("client_kind = %q, want %s", got, ClientKindCLI)
	}
}

func TestOAuthTreatsAnUnknownSoftwareIDAsAnMCPClient(t *testing.T) {
	fx := newOAuthFixture(t)
	clientID := fx.registerAs(t, "some-agent")
	code := fx.approve(t, fx.authorize(t, clientID))
	if rec := fx.token(t, clientID, code, verifier, loopback); rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", rec.Code, rec.Body)
	}
	if got := fx.fid.mintUserTokenReq.GetClientKind(); got != ClientKindMCP {
		t.Fatalf("client_kind = %q, want %s", got, ClientKindMCP)
	}
}

func TestOAuthMCPOffStillSignsInTheCLI(t *testing.T) {
	fx := newOAuthFixture(t)
	fx.o.MCPDisabled = true
	if rec := fx.do(t, http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil, false); rec.Code != http.StatusOK {
		t.Fatalf("metadata: status=%d body=%s", rec.Code, rec.Body)
	}
	clientID := fx.registerAs(t, CLISoftwareID)
	reqID := fx.authorize(t, clientID)
	if rec := fx.do(t, http.MethodGet, "/oauth2/consent/"+reqID, nil, nil, true); rec.Code != http.StatusOK {
		t.Fatalf("consent details: status=%d body=%s", rec.Code, rec.Body)
	}
	code := fx.approve(t, reqID)
	if rec := fx.token(t, clientID, code, verifier, loopback); rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", rec.Code, rec.Body)
	}
	if got := fx.fid.mintUserTokenReq.GetClientKind(); got != ClientKindCLI {
		t.Fatalf("client_kind = %q, want %s", got, ClientKindCLI)
	}
}

func TestOAuthMCPOffRefusesToRegisterAnMCPClient(t *testing.T) {
	fx := newOAuthFixture(t)
	fx.o.MCPDisabled = true
	for _, softwareID := range []string{"", "some-agent"} {
		in := map[string]any{"client_name": "agent", "redirect_uris": []string{loopback}}
		if softwareID != "" {
			in["software_id"] = softwareID
		}
		body, _ := json.Marshal(in)
		rec := fx.do(t, http.MethodPost, "/oauth2/register", body, nil, false)
		if rec.Code != http.StatusForbidden || refusalCode(t, rec) != CodeMCPDisabled {
			t.Fatalf("software_id %q: status=%d body=%s", softwareID, rec.Code, rec.Body)
		}
	}
}

// An MCP client registered, or a consent started, while the MCP was on is
// refused at every later step once it's off.
func TestOAuthMCPOffRefusesAnMCPClientAtEveryStep(t *testing.T) {
	fx := newOAuthFixture(t)
	clientID := fx.registerAs(t, "")
	reqID := fx.authorize(t, clientID)
	code := fx.approve(t, fx.authorize(t, clientID))
	fx.o.MCPDisabled = true

	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {loopback},
		"code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"}, "state": {"st-1"},
	}
	approve, _ := json.Marshal(map[string]any{"approve": true, "factor": map[string]string{"kind": "totp", "code": "123456"}})
	steps := []struct {
		name string
		do   func() *http.Response
	}{
		{"authorize", func() *http.Response {
			return fx.do(t, http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil, nil, false).Result()
		}},
		{"consent details", func() *http.Response {
			return fx.do(t, http.MethodGet, "/oauth2/consent/"+reqID, nil, nil, true).Result()
		}},
		{"email code", func() *http.Response {
			return fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID+"/email-code", nil, nil, true).Result()
		}},
		{"passkey begin", func() *http.Response {
			return fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID+"/passkey/begin", nil, nil, true).Result()
		}},
		{"consent", func() *http.Response {
			return fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID, approve, nil, true).Result()
		}},
		{"token", func() *http.Response { return fx.token(t, clientID, code, verifier, loopback).Result() }},
	}
	for _, step := range steps {
		res := step.do()
		var body struct{ Error string }
		_ = json.NewDecoder(res.Body).Decode(&body)
		_ = res.Body.Close()
		if res.StatusCode != http.StatusForbidden || body.Error != CodeMCPDisabled {
			t.Errorf("%s: status=%d error=%q, want 403 %s", step.name, res.StatusCode, body.Error, CodeMCPDisabled)
		}
	}
	if fx.fid.mintUserTokenReq != nil {
		t.Fatal("an MCP token was minted while the MCP is off")
	}
}
