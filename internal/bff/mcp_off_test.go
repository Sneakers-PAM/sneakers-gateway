// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

func userTokenIdentity(kind string) *fakeIdentity {
	return &fakeIdentity{verifyUserTokenResp: &identityv1.VerifyUserTokenResponse{
		Valid: true, TokenId: "utok-1", ClientKind: kind, User: &identityv1.User{Id: "u-ada"},
	}}
}

func serveMachineRec(h *Handler, bearer string) (*httptest.ResponseRecorder, bool) {
	ran := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran = true })
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rec := httptest.NewRecorder()
	h.MachineActor(next).ServeHTTP(rec, req)
	return rec, ran
}

func refusalCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct{ Error, Message string }
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal body %q: %v", rec.Body, err)
	}
	return body.Error
}

func TestMCPOffRefusesAnMCPAgentToken(t *testing.T) {
	rec, ran := serveMachineRec(&Handler{Identity: userTokenIdentity("mcp"), MCPDisabled: true}, "snk_u_agent")
	if ran || rec.Code != http.StatusForbidden || refusalCode(t, rec) != CodeMCPDisabled {
		t.Fatalf("ran=%v status=%d body=%s", ran, rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "MCP is turned off on this appliance (setting mcp.enabled)") {
		t.Fatalf("the refusal doesn't name the setting: %s", rec.Body)
	}
}

func TestMCPOffKeepsCLITokensWorking(t *testing.T) {
	for _, kind := range []string{"cli", ""} {
		rec, ran := serveMachineRec(&Handler{Identity: userTokenIdentity(kind), MCPDisabled: true}, "snk_u_cli")
		if !ran || rec.Code != http.StatusOK {
			t.Fatalf("kind %q: ran=%v status=%d", kind, ran, rec.Code)
		}
	}
}

func TestMCPOffRefusesAHydraJWT(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln"
	rec, ran := serveMachineRec(&Handler{Identity: &fakeIdentity{}, MCPDisabled: true}, jwt)
	if ran || rec.Code != http.StatusForbidden || refusalCode(t, rec) != CodeMCPDisabled {
		t.Fatalf("ran=%v status=%d body=%s", ran, rec.Code, rec.Body)
	}
}

func TestMCPOnLetsAnAgentTokenThrough(t *testing.T) {
	rec, ran := serveMachineRec(&Handler{Identity: userTokenIdentity("mcp")}, "snk_u_agent")
	if !ran || rec.Code != http.StatusOK {
		t.Fatalf("ran=%v status=%d", ran, rec.Code)
	}
}

func TestMCPOffAnswersTheOAuthRoutes(t *testing.T) {
	for _, path := range []string{"/oauth2/token", "/oauth2/register", "/.well-known/oauth-authorization-server"} {
		rec := httptest.NewRecorder()
		MCPOff().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		if rec.Code != http.StatusForbidden || refusalCode(t, rec) != CodeMCPDisabled {
			t.Fatalf("%s: status=%d body=%s", path, rec.Code, rec.Body)
		}
	}
}

func TestOAuthMintsAnMCPToken(t *testing.T) {
	fx := newOAuthFixture(t)
	clientID := fx.register(t, loopback)
	code := fx.approve(t, fx.authorize(t, clientID))
	if rec := fx.token(t, clientID, code, verifier, loopback); rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", rec.Code, rec.Body)
	}
	if got := fx.fid.mintUserTokenReq.GetClientKind(); got != ClientKindMCP {
		t.Fatalf("client_kind = %q, want %s", got, ClientKindMCP)
	}
}
