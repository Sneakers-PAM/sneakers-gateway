// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc"
)

const oauthUI = "https://sneakers.example.org"

func (f *fakeIdentity) MintUserToken(_ context.Context, in *identityv1.MintUserTokenRequest, _ ...grpc.CallOption) (*identityv1.MintUserTokenResponse, error) {
	f.mintUserTokenReq = in
	return &identityv1.MintUserTokenResponse{Token: "snk_u_minted", Meta: &identityv1.UserToken{Id: "utok-1", UserId: in.GetUserId()}}, nil
}

type oauthFixture struct {
	h   *Handler
	o   *OAuth
	fid *fakeIdentity
	now time.Time
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	fx := &oauthFixture{now: time.Unix(1790000000, 0), fid: &fakeIdentity{verifyOk: true}}
	fx.h = &Handler{Store: NewMemStore(time.Hour), Identity: fx.fid, TTL: time.Hour}
	fx.o = &OAuth{Handler: fx.h, Store: NewMemOAuthStore(), PublicURL: oauthUI, Now: func() time.Time { return fx.now }}
	_ = fx.h.Store.Create(context.Background(), "sid-ada", Session{
		UserID: "u-ada", KeycloakSubject: "kid-ada", CSRFToken: "csrf-ada", MFAVerified: true, ExpiresAt: time.Now().Add(time.Hour),
	})
	fx.fid.resolveRes = &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "u-ada"}}
	return fx
}

func (fx *oauthFixture) do(t *testing.T, method, target string, body []byte, form url.Values, signedIn bool) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	switch {
	case form != nil:
		req = httptest.NewRequest(method, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	default:
		req = httptest.NewRequest(method, target, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	if signedIn {
		req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid-ada"})
		req.Header.Set("X-CSRF-Token", "csrf-ada")
	}
	rec := httptest.NewRecorder()
	fx.o.Routes().ServeHTTP(rec, req)
	return rec
}

func (fx *oauthFixture) register(t *testing.T, redirects ...string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client_name": "Example CLI", "redirect_uris": redirects})
	rec := fx.do(t, http.MethodPost, "/oauth2/register", body, nil, false)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status=%d body=%s", rec.Code, rec.Body)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ClientID
}

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const (
	loopback = "http://127.0.0.1:53682/callback"
	verifier = "a-very-long-pkce-code-verifier-string-of-43+chars"
)

func (fx *oauthFixture) authorize(t *testing.T, clientID string) string {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {loopback},
		"code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"}, "state": {"st-1"},
	}
	rec := fx.do(t, http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil, nil, false)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize: status=%d body=%s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Scheme+"://"+loc.Host != oauthUI || loc.Path != "/oauth/consent" || loc.Query().Get("req") == "" {
		t.Fatalf("authorize must send the browser to the native consent page, got %s", loc)
	}
	return loc.Query().Get("req")
}

func (fx *oauthFixture) approve(t *testing.T, reqID string) (code string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"approve": true, "label": "laptop", "factor": map[string]string{"kind": "totp", "code": "123456"}})
	rec := fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID, body, nil, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: status=%d body=%s", rec.Code, rec.Body)
	}
	var out struct{ Redirect string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	u, _ := url.Parse(out.Redirect)
	if !strings.HasPrefix(out.Redirect, loopback) || u.Query().Get("state") != "st-1" || u.Query().Get("code") == "" {
		t.Fatalf("approve redirect = %q", out.Redirect)
	}
	return u.Query().Get("code")
}

func (fx *oauthFixture) token(t *testing.T, clientID, code, verifierUsed, redirect string) *httptest.ResponseRecorder {
	t.Helper()
	return fx.do(t, http.MethodPost, "/oauth2/token", nil, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifierUsed},
	}, false)
}

func TestOAuthMetadataAdvertisesPKCEAndPublicClients(t *testing.T) {
	fx := newOAuthFixture(t)
	rec := fx.do(t, http.MethodGet, "/.well-known/oauth-authorization-server", nil, nil, false)
	var md map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &md)
	if md["issuer"] != oauthUI || md["authorization_endpoint"] != oauthUI+"/oauth2/authorize" ||
		md["token_endpoint"] != oauthUI+"/oauth2/token" || md["registration_endpoint"] != oauthUI+"/oauth2/register" {
		t.Fatalf("metadata endpoints = %v", md)
	}
	if b, _ := json.Marshal(md["code_challenge_methods_supported"]); string(b) != `["S256"]` {
		t.Fatalf("code_challenge_methods_supported = %s", b)
	}
	if b, _ := json.Marshal(md["token_endpoint_auth_methods_supported"]); string(b) != `["none"]` {
		t.Fatalf("token_endpoint_auth_methods_supported = %s", b)
	}
}

func TestOAuthRegisterAcceptsOnlyLoopbackRedirects(t *testing.T) {
	fx := newOAuthFixture(t)
	for _, bad := range []string{"https://evil.example.org/cb", "http://192.0.2.5:8080/cb", "http://127.0.0.1.evil.example.org/cb", "http://localhost.evil.example.org:80/cb"} {
		body, _ := json.Marshal(map[string]any{"client_name": "x", "redirect_uris": []string{bad}})
		if rec := fx.do(t, http.MethodPost, "/oauth2/register", body, nil, false); rec.Code != http.StatusBadRequest {
			t.Errorf("redirect %q: status=%d, want 400", bad, rec.Code)
		}
	}
	if fx.register(t, loopback, "http://localhost:8123/cb", "http://[::1]:9000/cb") == "" {
		t.Fatal("loopback redirects must register")
	}
}

func TestOAuthAuthorizeNeverRedirectsToAnUnregisteredURI(t *testing.T) {
	fx := newOAuthFixture(t)
	id := fx.register(t, loopback)
	for name, q := range map[string]url.Values{
		"unknown client": {"response_type": {"code"}, "client_id": {"nope"}, "redirect_uri": {loopback}, "code_challenge": {"c"}, "code_challenge_method": {"S256"}},
		"other redirect": {"response_type": {"code"}, "client_id": {id}, "redirect_uri": {"http://127.0.0.1:1/other"}, "code_challenge": {"c"}, "code_challenge_method": {"S256"}},
	} {
		rec := fx.do(t, http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil, nil, false)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: status=%d location=%q, want a 400 with no redirect", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestOAuthAuthorizeRequiresS256(t *testing.T) {
	fx := newOAuthFixture(t)
	id := fx.register(t, loopback)
	q := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {loopback}, "code_challenge": {"plain-challenge"}, "code_challenge_method": {"plain"}, "state": {"s"}}
	rec := fx.do(t, http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil, nil, false)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || !strings.HasPrefix(loc.String(), loopback) || loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("plain PKCE: status=%d location=%s", rec.Code, loc)
	}
}

func TestOAuthConsentRequiresASignedInSession(t *testing.T) {
	fx := newOAuthFixture(t)
	reqID := fx.authorize(t, fx.register(t, loopback))
	if rec := fx.do(t, http.MethodGet, "/oauth2/consent/"+reqID, nil, nil, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("consent without a session: status=%d, want 401", rec.Code)
	}
	rec := fx.do(t, http.MethodGet, "/oauth2/consent/"+reqID, nil, nil, true)
	var out struct{ ClientName string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.ClientName != "Example CLI" {
		t.Fatalf("consent details: status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestOAuthConsentApprovalNeedsAFreshSecondFactor(t *testing.T) {
	fx := newOAuthFixture(t)
	reqID := fx.authorize(t, fx.register(t, loopback))
	fx.fid.verifyOk = false
	body, _ := json.Marshal(map[string]any{"approve": true, "label": "laptop", "factor": map[string]string{"kind": "totp", "code": "000000"}})
	if rec := fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID, body, nil, true); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: status=%d, want 401", rec.Code)
	}
	if fx.fid.verifyReq.GetUserId() != "u-ada" {
		t.Fatalf("factor checked for %q, want the signed-in user", fx.fid.verifyReq.GetUserId())
	}
}

func TestOAuthDenyReturnsAccessDenied(t *testing.T) {
	fx := newOAuthFixture(t)
	reqID := fx.authorize(t, fx.register(t, loopback))
	body, _ := json.Marshal(map[string]any{"approve": false})
	rec := fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID, body, nil, true)
	var out struct{ Redirect string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	u, _ := url.Parse(out.Redirect)
	if u.Query().Get("error") != "access_denied" || u.Query().Get("code") != "" {
		t.Fatalf("deny redirect = %q", out.Redirect)
	}
}

func TestOAuthFullFlowIssuesANonExpiringPersonalToken(t *testing.T) {
	fx := newOAuthFixture(t)
	clientID := fx.register(t, loopback)
	code := fx.approve(t, fx.authorize(t, clientID))

	rec := fx.token(t, clientID, code, verifier, loopback)
	if rec.Code != http.StatusOK {
		t.Fatalf("token: status=%d body=%s", rec.Code, rec.Body)
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["access_token"] != "snk_u_minted" || out["token_type"] != "Bearer" {
		t.Fatalf("token response = %v", out)
	}
	if _, has := out["expires_in"]; has {
		t.Fatal("a personal token must not advertise an expiry")
	}
	if _, has := out["refresh_token"]; has {
		t.Fatal("no refresh token is issued")
	}
	if r := fx.fid.mintUserTokenReq; r.GetUserId() != "u-ada" || r.GetLabel() != "laptop" || r.GetClientName() != "Example CLI" {
		t.Fatalf("MintUserToken request = %+v", r)
	}
}

func TestOAuthTokenRejectsBadExchanges(t *testing.T) {
	fx := newOAuthFixture(t)
	clientID := fx.register(t, loopback)
	other := fx.register(t, loopback)

	cases := []struct {
		name                      string
		client, verifier, redirct string
		after                     time.Duration
	}{
		{"wrong verifier", clientID, "not-the-verifier-not-the-verifier-not-it", loopback, 0},
		{"wrong client", other, verifier, loopback, 0},
		{"wrong redirect", clientID, verifier, "http://127.0.0.1:53682/other", 0},
		{"expired code", clientID, verifier, loopback, 2 * time.Minute},
	}
	for _, c := range cases {
		code := fx.approve(t, fx.authorize(t, clientID))
		fx.now = fx.now.Add(c.after)
		rec := fx.token(t, c.client, code, c.verifier, c.redirct)
		var out map[string]string
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != http.StatusBadRequest || out["error"] != "invalid_grant" {
			t.Errorf("%s: status=%d body=%s, want 400 invalid_grant", c.name, rec.Code, rec.Body)
		}
	}
}

func TestOAuthCodeIsSingleUse(t *testing.T) {
	fx := newOAuthFixture(t)
	clientID := fx.register(t, loopback)
	code := fx.approve(t, fx.authorize(t, clientID))
	if rec := fx.token(t, clientID, code, verifier, loopback); rec.Code != http.StatusOK {
		t.Fatalf("first exchange: %d", rec.Code)
	}
	if rec := fx.token(t, clientID, code, verifier, loopback); rec.Code != http.StatusBadRequest {
		t.Fatalf("reused code: status=%d, want 400", rec.Code)
	}
}

func TestOAuthConsentCanEmailACodeToTheSignedInUser(t *testing.T) {
	fx := newOAuthFixture(t)
	reqID := fx.authorize(t, fx.register(t, loopback))
	if rec := fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID+"/email-code", nil, nil, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("without a session: status=%d, want 401", rec.Code)
	}
	rec := fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID+"/email-code", nil, nil, true)
	if rec.Code != http.StatusOK || fx.fid.sendEmailReq.GetUserId() != "u-ada" || fx.fid.sendEmailReq.GetPurpose() != mfaLoginPurpose {
		t.Fatalf("status=%d request=%+v", rec.Code, fx.fid.sendEmailReq)
	}
}

func TestOAuthConsentPasskeyBeginReturnsAChallenge(t *testing.T) {
	fx := newOAuthFixture(t)
	fx.fid.waAssertBeginResp = &identityv1.WebauthnAssertBeginResponse{OptionsJson: `{"challenge":"x"}`, SessionId: "wa-1"}
	reqID := fx.authorize(t, fx.register(t, loopback))
	rec := fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID+"/passkey/begin", nil, nil, true)
	var out struct{ Options, WebauthnSessionID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || fx.fid.waAssertBeginReq.GetUserId() != "u-ada" || out.Options != `{"challenge":"x"}` || out.WebauthnSessionID != "wa-1" {
		t.Fatalf("status=%d out=%+v req=%+v", rec.Code, out, fx.fid.waAssertBeginReq)
	}
}
