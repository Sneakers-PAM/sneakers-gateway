// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const (
	privateScheme = "com.example.app:/oauth2redirect"
	claimedLink   = "https://app.example.org/oauth2redirect"
)

func (fx *oauthFixture) tryRegister(t *testing.T, redirect string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client_name": "Example app", "redirect_uris": []string{redirect}})
	return fx.do(t, http.MethodPost, "/oauth2/register", body, nil, false).Code
}

func (fx *oauthFixture) authorizeWith(t *testing.T, clientID, redirect string, extra url.Values) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {challengeFor(verifier)}, "code_challenge_method": {"S256"}, "state": {"st-1"},
	}
	for k, v := range extra {
		q[k] = v
	}
	return fx.do(t, http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil, nil, false)
}

func TestOAuthRegisterAcceptsPrivateUseSchemeAndClaimedHTTPSRedirects(t *testing.T) {
	fx := newOAuthFixture(t)
	for _, ok := range []string{privateScheme, claimedLink, "https://app.example.org:8443/oauth2redirect", loopback} {
		if code := fx.tryRegister(t, ok); code != http.StatusCreated {
			t.Errorf("redirect %q: status=%d, want 201", ok, code)
		}
	}
}

func TestOAuthRegisterRefusesEveryOtherRedirectShape(t *testing.T) {
	fx := newOAuthFixture(t)
	for name, bad := range map[string]string{
		"plain http off loopback":          "http://app.example.org/cb",
		"plain http on a lookalike":        "http://127.0.0.1.example.org/cb",
		"scheme without a reverse domain":  "myapp:/cb",
		"script scheme":                    "javascript:alert(1)",
		"data scheme":                      "data:text/html,x",
		"private scheme with an authority": "com.example.app://host/cb",
		"private scheme with a fragment":   "com.example.app:/cb#frag",
		"private scheme with userinfo":     "com.example.app://user@host/cb",
		"https with a wildcard host":       "https://*.example.org/cb",
		"https with a wildcard path":       "https://app.example.org/*",
		"https with userinfo":              "https://user:pw@app.example.org/cb",
		"https with a fragment":            "https://app.example.org/cb#frag",
		"https without a host":             "https:///cb",
		"https without a path":             "https://app.example.org",
		"a relative reference":             "/oauth2redirect",
		"an empty value":                   "",
	} {
		if code := fx.tryRegister(t, bad); code != http.StatusBadRequest {
			t.Errorf("%s (%q): status=%d, want 400", name, bad, code)
		}
	}
}

func TestOAuthAuthorizeMatchesANonLoopbackRedirectExactly(t *testing.T) {
	fx := newOAuthFixture(t)
	privateID := fx.register(t, privateScheme)
	httpsID := fx.register(t, claimedLink)
	for name, c := range map[string]struct{ id, redirect string }{
		"private scheme, longer path":     {privateID, privateScheme + "/extra"},
		"private scheme, prefix":          {privateID, "com.example.app:/oauth2"},
		"private scheme, other path":      {privateID, "com.example.app:/other"},
		"private scheme, other scheme":    {privateID, "com.example.other:/oauth2redirect"},
		"private scheme, added query":     {privateID, privateScheme + "?x=1"},
		"private scheme, upper case":      {privateID, "com.example.app:/OAuth2Redirect"},
		"https, trailing slash":           {httpsID, claimedLink + "/"},
		"https, other host":               {httpsID, "https://evil.example.org/oauth2redirect"},
		"https, subdomain":                {httpsID, "https://x.app.example.org/oauth2redirect"},
		"https, other port":               {httpsID, "https://app.example.org:8443/oauth2redirect"},
		"https, added query":              {httpsID, claimedLink + "?x=1"},
		"https, downgraded to http":       {httpsID, "http://app.example.org/oauth2redirect"},
		"https, a loopback port is not a": {httpsID, "http://127.0.0.1:1/oauth2redirect"},
	} {
		rec := fx.authorizeWith(t, c.id, c.redirect, nil)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
			t.Errorf("%s: status=%d location=%q, want a 400 with no redirect", name, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestOAuthLoopbackStillIgnoresThePort(t *testing.T) {
	fx := newOAuthFixture(t)
	id := fx.register(t, loopback)
	rec := fx.authorizeWith(t, id, "http://127.0.0.1:61234/callback", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("loopback on another port: status=%d", rec.Code)
	}
}

func TestOAuthFullFlowForAPrivateSchemeAndAClaimedLink(t *testing.T) {
	for _, redirect := range []string{privateScheme, claimedLink} {
		fx := newOAuthFixture(t)
		clientID := fx.register(t, redirect)
		rec := fx.authorizeWith(t, clientID, redirect, nil)
		if rec.Code != http.StatusFound {
			t.Fatalf("%s authorize: status=%d body=%s", redirect, rec.Code, rec.Body)
		}
		loc, _ := url.Parse(rec.Header().Get("Location"))
		reqID := loc.Query().Get("req")

		body, _ := json.Marshal(map[string]any{"approve": true, "label": "phone", "factor": map[string]string{"kind": "totp", "code": "123456"}})
		app := fx.do(t, http.MethodPost, "/oauth2/consent/"+reqID, body, nil, true)
		var out struct{ Redirect string }
		_ = json.Unmarshal(app.Body.Bytes(), &out)
		back, _ := url.Parse(out.Redirect)
		if !strings.HasPrefix(out.Redirect, redirect+"?") || back.Query().Get("code") == "" || back.Query().Get("state") != "st-1" {
			t.Fatalf("%s: approve redirect = %q", redirect, out.Redirect)
		}
		code := back.Query().Get("code")

		if r := fx.token(t, clientID, code, verifier, redirect+"/x"); r.Code != http.StatusBadRequest {
			t.Fatalf("%s: a token request with another redirect must fail, got %d", redirect, r.Code)
		}
		code2 := fx.approve2(t, clientID, redirect)
		if r := fx.token(t, clientID, code2, verifier, redirect); r.Code != http.StatusOK {
			t.Fatalf("%s: token: status=%d body=%s", redirect, r.Code, r.Body)
		}
	}
}

func (fx *oauthFixture) approve2(t *testing.T, clientID, redirect string) string {
	t.Helper()
	rec := fx.authorizeWith(t, clientID, redirect, nil)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	body, _ := json.Marshal(map[string]any{"approve": true, "label": "phone", "factor": map[string]string{"kind": "totp", "code": "123456"}})
	app := fx.do(t, http.MethodPost, "/oauth2/consent/"+loc.Query().Get("req"), body, nil, true)
	var out struct{ Redirect string }
	_ = json.Unmarshal(app.Body.Bytes(), &out)
	back, _ := url.Parse(out.Redirect)
	return back.Query().Get("code")
}

func TestOAuthPKCEStaysRequiredForNativeRedirects(t *testing.T) {
	fx := newOAuthFixture(t)
	for _, redirect := range []string{privateScheme, claimedLink} {
		id := fx.register(t, redirect)
		for name, extra := range map[string]url.Values{
			"no challenge": {"code_challenge": {""}},
			"plain method": {"code_challenge_method": {"plain"}},
			"no method":    {"code_challenge_method": {""}},
		} {
			rec := fx.authorizeWith(t, id, redirect, extra)
			loc, _ := url.Parse(rec.Header().Get("Location"))
			if rec.Code != http.StatusFound || !strings.HasPrefix(loc.String(), redirect+"?") || loc.Query().Get("error") != "invalid_request" {
				t.Errorf("%s, %s: status=%d location=%s, want invalid_request back to the app", redirect, name, rec.Code, loc)
			}
		}
	}
}

func TestOAuthFirstPartyMobileClientsAreRegisteredByTheGateway(t *testing.T) {
	fx := newOAuthFixture(t)
	clients, err := FirstPartyClients(func(k string) string {
		return map[string]string{
			"OAUTH_IOS_REDIRECT_URIS":     "com.example.sneakers:/oauth2redirect, https://app.example.org/ios",
			"OAUTH_ANDROID_REDIRECT_URIS": "com.example.sneakers:/oauth2redirect",
		}[k]
	})
	if err != nil || len(clients) != 2 {
		t.Fatalf("clients=%+v err=%v", clients, err)
	}
	fx.o.FirstParty = clients
	if rec := fx.authorizeWith(t, "sneakers-ios", "https://app.example.org/ios", nil); rec.Code != http.StatusFound {
		t.Fatalf("ios: status=%d body=%s", rec.Code, rec.Body)
	}
	if rec := fx.authorizeWith(t, "sneakers-android", "com.example.sneakers:/oauth2redirect", nil); rec.Code != http.StatusFound {
		t.Fatalf("android: status=%d body=%s", rec.Code, rec.Body)
	}
	if rec := fx.authorizeWith(t, "sneakers-android", "https://app.example.org/ios", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("android with the iOS link: status=%d, want 400", rec.Code)
	}
}

func TestOAuthFirstPartyClientsNeedValidRedirectsAndStayOffWithoutThem(t *testing.T) {
	none, err := FirstPartyClients(func(string) string { return "" })
	if err != nil || len(none) != 0 {
		t.Fatalf("unset: clients=%+v err=%v", none, err)
	}
	if _, err := FirstPartyClients(func(k string) string {
		if k == "OAUTH_IOS_REDIRECT_URIS" {
			return "http://app.example.org/cb"
		}
		return ""
	}); err == nil {
		t.Fatal("an invalid first-party redirect must stop start-up")
	}
}
