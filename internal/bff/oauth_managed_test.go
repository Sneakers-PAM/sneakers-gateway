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

// Require-managed (#164): with the setting on, the gateway refuses a phone
// app's sign-in unless the app says it was installed and configured by the
// organisation's MDM, by sending X-Sneakers-Managed-Config: 1 on the token
// request. The header is the app's own word, so it narrows the honest cases;
// real enforcement needs the MDM's attestation. Browser and CLI sign-in carry
// no such header and aren't affected.

const iosRedirect = "com.example.sneakers:/oauth2redirect"

func managedFixture(t *testing.T, on, known bool) *oauthFixture {
	t.Helper()
	fx := newOAuthFixture(t)
	fx.o.FirstParty = []NativeClient{
		{ID: "sneakers-ios", Name: "Sneakers for iOS", RedirectURIs: []string{iosRedirect}},
		{ID: "sneakers-android", Name: "Sneakers for Android", RedirectURIs: []string{iosRedirect}},
	}
	fx.o.RequireManaged = func() (bool, bool) { return on, known }
	return fx
}

func (fx *oauthFixture) tokenWith(t *testing.T, clientID, code, redirect string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	fx.o.Routes().ServeHTTP(rec, req)
	return rec
}

func errorCode(rec *httptest.ResponseRecorder) string {
	var out struct{ Error string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Error
}

func TestRequireManagedRefusesAnUnmanagedPhoneAppAndKeepsTheCodeUsable(t *testing.T) {
	for _, app := range []string{"sneakers-ios", "sneakers-android"} {
		fx := managedFixture(t, true, true)
		code := fx.approve2(t, app, iosRedirect)
		rec := fx.tokenWith(t, app, code, iosRedirect, nil)
		if rec.Code != http.StatusForbidden || errorCode(rec) != "MANAGED_APP_REQUIRED" || !strings.Contains(rec.Body.String(), "error_description") {
			t.Fatalf("%s unmanaged: %d %s", app, rec.Code, rec.Body)
		}
		if fx.fid.mintUserTokenReq != nil {
			t.Fatalf("%s: a refused sign-in must mint nothing", app)
		}
		if rec := fx.tokenWith(t, app, code, iosRedirect, map[string]string{"X-Sneakers-Managed-Config": "1"}); rec.Code != http.StatusOK {
			t.Fatalf("%s: the same code with the header: %d %s", app, rec.Code, rec.Body)
		}
	}
}

func TestRequireManagedOnlyAcceptsTheOneValue(t *testing.T) {
	for _, v := range []string{"0", "true", "yes", "", " 1x", "11"} {
		fx := managedFixture(t, true, true)
		code := fx.approve2(t, "sneakers-ios", iosRedirect)
		if rec := fx.tokenWith(t, "sneakers-ios", code, iosRedirect, map[string]string{"X-Sneakers-Managed-Config": v}); rec.Code != http.StatusForbidden {
			t.Errorf("header %q: %d, want refused", v, rec.Code)
		}
	}
}

func TestRequireManagedOffLetsEveryAppIn(t *testing.T) {
	fx := managedFixture(t, false, true)
	code := fx.approve2(t, "sneakers-ios", iosRedirect)
	if rec := fx.tokenWith(t, "sneakers-ios", code, iosRedirect, nil); rec.Code != http.StatusOK {
		t.Fatalf("setting off: %d %s", rec.Code, rec.Body)
	}
}

func TestRequireManagedLeavesBrowserAndCLISignInAlone(t *testing.T) {
	fx := managedFixture(t, true, true)
	cli := fx.register(t, loopback)
	code := fx.approve(t, fx.authorize(t, cli))
	if rec := fx.token(t, cli, code, verifier, loopback); rec.Code != http.StatusOK {
		t.Fatalf("a CLI client with the setting on: %d %s", rec.Code, rec.Body)
	}
	third := fx.register(t, "com.example.other:/cb")
	code2 := fx.approve2(t, third, "com.example.other:/cb")
	if rec := fx.tokenWith(t, third, code2, "com.example.other:/cb", nil); rec.Code != http.StatusOK {
		t.Fatalf("a third-party native client is not a first-party phone app: %d %s", rec.Code, rec.Body)
	}
}

func TestRequireManagedFailsClosedWhileTheSettingIsUnknown(t *testing.T) {
	fx := managedFixture(t, false, false)
	code := fx.approve2(t, "sneakers-ios", iosRedirect)
	rec := fx.tokenWith(t, "sneakers-ios", code, iosRedirect, nil)
	if rec.Code != http.StatusServiceUnavailable || errorCode(rec) != "temporarily_unavailable" {
		t.Fatalf("unknown: %d %s", rec.Code, rec.Body)
	}
	fx.o.RequireManaged = func() (bool, bool) { return false, true }
	if rec := fx.tokenWith(t, "sneakers-ios", code, iosRedirect, nil); rec.Code != http.StatusOK {
		t.Fatalf("once known the same code works: %d", rec.Code)
	}
}

func TestSignInWithNoPolicyWiredStillWorks(t *testing.T) {
	fx := managedFixture(t, true, true)
	fx.o.RequireManaged = nil
	code := fx.approve2(t, "sneakers-ios", iosRedirect)
	if rec := fx.tokenWith(t, "sneakers-ios", code, iosRedirect, nil); rec.Code != http.StatusOK {
		t.Fatalf("no policy: %d", rec.Code)
	}
}
