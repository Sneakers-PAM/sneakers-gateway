// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEveryCookieHonoursSecure(t *testing.T) {
	for _, secure := range []bool{true, false} {
		h := ssoHandler(t, "http://unused", &fakeIdentity{})
		h.Secure = secure

		var cookies []*http.Cookie

		rec := httptest.NewRecorder()
		h.setCookie(rec, "sid", 60)
		cookies = append(cookies, rec.Result().Cookies()...)

		rec = httptest.NewRecorder()
		h.setCookie(rec, "", -1)
		cookies = append(cookies, rec.Result().Cookies()...)

		rec = httptest.NewRecorder()
		h.SSOLogin(rec, httptest.NewRequest(http.MethodGet, "/auth/sso/login", nil))
		cookies = append(cookies, rec.Result().Cookies()...)

		req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state=attacker", nil)
		req.AddCookie(&http.Cookie{Name: ssoStateCookie, Value: "real-state"})
		rec = httptest.NewRecorder()
		h.SSOCallback(rec, req)
		cookies = append(cookies, rec.Result().Cookies()...)

		if len(cookies) != 4 {
			t.Fatalf("secure=%v: got %d cookies; want 4", secure, len(cookies))
		}
		for _, c := range cookies {
			if c.Secure != secure {
				t.Errorf("secure=%v: cookie %q (MaxAge %d) Secure = %v", secure, c.Name, c.MaxAge, c.Secure)
			}
			if !c.HttpOnly {
				t.Errorf("secure=%v: cookie %q (MaxAge %d) not HttpOnly", secure, c.Name, c.MaxAge)
			}
		}
	}
}
