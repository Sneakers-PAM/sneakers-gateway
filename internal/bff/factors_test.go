// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

func factorsHandler(fid *fakeIdentity) *Handler {
	return &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour}
}

// factorSession seeds sid-1 for usr-42 whose last MFA was age ago (age < 0
// means the session never proved a factor).
func factorSession(t *testing.T, h *Handler, age time.Duration) (string, string) {
	t.Helper()
	sess := Session{UserID: "usr-42", CSRFToken: "csrf-1"}
	if age >= 0 {
		sess.MFAVerified = true
		sess.MFAVerifiedAt = time.Now().Add(-age)
	}
	seedSession(t, h, sess)
	return "sid-1", "csrf-1"
}

func authedGet(h http.HandlerFunc, path, sid, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func errorSlug(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.Error
}

// The list carries one entry per factor, the exact five keys and nothing
// that could be credential material.
func TestMfaFactors_ListShape(t *testing.T) {
	fid := &fakeIdentity{
		userFactors: []*identityv1.UserFactor{
			{Kind: factorTotp, EnrolledAt: "2026-01-02T03:04:05Z"},
			{Kind: factorPasskey, EnrolledAt: "2026-02-01T00:00:00Z"},
			{Kind: factorEmail},
		},
		waCreds: []*identityv1.WebauthnCredential{
			{Id: "cred-a", Label: "Laptop", CreatedAt: "2026-02-01T00:00:00Z", LastUsedAt: "2026-03-01T00:00:00Z", Transports: []string{"internal"}},
			{Id: "cred-b", CreatedAt: "2026-02-05T00:00:00Z"},
		},
	}
	h := factorsHandler(fid)
	sid, csrf := factorSession(t, h, time.Minute)

	rec := authedGet(h.MfaFactors, "/auth/mfa/factors", sid, csrf)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var raw struct {
		Factors []map[string]any `json:"factors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []map[string]any{
		{"kind": "totp", "id": "totp", "label": "Authenticator app", "createdAt": "2026-01-02T03:04:05Z", "lastUsedAt": nil},
		{"kind": "passkey", "id": "cred-a", "label": "Laptop", "createdAt": "2026-02-01T00:00:00Z", "lastUsedAt": "2026-03-01T00:00:00Z"},
		{"kind": "passkey", "id": "cred-b", "label": "Passkey", "createdAt": "2026-02-05T00:00:00Z", "lastUsedAt": nil},
		{"kind": "email", "id": "email", "label": "Email", "createdAt": nil, "lastUsedAt": nil},
	}
	if len(raw.Factors) != len(want) {
		t.Fatalf("got %d factors, want %d: %s", len(raw.Factors), len(want), rec.Body)
	}
	for i, f := range raw.Factors {
		keys := make([]string, 0, len(f))
		for k := range f {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != "createdAt,id,kind,label,lastUsedAt" {
			t.Fatalf("factor %d has keys %v, want exactly kind,id,label,createdAt,lastUsedAt", i, keys)
		}
		for k, v := range want[i] {
			if f[k] != v {
				t.Fatalf("factor %d %s=%v, want %v", i, k, f[k], v)
			}
		}
	}
	for _, leak := range []string{"secret", "transports", "publicKey", "otpauth"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("factor list must not carry %q: %s", leak, rec.Body)
		}
	}
}

// A user with no factor gets an empty array, not null.
func TestMfaFactors_EmptyIsArray(t *testing.T) {
	h := factorsHandler(&fakeIdentity{userFactors: []*identityv1.UserFactor{}})
	sid, csrf := factorSession(t, h, -1)
	rec := authedGet(h.MfaFactors, "/auth/mfa/factors", sid, csrf)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != `{"factors":[]}` {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

// The list is the session user's own: identity is asked for usr-42 only.
func TestMfaFactors_NeedsSessionAndCSRF(t *testing.T) {
	h := factorsHandler(&fakeIdentity{factors: []string{factorTotp}})
	if rec := authedGet(h.MfaFactors, "/auth/mfa/factors", "nope", "x"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: status=%d", rec.Code)
	}
	sid, _ := factorSession(t, h, time.Minute)
	if rec := authedGet(h.MfaFactors, "/auth/mfa/factors", sid, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("no csrf: status=%d", rec.Code)
	}
}

func TestMfaFactors_IdentityDown(t *testing.T) {
	h := factorsHandler(&fakeIdentity{factorsErr: errors.New("down")})
	sid, csrf := factorSession(t, h, time.Minute)
	if rec := authedGet(h.MfaFactors, "/auth/mfa/factors", sid, csrf); rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", rec.Code)
	}
	h = factorsHandler(&fakeIdentity{factors: []string{factorPasskey}, waCredsErr: errors.New("down")})
	sid, csrf = factorSession(t, h, time.Minute)
	if rec := authedGet(h.MfaFactors, "/auth/mfa/factors", sid, csrf); rec.Code != http.StatusBadGateway {
		t.Fatalf("passkey list down: status=%d", rec.Code)
	}
}

func TestMfaRemove_StaleMFARefused(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true, factors: []string{factorTotp, factorPasskey}}
	h := factorsHandler(fid)
	sid, csrf := factorSession(t, h, 6*time.Minute)

	rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{})
	if rec.Code != http.StatusForbidden || errorSlug(t, rec) != "step_up_required" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.removeFactorReq != nil {
		t.Fatal("a stale session must not reach RemoveFactor")
	}
	if _, ok := storedSession(t, h); !ok {
		t.Fatal("a refused removal keeps the session")
	}
}

func TestMfaRemove_NeverVerifiedRefused(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true, factors: []string{factorTotp, factorPasskey}}
	h := factorsHandler(fid)
	sid, csrf := factorSession(t, h, -1)
	rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{})
	if rec.Code != http.StatusForbidden || errorSlug(t, rec) != "step_up_required" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestMfaRemove_FreshMFAAllowed(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true, factors: []string{factorTotp, factorPasskey}}
	h := factorsHandler(fid)
	h.MfaEnforced = true
	sid, csrf := factorSession(t, h, 4*time.Minute)
	rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"signedOut":true`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.removeFactorReq.GetKind() != factorTotp || fid.removeFactorReq.GetUserId() != "usr-42" {
		t.Fatalf("RemoveFactor req=%+v", fid.removeFactorReq)
	}
}

// MFA_MAX_AGE sets the window: with 1m, two minutes is stale and thirty
// seconds is fresh.
func TestMfaRemove_HonoursMFAMaxAge(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true, factors: []string{factorTotp, factorPasskey}}
	h := factorsHandler(fid)
	h.MFAMaxAge = time.Minute
	sid, csrf := factorSession(t, h, 2*time.Minute)
	if rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{}); rec.Code != http.StatusForbidden {
		t.Fatalf("2m with a 1m window: status=%d", rec.Code)
	}
	h = factorsHandler(fid)
	h.MFAMaxAge = time.Minute
	sid, csrf = factorSession(t, h, 30*time.Second)
	if rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{}); rec.Code != http.StatusOK {
		t.Fatalf("30s with a 1m window: status=%d body=%s", rec.Code, rec.Body)
	}
}

// Removing TOTP from an enforced user whose only other factor is the implicit
// email would drop them back to the enrolment wall.
func TestMfaRemove_LastFactorRefused(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true, factors: []string{factorTotp, factorEmail}}
	h := factorsHandler(fid)
	h.MfaEnforced = true
	sid, csrf := factorSession(t, h, time.Minute)
	rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{})
	if rec.Code != http.StatusConflict || errorSlug(t, rec) != "last_factor" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.removeFactorReq != nil {
		t.Fatal("the last factor must not be removed")
	}
	if _, ok := storedSession(t, h); !ok {
		t.Fatal("a refused removal keeps the session")
	}
}

func TestMfaRemove_LastFactorAllowedWhenNotEnforced(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true, factors: []string{factorTotp, factorEmail}}
	h := factorsHandler(fid)
	sid, csrf := factorSession(t, h, time.Minute)
	if rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{}); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestMfaRemove_FactorListDownFailsClosed(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true, factorsErr: errors.New("down")}
	h := factorsHandler(fid)
	h.MfaEnforced = true
	sid, csrf := factorSession(t, h, time.Minute)
	if rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{}); rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", rec.Code)
	}
	if fid.removeFactorReq != nil {
		t.Fatal("no removal when the factor count is unknown")
	}
}

func TestMfaEnroll_StaleWithFactorRefused(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true}
	h := factorsHandler(fid)
	sid, csrf := factorSession(t, h, 10*time.Minute)
	rec := authedPost(h.MfaEnroll, "/auth/mfa/enroll", sid, csrf, map[string]string{})
	if rec.Code != http.StatusForbidden || errorSlug(t, rec) != "step_up_required" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.enrollReq != nil {
		t.Fatal("a stale session must not start an enrolment")
	}
}

func TestMfaEnroll_FreshWithFactorAllowed(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: true}
	h := factorsHandler(fid)
	sid, csrf := factorSession(t, h, time.Minute)
	if rec := authedPost(h.MfaEnroll, "/auth/mfa/enroll", sid, csrf, map[string]string{}); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

// A user with no factor has nothing to step up with, so the first enrolment
// stays open on a half-session.
func TestMfaEnroll_FirstFactorNeedsNoStepUp(t *testing.T) {
	fid := &fakeIdentity{mfaEnrolled: false, factors: []string{factorEmail}}
	h := factorsHandler(fid)
	h.MfaEnforced = true
	sid, csrf := factorSession(t, h, -1)
	if rec := authedPost(h.MfaEnroll, "/auth/mfa/enroll", sid, csrf, map[string]string{}); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestMfaEnroll_StatusDownFailsClosed(t *testing.T) {
	fid := &fakeIdentity{mfaStatusErr: errors.New("down")}
	h := factorsHandler(fid)
	sid, csrf := factorSession(t, h, -1)
	if rec := authedPost(h.MfaEnroll, "/auth/mfa/enroll", sid, csrf, map[string]string{}); rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", rec.Code)
	}
	if fid.enrollReq != nil {
		t.Fatal("no enrolment when the factor state is unknown")
	}
}

func TestEnrollWebauthnBegin_StaleWithFactorRefused(t *testing.T) {
	h := factorsHandler(&fakeIdentity{mfaEnrolled: true})
	sid, csrf := factorSession(t, h, 10*time.Minute)
	rec := authedPost(h.EnrollWebauthnBegin, "/auth/mfa/webauthn/register/begin", sid, csrf, map[string]string{})
	if rec.Code != http.StatusForbidden || errorSlug(t, rec) != "step_up_required" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestEnrollWebauthnBegin_FirstFactorNeedsNoStepUp(t *testing.T) {
	h := factorsHandler(&fakeIdentity{mfaEnrolled: false})
	sid, csrf := factorSession(t, h, -1)
	if rec := authedPost(h.EnrollWebauthnBegin, "/auth/mfa/webauthn/register/begin", sid, csrf, map[string]string{}); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestParseMFAMaxAge(t *testing.T) {
	cases := map[string]struct {
		want time.Duration
		ok   bool
	}{
		"":    {5 * time.Minute, true},
		"10m": {10 * time.Minute, true},
		"1m":  {time.Minute, true},
		"1h":  {time.Hour, true},
		"30s": {0, false},
		"2h":  {0, false},
		"abc": {0, false},
	}
	for in, c := range cases {
		got, err := ParseMFAMaxAge(func(string) string { return in })
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("MFA_MAX_AGE=%q: got %v err=%v, want %v ok=%v", in, got, err, c.want, c.ok)
		}
	}
}

// freshMFA marks a seeded session as having proved a factor just now, so a
// factor change passes the step-up check.
func freshMFA(t *testing.T, h *Handler, sid string) {
	t.Helper()
	sess, ok, err := h.Store.Get(t.Context(), sid)
	if err != nil || !ok {
		t.Fatalf("session %q: ok=%v err=%v", sid, ok, err)
	}
	sess.MFAVerified, sess.MFAVerifiedAt = true, time.Now()
	if err := h.Store.Save(t.Context(), sid, sess); err != nil {
		t.Fatal(err)
	}
}
