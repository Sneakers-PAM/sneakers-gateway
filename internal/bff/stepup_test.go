// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

func stepUpHandler(fid *fakeIdentity) *Handler {
	return &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour}
}

func seedSession(t *testing.T, h *Handler, sess Session) {
	t.Helper()
	if sess.ExpiresAt.IsZero() {
		sess.ExpiresAt = time.Now().Add(time.Hour)
	}
	if err := h.Store.Create(context.Background(), "sid-1", sess); err != nil {
		t.Fatal(err)
	}
}

func storedSession(t *testing.T, h *Handler) (Session, bool) {
	t.Helper()
	s, ok, err := h.Store.Get(context.Background(), "sid-1")
	if err != nil {
		t.Fatal(err)
	}
	return s, ok
}

// A verified login stamps when the second factor was proven.
func TestVerifyOtp_StampsMFAVerifiedAt(t *testing.T) {
	fid := &fakeIdentity{verifyOk: true}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{AccessToken: "AT", ExpiresIn: 300, UserID: "usr-42", Subject: "sub-abc-123"})
	before := time.Now()
	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "123456"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	sess, ok, _ := h.Store.Get(context.Background(), cookieValue(rec, CookieName))
	if !ok || sess.MFAVerifiedAt.Before(before) || sess.MFAVerifiedAt.After(time.Now()) {
		t.Fatalf("MFAVerifiedAt = %v, want the verify time", sess.MFAVerifiedAt)
	}
}

func TestMfaStepUp_FreshFactorRefreshesTheSession(t *testing.T) {
	fid := &fakeIdentity{verifyOk: true}
	h := stepUpHandler(fid)
	stale := time.Now().Add(-2 * time.Hour)
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true, MFAVerifiedAt: stale})

	before := time.Now()
	rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "csrf-1", map[string]string{"kind": "totp", "code": "123456"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.verifyReq == nil || fid.verifyReq.GetUserId() != "usr-42" || fid.verifyReq.GetCode() != "123456" {
		t.Fatalf("VerifyTotp not called for the session user: %+v", fid.verifyReq)
	}
	sess, _ := storedSession(t, h)
	if sess.MFAVerifiedAt.Before(before) {
		t.Fatalf("MFAVerifiedAt = %v, want refreshed", sess.MFAVerifiedAt)
	}
	var out map[string]int64
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["mfaVerifiedAt"] != sess.MFAVerifiedAt.Unix() {
		t.Fatalf("body = %s", rec.Body)
	}
}

func TestMfaStepUp_WrongCodeLeavesTheSessionStale(t *testing.T) {
	fid := &fakeIdentity{verifyOk: false}
	h := stepUpHandler(fid)
	stale := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true, MFAVerifiedAt: stale})

	rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "csrf-1", map[string]string{"kind": "totp", "code": "000000"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	sess, ok := storedSession(t, h)
	if !ok || !sess.MFAVerifiedAt.Equal(stale) || sess.StepUpFailures != 1 {
		t.Fatalf("session = %+v ok=%v", sess, ok)
	}
}

// Repeated wrong codes end the session, so step-up can't be used to guess codes.
func TestMfaStepUp_AttemptBudgetEndsTheSession(t *testing.T) {
	h := stepUpHandler(&fakeIdentity{verifyOk: false})
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true})
	for i := 0; i < maxPendingAttempts; i++ {
		authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "csrf-1", map[string]string{"kind": "totp", "code": "000000"})
	}
	if _, ok := storedSession(t, h); ok {
		t.Fatal("the session must be revoked once the step-up budget is spent")
	}
}

func TestMfaStepUp_SuccessResetsTheFailureCount(t *testing.T) {
	h := stepUpHandler(&fakeIdentity{verifyOk: true})
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true, StepUpFailures: 3})
	if rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "csrf-1", map[string]string{"kind": "totp", "code": "123456"}); rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	if sess, _ := storedSession(t, h); sess.StepUpFailures != 0 {
		t.Fatalf("StepUpFailures = %d", sess.StepUpFailures)
	}
}

func TestMfaStepUp_NeedsSessionAndCSRF(t *testing.T) {
	h := stepUpHandler(&fakeIdentity{verifyOk: true})
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true})
	if rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "", map[string]string{"kind": "totp", "code": "1"}); rec.Code != http.StatusForbidden {
		t.Fatalf("no CSRF: status=%d", rec.Code)
	}
	if rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-other", "csrf-1", map[string]string{"kind": "totp", "code": "1"}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no session: status=%d", rec.Code)
	}
}

// A session still waiting on MFA enrollment can't step up: there's no factor.
func TestMfaStepUp_UnverifiedSessionRefused(t *testing.T) {
	fid := &fakeIdentity{verifyOk: true}
	h := stepUpHandler(fid)
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1"})
	if rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "csrf-1", map[string]string{"kind": "totp", "code": "1"}); rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d", rec.Code)
	}
	if fid.verifyReq != nil {
		t.Fatal("identity must not be asked")
	}
}

func TestMfaStepUp_BadKindRefused(t *testing.T) {
	h := stepUpHandler(&fakeIdentity{verifyOk: true})
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true})
	for _, body := range []map[string]string{{"kind": "sms", "code": "1"}, {"kind": "totp"}, {"kind": "passkey"}} {
		if rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "csrf-1", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%v: status=%d", body, rec.Code)
		}
	}
}

func TestMfaStepUp_IdentityDownBurnsNoAttempt(t *testing.T) {
	h := stepUpHandler(&fakeIdentity{verifyErr: errors.New("down")})
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true})
	if rec := authedPost(h.MfaStepUp, "/auth/mfa/step-up", "sid-1", "csrf-1", map[string]string{"kind": "totp", "code": "1"}); rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", rec.Code)
	}
	if sess, _ := storedSession(t, h); sess.StepUpFailures != 0 {
		t.Fatalf("StepUpFailures = %d", sess.StepUpFailures)
	}
}

func TestMfaStepUpEmailSend(t *testing.T) {
	fid := &fakeIdentity{}
	h := stepUpHandler(fid)
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true})
	if rec := authedPost(h.MfaStepUpEmailSend, "/auth/mfa/step-up/email/send", "sid-1", "csrf-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.sendEmailReq == nil || fid.sendEmailReq.GetUserId() != "usr-42" || fid.sendEmailReq.GetPurpose() != mfaLoginPurpose {
		t.Fatalf("SendEmailOtp = %+v", fid.sendEmailReq)
	}
}

// The request gate carries the session's MFA time to the resolvers.
func TestSessionActor_CarriesMFAVerifiedAt(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := stepUpHandler(fid)
	at := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
	seedSession(t, h, Session{AccessToken: "tok", UserID: "usr-42", Subject: "sub-1", CSRFToken: "csrf-1", MFAVerified: true, MFAVerifiedAt: at})

	var got time.Time
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = resolvers.MFAVerifiedAt(r.Context()) })
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid-1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	h.SessionActor(next).ServeHTTP(httptest.NewRecorder(), req)
	if !got.Equal(at) {
		t.Fatalf("MFAVerifiedAt on the context = %v, want %v", got, at)
	}
}

func TestSession_ReportsMFAVerifiedAt(t *testing.T) {
	h := stepUpHandler(&fakeIdentity{})
	at := time.Unix(1790000000, 0)
	seedSession(t, h, Session{UserID: "usr-42", CSRFToken: "csrf-1", MFAVerified: true, MFAVerifiedAt: at})
	req := httptest.NewRequest(http.MethodGet, "/auth/session", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid-1"})
	rec := httptest.NewRecorder()
	h.Session(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["mfaVerifiedAt"] != float64(at.Unix()) {
		t.Fatalf("body = %s", rec.Body)
	}
}

// The request gate carries an opaque reference to the web session, never the
// session id, distinct per session; break-glass browse binds to it.
func TestSessionActor_CarriesAnOpaqueSessionRef(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := stepUpHandler(fid)
	refs := map[string]string{}
	for _, sid := range []string{"sid-1", "sid-2"} {
		if err := h.Store.Create(context.Background(), sid, Session{AccessToken: "tok", UserID: "usr-42", Subject: "sub-1", CSRFToken: "csrf-1", MFAVerified: true, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		var got string
		next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = resolvers.SessionRef(r.Context()) })
		req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
		req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
		req.Header.Set("X-CSRF-Token", "csrf-1")
		h.SessionActor(next).ServeHTTP(httptest.NewRecorder(), req)
		if got == "" || strings.Contains(got, sid) {
			t.Fatalf("session ref for %s = %q", sid, got)
		}
		refs[sid] = got
	}
	if refs["sid-1"] == refs["sid-2"] {
		t.Fatal("two web sessions must have different references")
	}
}
