// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mfaLoginHandler builds a real-login Handler wired with the given fake identity
// and an in-memory pending store.
func mfaLoginHandler(t *testing.T, fid *fakeIdentity) (*Handler, *memPending) {
	t.Helper()
	cfg := defaultKratosLoginConfig()
	cfg.identityID = "sub-abc-123"
	kratos := newKratosLoginServer(t, cfg)
	pend := newMemPending()
	h := &Handler{
		Store:    NewMemStore(time.Hour),
		Auth:     NewKratosClient(kratos.URL, kratos.URL),
		Identity: fid,
		Pending:  pend,
		TTL:      time.Hour,
	}
	return h, pend
}

func doLogin(h *Handler) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "good"})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	return rec
}

func cookieValue(rec *httptest.ResponseRecorder, name string) string {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

// TestLogin_EnrolledUser_RequiresMFA: an enrolled user gets no session on the
// password step — only mfaRequired + a pendingId that parks the tokens.
func TestLogin_EnrolledUser_RequiresMFA(t *testing.T) {
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-42"}, mfaEnrolled: true}
	h, pend := mfaLoginHandler(t, fid)

	rec := doLogin(h)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if cookieValue(rec, CookieName) != "" {
		t.Fatal("no session cookie may be set before the second factor")
	}
	var out struct {
		MfaRequired bool   `json:"mfaRequired"`
		PendingID   string `json:"pendingId"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.MfaRequired || out.PendingID == "" {
		t.Fatalf("expected mfaRequired + pendingId, got %+v", out)
	}
	p, ok, _ := pend.Get(context.Background(), out.PendingID)
	if !ok || p.UserID != "usr-42" || p.Subject != "sub-abc-123" || p.AccessToken == "" {
		t.Fatalf("pending record not parked with tokens/user/subject: %+v ok=%v", p, ok)
	}
}

// TestLogin_MfaStatusUnreachable_FailsClosed: if the factor requirement can't be
// evaluated, no session and no pending record are created.
func TestLogin_MfaStatusUnreachable_FailsClosed(t *testing.T) {
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-42"}, mfaStatusErr: errors.New("identity down")}
	h, _ := mfaLoginHandler(t, fid)
	rec := doLogin(h)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 fail-closed, got %d body=%s", rec.Code, rec.Body)
	}
	if cookieValue(rec, CookieName) != "" {
		t.Fatal("no session cookie should be set when mfa status fails")
	}
}

// doEmailEnrolledLogin drives the real Login -> beginStepUp path for a user
// enrolled only in email-OTP and decodes the {mfaRequired, pendingId,
// factors} response.
func doEmailEnrolledLogin(t *testing.T, h *Handler) (pendingID string, factors []string) {
	t.Helper()
	rec := doLogin(h)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var out struct {
		MfaRequired bool     `json:"mfaRequired"`
		PendingID   string   `json:"pendingId"`
		Factors     []string `json:"factors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.MfaRequired || out.PendingID == "" {
		t.Fatalf("expected mfaRequired + pendingId, got %+v", out)
	}
	return out.PendingID, out.Factors
}

// TestLogin_EmailOnlyEnrolled_OffersEmailFactor: beginStepUp must not strip
// "email" from the factors offered on the pending record, or a user enrolled
// ONLY in email-OTP has nothing left to challenge. This drives the REAL
// Login -> beginStepUp path (no hand-seeded Pending) and asserts the email
// factor is offered both in the response and on the parked pending record.
func TestLogin_EmailOnlyEnrolled_OffersEmailFactor(t *testing.T) {
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-42"}, mfaEnrolled: true, factors: []string{"email"}}
	h, pend := mfaLoginHandler(t, fid)

	pendingID, factors := doEmailEnrolledLogin(t, h)
	if !factorOffered(factors, factorEmail) {
		t.Fatalf("an email-only-enrolled user must be offered the email factor at login, got factors=%v", factors)
	}
	p, ok, _ := pend.Get(context.Background(), pendingID)
	if !ok || !factorOffered(p.Factors, factorEmail) {
		t.Fatalf("pending record must carry the email factor, got %+v ok=%v", p, ok)
	}
}

// TestLogin_EmailOnlyEnrolled_CompletesLoginViaEmailOtp continues the same
// real login path through the whole email-OTP continuation — MfaOtpSend then
// VerifyOtp{kind:"email"} — and asserts an email-only-enrolled user can
// actually finish login (both MfaOtpSend and VerifyOtp's email branch gate
// on factorOffered(p.Factors, "email"), so a stripped factor would make this
// continuation unreachable).
func TestLogin_EmailOnlyEnrolled_CompletesLoginViaEmailOtp(t *testing.T) {
	fid := &fakeIdentity{
		adoptUser:     &identityv1.User{Id: "usr-42"},
		mfaEnrolled:   true,
		factors:       []string{"email"},
		verifyEmailOk: true,
	}
	h, _ := mfaLoginHandler(t, fid)
	pendingID, _ := doEmailEnrolledLogin(t, h)

	sendRec := postJSON(h.MfaOtpSend, "/auth/mfa/otp/send", map[string]string{"pendingId": pendingID})
	if sendRec.Code != http.StatusOK {
		t.Fatalf("otp send status=%d body=%s", sendRec.Code, sendRec.Body)
	}
	if fid.sendEmailReq == nil || fid.sendEmailReq.GetUserId() != "usr-42" || fid.sendEmailReq.GetPurpose() != mfaLoginPurpose {
		t.Fatalf("SendEmailOtp not called for the pending user with login purpose: %+v", fid.sendEmailReq)
	}

	verifyRec := postJSON(h.VerifyOtp, "/auth/verify-otp",
		map[string]string{"pendingId": pendingID, "code": "123456", "kind": "email"})
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyRec.Code, verifyRec.Body)
	}
	sid := cookieValue(verifyRec, CookieName)
	if sid == "" {
		t.Fatal("expected a session cookie after email-OTP verify")
	}
	sess, ok, _ := h.Store.Get(context.Background(), sid)
	if !ok || sess.UserID != "usr-42" || !sess.MFAVerified {
		t.Fatalf("email-only-enrolled user did not complete login: %+v ok=%v", sess, ok)
	}
}

// TestLogin_TotpAndEmailEnrolled_BothFactorsOffered: a user enrolled in both
// totp and email must be offered both at login — "email" must not be dropped
// when totp is also present.
func TestLogin_TotpAndEmailEnrolled_BothFactorsOffered(t *testing.T) {
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-42"}, mfaEnrolled: true, factors: []string{"totp", "email"}}
	h, _ := mfaLoginHandler(t, fid)

	rec := doLogin(h)
	var out struct {
		Factors []string `json:"factors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !factorOffered(out.Factors, factorTotp) || !factorOffered(out.Factors, factorEmail) {
		t.Fatalf("expected both totp and email offered, got %v", out.Factors)
	}
}

// TestLogin_TotpOnlyEnrolled_EmailNotOfferedAndTotpStillWorks: a user enrolled
// only in totp is never offered email (nothing to strip — it just isn't an
// enrolled factor), a kind=email verify against that pending is rejected as a
// factor never offered, and the real totp factor still completes login,
// driven through the real login path.
func TestLogin_TotpOnlyEnrolled_EmailNotOfferedAndTotpStillWorks(t *testing.T) {
	fid := &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-42"}, mfaEnrolled: true, factors: []string{"totp"}, verifyOk: true}
	h, pend := mfaLoginHandler(t, fid)

	rec := doLogin(h)
	var out struct {
		PendingID string   `json:"pendingId"`
		Factors   []string `json:"factors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if factorOffered(out.Factors, factorEmail) {
		t.Fatalf("email must not be offered when the user has no email factor enrolled, got %v", out.Factors)
	}

	// A kind=email verify against this pending is a uniform reject (never offered).
	badKindRec := postJSON(h.VerifyOtp, "/auth/verify-otp",
		map[string]string{"pendingId": out.PendingID, "code": "123456", "kind": "email"})
	if badKindRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a non-offered kind, got %d body=%s", badKindRec.Code, badKindRec.Body)
	}
	p, ok, _ := pend.Get(context.Background(), out.PendingID)
	if !ok || p.Attempts != 1 {
		t.Fatalf("expected one attempt burned on the non-offered kind, got %+v ok=%v", p, ok)
	}

	// The real totp factor still completes login.
	okRec := postJSON(h.VerifyOtp, "/auth/verify-otp",
		map[string]string{"pendingId": out.PendingID, "code": "123456", "kind": "totp"})
	if okRec.Code != http.StatusOK {
		t.Fatalf("totp verify status=%d body=%s", okRec.Code, okRec.Body)
	}
	if cookieValue(okRec, CookieName) == "" {
		t.Fatal("expected a session cookie after totp verify")
	}
}

func postJSON(h http.HandlerFunc, path string, v any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(v)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
	return rec
}

// TestVerifyOtp_Success: a correct code consumes the pending record and issues a
// real, MFA-verified session.
func TestVerifyOtp_Success(t *testing.T) {
	fid := &fakeIdentity{verifyOk: true}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{
		AccessToken: "AT", ExpiresIn: 300, UserID: "usr-42", Subject: "sub-abc-123",
	})

	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "123456"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.verifyReq == nil || fid.verifyReq.GetUserId() != "usr-42" || fid.verifyReq.GetCode() != "123456" {
		t.Fatalf("VerifyTotp not called with pending user/code: %+v", fid.verifyReq)
	}
	sid := cookieValue(rec, CookieName)
	if sid == "" {
		t.Fatal("expected a session cookie after verified factor")
	}
	sess, ok, _ := h.Store.Get(context.Background(), sid)
	if !ok || sess.UserID != "usr-42" || sess.Subject != "sub-abc-123" || !sess.MFAVerified {
		t.Fatalf("session not MFA-verified/complete: %+v ok=%v", sess, ok)
	}
	if _, ok, _ := pend.Get(context.Background(), "pend-1"); ok {
		t.Fatal("pending record must be consumed (single-use)")
	}
}

// TestVerifyOtp_WrongCode_BurnsAttempt: a wrong code fails uniformly and burns
// one attempt without issuing a session.
func TestVerifyOtp_WrongCode_BurnsAttempt(t *testing.T) {
	fid := &fakeIdentity{verifyOk: false}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{UserID: "usr-42", AccessToken: "AT"})

	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "000000"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 invalid_code, got %d body=%s", rec.Code, rec.Body)
	}
	if cookieValue(rec, CookieName) != "" {
		t.Fatal("no session on a wrong code")
	}
	p, ok, _ := pend.Get(context.Background(), "pend-1")
	if !ok || p.Attempts != 1 {
		t.Fatalf("expected attempt burned (1), got %+v ok=%v", p, ok)
	}
}

// TestVerifyOtp_AttemptBudget: at maxPendingAttempts the record is discarded and
// further verifies see invalid_pending (restart login).
func TestVerifyOtp_AttemptBudget(t *testing.T) {
	fid := &fakeIdentity{verifyOk: false}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{UserID: "usr-42", Attempts: maxPendingAttempts - 1})

	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "000000"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if _, ok, _ := pend.Get(context.Background(), "pend-1"); ok {
		t.Fatal("record should be deleted once the attempt budget is exhausted")
	}
	// A subsequent verify against the gone record is invalid_pending.
	rec2 := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "000000"})
	var out map[string]string
	_ = json.Unmarshal(rec2.Body.Bytes(), &out)
	if rec2.Code != http.StatusUnauthorized || out["error"] != "invalid_pending" {
		t.Fatalf("expected invalid_pending, got %d %v", rec2.Code, out)
	}
}

// TestVerifyOtp_IdentityUnreachable_NoAttemptBurned: an infra fault fails closed
// (502) and does NOT burn an attempt.
func TestVerifyOtp_IdentityUnreachable_NoAttemptBurned(t *testing.T) {
	fid := &fakeIdentity{verifyErr: errors.New("identity down")}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{UserID: "usr-42"})

	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "123456"})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d body=%s", rec.Code, rec.Body)
	}
	p, ok, _ := pend.Get(context.Background(), "pend-1")
	if !ok || p.Attempts != 0 {
		t.Fatalf("no attempt should be burned on infra fault: %+v ok=%v", p, ok)
	}
}

// TestVerifyOtp_InvalidPending: an unknown pending id is invalid_pending.
func TestVerifyOtp_InvalidPending(t *testing.T) {
	h, _ := mfaLoginHandler(t, &fakeIdentity{})
	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "nope", "code": "123456"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

// enrolledSession seeds an authed session and returns its cookie + CSRF.
func enrolledSession(t *testing.T, h *Handler, userID string) (string, string) {
	t.Helper()
	csrf := "csrf-1"
	sid := "sid-authed"
	_ = h.Store.Create(context.Background(), sid, Session{UserID: userID, CSRFToken: csrf, ExpiresAt: time.Now().Add(time.Hour)})
	return sid, csrf
}

func authedPost(h http.HandlerFunc, path, sid, csrf string, v any) *httptest.ResponseRecorder {
	body, _ := json.Marshal(v)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// TestMfaEnroll_AuthedUser: enroll returns the secret + otpauth URI for the
// session's user.
func TestMfaEnroll_AuthedUser(t *testing.T) {
	fid := &fakeIdentity{}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := enrolledSession(t, h, "usr-42")

	rec := authedPost(h.MfaEnroll, "/auth/mfa/enroll", sid, csrf, map[string]string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.enrollReq == nil || fid.enrollReq.GetUserId() != "usr-42" {
		t.Fatalf("EnrollTotp not called for session user: %+v", fid.enrollReq)
	}
	var out struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauthUri"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Secret == "" || out.OtpauthURI == "" {
		t.Fatalf("expected secret + otpauthUri, got %+v", out)
	}
}

// TestMfaEnroll_NoSession: enroll without a session is rejected.
func TestMfaEnroll_NoSession(t *testing.T) {
	h, _ := mfaLoginHandler(t, &fakeIdentity{})
	rec := postJSON(h.MfaEnroll, "/auth/mfa/enroll", map[string]string{})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 no_session, got %d", rec.Code)
	}
}

// TestMfaEnroll_CSRFRequired: a valid session without the CSRF header is 403.
func TestMfaEnroll_CSRFRequired(t *testing.T) {
	h, _ := mfaLoginHandler(t, &fakeIdentity{})
	sid, _ := enrolledSession(t, h, "usr-42")
	rec := authedPost(h.MfaEnroll, "/auth/mfa/enroll", sid, "", map[string]string{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 csrf, got %d", rec.Code)
	}
}

// TestMfaConfirm_Success: a valid code confirms enrollment and marks the live
// session MFA-verified.
func TestMfaConfirm_Success(t *testing.T) {
	fid := &fakeIdentity{}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := enrolledSession(t, h, "usr-42")

	rec := authedPost(h.MfaConfirm, "/auth/mfa/confirm", sid, csrf, map[string]string{"code": "123456"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.confirmReq == nil || fid.confirmReq.GetCode() != "123456" || fid.confirmReq.GetUserId() != "usr-42" {
		t.Fatalf("ConfirmTotp not called with user/code: %+v", fid.confirmReq)
	}
	sess, _, _ := h.Store.Get(context.Background(), sid)
	if !sess.MFAVerified {
		t.Fatal("session should be marked MFAVerified after confirm")
	}
}

// TestMfaOtpSend_Success: when email is an offered factor, the BFF asks identity
// to email a LOGIN-purpose code for the pending user.
func TestMfaOtpSend_Success(t *testing.T) {
	fid := &fakeIdentity{}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{UserID: "usr-42", Factors: []string{"totp", "email"}})

	rec := postJSON(h.MfaOtpSend, "/auth/mfa/otp/send", map[string]string{"pendingId": "pend-1"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.sendEmailReq == nil || fid.sendEmailReq.GetUserId() != "usr-42" || fid.sendEmailReq.GetPurpose() != "login" {
		t.Fatalf("SendEmailOtp not called with pending user + login purpose: %+v", fid.sendEmailReq)
	}
}

// TestMfaOtpSend_EmailNotOffered: a pending login that did not offer email can't
// request an email code (no factor leak).
func TestMfaOtpSend_EmailNotOffered(t *testing.T) {
	fid := &fakeIdentity{}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{UserID: "usr-42", Factors: []string{"totp"}})

	rec := postJSON(h.MfaOtpSend, "/auth/mfa/otp/send", map[string]string{"pendingId": "pend-1"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when email not offered, got %d body=%s", rec.Code, rec.Body)
	}
	if fid.sendEmailReq != nil {
		t.Fatal("SendEmailOtp must not be called when email is not an offered factor")
	}
}

// TestMfaOtpSend_RateLimited: identity's cooldown surfaces as 429.
func TestMfaOtpSend_RateLimited(t *testing.T) {
	fid := &fakeIdentity{sendEmailErr: status.Error(codes.ResourceExhausted, "cooldown")}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{UserID: "usr-42", Factors: []string{"email"}})

	rec := postJSON(h.MfaOtpSend, "/auth/mfa/otp/send", map[string]string{"pendingId": "pend-1"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d body=%s", rec.Code, rec.Body)
	}
}

// TestVerifyOtp_EmailKind_Success: a kind=email verify hits VerifyEmailOtp with
// the login purpose and, on success, issues an MFA-verified session.
func TestVerifyOtp_EmailKind_Success(t *testing.T) {
	fid := &fakeIdentity{verifyEmailOk: true}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{
		AccessToken: "AT", ExpiresIn: 300, UserID: "usr-42",
		Subject: "sub-abc-123", Factors: []string{"totp", "email"},
	})

	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "123456", "kind": "email"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.verifyEmailReq == nil || fid.verifyEmailReq.GetPurpose() != "login" || fid.verifyEmailReq.GetCode() != "123456" {
		t.Fatalf("VerifyEmailOtp not called with login purpose/code: %+v", fid.verifyEmailReq)
	}
	if fid.verifyReq != nil {
		t.Fatal("VerifyTotp must not be called for a kind=email verify")
	}
	if cookieValue(rec, CookieName) == "" {
		t.Fatal("expected a session cookie after a verified email factor")
	}
}

// TestVerifyOtp_EmailKind_NotOffered: verifying email when only totp was offered
// is a uniform invalid_code (burns an attempt), never a factor leak, and never
// calls identity.
func TestVerifyOtp_EmailKind_NotOffered(t *testing.T) {
	fid := &fakeIdentity{verifyEmailOk: true}
	h, pend := mfaLoginHandler(t, fid)
	_ = pend.Create(context.Background(), "pend-1", Pending{UserID: "usr-42", Factors: []string{"totp"}})

	rec := postJSON(h.VerifyOtp, "/auth/verify-otp", map[string]string{"pendingId": "pend-1", "code": "123456", "kind": "email"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 invalid_code, got %d body=%s", rec.Code, rec.Body)
	}
	if fid.verifyEmailReq != nil {
		t.Fatal("VerifyEmailOtp must not be called for a factor the user was not offered")
	}
	p, ok, _ := pend.Get(context.Background(), "pend-1")
	if !ok || p.Attempts != 1 {
		t.Fatalf("expected one attempt burned, got %+v ok=%v", p, ok)
	}
}

// TestMfaEmailVerify_Authed: an authed user proving mailbox control (enroll
// purpose) marks the live session MFA-verified.
func TestMfaEmailVerify_Authed(t *testing.T) {
	fid := &fakeIdentity{verifyEmailOk: true}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := enrolledSession(t, h, "usr-42")

	rec := authedPost(h.MfaEmailVerify, "/auth/mfa/email/verify", sid, csrf, map[string]string{"code": "123456"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.verifyEmailReq == nil || fid.verifyEmailReq.GetPurpose() != "enroll" {
		t.Fatalf("VerifyEmailOtp not called with enroll purpose: %+v", fid.verifyEmailReq)
	}
	sess, _, _ := h.Store.Get(context.Background(), sid)
	if !sess.MFAVerified {
		t.Fatal("session should be MFA-verified after proving the email factor")
	}
}

// TestMfaConfirm_BadCode: identity's InvalidArgument maps to 400 invalid_code and
// does not mark the session verified.
func TestMfaConfirm_BadCode(t *testing.T) {
	fid := &fakeIdentity{confirmErr: status.Error(codes.InvalidArgument, "invalid code")}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := enrolledSession(t, h, "usr-42")

	rec := authedPost(h.MfaConfirm, "/auth/mfa/confirm", sid, csrf, map[string]string{"code": "000000"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid_code, got %d body=%s", rec.Code, rec.Body)
	}
	sess, _, _ := h.Store.Get(context.Background(), sid)
	if sess.MFAVerified {
		t.Fatal("session must not be verified on a bad code")
	}
}

// TestMfaRemove_AuthedUser: the session user can remove their own TOTP factor;
// on success the session is INVALIDATED (dropped server-side + cookie expired)
// and the response signals the SPA to sign out.
func TestMfaRemove_AuthedUser(t *testing.T) {
	fid := &fakeIdentity{}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := enrolledSession(t, h, "usr-42")
	freshMFA(t, h, sid)

	rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.removeFactorReq == nil || fid.removeFactorReq.GetUserId() != "usr-42" || fid.removeFactorReq.GetKind() != factorTotp {
		t.Fatalf("RemoveFactor not called for session user+totp: %+v", fid.removeFactorReq)
	}
	// Session invalidated: the id no longer resolves.
	if _, ok, _ := h.Store.Get(context.Background(), sid); ok {
		t.Fatal("session must be invalidated after self-removing the factor")
	}
	// Cookie expired (MaxAge<0) so the browser drops it.
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("session cookie should be expired on self-removal")
	}
	var out struct {
		SignedOut bool `json:"signedOut"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.SignedOut {
		t.Fatal("response should carry signedOut:true so the SPA routes to login")
	}
}

// TestMfaRemove_IdentityError_KeepsSession: a downstream RemoveFactor failure
// must NOT tear down the session (fail closed — the factor is still present).
func TestMfaRemove_IdentityError_KeepsSession(t *testing.T) {
	fid := &fakeIdentity{removeFactorErr: errors.New("identity down")}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := enrolledSession(t, h, "usr-42")
	freshMFA(t, h, sid)

	rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, csrf, map[string]string{})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d body=%s", rec.Code, rec.Body)
	}
	if _, ok, _ := h.Store.Get(context.Background(), sid); !ok {
		t.Fatal("session must survive when factor removal fails")
	}
}

// TestMfaRemove_NoSession: remove without a session is rejected.
func TestMfaRemove_NoSession(t *testing.T) {
	h, _ := mfaLoginHandler(t, &fakeIdentity{})
	rec := postJSON(h.MfaRemove, "/auth/mfa/remove", map[string]string{})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 no_session, got %d", rec.Code)
	}
}

// TestMfaRemove_CSRFRequired: a valid session without the CSRF header is 403.
func TestMfaRemove_CSRFRequired(t *testing.T) {
	h, _ := mfaLoginHandler(t, &fakeIdentity{})
	sid, _ := enrolledSession(t, h, "usr-42")
	rec := authedPost(h.MfaRemove, "/auth/mfa/remove", sid, "", map[string]string{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 csrf, got %d", rec.Code)
	}
}

// adminSession creates an authed session (with a login subject, needed for
// the admin path's ResolveUserContext) for the given acting user id.
func adminSession(t *testing.T, h *Handler, userID, subject string) (string, string) {
	t.Helper()
	csrf := "csrf-admin"
	sid := "sid-admin"
	_ = h.Store.Create(context.Background(), sid, Session{
		UserID: userID, Subject: subject, CSRFToken: csrf, ExpiresAt: time.Now().Add(time.Hour),
	})
	return sid, csrf
}

// TestMfaAdminRemoveTotp_SiteAdmin: a site-admin session removes another user's
// TOTP factor.
func TestMfaAdminRemoveTotp_SiteAdmin(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User:  &identityv1.User{Id: "usr-admin"},
		Roles: []string{"user", "site-admin"},
	}}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := adminSession(t, h, "usr-admin", "sub-admin-1")

	rec := authedPost(h.MfaAdminRemoveTotp, "/auth/mfa/admin/remove-totp", sid, csrf, map[string]string{"userId": "usr-locked-out"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.removeFactorReq == nil || fid.removeFactorReq.GetUserId() != "usr-locked-out" || fid.removeFactorReq.GetKind() != factorTotp {
		t.Fatalf("RemoveFactor not called for target user+totp: %+v", fid.removeFactorReq)
	}
}

// TestMfaAdminRemoveTotp_NotAdmin: a non-admin session is rejected fail-closed,
// and the target's factor is never touched.
func TestMfaAdminRemoveTotp_NotAdmin(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User:  &identityv1.User{Id: "usr-42"},
		Roles: []string{"user"},
	}}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := adminSession(t, h, "usr-42", "sub-abc-123")

	rec := authedPost(h.MfaAdminRemoveTotp, "/auth/mfa/admin/remove-totp", sid, csrf, map[string]string{"userId": "usr-other"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 admin_required, got %d body=%s", rec.Code, rec.Body)
	}
	if fid.removeFactorReq != nil {
		t.Fatalf("RemoveFactor must not be called for a non-admin acting session: %+v", fid.removeFactorReq)
	}
}

// TestMfaAdminRemoveTotp_NoSession: the admin route also requires a session.
func TestMfaAdminRemoveTotp_NoSession(t *testing.T) {
	h, _ := mfaLoginHandler(t, &fakeIdentity{})
	rec := postJSON(h.MfaAdminRemoveTotp, "/auth/mfa/admin/remove-totp", map[string]string{"userId": "usr-other"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 no_session, got %d", rec.Code)
	}
}

// TestMfaAdminRemoveTotp_CSRFRequired: a valid admin session without the CSRF
// header is 403 (indistinguishable from admin_required by status code, but the
// CSRF gate runs first — mirrors every other authed MFA mutation).
func TestMfaAdminRemoveTotp_CSRFRequired(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User:  &identityv1.User{Id: "usr-admin"},
		Roles: []string{"site-admin"},
	}}
	h, _ := mfaLoginHandler(t, fid)
	sid, _ := adminSession(t, h, "usr-admin", "sub-admin-1")

	rec := authedPost(h.MfaAdminRemoveTotp, "/auth/mfa/admin/remove-totp", sid, "", map[string]string{"userId": "usr-other"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 csrf, got %d", rec.Code)
	}
}

// TestMfaAdminRemoveTotp_RevokesTargetSessions: after removing the target's
// factor, every session for that user is revoked (kicked out), while another
// user's session is left untouched.
func TestMfaAdminRemoveTotp_RevokesTargetSessions(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User:  &identityv1.User{Id: "usr-admin"},
		Roles: []string{"site-admin"},
	}}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := adminSession(t, h, "usr-admin", "sub-admin-1")
	// Two live sessions for the target + one for a bystander.
	_ = h.Store.Create(context.Background(), "t-sid-1", Session{UserID: "usr-locked-out", ExpiresAt: time.Now().Add(time.Hour)})
	_ = h.Store.Create(context.Background(), "t-sid-2", Session{UserID: "usr-locked-out", ExpiresAt: time.Now().Add(time.Hour)})
	_ = h.Store.Create(context.Background(), "other-sid", Session{UserID: "usr-bystander", ExpiresAt: time.Now().Add(time.Hour)})

	rec := authedPost(h.MfaAdminRemoveTotp, "/auth/mfa/admin/remove-totp", sid, csrf, map[string]string{"userId": "usr-locked-out"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	for _, id := range []string{"t-sid-1", "t-sid-2"} {
		if _, ok, _ := h.Store.Get(context.Background(), id); ok {
			t.Fatalf("target session %s should be revoked", id)
		}
	}
	if _, ok, _ := h.Store.Get(context.Background(), "other-sid"); !ok {
		t.Fatal("a different user's session must not be revoked")
	}
}

// TestMfaAdminStatus_SiteAdmin: a site-admin can read a target's factor status.
func TestMfaAdminStatus_SiteAdmin(t *testing.T) {
	fid := &fakeIdentity{
		resolveRes:  &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-admin"}, Roles: []string{"site-admin"}},
		mfaEnrolled: true,
	}
	h, _ := mfaLoginHandler(t, fid)
	sid, csrf := adminSession(t, h, "usr-admin", "sub-admin-1")

	req := httptest.NewRequest(http.MethodGet, "/auth/mfa/admin/status?userId=usr-target", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	req.Header.Set("X-CSRF-Token", csrf)
	rec := httptest.NewRecorder()
	h.MfaAdminStatus(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var out struct {
		Enrolled bool `json:"enrolled"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if !out.Enrolled {
		t.Fatal("expected enrolled:true from the target's factor status")
	}
}

// TestMfaAdminStatus_NotAdmin: a non-admin session can't read factor status.
func TestMfaAdminStatus_NotAdmin(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User: &identityv1.User{Id: "usr-42"}, Roles: []string{"user"},
	}}
	h, _ := mfaLoginHandler(t, fid)
	sid, _ := adminSession(t, h, "usr-42", "sub-abc-123")

	req := httptest.NewRequest(http.MethodGet, "/auth/mfa/admin/status?userId=usr-target", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	rec := httptest.NewRecorder()
	h.MfaAdminStatus(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 admin_required, got %d", rec.Code)
	}
}

// TestMfaAdminStatus_MissingUserId: an admin call without userId is 400.
func TestMfaAdminStatus_MissingUserId(t *testing.T) {
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User: &identityv1.User{Id: "usr-admin"}, Roles: []string{"site-admin"},
	}}
	h, _ := mfaLoginHandler(t, fid)
	sid, _ := adminSession(t, h, "usr-admin", "sub-admin-1")

	req := httptest.NewRequest(http.MethodGet, "/auth/mfa/admin/status", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: sid})
	rec := httptest.NewRecorder()
	h.MfaAdminStatus(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 invalid_request, got %d", rec.Code)
	}
}

// TestMemStore_DeleteByUser: the in-memory store revokes exactly the target
// user's sessions and leaves others intact.
func TestMemStore_DeleteByUser(t *testing.T) {
	s := NewMemStore(time.Hour)
	ctx := context.Background()
	_ = s.Create(ctx, "a1", Session{UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = s.Create(ctx, "a2", Session{UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = s.Create(ctx, "b1", Session{UserID: "u2", ExpiresAt: time.Now().Add(time.Hour)})

	if err := s.DeleteByUser(ctx, "u1"); err != nil {
		t.Fatalf("DeleteByUser: %v", err)
	}
	for _, id := range []string{"a1", "a2"} {
		if _, ok, _ := s.Get(ctx, id); ok {
			t.Fatalf("session %s should be gone", id)
		}
	}
	if _, ok, _ := s.Get(ctx, "b1"); !ok {
		t.Fatal("u2's session must remain")
	}
	// Empty user id is a safe no-op.
	if err := s.DeleteByUser(ctx, ""); err != nil {
		t.Fatalf("empty DeleteByUser should be a no-op, got %v", err)
	}
}
