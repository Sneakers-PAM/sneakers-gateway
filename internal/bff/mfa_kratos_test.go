// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

func TestLogin_KratosBackend_MfaEnforced_NoSessionBeforeVerify(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fid := &fakeIdentity{
		adoptUser:   &identityv1.User{Id: "usr-42"},
		mfaEnrolled: true, // GetMfaStatus.Enrolled = true → must step up
		factors:     []string{"totp"},
		verifyOk:    true,
	}
	h := &Handler{
		Store: NewMemStore(time.Hour), Identity: fid, Pending: newMemPending(), TTL: time.Hour,
		Auth: NewKratosClient(kratos.URL, kratos.URL), MfaEnforced: true,
	}

	body, _ := json.Marshal(map[string]string{"username": cfg.email, "password": cfg.goodPassword})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var loginOut struct {
		MfaRequired bool     `json:"mfaRequired"`
		PendingID   string   `json:"pendingId"`
		Factors     []string `json:"factors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginOut)
	if !loginOut.MfaRequired || loginOut.PendingID == "" {
		t.Fatalf("expected a pending 2-step challenge, got %s", rec.Body)
	}
	// NO session cookie may be set before the second factor is verified.
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("a session cookie was set before MFA verification — MFA-always violated")
	}

	// Complete the second factor and confirm the session now mints.
	verifyBody, _ := json.Marshal(map[string]string{"pendingId": loginOut.PendingID, "code": "123456", "kind": "totp"})
	verifyRec := httptest.NewRecorder()
	h.VerifyOtp(verifyRec, httptest.NewRequest(http.MethodPost, "/auth/verify-otp", bytes.NewReader(verifyBody)))

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyRec.Code, verifyRec.Body)
	}
	var sid string
	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == CookieName {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie after successful MFA verify")
	}
	sess, ok, _ := h.Store.Get(context.Background(), sid)
	if !ok || !sess.MFAVerified || sess.Subject != cfg.identityID {
		t.Fatalf("session not correctly promoted after MFA: %+v ok=%v", sess, ok)
	}
}

func TestSessionActor_KratosBackend_HalfSessionBlockedFromGraphQL(t *testing.T) {
	// A Kratos-backed session issued with MFAVerified=false (enforced, not yet
	// enrolled) must be rejected from /graphql — mfaFlags/SessionActor's
	// enforcement gate.
	// ResolveUserContext must succeed (as it would for any live session) so the
	// request reaches the MFA gate rather than failing earlier on actor
	// resolution — resolveSessionActor resolves the actor before SessionActor
	// evaluates mfaFlags.
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}}}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour, MfaEnforced: true}
	sess := Session{AccessToken: "opaque-tok", ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf-1", UserID: "usr-42", Subject: "identity-1", MFAVerified: false}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rec := httptest.NewRecorder()
	ran := false
	h.SessionActor(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden || ran {
		t.Fatalf("expected 403 mfa_required with next NOT run, got %d ran=%v body=%s", rec.Code, ran, rec.Body)
	}
}

func TestLogin_KratosBackend_PasskeyStepUpUnchanged(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fid := &fakeIdentity{
		adoptUser: &identityv1.User{Id: "usr-42"}, mfaEnrolled: true, factors: []string{"passkey"},
		waAssertBeginResp: &identityv1.WebauthnAssertBeginResponse{OptionsJson: "{}", SessionId: "wa-sess-1"},
		waAssertFinishOk:  true,
	}
	h := &Handler{
		Store: NewMemStore(time.Hour), Identity: fid, Pending: newMemPending(), TTL: time.Hour,
		Auth: NewKratosClient(kratos.URL, kratos.URL), MfaEnforced: true,
	}
	body, _ := json.Marshal(map[string]string{"username": cfg.email, "password": cfg.goodPassword})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	var loginOut struct {
		PendingID string `json:"pendingId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginOut)

	beginBody, _ := json.Marshal(map[string]string{"pendingId": loginOut.PendingID})
	beginRec := httptest.NewRecorder()
	h.MfaWebauthnBegin(beginRec, httptest.NewRequest(http.MethodPost, "/auth/mfa/webauthn/begin", bytes.NewReader(beginBody)))
	if beginRec.Code != http.StatusOK {
		t.Fatalf("webauthn begin status=%d body=%s", beginRec.Code, beginRec.Body)
	}

	finishBody, _ := json.Marshal(map[string]string{"pendingId": loginOut.PendingID, "kind": "passkey", "credentialJson": "{}"})
	finishRec := httptest.NewRecorder()
	h.VerifyOtp(finishRec, httptest.NewRequest(http.MethodPost, "/auth/verify-otp", bytes.NewReader(finishBody)))
	if finishRec.Code != http.StatusOK {
		t.Fatalf("passkey verify status=%d body=%s", finishRec.Code, finishRec.Body)
	}
	found := false
	for _, c := range finishRec.Result().Cookies() {
		found = found || c.Name == CookieName
	}
	if !found {
		t.Fatal("no session cookie after successful passkey verify")
	}
}

func TestLogin_KratosBackend_EmailOtpStepUpUnchanged(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fid := &fakeIdentity{
		adoptUser: &identityv1.User{Id: "usr-42"}, mfaEnrolled: true, factors: []string{"totp"}, verifyEmailOk: true,
	}
	h := &Handler{
		Store: NewMemStore(time.Hour), Identity: fid, Pending: newMemPending(), TTL: time.Hour,
		Auth: NewKratosClient(kratos.URL, kratos.URL), MfaEnforced: true,
	}
	body, _ := json.Marshal(map[string]string{"username": cfg.email, "password": cfg.goodPassword})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	var loginOut struct {
		PendingID string `json:"pendingId"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &loginOut)

	// This fake's enrolled factors are ["totp"] only (email-OTP login is
	// exercised end-to-end by the
	// TestLogin_EmailOnlyEnrolled_* tests in mfa_test.go). Append email onto
	// the already-Kratos-parked record, exactly as an enrolled user's pending
	// record would look coming out of the separate email-bootstrap flow, so
	// this test can drive the identity-service email-OTP RPCs themselves
	// (MfaOtpSend/VerifyOtp kind=email) — the thing this test proves is
	// backend-agnostic — without needing a second Kratos fake enrolled in
	// email.
	p, ok, err := h.Pending.Get(context.Background(), loginOut.PendingID)
	if err != nil || !ok {
		t.Fatalf("pending record not parked after Kratos login: ok=%v err=%v", ok, err)
	}
	p.Factors = append(p.Factors, factorEmail)
	if err := h.Pending.Save(context.Background(), loginOut.PendingID, p); err != nil {
		t.Fatalf("save pending: %v", err)
	}

	sendBody, _ := json.Marshal(map[string]string{"pendingId": loginOut.PendingID})
	sendRec := httptest.NewRecorder()
	h.MfaOtpSend(sendRec, httptest.NewRequest(http.MethodPost, "/auth/mfa/otp/send", bytes.NewReader(sendBody)))
	if sendRec.Code != http.StatusOK {
		t.Fatalf("otp send status=%d body=%s", sendRec.Code, sendRec.Body)
	}

	verifyBody, _ := json.Marshal(map[string]string{"pendingId": loginOut.PendingID, "kind": "email", "code": "654321"})
	verifyRec := httptest.NewRecorder()
	h.VerifyOtp(verifyRec, httptest.NewRequest(http.MethodPost, "/auth/verify-otp", bytes.NewReader(verifyBody)))
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("email-otp verify status=%d body=%s", verifyRec.Code, verifyRec.Body)
	}
}
