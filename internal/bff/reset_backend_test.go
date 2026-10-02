// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func postReset(h http.HandlerFunc, path string, body any) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b)))
	return rec
}

// A headless gateway cannot redeem a code inside a Kratos browser flow, so on
// every backend the reset code is identity's own and identity writes the
// password; the gateway never runs a Kratos recovery flow.
func TestReset_KratosBackend_UsesIdentityResetCodes(t *testing.T) {
	fid := &fakeIdentity{confirmResetOk: true}
	h := &Handler{Identity: fid}

	if rec := postReset(h.ResetRequest, "/auth/reset/request", map[string]string{"email": "ada@example.org"}); rec.Code != http.StatusOK {
		t.Fatalf("request: status=%d body=%s", rec.Code, rec.Body)
	}
	if fid.resetReqPwd.GetEmail() != "ada@example.org" {
		t.Fatalf("identity RequestPasswordReset not called: %+v", fid.resetReqPwd)
	}

	rec := postReset(h.ResetConfirm, "/auth/reset/confirm", map[string]string{"email": "ada@example.org", "code": "123456", "newPassword": "a-long-new-password"})
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: status=%d body=%s", rec.Code, rec.Body)
	}
	if r := fid.confirmResetReq; r.GetEmail() != "ada@example.org" || r.GetCode() != "123456" || r.GetNewPassword() != "a-long-new-password" {
		t.Fatalf("identity ConfirmPasswordReset request = %+v", r)
	}
}

func TestReset_KratosBackend_WrongCodeIsInvalid(t *testing.T) {
	h := &Handler{Identity: &fakeIdentity{confirmResetOk: false}}
	rec := postReset(h.ResetConfirm, "/auth/reset/confirm", map[string]string{"email": "ada@example.org", "code": "000000", "newPassword": "a-long-new-password"})
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusBadRequest || out["error"] != "invalid_code" {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}
