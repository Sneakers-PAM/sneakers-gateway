// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestVerifyRequest: the public request endpoint always returns 200 (opaque)
// and forwards the userId to identity.
func TestVerifyRequest(t *testing.T) {
	fid := &fakeIdentity{}
	h := &Handler{Identity: fid}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/verify/request", strings.NewReader(`{"userId":"user-1"}`))
	h.VerifyRequest(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body)
	}
	if fid.verifyEmailReqReq.GetUserId() != "user-1" {
		t.Errorf("userId not forwarded: %+v", fid.verifyEmailReqReq)
	}

	// Missing userId is a 400.
	rec = httptest.NewRecorder()
	h.VerifyRequest(rec, httptest.NewRequest(http.MethodPost, "/auth/verify/request", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("empty userId: want 400, got %d", rec.Code)
	}
}

// TestVerifyConfirm: a good code is 200; a wrong code is 400 invalid_code;
// missing code/subject is 400 invalid_request.
func TestVerifyConfirm(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		ok       bool
		wantCode int
		wantErr  string
	}{
		{"good code", `{"userId":"user-1","code":"123456"}`, true, http.StatusOK, ""},
		{"wrong code", `{"email":"a@example.org","code":"000000"}`, false, http.StatusBadRequest, "invalid_code"},
		{"missing code", `{"userId":"user-1"}`, false, http.StatusBadRequest, "invalid_request"},
		{"missing subject", `{"code":"123456"}`, false, http.StatusBadRequest, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{Identity: &fakeIdentity{confirmEmailOk: tc.ok}}
			rec := httptest.NewRecorder()
			h.VerifyConfirm(rec, httptest.NewRequest(http.MethodPost, "/auth/verify/confirm", strings.NewReader(tc.body)))
			if rec.Code != tc.wantCode {
				t.Fatalf("want %d, got %d body=%s", tc.wantCode, rec.Code, rec.Body)
			}
			if tc.wantErr != "" && !strings.Contains(rec.Body.String(), tc.wantErr) {
				t.Errorf("want error %q, got %s", tc.wantErr, rec.Body)
			}
		})
	}
}
