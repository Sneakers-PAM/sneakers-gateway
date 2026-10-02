// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

// Email verification — public, unauthenticated, mirroring the password
// reset endpoints. Verification confirms an account's email/username spelling,
// so a misspelled account is caught. identity mints/emails/verifies the code
// and sets the flag; the gateway is a thin pass-through. These serve the flows
// that have no session yet: the /setup wizard and the post-account-creation verify screen.

// VerifyRequest serves POST /auth/verify/request {userId}. Best-effort: it
// ALWAYS returns 200 so the outcome (unknown user, rate-limit, send failure)
// never leaks — matching the reset request endpoint.
func (h *Handler) VerifyRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	_, _ = h.Identity.RequestEmailVerification(r.Context(), &identityv1.RequestEmailVerificationRequest{UserId: in.UserID})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// VerifyConfirm serves POST /auth/verify/confirm {userId?, email?, code}: it
// verifies the emailed code (keyed by userId or email) and, on success, marks
// the account verified. A wrong/expired code is 400 {"error":"invalid_code"}.
func (h *Handler) VerifyConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		UserID string `json:"userId"`
		Email  string `json:"email"`
		Code   string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Code == "" || (in.UserID == "" && in.Email == "") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	resp, err := h.Identity.ConfirmEmailVerification(r.Context(), &identityv1.ConfirmEmailVerificationRequest{
		UserId: in.UserID, Email: in.Email, Code: in.Code,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !resp.GetOk() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
