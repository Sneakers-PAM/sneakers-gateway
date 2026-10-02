// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Self-service password reset, public and unauthenticated. On every backend
// identity mints, emails and verifies its own reset code and writes the new
// password to the user's Ory Kratos identity. A
// Kratos recovery flow is never used: its codes are bound to a browser flow a
// headless gateway cannot complete.

// ResetRequest serves POST /auth/reset/request {email}. Always 200 —
// anti-enumeration — on both backends.
func (h *Handler) ResetRequest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	_, _ = h.Identity.RequestPasswordReset(r.Context(), &identityv1.RequestPasswordResetRequest{Email: in.Email})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ResetConfirm serves POST /auth/reset/confirm {email, code, newPassword}.
func (h *Handler) ResetConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email       string `json:"email"`
		Code        string `json:"code"`
		NewPassword string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Email == "" || in.Code == "" || in.NewPassword == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	resp, err := h.Identity.ConfirmPasswordReset(r.Context(), &identityv1.ConfirmPasswordResetRequest{
		Email: in.Email, Code: in.Code, NewPassword: in.NewPassword,
	})
	if err != nil {
		switch status.Code(err) {
		case codes.InvalidArgument:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "weak_password"})
		case codes.Unavailable:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "reset_unavailable"})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		}
		return
	}
	if !resp.GetOk() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
