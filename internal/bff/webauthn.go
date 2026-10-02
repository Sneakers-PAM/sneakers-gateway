// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Passkey/WebAuthn BFF. The gateway is a thin pass-through: it shuttles the
// opaque options/credential JSON between browser and identity (the RP). Two
// surfaces, matching the rest of Sneakers MFA:
//   - LOGIN assert — keyed by the 2-step pendingId; the identity session handle
//     is held server-side on the Pending record (never sent to the client). The
//     finish is /auth/verify-otp with kind=passkey (see VerifyOtp).
//   - ENROLL — on the AUTHED (half-)session, like MfaEnroll/MfaConfirm; the
//     ceremony handle is returned to the authed client to echo back on finish.

// MfaWebauthnBegin serves POST /auth/mfa/webauthn/begin {pendingId}: starts a
// passkey login assertion and parks the ceremony handle on the pending record.
func (h *Handler) MfaWebauthnBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID string `json:"pendingId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if h.Pending == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	p, ok, err := h.Pending.Get(r.Context(), in.PendingID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_pending"})
		return
	}
	if !factorOffered(p.Factors, factorPasskey) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	resp, err := h.Identity.WebauthnAssertBegin(r.Context(), &identityv1.WebauthnAssertBeginRequest{UserId: p.UserID})
	if err != nil {
		writeJSON(w, webauthnHTTPCode(err), map[string]string{"error": webauthnErr(err)})
		return
	}
	p.WebauthnSessionID = resp.GetSessionId()
	if err := h.Pending.Save(r.Context(), in.PendingID, p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"optionsJson": resp.GetOptionsJson()})
}

// EnrollWebauthnBegin serves POST /auth/mfa/webauthn/register/begin for the AUTHED
// user: returns the creation options + the ceremony handle to echo back on finish.
func (h *Handler) EnrollWebauthnBegin(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	resp, err := h.Identity.WebauthnRegisterBegin(r.Context(), &identityv1.WebauthnRegisterBeginRequest{UserId: sess.UserID})
	if err != nil {
		writeJSON(w, webauthnHTTPCode(err), map[string]string{"error": webauthnErr(err)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"optionsJson": resp.GetOptionsJson(), "sessionId": resp.GetSessionId()})
}

// EnrollWebauthnFinish serves POST /auth/mfa/webauthn/register/finish
// {sessionId, credentialJson, label?} for the AUTHED user: verifies + stores the
// passkey, then marks the session MFA-verified (a passkey is a strong factor, so
// enrolling one lifts the enforcement gate — mirrors MfaConfirm).
func (h *Handler) EnrollWebauthnFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SessionID      string `json:"sessionId"`
		CredentialJSON string `json:"credentialJson"`
		Label          string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.SessionID == "" || in.CredentialJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	sess, sid, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	_, err := h.Identity.WebauthnRegisterFinish(r.Context(), &identityv1.WebauthnRegisterFinishRequest{
		UserId: sess.UserID, SessionId: in.SessionID, CredentialJson: in.CredentialJSON, Label: in.Label,
	})
	if err != nil {
		writeJSON(w, webauthnHTTPCode(err), map[string]string{"error": webauthnErr(err)})
		return
	}
	sess.MFAVerified = true
	sess.Enrolled = true
	_ = h.Store.Save(r.Context(), sid, sess)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// webauthnHTTPCode/webauthnErr map identity gRPC codes to HTTP + a stable error slug.
func webauthnHTTPCode(err error) int {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.AlreadyExists:
		return http.StatusConflict
	case codes.FailedPrecondition:
		return http.StatusBadRequest
	case codes.NotFound:
		return http.StatusBadRequest
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadGateway
	}
}

func webauthnErr(err error) string {
	switch status.Code(err) {
	case codes.InvalidArgument:
		return "invalid_credential"
	case codes.AlreadyExists:
		return "already_enrolled"
	case codes.FailedPrecondition:
		return "no_passkeys"
	case codes.NotFound:
		return "invalid_session"
	case codes.Unavailable:
		return "passkeys_unavailable"
	default:
		return "identity_unreachable"
	}
}
