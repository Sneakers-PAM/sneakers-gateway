// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"encoding/json"
	"net/http"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MfaStepUp serves POST /auth/mfa/step-up {kind, code | credentialJson +
// webauthnSessionId}: a signed-in user proves a second factor again, and the
// session's MFAVerifiedAt moves to now. The vault reads that time to decide
// whether a sensitive reveal or check-out may go ahead, and answers
// STEP_UP_REQUIRED when it is too old. A wrong proof is 401 invalid_code and
// counts toward maxPendingAttempts, after which the session is revoked.
func (h *Handler) MfaStepUp(w http.ResponseWriter, r *http.Request) {
	sess, sid, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	log := h.logger().Ctx(r.Context())
	if !sess.MFAVerified {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "mfa_required"})
		return
	}
	var in struct {
		Kind              string `json:"kind"`
		Code              string `json:"code"`
		CredentialJSON    string `json:"credentialJson"`
		WebauthnSessionID string `json:"webauthnSessionId"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	switch {
	case in.Kind == factorPasskey && in.CredentialJSON != "" && in.WebauthnSessionID != "":
	case (in.Kind == factorTotp || in.Kind == factorEmail) && in.Code != "":
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	verified, err := h.verifyFactor(r.Context(), sess.UserID, in.Kind, in.Code, in.WebauthnSessionID, in.CredentialJSON)
	if err != nil {
		log.Error(err, "mfa step-up: identity unreachable")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !verified {
		sess.StepUpFailures++
		if sess.StepUpFailures >= maxPendingAttempts {
			log.Warn("mfa step-up: attempt budget spent, session revoked")
			_ = h.Store.Delete(r.Context(), sid)
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "session_revoked"})
			return
		}
		log.Info("mfa step-up: wrong proof")
		_ = h.Store.Save(r.Context(), sid, sess)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	sess.MFAVerifiedAt = time.Now()
	sess.StepUpFailures = 0
	if err := h.Store.Save(r.Context(), sid, sess); err != nil {
		log.Error(err, "mfa step-up: session save failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	log.Info("mfa step-up: verified")
	writeJSON(w, http.StatusOK, map[string]int64{"mfaVerifiedAt": sess.MFAVerifiedAt.Unix()})
}

// MfaStepUpEmailSend serves POST /auth/mfa/step-up/email/send: it emails the
// signed-in user a code for a step-up. Identity's re-issue cooldown answers 429.
func (h *Handler) MfaStepUpEmailSend(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	if _, err := h.Identity.SendEmailOtp(r.Context(), &identityv1.SendEmailOtpRequest{UserId: sess.UserID, Purpose: mfaLoginPurpose}); err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

// MfaStepUpPasskeyBegin serves POST /auth/mfa/step-up/passkey/begin: it starts
// a passkey assertion for the signed-in user and returns the options and the
// webauthnSessionId to send back with the assertion.
func (h *Handler) MfaStepUpPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	resp, err := h.Identity.WebauthnAssertBegin(r.Context(), &identityv1.WebauthnAssertBeginRequest{UserId: sess.UserID})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"options": resp.GetOptionsJson(), "webauthnSessionId": resp.GetSessionId()})
}
