// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

// MFA second-factor orchestration for the 2-step BFF login and the authed
// user's TOTP enrollment. The password step is Login; when the user has a
// confirmed TOTP factor the Kratos session_token is parked server-side
// under a short-lived pending id and the session cookie is only issued after
// the identity service verifies a code.
//
// No secrets are compared in this process: all code verification happens inside
// the identity service (constant-time there); the only local comparisons are
// non-secret Redis key lookups and CSRF tokens.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxPendingAttempts is the per-pending-id verify budget. The counter lives on
// the pending record, so it doubles as the rate limit for /auth/verify-otp:
// after this many failed factor attempts the record (and the held tokens) is
// discarded and the user must restart login.
const maxPendingAttempts = 5

// Second-factor kinds the kind-dispatched verify understands.
const (
	factorTotp    = "totp"
	factorEmail   = "email"
	factorPasskey = "passkey" // verified via WebAuthn assertion, not a code
)

// Email-OTP purposes scope a code to a flow so a code minted for enrollment can
// never satisfy a login challenge (and vice versa). Identity enforces the same
// vocabulary.
const (
	mfaLoginPurpose  = "login"
	mfaEnrollPurpose = "enroll"
)

// factorOffered reports whether kind is among the factors captured for this
// login. A client can only verify against a factor the user actually has.
func factorOffered(factors []string, kind string) bool {
	for _, f := range factors {
		if f == kind {
			return true
		}
	}
	return false
}

// beginStepUp is the second-factor branch of Login: the password grant
// succeeded but no session may be issued yet. It resolves which factor kinds the
// user can satisfy (identity.ListUserFactors), parks the granted tokens under a
// fresh pending id, and returns {mfaRequired, pendingId, factors} so the widget
// can offer the right challenge (authenticator code vs. "email me a code"). The
// tokens never reach the client. Fail-closed: if the factors can't be resolved
// (identity down) or parking fails, no session and no pending state are created.
func (h *Handler) beginStepUp(w http.ResponseWriter, r *http.Request, tok Tokens, userID, subject string) {
	if h.Pending == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	factorsResp, err := h.Identity.ListUserFactors(r.Context(), &identityv1.ListUserFactorsRequest{UserId: userID})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	// Email IS an acceptable standing second factor: a user who has it
	// enrolled must be offered it here, or email-OTP login is unreachable.
	// Include every kind identity lists, verbatim.
	kinds := make([]string, 0, len(factorsResp.GetFactors()))
	for _, f := range factorsResp.GetFactors() {
		kinds = append(kinds, f.GetKind())
	}
	pendingID, err := newSessionID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	p := Pending{
		AccessToken: tok.AccessToken,
		ExpiresIn:   tok.ExpiresIn,
		UserID:      userID,
		Subject:     subject,
		Factors:     kinds,
	}
	if err := h.Pending.Create(r.Context(), pendingID, p); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"mfaRequired": true, "pendingId": pendingID, "factors": kinds})
}

// VerifyOtp serves POST /auth/verify-otp {pendingId, code, kind?}: it verifies
// the second factor for the pending user and, on success, atomically consumes
// the pending record and issues the real session (marked MFAVerified) exactly as
// a direct login would. kind selects the factor — "totp" (default, back-compat)
// or "email" — and must be one the user was offered at the password step; the
// email branch verifies a login-purpose emailed code. Failures are uniform — 401
// {"error":"invalid_code"} — and each burns one of maxPendingAttempts; a
// missing/expired record is {"error":"invalid_pending"} (restart login).
// Fail-closed throughout: no secret is compared here (identity verifies
// constant-time); the only local checks are the non-secret kind + Redis lookup.
//
//nolint:gocognit,gocyclo // one request flow: decode, pending lookup, kind dispatch, attempt budget and promotion share state
func (h *Handler) VerifyOtp(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PendingID      string `json:"pendingId"`
		Code           string `json:"code"`
		Kind           string `json:"kind"`
		CredentialJSON string `json:"credentialJson"` // passkey assertion payload
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.PendingID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	kind := in.Kind
	if kind == "" {
		kind = factorTotp // a request without a kind is a TOTP verify
	}
	if kind != factorTotp && kind != factorEmail && kind != factorPasskey {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	// Code-based factors need a code; passkey needs the assertion payload.
	if (kind == factorPasskey && in.CredentialJSON == "") || (kind != factorPasskey && in.Code == "") {
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

	// A kind the user was not offered can never verify — treat as a failed guess
	// (uniform answer, burns an attempt) rather than leaking factor availability.
	// A pending record with no Factors recorded is a TOTP-only challenge.
	offered := kind == factorTotp && len(p.Factors) == 0
	offered = offered || factorOffered(p.Factors, kind)

	verified := false
	if offered {
		var verr error
		verified, verr = h.verifyFactor(r.Context(), p.UserID, kind, in.Code, p.WebauthnSessionID, in.CredentialJSON)
		if verr != nil {
			// Infrastructure fault, not a guess: no attempt burned, fail closed.
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
			return
		}
	}
	if !verified {
		h.burnAttempt(r, in.PendingID, p)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	// Verified: single-use consume, then promote to a real session.
	final, ok, err := h.Pending.Consume(r.Context(), in.PendingID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_pending"})
		return
	}
	h.issueSession(w, r, Session{
		AccessToken: final.AccessToken,
		ExpiresAt:   time.Now().Add(time.Duration(final.ExpiresIn) * time.Second),
		UserID:      final.UserID,
		Subject:     final.Subject,
		MFAVerified: true,
		Enrolled:    true, // step-up only happens for users with a confirmed factor
	})
}

// MfaOtpSend serves POST /auth/mfa/otp/send {pendingId}: asks identity to email
// a login-purpose OTP to the pending user, so a user challenged for a second
// factor can complete login by email instead of an authenticator. The email
// factor must have been offered at the password step. Identity enforces its own
// re-issue cooldown (ResourceExhausted → 429). Fail-closed: an unknown/expired
// pending id is invalid_pending (restart login).
func (h *Handler) MfaOtpSend(w http.ResponseWriter, r *http.Request) {
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
	if !factorOffered(p.Factors, factorEmail) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if _, err := h.Identity.SendEmailOtp(r.Context(), &identityv1.SendEmailOtpRequest{
		UserId: p.UserID, Purpose: mfaLoginPurpose,
	}); err != nil {
		if status.Code(err) == codes.ResourceExhausted {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
			return
		}
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// burnAttempt records one failed factor guess. At the attempt budget the record
// (and the held tokens) is discarded so the user must restart login; below it
// the incremented counter is saved in place, preserving the record's TTL.
func (h *Handler) burnAttempt(r *http.Request, id string, p Pending) {
	p.Attempts++
	if p.Attempts >= maxPendingAttempts {
		_ = h.Pending.Delete(r.Context(), id)
		return
	}
	_ = h.Pending.Save(r.Context(), id, p)
}

// authedSession resolves the request's session cookie and enforces the CSRF
// double-submit for the state-changing enroll endpoints. It writes the failure
// response itself; callers only branch on ok. Returns the session and its id
// (so the caller can persist an update).
func (h *Handler) authedSession(w http.ResponseWriter, r *http.Request) (Session, string, bool) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no_session"})
		return Session{}, "", false
	}
	sess, ok, err := h.Store.Get(r.Context(), c.Value)
	if err != nil || !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no_session"})
		return Session{}, "", false
	}
	if !CSRFEqual(r.Header.Get("X-CSRF-Token"), sess.CSRFToken) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
		return Session{}, "", false
	}
	return sess, c.Value, true
}

// MfaEnroll serves POST /auth/mfa/enroll for the AUTHED user: it starts TOTP
// enrollment and returns the base32 secret + otpauth:// URI for the
// authenticator app / QR. An existing confirmed factor is 409; TOTP not
// configured (no key) is 503.
func (h *Handler) MfaEnroll(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	resp, err := h.Identity.EnrollTotp(r.Context(), &identityv1.EnrollTotpRequest{UserId: sess.UserID})
	if err != nil {
		switch status.Code(err) {
		case codes.AlreadyExists:
			writeJSON(w, http.StatusConflict, map[string]string{"error": "already_enrolled"})
		case codes.Unavailable:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mfa_unavailable"})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":     resp.GetSecret(),
		"otpauthUri": resp.GetOtpauthUri(),
	})
}

// MfaConfirm serves POST /auth/mfa/confirm {code} for the AUTHED user: it
// activates the pending TOTP enrollment by proving possession of a current
// code, then marks the live session MFAVerified. A rejected code / no pending
// enrollment is 400 {"error":"invalid_code"}; TOTP not configured is 503.
func (h *Handler) MfaConfirm(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	sess, sid, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	_, err := h.Identity.ConfirmTotp(r.Context(), &identityv1.ConfirmTotpRequest{UserId: sess.UserID, Code: in.Code})
	if err != nil {
		switch status.Code(err) {
		case codes.InvalidArgument, codes.FailedPrecondition:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code"})
		case codes.Unavailable:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mfa_unavailable"})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		}
		return
	}
	// The user has now proven possession of a strong factor on this session.
	// Both flags flip: the session is verified (lifts the enforcement gate) and
	// the user is now enrolled (clears the not-enforced setup banner).
	sess.MFAVerified = true
	sess.Enrolled = true
	_ = h.Store.Save(r.Context(), sid, sess)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// MfaEmailSend serves POST /auth/mfa/email/send for the AUTHED user: it emails
// an enrollment-purpose OTP to prove mailbox control (the email factor itself is
// implicit — every user with an address has it). Mirrors MfaEnroll. Identity
// enforces its own re-issue cooldown (ResourceExhausted → 429) and rejects a
// user with no email address (FailedPrecondition → 400).
func (h *Handler) MfaEmailSend(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	if _, err := h.Identity.SendEmailOtp(r.Context(), &identityv1.SendEmailOtpRequest{
		UserId: sess.UserID, Purpose: mfaEnrollPurpose,
	}); err != nil {
		switch status.Code(err) {
		case codes.ResourceExhausted:
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limited"})
		case codes.FailedPrecondition, codes.NotFound:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no_email"})
		case codes.Unavailable:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mfa_unavailable"})
		default:
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// MfaEmailVerify serves POST /auth/mfa/email/verify {code} for the AUTHED user:
// it verifies the enrollment-purpose OTP (proving mailbox control) and marks the
// live session MFAVerified. Mirrors MfaConfirm. A rejected/expired code is 400
// {"error":"invalid_code"}.
func (h *Handler) MfaEmailVerify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	sess, sid, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	resp, err := h.Identity.VerifyEmailOtp(r.Context(), &identityv1.VerifyEmailOtpRequest{
		UserId: sess.UserID, Code: in.Code, Purpose: mfaEnrollPurpose,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !resp.GetOk() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code"})
		return
	}
	sess.MFAVerified = true
	sess.Enrolled = true
	_ = h.Store.Save(r.Context(), sid, sess)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// MfaRemove serves POST /auth/mfa/remove for the AUTHED user: self-service
// removal of their own TOTP factor (a lost-device reset). Mirrors MfaEnroll:
// session cookie + CSRF required. On success it INVALIDATES the current session
// with the same teardown as Logout — revoke the Kratos session, drop the
// server-side session, expire the cookie — so the user is kicked out and must
// sign in again (re-hitting the mandatory enroll wall when MFA is enforced). The
// {signedOut:true} flag tells the SPA to route to the login screen.
func (h *Handler) MfaRemove(w http.ResponseWriter, r *http.Request) {
	sess, sid, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	if _, err := h.Identity.RemoveFactor(r.Context(), &identityv1.RemoveFactorRequest{
		UserId: sess.UserID, Kind: factorTotp,
	}); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	// Same teardown as Logout: the factor that gated this session is gone, so the
	// session must not survive. Best-effort Kratos revoke, then hard-drop the
	// server session and expire the cookie.
	if h.Auth != nil && sess.AccessToken != "" {
		_ = h.Auth.Logout(r.Context(), sess.AccessToken)
	}
	_ = h.Store.Delete(r.Context(), sid)
	h.setCookie(w, "", -1)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "signedOut": true})
}

// requireAdminSession resolves the request's session cookie and enforces that
// the acting user is a site-admin or root — authorization resolved the same way
// the GraphQL data plane does (ResolveUserContext against the session's login
// subject, never a token claim). CSRF is enforced only for state-changing callers
// (checkCSRF). It writes the failure response itself; callers branch on ok.
func (h *Handler) requireAdminSession(w http.ResponseWriter, r *http.Request, checkCSRF bool) bool {
	c, err := r.Cookie(CookieName)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no_session"})
		return false
	}
	sess, ok, err := h.Store.Get(r.Context(), c.Value)
	if err != nil || !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no_session"})
		return false
	}
	if checkCSRF && !CSRFEqual(r.Header.Get("X-CSRF-Token"), sess.CSRFToken) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
		return false
	}
	resolved, err := h.Identity.ResolveUserContext(r.Context(), &identityv1.ResolveUserContextRequest{
		Subject: sess.Subject,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return false
	}
	attrs, aerr := actorAttrsFrom(resolved)
	if aerr != nil || (!attrs.siteAdmin && !attrs.root) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin_required"})
		return false
	}
	return true
}

// MfaAdminRemoveTotp serves POST /auth/mfa/admin/remove-totp {userId} for a
// SITE-ADMIN (or root) session: it removes ANOTHER user's TOTP factor — the
// account-recovery path when a user has lost their authenticator and can't reach
// the self-service MfaRemove themselves. After removing the factor it REVOKES
// every active session for the target user (DeleteByUser) so they are kicked out
// and forced to re-enroll on next sign-in. A non-admin acting session is
// rejected fail-closed with 403 before the target user id is even read.
func (h *Handler) MfaAdminRemoveTotp(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminSession(w, r, true) {
		return
	}
	var in struct {
		UserID string `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if _, err := h.Identity.RemoveFactor(r.Context(), &identityv1.RemoveFactorRequest{
		UserId: in.UserID, Kind: factorTotp,
	}); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	// Kick the target: their sessions were gated on the factor that no longer
	// exists. Best-effort — the factor is already gone, so an index hiccup must
	// not report failure.
	_ = h.Store.DeleteByUser(r.Context(), in.UserID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// MfaAdminStatus serves GET /auth/mfa/admin/status?userId=… for a SITE-ADMIN
// (or root) session: it reports whether the target user has a confirmed factor,
// so the admin UI can disable "remove authenticator" when there is nothing to
// remove. A safe read — session + admin required, but no CSRF (GET).
func (h *Handler) MfaAdminStatus(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdminSession(w, r, false) {
		return
	}
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	resp, err := h.Identity.GetMfaStatus(r.Context(), &identityv1.GetMfaStatusRequest{UserId: userID})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enrolled": resp.GetEnrolled()})
}

// verifyFactor checks one second-factor proof for userID. An error means
// identity couldn't be asked, not that the proof was wrong.
func (h *Handler) verifyFactor(ctx context.Context, userID, kind, code, webauthnSessionID, credentialJSON string) (bool, error) {
	switch kind {
	case factorTotp:
		resp, err := h.Identity.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: userID, Code: code})
		return resp.GetOk(), err
	case factorEmail:
		resp, err := h.Identity.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: userID, Code: code, Purpose: mfaLoginPurpose})
		return resp.GetOk(), err
	case factorPasskey:
		resp, err := h.Identity.WebauthnAssertFinish(ctx, &identityv1.WebauthnAssertFinishRequest{
			UserId: userID, SessionId: webauthnSessionID, CredentialJson: credentialJSON,
		})
		return resp.GetOk(), err
	}
	return false, nil
}
