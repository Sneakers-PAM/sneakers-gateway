// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"fmt"
	"net/http"
	"time"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

// MFAMaxAgeEnv is the setting the vault and the workflow already read for how
// recent a second factor must be; the gateway reads the same one.
const MFAMaxAgeEnv = "MFA_MAX_AGE"

// DefaultMFAMaxAge applies when MFA_MAX_AGE is unset.
const DefaultMFAMaxAge = 30 * time.Minute

// MaxMFAMaxAge is the longest window MFA_MAX_AGE accepts.
const MaxMFAMaxAge = 4 * time.Hour

// MFAEveryTime is the window MFA_MAX_AGE=0 parses to: shorter than the clock
// skew allowance, so a step-up covers only the action retried right after it.
const MFAEveryTime = time.Nanosecond

// mfaClockSkew tolerates an MFA time slightly ahead of this clock, as the
// vault does.
const mfaClockSkew = 30 * time.Second

// ParseMFAMaxAge parses MFA_MAX_AGE exactly as the vault and the workflow do: a
// Go duration from 0 to 4h, default 30m, where 0 means every sensitive action
// needs its own step-up (returned as MFAEveryTime). A bad value is an error so
// the gateway stops at boot.
func ParseMFAMaxAge(getenv func(string) string) (time.Duration, error) {
	v := getenv(MFAMaxAgeEnv)
	if v == "" {
		return DefaultMFAMaxAge, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 || d > MaxMFAMaxAge {
		return 0, fmt.Errorf("%s=%q: want a duration from 0 to 4h", MFAMaxAgeEnv, v)
	}
	if d == 0 {
		return MFAEveryTime, nil
	}
	return d, nil
}

func (h *Handler) mfaMaxAge() time.Duration {
	if h.MFAMaxAge > 0 {
		return h.MFAMaxAge
	}
	return DefaultMFAMaxAge
}

// mfaFresh reports whether the session proved a second factor within
// MFA_MAX_AGE (at least the clock skew, so a step-up covers its own retry).
func (h *Handler) mfaFresh(sess Session) bool {
	if sess.MFAVerifiedAt.IsZero() {
		return false
	}
	age := time.Since(sess.MFAVerifiedAt)
	return age >= -mfaClockSkew && age <= max(h.mfaMaxAge(), mfaClockSkew)
}

// requireStepUp refuses a factor change with 403 step_up_required when the
// session's MFA is stale. It writes the failure response itself.
func (h *Handler) requireStepUp(w http.ResponseWriter, r *http.Request, sess Session, route string) bool {
	if h.mfaFresh(sess) {
		return true
	}
	h.logger().Ctx(r.Context()).Info("mfa factor change refused: step-up required", log.F("route", route))
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "step_up_required"})
	return false
}

// requireEnrolStepUp is requireStepUp for enrolment: a user with no factor yet
// has nothing to step up with, so the first enrolment needs no fresh MFA.
// Whether the user has a factor is asked of identity, not read off the
// session, so a factor removed elsewhere is seen. Fails closed.
func (h *Handler) requireEnrolStepUp(w http.ResponseWriter, r *http.Request, sess Session, route string) bool {
	if h.mfaFresh(sess) {
		return true
	}
	st, err := h.Identity.GetMfaStatus(r.Context(), &identityv1.GetMfaStatusRequest{UserId: sess.UserID})
	if err != nil {
		h.logger().Ctx(r.Context()).Error(err, "mfa enrolment: factor state unknown", log.F("route", route))
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return false
	}
	if !st.GetEnrolled() {
		h.logger().Ctx(r.Context()).Debug("mfa enrolment: first factor, no step-up needed", log.F("route", route))
		return true
	}
	return h.requireStepUp(w, r, sess, route)
}

// strongFactorsLeft counts the factors that would remain after removing
// kind. The implicit email factor does not count: identity's GetMfaStatus,
// which decides whether a login owes a second factor, ignores it too.
func strongFactorsLeft(factors []*identityv1.UserFactor, kind string) int {
	n := 0
	for _, f := range factors {
		if f.GetKind() != kind && (f.GetKind() == factorTotp || f.GetKind() == factorPasskey) {
			n++
		}
	}
	return n
}

// factorView is one entry of GET /auth/mfa/factors. It holds ids, labels and
// times only; never a secret, public key or other credential material.
type factorView struct {
	Kind       string  `json:"kind"`
	ID         string  `json:"id"`
	Label      string  `json:"label"`
	CreatedAt  *string `json:"createdAt"`
	LastUsedAt *string `json:"lastUsedAt"`
}

func optTime(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// MfaFactors serves GET /auth/mfa/factors for the AUTHED user (session cookie
// + CSRF): the user's own second factors. TOTP and the implicit email factor
// come from identity's ListUserFactors; each passkey is listed separately from
// ListWebauthnCredentials. Identity unreachable is 502.
func (h *Handler) MfaFactors(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := h.authedSession(w, r)
	if !ok {
		return
	}
	lg := h.logger().Ctx(r.Context())
	resp, err := h.Identity.ListUserFactors(r.Context(), &identityv1.ListUserFactorsRequest{UserId: sess.UserID})
	if err != nil {
		lg.Error(err, "mfa factors: list failed")
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	out := []factorView{}
	for _, f := range resp.GetFactors() {
		switch f.GetKind() {
		case factorTotp:
			out = append(out, factorView{Kind: factorTotp, ID: factorTotp, Label: "Authenticator app", CreatedAt: optTime(f.GetEnrolledAt())})
		case factorEmail:
			out = append(out, factorView{Kind: factorEmail, ID: factorEmail, Label: "Email", CreatedAt: optTime(f.GetEnrolledAt())})
		case factorPasskey:
			creds, cerr := h.Identity.ListWebauthnCredentials(r.Context(), &identityv1.ListWebauthnCredentialsRequest{UserId: sess.UserID})
			if cerr != nil {
				lg.Error(cerr, "mfa factors: passkey list failed")
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
				return
			}
			for _, c := range creds.GetCredentials() {
				label := c.GetLabel()
				if label == "" {
					label = "Passkey"
				}
				out = append(out, factorView{Kind: factorPasskey, ID: c.GetId(), Label: label, CreatedAt: optTime(c.GetCreatedAt()), LastUsedAt: optTime(c.GetLastUsedAt())})
			}
		}
	}
	lg.Debug("mfa factors: listed", log.F("count", len(out)))
	writeJSON(w, http.StatusOK, map[string]any{"factors": out})
}
