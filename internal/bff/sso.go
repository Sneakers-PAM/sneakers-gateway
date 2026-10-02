// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Single-domain Polis SAML SSO leg over one static connection. Login-only: a
// SAML assertion never mints a session by itself — every SSO login resolves an
// EXISTING user by email (no JIT) and then routes through the same 2-step MFA
// and the same sneakers_sid session as local login. These are browser-redirect
// routes (not XHR): the callback never writes JSON to a top-level navigation —
// it sets a cookie and/or redirects back to the SPA.
package bff

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	apperr "github.com/Bugs5382/go-apperr"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

const ssoStateCookie = "sneakers_sso_state"

// codePolisNoUser (2218): SSO login rejected — no platform user for the
// federated email (no-JIT). codePolisState/codePolisCodeExchange/
// codePolisUserInfo (2215-2217) are declared in polis.go.
const codePolisNoUser = 2218

// errBadSSOState is the cause wrapped by codePolisState when the callback's
// state query param doesn't match the short-lived state cookie.
var errBadSSOState = status.Error(codes.InvalidArgument, "sso state mismatch")

// errNoSSOEmail is the cause wrapped by codePolisNoUser when the federated
// profile carried no email at all (distinct from errBadSSOState so the
// server log line isn't misleading).
var errNoSSOEmail = status.Error(codes.InvalidArgument, "sso: federated profile carried no email")

// SSOLogin starts the SAML login: mint a state nonce, stash it in a short-lived
// cookie, and redirect the browser to Jackson's authorize endpoint for the one
// fixed tenant+product.
func (h *Handler) SSOLogin(w http.ResponseWriter, r *http.Request) {
	if h.Polis == nil {
		http.Error(w, "sso not configured", http.StatusServiceUnavailable)
		return
	}
	state, err := NewCSRFToken()
	if err != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, err), "state")
		return
	}
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure comes from cookieSecure (on unless COOKIE_SECURE=false or AUTH_MODE=noauth); HttpOnly and SameSite are set
		Name: ssoStateCookie, Value: state, Path: "/auth/sso",
		HttpOnly: true, Secure: h.Secure, SameSite: http.SameSiteLaxMode, MaxAge: 300,
	})
	redirectURI := strings.TrimRight(h.SSORedirectBase, "/") + "/auth/sso/callback"
	http.Redirect(w, r, h.Polis.AuthorizeURL(redirectURI, state), http.StatusFound)
}

// SSOCallback completes the SAML login.
func (h *Handler) SSOCallback(w http.ResponseWriter, r *http.Request) {
	if h.Polis == nil {
		http.Error(w, "sso not configured", http.StatusServiceUnavailable)
		return
	}
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	c, cerr := r.Cookie(ssoStateCookie)
	// Clear the state cookie regardless of outcome (single-use).
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure comes from cookieSecure (on unless COOKIE_SECURE=false or AUTH_MODE=noauth); HttpOnly and SameSite are set
		Name: ssoStateCookie, Value: "", Path: "/auth/sso",
		HttpOnly: true, Secure: h.Secure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	if code == "" || state == "" || cerr != nil || !CSRFEqual(state, c.Value) {
		h.ssoReject(w, r, apperr.Coded(codePolisState, errBadSSOState), "state")
		return
	}

	redirectURI := strings.TrimRight(h.SSORedirectBase, "/") + "/auth/sso/callback"
	tok, err := h.Polis.CodeExchange(r.Context(), code, redirectURI)
	if err != nil {
		h.ssoReject(w, r, err, "exchange")
		return
	}
	profile, err := h.Polis.UserInfo(r.Context(), tok.AccessToken)
	if err != nil {
		h.ssoReject(w, r, err, "userinfo")
		return
	}

	user, err := h.resolveSSOUserByEmail(r.Context(), profile.Email)
	if err != nil {
		if code, ok := apperr.Code(err); ok && code == codePolisNoUser {
			h.ssoReject(w, r, err, "no_user")
			return
		}
		h.ssoReject(w, r, err, "resolve")
		return
	}

	userID := user.GetId()
	subject := user.GetKeycloakSubject()
	if subject == "" {
		// A pre-provisioned SSO-only user may have no Keycloak/Kratos subject;
		// the platform user id is the stable actor key.
		subject = userID
	}

	// MFA-always: a SAML assertion alone never mints a session.
	mfa, serr := h.Identity.GetMfaStatus(r.Context(), &identityv1.GetMfaStatusRequest{UserId: userID})
	if serr != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, serr), "resolve")
		return
	}
	if mfa.GetEnrolled() {
		h.beginStepUpRedirect(w, r, userID, subject)
		return
	}
	h.issueSessionRedirect(w, r, Session{
		UserID: userID, KeycloakSubject: subject,
		ExpiresAt: time.Now().Add(h.sessionTTL()),
	})
}

// resolveSSOUserByEmail enforces no-JIT: an unknown email is a coded reject
// (2218), never a provision.
func (h *Handler) resolveSSOUserByEmail(ctx context.Context, email string) (*identityv1.User, error) {
	if email == "" {
		return nil, apperr.Coded(codePolisNoUser, errNoSSOEmail)
	}
	resp, err := h.Identity.ResolveUserByEmail(ctx, &identityv1.ResolveUserByEmailRequest{Email: email})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil, apperr.Coded(codePolisNoUser, err)
		}
		return nil, err
	}
	if resp.GetUser() == nil {
		return nil, apperr.Coded(codePolisNoUser, status.Error(codes.NotFound, "resolve returned no user"))
	}
	return resp.GetUser(), nil
}

// issueSessionRedirect mints the sneakers_sid session (identical shape to the
// local-login issueSession) then redirects the browser to the SPA — the
// browser-flow variant that does not write JSON.
func (h *Handler) issueSessionRedirect(w http.ResponseWriter, r *http.Request, sess Session) {
	if h.Store == nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, errBadSSOState), "state")
		return
	}
	csrf, err := NewCSRFToken()
	if err != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, err), "state")
		return
	}
	id, err := newSessionID()
	if err != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, err), "state")
		return
	}
	sess.CSRFToken = csrf
	if err := h.Store.Create(r.Context(), id, sess); err != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, err), "state")
		return
	}
	h.setCookie(w, id, int(h.sessionTTL().Seconds()))
	http.Redirect(w, r, strings.TrimRight(h.SSOAppBase, "/")+"/", http.StatusFound)
}

// beginStepUpRedirect parks a Pending record (same shape/store as beginStepUp)
// with no backend tokens (SSO carries none) and redirects the browser back to
// the SPA with the pending id + factors so the existing MFA challenge view and
// /auth/mfa/verify XHR finish the login.
func (h *Handler) beginStepUpRedirect(w http.ResponseWriter, r *http.Request, userID, subject string) {
	if h.Pending == nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, errBadSSOState), "state")
		return
	}
	factorsResp, err := h.Identity.ListUserFactors(r.Context(), &identityv1.ListUserFactorsRequest{UserId: userID})
	if err != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, err), "resolve")
		return
	}
	// Email IS an acceptable standing second factor: mirror beginStepUp
	// (mfa.go) and include every kind identity lists, verbatim, so email-OTP
	// login is reachable on the SSO step-up path too.
	kinds := make([]string, 0, len(factorsResp.GetFactors()))
	for _, f := range factorsResp.GetFactors() {
		kinds = append(kinds, f.GetKind())
	}
	pendingID, err := newSessionID()
	if err != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, err), "state")
		return
	}
	// ExpiresIn seeds VerifyOtp's promoted Session.ExpiresAt (mfa.go:
	// time.Now().Add(final.ExpiresIn seconds)). An SSO login carries no
	// backend token to derive a real expiry from, so without this the field
	// defaults to 0 and the promoted session is minted already-expired — a
	// dead-on-arrival session killed by resolveSessionActor on the very next
	// request. Seed it with the session TTL instead.
	p := Pending{UserID: userID, KeycloakSubject: subject, Factors: kinds, ExpiresIn: int(h.sessionTTL().Seconds())}
	if err := h.Pending.Create(r.Context(), pendingID, p); err != nil {
		h.ssoReject(w, r, apperr.Coded(codePolisState, err), "state")
		return
	}
	q := url.Values{"sso_pending": {pendingID}, "factors": {strings.Join(kinds, ",")}}
	http.Redirect(w, r, strings.TrimRight(h.SSOAppBase, "/")+"/?"+q.Encode(), http.StatusFound)
}

func (h *Handler) logger() log.Logger {
	if h.Log == nil {
		return log.Nop()
	}
	return h.Log
}

// ssoReject logs (via the coded error) and redirects the browser back to the
// login screen with a stable, non-enumerating reason. An unknown email and a
// disabled/absent user yield the SAME "no_user" answer — never confirm which.
func (h *Handler) ssoReject(w http.ResponseWriter, r *http.Request, err error, reason string) {
	fields := []log.Field{log.F("sso_reason", reason)}
	if code, ok := apperr.Code(err); ok {
		fields = append(fields, log.F("code", code))
	}
	fields = append(fields, log.F("error", err.Error()))
	h.logger().Ctx(r.Context()).Warn("sso login rejected", fields...)
	base := strings.TrimRight(h.SSOAppBase, "/")
	http.Redirect(w, r, base+"/?sso_error="+url.QueryEscape(reason), http.StatusFound)
}
