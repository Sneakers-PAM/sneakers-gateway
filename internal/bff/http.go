// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package bff is the gateway's authenticated-session layer (AUTH_MODE=real):
// it exchanges credentials for Keycloak tokens, keeps them server-side behind
// an opaque HttpOnly cookie, and resolves that cookie to the acting user on
// every GraphQL request. The acting user is placed on the resolver context
// (Sneakers has no JWT-claims layer).
package bff

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
	"google.golang.org/grpc"
)

const CookieName = "sneakers_sid"

// roleSiteAdmin and roleAdmin both grant full backend-admin authority in the
// vault ActorContext. "admin" is the assignable/removable admin role (root is an
// admin that additionally can't be deleted); "site-admin" is an equivalent
// synonym. Either confers the same privileges.
const (
	roleSiteAdmin = "site-admin"
	roleAdmin     = "admin"
)

// IdentityClient is the narrow identity-service surface the real-login flow
// needs: adopt/provision at login and resolve the effective actor context per
// request. The generated identityv1.IdentityServiceClient satisfies it, and a
// stub can implement it in tests without the full interface.
type IdentityClient interface {
	MintUserToken(ctx context.Context, in *identityv1.MintUserTokenRequest, opts ...grpc.CallOption) (*identityv1.MintUserTokenResponse, error)
	VerifyUserToken(ctx context.Context, in *identityv1.VerifyUserTokenRequest, opts ...grpc.CallOption) (*identityv1.VerifyUserTokenResponse, error)
	SearchUsers(ctx context.Context, in *identityv1.SearchUsersRequest, opts ...grpc.CallOption) (*identityv1.SearchUsersResponse, error)
	AdoptOrProvisionFederatedUser(ctx context.Context, in *identityv1.AdoptOrProvisionFederatedUserRequest, opts ...grpc.CallOption) (*identityv1.AdoptOrProvisionFederatedUserResponse, error)
	ResolveUserByEmail(ctx context.Context, in *identityv1.ResolveUserByEmailRequest, opts ...grpc.CallOption) (*identityv1.ResolveUserByEmailResponse, error)
	ResolveUserContext(ctx context.Context, in *identityv1.ResolveUserContextRequest, opts ...grpc.CallOption) (*identityv1.ResolveUserContextResponse, error)
	// MFA (2-step): status + the kind-dispatched verify drive the login
	// challenge; enroll + confirm serve the authed user's factor setup.
	GetMfaStatus(ctx context.Context, in *identityv1.GetMfaStatusRequest, opts ...grpc.CallOption) (*identityv1.GetMfaStatusResponse, error)
	VerifyTotp(ctx context.Context, in *identityv1.VerifyTotpRequest, opts ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error)
	EnrollTotp(ctx context.Context, in *identityv1.EnrollTotpRequest, opts ...grpc.CallOption) (*identityv1.EnrollTotpResponse, error)
	ConfirmTotp(ctx context.Context, in *identityv1.ConfirmTotpRequest, opts ...grpc.CallOption) (*identityv1.ConfirmTotpResponse, error)
	// MFA email OTP + generalized factor model. ListUserFactors backs the
	// kind-dispatched login challenge; SendEmailOtp/VerifyEmailOtp back the
	// email second factor (login + enroll). RemoveFactor is the factor-management
	// hook (email is implicit).
	ListUserFactors(ctx context.Context, in *identityv1.ListUserFactorsRequest, opts ...grpc.CallOption) (*identityv1.ListUserFactorsResponse, error)
	SendEmailOtp(ctx context.Context, in *identityv1.SendEmailOtpRequest, opts ...grpc.CallOption) (*identityv1.SendEmailOtpResponse, error)
	VerifyEmailOtp(ctx context.Context, in *identityv1.VerifyEmailOtpRequest, opts ...grpc.CallOption) (*identityv1.VerifyEmailOtpResponse, error)
	// Self-service password reset: public, unauthenticated.
	RequestPasswordReset(ctx context.Context, in *identityv1.RequestPasswordResetRequest, opts ...grpc.CallOption) (*identityv1.RequestPasswordResetResponse, error)
	ConfirmPasswordReset(ctx context.Context, in *identityv1.ConfirmPasswordResetRequest, opts ...grpc.CallOption) (*identityv1.ConfirmPasswordResetResponse, error)
	// SendTransactionalEmail delivers an operator-composed email (Kratos
	// recovery-code delivery) through identity's SMTP sender.
	SendTransactionalEmail(ctx context.Context, in *identityv1.SendTransactionalEmailRequest, opts ...grpc.CallOption) (*identityv1.SendTransactionalEmailResponse, error)
	// Email verification: confirm an account's email/username spelling.
	// The public request/confirm serve the unauthenticated /setup + pre-login flows.
	RequestEmailVerification(ctx context.Context, in *identityv1.RequestEmailVerificationRequest, opts ...grpc.CallOption) (*identityv1.RequestEmailVerificationResponse, error)
	ConfirmEmailVerification(ctx context.Context, in *identityv1.ConfirmEmailVerificationRequest, opts ...grpc.CallOption) (*identityv1.ConfirmEmailVerificationResponse, error)
	// Passkey/WebAuthn: register (authed enroll) + assert (login) ceremonies.
	WebauthnRegisterBegin(ctx context.Context, in *identityv1.WebauthnRegisterBeginRequest, opts ...grpc.CallOption) (*identityv1.WebauthnRegisterBeginResponse, error)
	WebauthnRegisterFinish(ctx context.Context, in *identityv1.WebauthnRegisterFinishRequest, opts ...grpc.CallOption) (*identityv1.WebauthnRegisterFinishResponse, error)
	WebauthnAssertBegin(ctx context.Context, in *identityv1.WebauthnAssertBeginRequest, opts ...grpc.CallOption) (*identityv1.WebauthnAssertBeginResponse, error)
	WebauthnAssertFinish(ctx context.Context, in *identityv1.WebauthnAssertFinishRequest, opts ...grpc.CallOption) (*identityv1.WebauthnAssertFinishResponse, error)
	RemoveFactor(ctx context.Context, in *identityv1.RemoveFactorRequest, opts ...grpc.CallOption) (*identityv1.RemoveFactorResponse, error)
	// VerifyApiToken: the gateway's machine bearer-auth path
	// (MachineActor) resolves a service-account API token to its principal here.
	// Does not distinguish unknown/expired/revoked to the caller — MachineActor
	// treats any valid=false the same: 401.
	VerifyApiToken(ctx context.Context, in *identityv1.VerifyApiTokenRequest, opts ...grpc.CallOption) (*identityv1.VerifyApiTokenResponse, error)
	// ResolveServiceAccountByOidc: the machine bearer-auth path's
	// OTHER leg — MachineActor resolves a Hydra-issued OIDC/OAuth2 JWT
	// (client-credentials) to its principal here, once bff.Verifier has
	// checked the token's signature/iss/aud. Keyed on (issuer, sub=client_id).
	// Like VerifyApiToken, does not distinguish unknown/disabled to the
	// caller — MachineActor treats any valid=false the same: 401.
	ResolveServiceAccountByOidc(ctx context.Context, in *identityv1.ResolveServiceAccountByOidcRequest, opts ...grpc.CallOption) (*identityv1.ResolveServiceAccountByOidcResponse, error)
	// Service-account + API-token admin management: the human /graphql
	// admin surface for the machine principals
	// VerifyApiToken authenticates above. These RPCs do not self-authorize —
	// the resolvers package (internal/resolvers) gates every one of them on
	// site-admin/root before calling through. Kept on this narrow interface
	// alongside VerifyApiToken for parity with the rest of the identity
	// surface the gateway pins to.
	CreateServiceAccount(ctx context.Context, in *identityv1.CreateServiceAccountRequest, opts ...grpc.CallOption) (*identityv1.CreateServiceAccountResponse, error)
	ListServiceAccounts(ctx context.Context, in *identityv1.ListServiceAccountsRequest, opts ...grpc.CallOption) (*identityv1.ListServiceAccountsResponse, error)
	DisableServiceAccount(ctx context.Context, in *identityv1.DisableServiceAccountRequest, opts ...grpc.CallOption) (*identityv1.DisableServiceAccountResponse, error)
	MintApiToken(ctx context.Context, in *identityv1.MintApiTokenRequest, opts ...grpc.CallOption) (*identityv1.MintApiTokenResponse, error)
	ListApiTokens(ctx context.Context, in *identityv1.ListApiTokensRequest, opts ...grpc.CallOption) (*identityv1.ListApiTokensResponse, error)
	RevokeApiToken(ctx context.Context, in *identityv1.RevokeApiTokenRequest, opts ...grpc.CallOption) (*identityv1.RevokeApiTokenResponse, error)
	// LinkOidcClient/UnlinkOidcClient: the human /graphql admin
	// surface that manages a service account's OIDC client linkage —
	// the counterpart ResolveServiceAccountByOidc resolves above. Kept on
	// this narrow interface for the same reason CreateServiceAccount is.
	LinkOidcClient(ctx context.Context, in *identityv1.LinkOidcClientRequest, opts ...grpc.CallOption) (*identityv1.LinkOidcClientResponse, error)
	UnlinkOidcClient(ctx context.Context, in *identityv1.UnlinkOidcClientRequest, opts ...grpc.CallOption) (*identityv1.UnlinkOidcClientResponse, error)
}

type Handler struct {
	Store    SessionStore
	KC       *KCClient
	Verifier *Verifier
	Identity IdentityClient
	// Pending parks the granted tokens between the password step and a verified
	// second factor (the 2-step login seam). Required when MFA is wired.
	Pending PendingStore
	// OAuthStore backs the MCP /login authorization server (see OAuth).
	OAuthStore OAuthStore
	// TTL is the static session lifetime fallback (used in tests). In production
	// TTLFn is set instead and returns the current admin-configured, clamped
	// session timeout, evaluated on every cookie write so a sliding renewal
	// always tracks the live setting.
	TTL    time.Duration
	TTLFn  func() time.Duration
	Secure bool
	// MfaEnforced is the org posture (env MFA_ENFORCED, default true): when true,
	// a session without a verified second factor is a half-session — it may only
	// reach the MFA enrollment endpoints, never /graphql or subscriptions, so an
	// un-enrolled user cannot bypass MFA by refreshing into the app. When false,
	// MFA is optional and the client shows a setup-recommended banner instead.
	MfaEnforced bool
	// Auth is the local-login password backend. nil (the default) falls back
	// to a kcVerifiedAuth wrapping KC+Verifier — see auth() in authclient.go.
	// main.go sets this explicitly to a *KratosClient under AUTH_BACKEND=kratos.
	Auth authClient
	// Backend records which auth backend is active ("" or "keycloak" | "kratos")
	// so backendToken/resolveSessionActor know which stored credential
	// to present on refresh/logout and whether a per-request JWT re-verify is
	// possible.
	Backend string
	// Polis is the single-domain SAML SSO broker client. nil disables the SSO
	// leg (SSOLogin/SSOCallback return 503). main.go sets it when POLIS_* env
	// is configured.
	Polis *PolisClient
	// SSORedirectBase is the gateway's own public base URL; the SAML callback
	// URI is SSORedirectBase + "/auth/sso/callback".
	SSORedirectBase string
	// SSOAppBase is the SPA base the callback redirects the browser back to
	// after a successful login (or, for MFA-enrolled users, with the pending id).
	SSOAppBase string
	// Log receives the handler's request-scoped lines, trace-correlated per
	// request. nil discards them.
	Log log.Logger
	// MachineOidcVerifier is the machine bearer-auth path's OIDC leg: when
	// set, MachineActor accepts a Hydra-issued JWT bearer (client-credentials)
	// alongside the opaque service-account API token path — see
	// oidc_machine.go. nil (the default) keeps the OIDC path INERT: a
	// JWT-shaped bearer simply fails closed with 401, and the opaque-token
	// path is completely unaffected. Wired from main.go only when
	// HYDRA_ENABLED is true (HYDRA_ISSUER/HYDRA_JWKS_URL/HYDRA_AUDIENCE may be
	// set even while disabled — see newHydraVerifier).
	MachineOidcVerifier *Verifier
	// MachineOidcIssuer is the expected `iss` a verified JWT's ResolveServiceAccountByOidc
	// lookup is keyed against. Kept alongside MachineOidcVerifier rather than
	// read off the token, since the token's iss was already checked by the
	// verifier and this is the gateway's own trusted value, not caller input.
	MachineOidcIssuer string
	// refreshGroup coalesces concurrent refreshSession calls per session id:
	// with Keycloak refresh-token ROTATION, two parallel requests
	// racing the same expired access token must not both call auth().Refresh
	// with the same (soon-to-be-invalidated) refresh token — the loser would
	// get invalid_grant on a session that was just legitimately refreshed by
	// the winner. The zero value is ready to use; no initialization needed.
	refreshGroup singleflight.Group
}

// mfaFlags reports the client-facing MFA posture for a session: enrollmentRequired
// gates the enroll wall (enforced + no verified factor); setupRecommended drives
// the not-enforced setup banner (optional + not yet enrolled).
func (h *Handler) mfaFlags(sess Session) (enrollmentRequired, setupRecommended bool) {
	enrollmentRequired = h.MfaEnforced && !sess.MFAVerified
	setupRecommended = !h.MfaEnforced && !sess.Enrolled
	return
}

func newSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// sessionTTL returns the current session lifetime: the dynamic, admin-configured
// value from TTLFn when set, otherwise the static TTL fallback.
func (h *Handler) sessionTTL() time.Duration {
	if h.TTLFn != nil {
		return h.TTLFn()
	}
	return h.TTL
}

func (h *Handler) setCookie(w http.ResponseWriter, id string, maxAge int) {
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- Secure comes from cookieSecure (on unless COOKIE_SECURE=false or AUTH_MODE=noauth); HttpOnly and SameSite are set
		Name: CookieName, Value: id, Path: "/", HttpOnly: true, Secure: h.Secure,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Username == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	ar, err := h.auth().VerifyPassword(r.Context(), h.loginIdentifier(r.Context(), in.Username), in.Password)
	if errors.Is(err, ErrInvalidCredentials) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	// Keycloak-only: a correct password whose freshly-issued access token still
	// fails JWKS verification (issuer/JWKS misconfig, key-rotation glitch) is
	// distinct from a bad password — 401 {"error": "token_verify"}, the same
	// string resolveSessionActor uses for the per-request re-verify. Kratos's
	// VerifyPassword never returns this sentinel.
	if errors.Is(err, ErrTokenVerifyFailed) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token_verify"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "auth_unreachable"})
		return
	}
	// Map the backend subject to the Sneakers identity user (adopt a
	// pre-created / email-matched local row, or JIT-provision a fresh one).
	// Fail closed:
	// no session is minted if identity can't resolve the user.
	adopt, aerr := h.Identity.AdoptOrProvisionFederatedUser(r.Context(), &identityv1.AdoptOrProvisionFederatedUserRequest{
		KeycloakSubject: ar.Subject, Email: ar.Email, Name: ar.Name, KeycloakUsername: ar.Username,
	})
	if aerr != nil || adopt.GetUser() == nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if adopt.GetUser().GetDisabledAtUnix() != 0 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account_disabled"})
		return
	}
	userID := adopt.GetUser().GetId()

	// 2-step MFA: if the user has a confirmed TOTP factor, DON'T issue a session
	// yet — park the granted tokens under a short-lived pending id and challenge
	// for the second factor. Fail closed: if the factor requirement can't be
	// evaluated (identity down), no session and no pending state are created.
	status, serr := h.Identity.GetMfaStatus(r.Context(), &identityv1.GetMfaStatusRequest{UserId: userID})
	if serr != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if status.GetEnrolled() {
		h.beginStepUp(w, r, asTokens(ar), userID, ar.Subject)
		return
	}

	// Not enrolled: issue a session with MFAVerified=false and Enrolled=false. When
	// MFA is enforced this is a HALF-SESSION — the request gate (SessionActor /
	// AuthenticateWS) rejects it from /graphql and subscriptions, so the only thing
	// it can do is drive the enrollment endpoints; issueSession returns
	// mfaEnrollmentRequired so the client shows the mandatory enroll wall. When MFA
	// is optional it's a full session with mfaSetupRecommended for the banner.
	h.issueSession(w, r, Session{
		AccessToken: ar.AccessToken, RefreshToken: ar.RefreshToken,
		ExpiresAt: ar.ExpiresAt, UserID: userID, KeycloakSubject: ar.Subject,
	})
}

// issueSession mints a CSRF token + opaque session id, persists the session, and
// sets the cookie — the final step shared by direct (non-MFA) login and the
// promotion of a verified 2-step login. On success it writes {csrfToken, userId}.
func (h *Handler) issueSession(w http.ResponseWriter, r *http.Request, sess Session) {
	csrf, err := NewCSRFToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	id, err := newSessionID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	sess.CSRFToken = csrf
	if err := h.Store.Create(r.Context(), id, sess); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server"})
		return
	}
	h.setCookie(w, id, int(h.sessionTTL().Seconds()))
	out := map[string]any{"csrfToken": csrf, "userId": sess.UserID}
	if enrollReq, setupRec := h.mfaFlags(sess); enrollReq {
		out["mfaEnrollmentRequired"] = true
	} else if setupRec {
		out["mfaSetupRecommended"] = true
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil {
		if sess, ok, err := h.Store.Get(r.Context(), c.Value); err == nil && ok {
			_ = h.auth().Logout(r.Context(), h.backendToken(sess))
		}
		_ = h.Store.Delete(r.Context(), c.Value)
	}
	h.setCookie(w, "", -1)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

func (h *Handler) Session(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	sess, ok, _ := h.Store.Get(r.Context(), c.Value)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	out := map[string]any{"authenticated": true, "csrfToken": sess.CSRFToken, "userId": sess.UserID}
	// Surface the MFA posture so a refresh re-enters the enroll wall (enforced +
	// unverified) or shows the setup banner (optional + not enrolled) instead of
	// silently landing on the dashboard. `enrolled` is the raw factor flag, so the
	// UI can disable "remove authenticator" when there is nothing to remove.
	enrollReq, setupRec := h.mfaFlags(sess)
	out["mfaEnrollmentRequired"] = enrollReq
	out["mfaSetupRecommended"] = setupRec
	out["enrolled"] = sess.Enrolled
	writeJSON(w, http.StatusOK, out)
}

// SessionActor is the AUTH_MODE=real request gate: it resolves the session
// cookie to the acting user and places it on the resolver context. It fails
// CLOSED — no valid session → 401 (never a silent fallback to no-auth/mock).
func (h *Handler) SessionActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(CookieName)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "no_session"})
			return
		}
		ctx, sess, err := h.resolveSessionActor(r.Context(), c.Value)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		// CSRF double-submit: the browser must echo the login-issued token in a
		// header (defends the SameSite cookie against cross-site POSTs).
		if !CSRFEqual(r.Header.Get("X-CSRF-Token"), sess.CSRFToken) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf"})
			return
		}
		// MFA enforcement gate: a half-session (no verified second factor) may only
		// reach the enrollment endpoints, never the app data plane. Reject /graphql
		// so an un-enrolled user cannot bypass MFA by refreshing or calling the API.
		if enrollReq, _ := h.mfaFlags(sess); enrollReq {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "mfa_required"})
			return
		}
		// Sliding session: renew the cookie on every authenticated request so
		// activity keeps the session alive.
		h.setCookie(w, c.Value, int(h.sessionTTL().Seconds()))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthenticateWS resolves the acting user for a WebSocket (subscription)
// connection from its session cookie and returns an actor-scoped context —
// mirroring SessionActor so HTTP and WS authenticate identically through the
// same resolveSessionActor core. It fails CLOSED (error → the socket's
// connection_init is rejected). It deliberately omits the two HTTP-only
// concerns: the CSRF double-submit (a browser cannot set headers on a WS
// upgrade — cross-origin is instead blocked by the Upgrader's same-origin
// Origin check) and the response cookie refresh (the handshake response is
// already committed to the 101 upgrade). Same session store, token verification
// and identity actor resolution as every authenticated HTTP request.
func (h *Handler) AuthenticateWS(ctx context.Context, r *http.Request) (context.Context, error) {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return nil, errors.New("no_session")
	}
	actorCtx, sess, err := h.resolveSessionActor(ctx, c.Value)
	if err != nil {
		return nil, err
	}
	// MFA enforcement gate (mirrors SessionActor): a half-session must not open a
	// subscription socket any more than it may call /graphql over HTTP.
	if enrollReq, _ := h.mfaFlags(sess); enrollReq {
		return nil, errors.New("mfa_required")
	}
	return actorCtx, nil
}

// resolveSessionActor is the shared authentication core behind both the HTTP
// request gate (SessionActor) and the WebSocket connection gate
// (AuthenticateWS): it loads the session, refreshes the backend credential via
// auth() when it is about to expire, re-verifies the subject per h.Backend
// (Keycloak: cryptographic JWKS re-verify every request; Kratos: trust the
// stored subject — see the branch below), and resolves that subject to the
// live identity ActorContext (real user id + roles + effective group names)
// placed on the returned context. Transport-specific concerns (CSRF, response
// cookies) are handled by the callers. Fails closed on every step. The
// (possibly refreshed) session is returned so the HTTP caller can read its
// CSRF token.
func (h *Handler) resolveSessionActor(ctx context.Context, sid string) (context.Context, Session, error) {
	sess, ok, err := h.Store.Get(ctx, sid)
	if err != nil || !ok {
		return nil, Session{}, errors.New("no_session")
	}
	if time.Until(sess.ExpiresAt) < 30*time.Second {
		if h.backendToken(sess) == "" {
			// SSO session: no backend token to refresh. The MFA-verified Redis
			// session (unguessable id, CSRF-checked by the caller, sliding TTL) is
			// the trust anchor — same argument as the Kratos opaque-token case
			// below. Slide the in-session expiry to match the Redis TTL renewal
			// instead of calling Refresh with an empty token (which would 401).
			sess.ExpiresAt = time.Now().Add(h.sessionTTL())
			_ = h.Store.Save(ctx, sid, sess)
		} else {
			// Token-bearing (Keycloak) session: proactively refresh via the
			// backend refresh token (the refreshSession helper).
			updated, rerr := h.refreshSession(ctx, sid, sess, h.backendToken(sess))
			if rerr != nil {
				_ = h.Store.Delete(ctx, sid)
				return nil, Session{}, errors.New("session_expired")
			}
			sess = updated
		}
	}

	subject := sess.KeycloakSubject
	if h.Backend != backendKratos {
		vc, updated, verr := h.verifyKeycloakAccessToken(ctx, sid, sess)
		if verr != nil {
			_ = h.Store.Delete(ctx, sid)
			return nil, Session{}, verr
		}
		sess = updated
		subject = vc.Subject
	}
	// Kratos: sess.KeycloakSubject was captured from AuthResult.Subject at
	// login/refresh time and trusted directly here — a Kratos session_token
	// is opaque, so there is no per-request signature to re-check; the Redis
	// session itself (looked up by an unguessable id, cleared above if
	// refresh fails, CSRF-checked by the caller) is the trust anchor.

	// Sliding session: renew the Redis TTL on every authenticated request.
	_ = h.Store.Save(ctx, sid, sess)
	actorCtx, aerr := h.actorContext(ctx, subject)
	if errors.Is(aerr, errAccountDisabled) {
		_ = h.Store.Delete(ctx, sid)
		return nil, Session{}, errAccountDisabled
	}
	if aerr != nil {
		return nil, Session{}, errors.New("actor_unresolved")
	}
	return actorCtx, sess, nil
}

// refreshSession calls auth().Refresh with the given backend credential and,
// on success, applies the resulting tokens/expiry/subject onto sess and
// persists it. Shared by resolveSessionActor's pre-expiry proactive refresh
// and verifyKeycloakAccessToken's reactive expired-access-token refresh —
// both paths update the session identically.
//
// Concurrent requests for the same session (the SPA's normal
// parallel-request pattern) can both observe the same expired/about-to-expire
// access token and both land here for the same sid. Under Keycloak refresh-
// token ROTATION, calling auth().Refresh independently for each would let the
// loser present the token the winner's call just invalidated, fail with
// invalid_grant, and spuriously log a just-refreshed session out. Coalescing
// per sid via refreshGroup prevents that: only the first caller (the "leader")
// invokes the backend Refresh; every concurrent caller for the same sid
// blocks on it and receives the SAME (Session, error) — so a genuine failure
// still fails closed for all of them (MFA-always preserved), and a success
// is shared instead of re-attempted with a now-stale token.
//
// Accepted edge: the coalesced Refresh runs in the winner's request ctx: if
// that specific request's context is canceled mid-refresh, every coalesced
// caller shares that failure. This matches an uncoalesced call (each
// caller's own ctx is its failure mode) and still fails safe — a canceled
// refresh just forces re-authentication, never grants access.
func (h *Handler) refreshSession(ctx context.Context, sid string, sess Session, token string) (Session, error) {
	v, err, _ := h.refreshGroup.Do(sid, func() (any, error) {
		ar, rerr := h.auth().Refresh(ctx, token)
		if rerr != nil {
			return Session{}, rerr
		}
		sess.AccessToken = ar.AccessToken
		if ar.RefreshToken != "" {
			sess.RefreshToken = ar.RefreshToken
		}
		sess.ExpiresAt = ar.ExpiresAt
		if ar.Subject != "" {
			sess.KeycloakSubject = ar.Subject
		}
		_ = h.Store.Save(ctx, sid, sess)
		return sess, nil
	})
	if err != nil {
		return Session{}, err
	}
	return v.(Session), nil
}

// verifyKeycloakAccessToken cryptographically re-verifies the session's access
// token on EVERY request — fail closed on signature/iss/aud/time. A merely
// EXPIRED token (the norm in practice — the UI's activity-gated
// keepalive routinely lands after the short-lived access token's exp, outside
// resolveSessionActor's 30s proactive-refresh window) is transparently
// refreshed here using the stored refresh token, then re-verified, instead of
// being treated as a logout. Any OTHER verify failure (bad signature/iss/aud
// — tampering) is never refreshed and fails closed immediately with
// token_verify; so does a failed refresh (session_expired) or a re-verify of
// the newly refreshed token that still fails (token_verify).
func (h *Handler) verifyKeycloakAccessToken(ctx context.Context, sid string, sess Session) (VerifiedClaims, Session, error) {
	vc, verr := h.Verifier.Verify(sess.AccessToken)
	if verr != nil && errors.Is(verr, jwt.ErrTokenExpired) {
		if rt := h.backendToken(sess); rt != "" {
			updated, rerr := h.refreshSession(ctx, sid, sess, rt)
			if rerr != nil {
				return VerifiedClaims{}, Session{}, errors.New("session_expired")
			}
			sess = updated
			vc, verr = h.Verifier.Verify(sess.AccessToken)
		}
	}
	if verr != nil {
		return VerifiedClaims{}, Session{}, errors.New("token_verify")
	}
	return vc, sess, nil
}

// actorContext resolves the Keycloak subject to the identity-backed actor and
// attaches it to the request context: the real Sneakers user id plus the authz
// attributes (site-admin / root / effective group names) that drive vault
// firewall-RACI. Returns an error if identity is unreachable or the subject
// maps to no user (fail-closed).
func (h *Handler) actorContext(ctx context.Context, subject string) (context.Context, error) {
	resp, err := h.Identity.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{KeycloakSubject: subject})
	if err != nil {
		return nil, err
	}
	a, err := actorAttrsFrom(resp)
	if err != nil {
		return nil, err
	}
	ctx = resolvers.WithActor(ctx, a.userID)
	ctx = resolvers.WithActorInfo(ctx, a.siteAdmin, a.root, a.groups)
	return ctx, nil
}

// actorAttrs is the authz projection of a resolved user context.
type actorAttrs struct {
	userID    string
	siteAdmin bool
	root      bool
	groups    []string
}

// actorAttrsFrom maps identity's ResolveUserContext response into the vault
// actor attributes: site-admin is derived from the role set, root from the user
// flag, and the effective group names pass through for RACI evaluation. It fails
// closed when the subject maps to no user.
func actorAttrsFrom(resp *identityv1.ResolveUserContextResponse) (actorAttrs, error) {
	user := resp.GetUser()
	if user == nil || user.GetId() == "" {
		return actorAttrs{}, errors.New("identity: no user for subject")
	}
	if user.GetDisabledAtUnix() != 0 {
		return actorAttrs{}, errAccountDisabled
	}
	a := actorAttrs{userID: user.GetId(), root: user.GetIsRoot(), groups: resp.GetGroupNames()}
	for _, role := range resp.GetRoles() {
		if role == roleSiteAdmin || role == roleAdmin {
			a.siteAdmin = true
			break
		}
	}
	return a, nil
}

var errAccountDisabled = errors.New("account_disabled")

// loginIdentifier maps a username to the user's email under Kratos, which
// identifies users by email, so people keep signing in with their username.
// Anything unresolved is passed through and Kratos rejects it as usual.
func (h *Handler) loginIdentifier(ctx context.Context, typed string) string {
	if h.Backend != backendKratos || strings.Contains(typed, "@") {
		return typed
	}
	resp, err := h.Identity.SearchUsers(ctx, &identityv1.SearchUsersRequest{Query: typed, Limit: 25})
	if err != nil {
		return typed
	}
	for _, u := range resp.GetUsers() {
		if strings.EqualFold(u.GetUsername(), typed) && u.GetEmail() != "" {
			return u.GetEmail()
		}
	}
	return typed
}
