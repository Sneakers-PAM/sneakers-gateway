// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

// ssoTestServer stubs Jackson's token + userinfo endpoints.
func ssoTestServer(t *testing.T, code, at, email string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("code") != code {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": at, "expires_in": 300})
	})
	mux.HandleFunc("/api/oauth/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "idp-1", "email": email, "firstName": "Ada"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func ssoHandler(t *testing.T, polisURL string, id *fakeIdentity) *Handler {
	t.Helper()
	return &Handler{
		Store:           NewMemStore(time.Hour),
		Pending:         newMemPending(),
		Identity:        id,
		TTL:             time.Hour,
		Polis:           NewPolisClient(polisURL, polisURL, "sneakers", "example.org"),
		SSORedirectBase: "https://gw.example.org",
		SSOAppBase:      "https://app.example.org",
		MfaEnforced:     true,
	}
}

func TestSSOLogin_RedirectsToAuthorizeAndSetsStateCookie(t *testing.T) {
	h := ssoHandler(t, "http://unused", &fakeIdentity{})
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/login", nil)
	rec := httptest.NewRecorder()
	h.SSOLogin(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "/api/oauth/authorize?") || !strings.Contains(loc, "tenant=example.org") {
		t.Fatalf("bad Location: %s", loc)
	}
	var stateCookie string
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoStateCookie {
			stateCookie = c.Value
		}
	}
	if stateCookie == "" {
		t.Fatal("state cookie not set")
	}
	u, _ := url.Parse(loc)
	if u.Query().Get("state") != stateCookie {
		t.Fatalf("authorize state %q != cookie %q", u.Query().Get("state"), stateCookie)
	}
}

// callbackWithState drives SSOCallback with a matching state cookie.
func callbackWithState(t *testing.T, h *Handler, code, state string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code="+code+"&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: ssoStateCookie, Value: state})
	rec := httptest.NewRecorder()
	h.SSOCallback(rec, req)
	return rec
}

func TestSSOCallback_NotEnrolled_IssuesSessionCookieAndRedirectsToApp(t *testing.T) {
	srv := ssoTestServer(t, "code-1", "at-1", "ada@example.org")
	id := &fakeIdentity{
		resolveByEmailResp: &identityv1.User{Id: "usr-1", Email: "ada@example.org", Subject: "sub-1"},
		mfaEnrolled:        false,
	}
	h := ssoHandler(t, srv.URL, id)

	rec := callbackWithState(t, h, "code-1", "st-1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Location"), "https://app.example.org/") {
		t.Fatalf("bad redirect: %s", rec.Header().Get("Location"))
	}
	var sid string
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("sneakers_sid cookie not set on non-MFA SSO login")
	}
}

func TestSSOCallback_Enrolled_ParksPendingAndRedirectsWithPendingId(t *testing.T) {
	srv := ssoTestServer(t, "code-1", "at-1", "ada@example.org")
	id := &fakeIdentity{
		resolveByEmailResp: &identityv1.User{Id: "usr-1", Email: "ada@example.org", Subject: "sub-1"},
		mfaEnrolled:        true,
		factors:            []string{"totp"},
	}
	h := ssoHandler(t, srv.URL, id)

	rec := callbackWithState(t, h, "code-1", "st-1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("sso_pending") == "" {
		t.Fatalf("expected sso_pending in redirect, got %s", rec.Header().Get("Location"))
	}
	if loc.Query().Get("factors") != "totp" {
		t.Fatalf("expected factors=totp, got %s", loc.Query().Get("factors"))
	}
	// No session cookie yet — MFA not verified.
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			t.Fatal("session cookie must NOT be set before MFA verify")
		}
	}
}

// TestSSOCallback_EmailEnrolled_ParksPendingWithEmailFactor: like
// beginStepUp, beginStepUpRedirect must offer "email", or an SSO user enrolled
// only in email-OTP would be redirected back with an empty factor list and no
// way to complete step-up. The redirect's factors query param must include
// "email".
func TestSSOCallback_EmailEnrolled_ParksPendingWithEmailFactor(t *testing.T) {
	srv := ssoTestServer(t, "code-1", "at-1", "ada@example.org")
	id := &fakeIdentity{
		resolveByEmailResp: &identityv1.User{Id: "usr-1", Email: "ada@example.org", Subject: "sub-1"},
		mfaEnrolled:        true,
		factors:            []string{"email"},
	}
	h := ssoHandler(t, srv.URL, id)

	rec := callbackWithState(t, h, "code-1", "st-1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302", rec.Code)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if loc.Query().Get("sso_pending") == "" {
		t.Fatalf("expected sso_pending in redirect, got %s", rec.Header().Get("Location"))
	}
	if !factorOffered(strings.Split(loc.Query().Get("factors"), ","), factorEmail) {
		t.Fatalf("expected factors to include email, got %q", loc.Query().Get("factors"))
	}
}

func TestSSOCallback_UnknownEmail_RejectsNoJIT(t *testing.T) {
	srv := ssoTestServer(t, "code-1", "at-1", "ghost@example.org")
	id := &fakeIdentity{resolveByEmailErr: status.Error(codes.NotFound, "no user for email")}
	h := ssoHandler(t, srv.URL, id)

	rec := callbackWithState(t, h, "code-1", "st-1")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d; want 302", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Location"), "sso_error=no_user") {
		t.Fatalf("expected no_user reject redirect, got %s", rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == CookieName {
			t.Fatal("no session may be minted for an unknown email (no-JIT)")
		}
	}
}

// TestSSOCallback_EnrolledMFA_PromotedSessionSurvivesFirstResolve: an SSO login
// that steps up through MFA must mint a session that survives the very next
// authenticated request. beginStepUpRedirect parks a Pending with no backend
// token (SSO carries none). Promoting it with ExpiresAt == time.Now()
// (ExpiresIn 0) would give a dead-on-arrival session: the next
// resolveSessionActor call would fall inside the "about to expire" refresh gate
// and call auth().Refresh(ctx, "") against Kratos, which 401s on an empty
// bearer that is treated as session_expired, deleting the session. This drives
// the REAL sequence — SSOCallback parks a Pending, VerifyOtp promotes it, then
// resolveSessionActor resolves the very next request — with a short TTL so the
// promoted session lands inside the 30s refresh-gate window, exercising both
// guarantees: a real minted expiry (not ~now) and a token-less session that
// slides instead of calling Refresh("").
func TestSSOCallback_EnrolledMFA_PromotedSessionSurvivesFirstResolve(t *testing.T) {
	polis := ssoTestServer(t, "code-1", "at-1", "ada@example.org")
	kratosCfg := defaultKratosLoginConfig()
	kratosCfg.identityID = "sub-1"
	kratos := newKratosLoginServer(t, kratosCfg)

	id := &fakeIdentity{
		resolveByEmailResp: &identityv1.User{Id: "usr-1", Email: "ada@example.org", Subject: "sub-1"},
		mfaEnrolled:        true,
		factors:            []string{"totp"},
		verifyOk:           true,
		resolveRes:         &identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-1"}},
	}
	const ttl = 5 * time.Second
	h := &Handler{
		Store:           NewMemStore(time.Hour),
		Pending:         newMemPending(),
		Identity:        id,
		TTL:             ttl,
		Auth:            NewKratosClient(kratos.URL, kratos.URL),
		Polis:           NewPolisClient(polis.URL, polis.URL, "sneakers", "example.org"),
		SSORedirectBase: "https://gw.example.org",
		SSOAppBase:      "https://app.example.org",
		MfaEnforced:     true,
	}

	// SAML callback for an MFA-enrolled user parks a Pending, no session yet.
	rec := callbackWithState(t, h, "code-1", "st-1")
	loc, _ := url.Parse(rec.Header().Get("Location"))
	pendingID := loc.Query().Get("sso_pending")
	if pendingID == "" {
		t.Fatalf("expected sso_pending in redirect, got %s", rec.Header().Get("Location"))
	}

	// Complete the second factor — promotes the pending record into a real
	// session, exactly as the SPA's /auth/verify-otp call would.
	verifyBody, _ := json.Marshal(map[string]string{"pendingId": pendingID, "code": "123456", "kind": "totp"})
	verifyRec := httptest.NewRecorder()
	h.VerifyOtp(verifyRec, httptest.NewRequest(http.MethodPost, "/auth/verify-otp", bytes.NewReader(verifyBody)))
	if verifyRec.Code != http.StatusOK {
		t.Fatalf("verify status=%d body=%s", verifyRec.Code, verifyRec.Body)
	}
	var sid string
	for _, c := range verifyRec.Result().Cookies() {
		if c.Name == CookieName {
			sid = c.Value
		}
	}
	if sid == "" {
		t.Fatal("no session cookie after successful MFA verify")
	}

	sess, ok, err := h.Store.Get(context.Background(), sid)
	if err != nil || !ok {
		t.Fatalf("session not stored after MFA promotion: ok=%v err=%v", ok, err)
	}
	if untilExp := time.Until(sess.ExpiresAt); untilExp < ttl-2*time.Second || untilExp > ttl {
		t.Fatalf("promoted SSO session ExpiresAt = now+%s; want ~now+%s (dead-on-arrival session bug)", untilExp, ttl)
	}

	// The FIRST subsequent authenticated request must not kill the session.
	// An SSO session carries no backend token, so resolveSessionActor must not
	// call auth().Refresh("") — which 401s against Kratos whoami and deletes
	// the session as session_expired.
	ctx, _, rerr := h.resolveSessionActor(context.Background(), sid)
	if rerr != nil {
		t.Fatalf("resolveSessionActor killed the freshly MFA-promoted SSO session: %v", rerr)
	}
	if ctx == nil {
		t.Fatal("resolveSessionActor returned no actor context")
	}
	if _, stillThere, _ := h.Store.Get(context.Background(), sid); !stillThere {
		t.Fatal("session was deleted by resolveSessionActor (session_expired path)")
	}
}

func TestSSOCallback_BadState_Rejected(t *testing.T) {
	srv := ssoTestServer(t, "code-1", "at-1", "ada@example.org")
	h := ssoHandler(t, srv.URL, &fakeIdentity{})
	// state cookie present but different from the query state
	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=code-1&state=attacker", nil)
	req.AddCookie(&http.Cookie{Name: ssoStateCookie, Value: "real-state"})
	rec := httptest.NewRecorder()
	h.SSOCallback(rec, req)

	if !strings.Contains(rec.Header().Get("Location"), "sso_error=state") {
		t.Fatalf("expected state-mismatch reject, got %s", rec.Header().Get("Location"))
	}
}
