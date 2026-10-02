// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc"
)

// fakeIdentity is a stub IdentityClient. It records the last request to each RPC
// and returns configurable responses/errors so the real-login wiring can be
// exercised without a live identity service.
type fakeIdentity struct {
	confirmResetReq *identityv1.ConfirmPasswordResetRequest
	confirmResetOk  bool

	mintUserTokenReq *identityv1.MintUserTokenRequest

	verifyUserTokenReq  *identityv1.VerifyUserTokenRequest
	verifyUserTokenResp *identityv1.VerifyUserTokenResponse

	searchReq   *identityv1.SearchUsersRequest
	searchUsers []*identityv1.User

	adoptReq   *identityv1.AdoptOrProvisionFederatedUserRequest
	adoptUser  *identityv1.User
	adoptErr   error
	resolveReq *identityv1.ResolveUserContextRequest
	resolveRes *identityv1.ResolveUserContextResponse
	resolveErr error

	// ResolveUserByEmail stubs (Polis SSO email-resolve leg).
	resolveByEmailResp *identityv1.User
	resolveByEmailErr  error

	// MFA (TOTP 2-step) stubs.
	mfaEnrolled  bool  // GetMfaStatus.Enrolled
	mfaStatusErr error // GetMfaStatus error
	verifyReq    *identityv1.VerifyTotpRequest
	verifyOk     bool
	verifyErr    error
	enrollReq    *identityv1.EnrollTotpRequest
	enrollResp   *identityv1.EnrollTotpResponse
	enrollErr    error
	confirmReq   *identityv1.ConfirmTotpRequest
	confirmErr   error

	// MFA email OTP + factor-model stubs.
	factors         []string // ListUserFactors kinds
	factorsErr      error
	sendEmailReq    *identityv1.SendEmailOtpRequest
	sendEmailErr    error
	verifyEmailReq  *identityv1.VerifyEmailOtpRequest
	verifyEmailOk   bool
	verifyEmailErr  error
	removeFactorReq *identityv1.RemoveFactorRequest
	removeFactorErr error

	// Email verification stubs.
	verifyEmailReqReq *identityv1.RequestEmailVerificationRequest
	confirmEmailReq   *identityv1.ConfirmEmailVerificationRequest
	confirmEmailOk    bool
	confirmEmailErr   error

	// Passkey/WebAuthn login-assertion stubs.
	waAssertBeginReq  *identityv1.WebauthnAssertBeginRequest
	waAssertBeginResp *identityv1.WebauthnAssertBeginResponse
	waAssertBeginErr  error
	waAssertFinishReq *identityv1.WebauthnAssertFinishRequest
	waAssertFinishOk  bool
	waAssertFinishErr error

	// Self-service password reset stubs: resetReqPwd records the
	// RequestPasswordReset RPC; sendEmailTxReq records the recovery-email
	// delivery via identity.SendTransactionalEmail.
	resetReqPwd    *identityv1.RequestPasswordResetRequest
	sendEmailTxReq *identityv1.SendTransactionalEmailRequest

	// Machine bearer-auth stub: VerifyApiToken backs
	// MachineActor's Bearer->ActorContext resolution.
	verifyApiTokenReq  *identityv1.VerifyApiTokenRequest
	verifyApiTokenResp *identityv1.VerifyApiTokenResponse
	verifyApiTokenErr  error

	// OIDC machine-auth stub: ResolveServiceAccountByOidc backs
	// MachineActor's OTHER Bearer->ActorContext leg (a Hydra JWT's verified
	// sub/issuer, once bff.Verifier has checked signature/iss/aud).
	resolveOidcReq  *identityv1.ResolveServiceAccountByOidcRequest
	resolveOidcResp *identityv1.ResolveServiceAccountByOidcResponse
	resolveOidcErr  error
}

func (f *fakeIdentity) VerifyApiToken(_ context.Context, in *identityv1.VerifyApiTokenRequest, _ ...grpc.CallOption) (*identityv1.VerifyApiTokenResponse, error) {
	f.verifyApiTokenReq = in
	if f.verifyApiTokenErr != nil {
		return nil, f.verifyApiTokenErr
	}
	if f.verifyApiTokenResp != nil {
		return f.verifyApiTokenResp, nil
	}
	return &identityv1.VerifyApiTokenResponse{}, nil
}

func (f *fakeIdentity) ResolveServiceAccountByOidc(_ context.Context, in *identityv1.ResolveServiceAccountByOidcRequest, _ ...grpc.CallOption) (*identityv1.ResolveServiceAccountByOidcResponse, error) {
	f.resolveOidcReq = in
	if f.resolveOidcErr != nil {
		return nil, f.resolveOidcErr
	}
	if f.resolveOidcResp != nil {
		return f.resolveOidcResp, nil
	}
	return &identityv1.ResolveServiceAccountByOidcResponse{}, nil
}

// Service-account + API-token admin RPCs and their OIDC-link counterparts:
// no BFF test drives these
// directly (the admin gating and behavior live in the resolvers package's
// own fakeIdentity/tests) — these stubs exist only to satisfy IdentityClient,
// per TestFakeIdentity_SatisfiesIdentityClient.
func (f *fakeIdentity) CreateServiceAccount(_ context.Context, _ *identityv1.CreateServiceAccountRequest, _ ...grpc.CallOption) (*identityv1.CreateServiceAccountResponse, error) {
	return &identityv1.CreateServiceAccountResponse{}, nil
}

func (f *fakeIdentity) LinkOidcClient(_ context.Context, _ *identityv1.LinkOidcClientRequest, _ ...grpc.CallOption) (*identityv1.LinkOidcClientResponse, error) {
	return &identityv1.LinkOidcClientResponse{}, nil
}

func (f *fakeIdentity) UnlinkOidcClient(_ context.Context, _ *identityv1.UnlinkOidcClientRequest, _ ...grpc.CallOption) (*identityv1.UnlinkOidcClientResponse, error) {
	return &identityv1.UnlinkOidcClientResponse{}, nil
}

func (f *fakeIdentity) ListServiceAccounts(_ context.Context, _ *identityv1.ListServiceAccountsRequest, _ ...grpc.CallOption) (*identityv1.ListServiceAccountsResponse, error) {
	return &identityv1.ListServiceAccountsResponse{}, nil
}

func (f *fakeIdentity) DisableServiceAccount(_ context.Context, _ *identityv1.DisableServiceAccountRequest, _ ...grpc.CallOption) (*identityv1.DisableServiceAccountResponse, error) {
	return &identityv1.DisableServiceAccountResponse{}, nil
}

func (f *fakeIdentity) MintApiToken(_ context.Context, _ *identityv1.MintApiTokenRequest, _ ...grpc.CallOption) (*identityv1.MintApiTokenResponse, error) {
	return &identityv1.MintApiTokenResponse{}, nil
}

func (f *fakeIdentity) ListApiTokens(_ context.Context, _ *identityv1.ListApiTokensRequest, _ ...grpc.CallOption) (*identityv1.ListApiTokensResponse, error) {
	return &identityv1.ListApiTokensResponse{}, nil
}

func (f *fakeIdentity) RevokeApiToken(_ context.Context, _ *identityv1.RevokeApiTokenRequest, _ ...grpc.CallOption) (*identityv1.RevokeApiTokenResponse, error) {
	return &identityv1.RevokeApiTokenResponse{}, nil
}

func (f *fakeIdentity) ListUserFactors(_ context.Context, in *identityv1.ListUserFactorsRequest, _ ...grpc.CallOption) (*identityv1.ListUserFactorsResponse, error) {
	if f.factorsErr != nil {
		return nil, f.factorsErr
	}
	out := &identityv1.ListUserFactorsResponse{}
	for _, k := range f.factors {
		out.Factors = append(out.Factors, &identityv1.UserFactor{Kind: k})
	}
	return out, nil
}

func (f *fakeIdentity) SendEmailOtp(_ context.Context, in *identityv1.SendEmailOtpRequest, _ ...grpc.CallOption) (*identityv1.SendEmailOtpResponse, error) {
	f.sendEmailReq = in
	if f.sendEmailErr != nil {
		return nil, f.sendEmailErr
	}
	return &identityv1.SendEmailOtpResponse{}, nil
}

func (f *fakeIdentity) VerifyEmailOtp(_ context.Context, in *identityv1.VerifyEmailOtpRequest, _ ...grpc.CallOption) (*identityv1.VerifyEmailOtpResponse, error) {
	f.verifyEmailReq = in
	if f.verifyEmailErr != nil {
		return nil, f.verifyEmailErr
	}
	return &identityv1.VerifyEmailOtpResponse{Ok: f.verifyEmailOk}, nil
}

func (f *fakeIdentity) RemoveFactor(_ context.Context, in *identityv1.RemoveFactorRequest, _ ...grpc.CallOption) (*identityv1.RemoveFactorResponse, error) {
	f.removeFactorReq = in
	if f.removeFactorErr != nil {
		return nil, f.removeFactorErr
	}
	return &identityv1.RemoveFactorResponse{}, nil
}

func (f *fakeIdentity) GetMfaStatus(_ context.Context, _ *identityv1.GetMfaStatusRequest, _ ...grpc.CallOption) (*identityv1.GetMfaStatusResponse, error) {
	if f.mfaStatusErr != nil {
		return nil, f.mfaStatusErr
	}
	return &identityv1.GetMfaStatusResponse{Enrolled: f.mfaEnrolled}, nil
}

func (f *fakeIdentity) VerifyTotp(_ context.Context, in *identityv1.VerifyTotpRequest, _ ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error) {
	f.verifyReq = in
	if f.verifyErr != nil {
		return nil, f.verifyErr
	}
	return &identityv1.VerifyTotpResponse{Ok: f.verifyOk}, nil
}

func (f *fakeIdentity) EnrollTotp(_ context.Context, in *identityv1.EnrollTotpRequest, _ ...grpc.CallOption) (*identityv1.EnrollTotpResponse, error) {
	f.enrollReq = in
	if f.enrollErr != nil {
		return nil, f.enrollErr
	}
	if f.enrollResp != nil {
		return f.enrollResp, nil
	}
	return &identityv1.EnrollTotpResponse{Secret: "JBSWY3DPEHPK3PXP", OtpauthUri: "otpauth://totp/Sneakers:u?secret=JBSWY3DPEHPK3PXP&issuer=Sneakers"}, nil
}

func (f *fakeIdentity) ConfirmTotp(_ context.Context, in *identityv1.ConfirmTotpRequest, _ ...grpc.CallOption) (*identityv1.ConfirmTotpResponse, error) {
	f.confirmReq = in
	if f.confirmErr != nil {
		return nil, f.confirmErr
	}
	return &identityv1.ConfirmTotpResponse{}, nil
}

// Self-service password reset and passkey/WebAuthn stubs — present so
// fakeIdentity satisfies the full IdentityClient interface. No BFF test drives
// these paths; they return empty successes.
func (f *fakeIdentity) RequestPasswordReset(_ context.Context, in *identityv1.RequestPasswordResetRequest, _ ...grpc.CallOption) (*identityv1.RequestPasswordResetResponse, error) {
	f.resetReqPwd = in
	return &identityv1.RequestPasswordResetResponse{}, nil
}

func (f *fakeIdentity) ConfirmPasswordReset(_ context.Context, in *identityv1.ConfirmPasswordResetRequest, _ ...grpc.CallOption) (*identityv1.ConfirmPasswordResetResponse, error) {
	f.confirmResetReq = in
	return &identityv1.ConfirmPasswordResetResponse{Ok: f.confirmResetOk}, nil
}

// SendTransactionalEmail delivers an operator-composed email (Kratos
// recovery-code delivery) through identity's SMTP sender.
func (f *fakeIdentity) SendTransactionalEmail(_ context.Context, in *identityv1.SendTransactionalEmailRequest, _ ...grpc.CallOption) (*identityv1.SendTransactionalEmailResponse, error) {
	f.sendEmailTxReq = in
	return &identityv1.SendTransactionalEmailResponse{}, nil
}

func (f *fakeIdentity) RequestEmailVerification(_ context.Context, in *identityv1.RequestEmailVerificationRequest, _ ...grpc.CallOption) (*identityv1.RequestEmailVerificationResponse, error) {
	f.verifyEmailReqReq = in
	return &identityv1.RequestEmailVerificationResponse{}, nil
}

func (f *fakeIdentity) ConfirmEmailVerification(_ context.Context, in *identityv1.ConfirmEmailVerificationRequest, _ ...grpc.CallOption) (*identityv1.ConfirmEmailVerificationResponse, error) {
	f.confirmEmailReq = in
	if f.confirmEmailErr != nil {
		return nil, f.confirmEmailErr
	}
	return &identityv1.ConfirmEmailVerificationResponse{Ok: f.confirmEmailOk}, nil
}

func (f *fakeIdentity) WebauthnRegisterBegin(_ context.Context, _ *identityv1.WebauthnRegisterBeginRequest, _ ...grpc.CallOption) (*identityv1.WebauthnRegisterBeginResponse, error) {
	return &identityv1.WebauthnRegisterBeginResponse{}, nil
}

func (f *fakeIdentity) WebauthnRegisterFinish(_ context.Context, _ *identityv1.WebauthnRegisterFinishRequest, _ ...grpc.CallOption) (*identityv1.WebauthnRegisterFinishResponse, error) {
	return &identityv1.WebauthnRegisterFinishResponse{}, nil
}

func (f *fakeIdentity) WebauthnAssertBegin(_ context.Context, in *identityv1.WebauthnAssertBeginRequest, _ ...grpc.CallOption) (*identityv1.WebauthnAssertBeginResponse, error) {
	f.waAssertBeginReq = in
	if f.waAssertBeginErr != nil {
		return nil, f.waAssertBeginErr
	}
	if f.waAssertBeginResp != nil {
		return f.waAssertBeginResp, nil
	}
	return &identityv1.WebauthnAssertBeginResponse{}, nil
}

func (f *fakeIdentity) WebauthnAssertFinish(_ context.Context, in *identityv1.WebauthnAssertFinishRequest, _ ...grpc.CallOption) (*identityv1.WebauthnAssertFinishResponse, error) {
	f.waAssertFinishReq = in
	if f.waAssertFinishErr != nil {
		return nil, f.waAssertFinishErr
	}
	return &identityv1.WebauthnAssertFinishResponse{Ok: f.waAssertFinishOk}, nil
}

// memPending is an in-memory PendingStore for the 2-step-login tests. It mimics
// the Redis store's single-use Consume and no-create Save semantics.
type memPending struct {
	data map[string]Pending
}

func newMemPending() *memPending { return &memPending{data: map[string]Pending{}} }

func (m *memPending) Create(_ context.Context, id string, p Pending) error {
	m.data[id] = p
	return nil
}

func (m *memPending) Get(_ context.Context, id string) (Pending, bool, error) {
	p, ok := m.data[id]
	return p, ok, nil
}

func (m *memPending) Save(_ context.Context, id string, p Pending) error {
	if _, ok := m.data[id]; !ok {
		return nil // XX semantics: never create
	}
	m.data[id] = p
	return nil
}

func (m *memPending) Consume(_ context.Context, id string) (Pending, bool, error) {
	p, ok := m.data[id]
	if ok {
		delete(m.data, id)
	}
	return p, ok, nil
}

func (m *memPending) Delete(_ context.Context, id string) error {
	delete(m.data, id)
	return nil
}

func (f *fakeIdentity) AdoptOrProvisionFederatedUser(_ context.Context, in *identityv1.AdoptOrProvisionFederatedUserRequest, _ ...grpc.CallOption) (*identityv1.AdoptOrProvisionFederatedUserResponse, error) {
	f.adoptReq = in
	if f.adoptErr != nil {
		return nil, f.adoptErr
	}
	return &identityv1.AdoptOrProvisionFederatedUserResponse{User: f.adoptUser}, nil
}

func (f *fakeIdentity) ResolveUserContext(_ context.Context, in *identityv1.ResolveUserContextRequest, _ ...grpc.CallOption) (*identityv1.ResolveUserContextResponse, error) {
	f.resolveReq = in
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return f.resolveRes, nil
}

func (f *fakeIdentity) ResolveUserByEmail(_ context.Context, in *identityv1.ResolveUserByEmailRequest, _ ...grpc.CallOption) (*identityv1.ResolveUserByEmailResponse, error) {
	if f.resolveByEmailErr != nil {
		return nil, f.resolveByEmailErr
	}
	return &identityv1.ResolveUserByEmailResponse{User: f.resolveByEmailResp}, nil
}

func TestLogin_IdentityUnreachable_FailsClosed(t *testing.T) {
	kratos := newKratosLoginServer(t, defaultKratosLoginConfig())
	fid := &fakeIdentity{adoptErr: errors.New("identity down")}
	h := &Handler{
		Store: NewMemStore(time.Hour), Auth: NewKratosClient(kratos.URL, kratos.URL),
		Identity: fid, TTL: time.Hour,
	}
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "good"})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 fail-closed, got %d body=%s", rec.Code, rec.Body)
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatal("no session cookie should be set when adopt fails")
	}
}

func TestSessionActor_ResolvesIdentityActorContext(t *testing.T) {
	at := "opaque-session-token"
	fid := &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{
		User:       &identityv1.User{Id: "usr-42", IsRoot: false},
		Roles:      []string{"user", "site-admin"},
		GroupNames: []string{"Platform Team", "example-group"},
	}}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour}

	sess := Session{AccessToken: at, ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf-1", UserID: "usr-42", Subject: "sub-abc-123"}
	_ = h.Store.Create(context.Background(), "sid1", sess)

	ran := false
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rec := httptest.NewRecorder()
	h.SessionActor(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !ran {
		t.Fatalf("expected authed pass-through 200, got %d ran=%v body=%s", rec.Code, ran, rec.Body)
	}
	if fid.resolveReq == nil || fid.resolveReq.GetSubject() != "sub-abc-123" {
		t.Fatalf("ResolveUserContext not called with session subject: %+v", fid.resolveReq)
	}
}

func TestActorAttrs_MapsRolesAndGroups(t *testing.T) {
	got, err := actorAttrsFrom(&identityv1.ResolveUserContextResponse{
		User:       &identityv1.User{Id: "usr-42", IsRoot: true},
		Roles:      []string{"user", "site-admin"},
		GroupNames: []string{"Platform Team"},
	})
	if err != nil {
		t.Fatalf("actorAttrsFrom err: %v", err)
	}
	if got.userID != "usr-42" || !got.siteAdmin || !got.root ||
		len(got.groups) != 1 || got.groups[0] != "Platform Team" {
		t.Fatalf("actor mapping wrong: %+v", got)
	}
}

func TestActorContext_FailsClosed(t *testing.T) {
	// identity error
	h := &Handler{Identity: &fakeIdentity{resolveErr: errors.New("down")}}
	if _, err := h.actorContext(context.Background(), "sub-abc-123"); err == nil {
		t.Fatal("expected error when identity unreachable")
	}
	// unknown subject → nil user
	h = &Handler{Identity: &fakeIdentity{resolveRes: &identityv1.ResolveUserContextResponse{}}}
	if _, err := h.actorContext(context.Background(), "sub-unknown"); err == nil {
		t.Fatal("expected error when subject maps to no user")
	}
}

func TestSessionActor_FailsClosedOnIdentityError(t *testing.T) {
	at := "opaque-session-token"
	fid := &fakeIdentity{resolveErr: errors.New("identity down")}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: fid, TTL: time.Hour}
	_ = h.Store.Create(context.Background(), "sid1", Session{AccessToken: at, ExpiresAt: time.Now().Add(time.Hour), CSRFToken: "csrf-1", Subject: "sub-abc-123"})

	ran := false
	req := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: "sid1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rec := httptest.NewRecorder()
	h.SessionActor(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { ran = true })).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized || ran {
		t.Fatalf("expected 401 fail-closed with next NOT run, got %d ran=%v", rec.Code, ran)
	}
}

// TestFakeIdentity_SatisfiesIdentityClient is a compile-time proof: this line
// alone fails to build if fakeIdentity is missing any IdentityClient method.
// Guards against the interface (http.go, webauthn.go, reset.go, verify.go)
// outgrowing the test double without the compiler catching it.
func TestFakeIdentity_SatisfiesIdentityClient(t *testing.T) {
	var _ IdentityClient = (*fakeIdentity)(nil)
}

func TestFakeIdentity_HasResolveUserByEmail(t *testing.T) {
	// Compile-time + behavior proof: fakeIdentity satisfies the extended
	// IdentityClient and returns its configured user.
	var _ IdentityClient = (*fakeIdentity)(nil)
	f := &fakeIdentity{resolveByEmailResp: &identityv1.User{Id: "usr-9", Email: "ada@example.org"}}
	resp, err := f.ResolveUserByEmail(context.Background(), &identityv1.ResolveUserByEmailRequest{Email: "ada@example.org"})
	if err != nil || resp.GetUser().GetId() != "usr-9" {
		t.Fatalf("ResolveUserByEmail stub: resp=%+v err=%v", resp, err)
	}
}
