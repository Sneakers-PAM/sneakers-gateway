// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package share

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// One-time share links (#148). The link carries a token; the gateway keeps only
// a record that names the vault's share use, and the vault holds the approval,
// the value and the audit. A GET never reaches the vault, so a chat app's link
// preview can't burn the view; a POST from the page does.

type memStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStore() *memStore { return &memStore{data: map[string][]byte{}} }

func (m *memStore) Put(_ context.Context, key string, v any, _ time.Duration) error {
	b, err := json.Marshal(v)
	m.mu.Lock()
	m.data[key] = b
	m.mu.Unlock()
	return err
}

func (m *memStore) Get(_ context.Context, key string, out any) (bool, error) {
	m.mu.Lock()
	b, ok := m.data[key]
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}

func (m *memStore) Take(_ context.Context, key string, out any) (bool, error) {
	m.mu.Lock()
	b, ok := m.data[key]
	delete(m.data, key)
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}

func (m *memStore) dump() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		sb.WriteString(k + "=" + string(m.data[k]) + "\n")
	}
	return sb.String()
}

func vaultErr(c codes.Code, reason string) error {
	st, _ := status.New(c, reason).WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: reason})
	return st.Err()
}

// fakeVault is the vault's share use in miniature.
type fakeVault struct {
	mu        sync.Mutex
	state     vaultv1.SecretUseState
	hash      string
	prepared  *vaultv1.PrepareSecretUseRequest
	redeems   int
	revokedBy string
	value     string
	prepErr   error
	now       func() time.Time
}

func (f *fakeVault) PrepareSecretUse(_ context.Context, in *vaultv1.PrepareSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.PrepareSecretUseResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prepErr != nil {
		return nil, f.prepErr
	}
	f.prepared, f.hash = in, in.GetShareHash()
	return &vaultv1.PrepareSecretUseResponse{Use: &vaultv1.SecretUse{
		Id: "use-1", SecretId: in.GetSecretId(), FieldKey: in.GetFieldKey(), State: f.state,
		ExpiresAtUnix: f.now().Add(time.Duration(in.GetShareTtlSeconds()) * time.Second).Unix(),
	}}, nil
}

func (f *fakeVault) RedeemSecretShare(_ context.Context, in *vaultv1.RedeemSecretShareRequest, _ ...grpc.CallOption) (*vaultv1.RedeemSecretShareResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.redeems++
	if in.GetUseId() != "use-1" || in.GetShareHash() != f.hash {
		return nil, status.Error(codes.NotFound, "secret share not found")
	}
	switch f.state {
	case vaultv1.SecretUseState_SECRET_USE_STATE_PENDING:
		return nil, vaultErr(codes.FailedPrecondition, "SHARE_NOT_APPROVED")
	case vaultv1.SecretUseState_SECRET_USE_STATE_DENIED:
		return nil, vaultErr(codes.FailedPrecondition, "SHARE_DENIED")
	case vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED:
		return nil, vaultErr(codes.FailedPrecondition, "SHARE_USED")
	case vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED:
		return nil, vaultErr(codes.FailedPrecondition, "SHARE_EXPIRED")
	}
	f.state = vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED
	return &vaultv1.RedeemSecretShareResponse{Value: f.value}, nil
}

func (f *fakeVault) RevokeSecretShare(_ context.Context, in *vaultv1.RevokeSecretShareRequest, _ ...grpc.CallOption) (*vaultv1.RevokeSecretShareResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.GetActor().GetUserId() != "user-ada" {
		return nil, status.Error(codes.PermissionDenied, "not the creator")
	}
	f.revokedBy = in.GetActor().GetUserId()
	f.state = vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED
	return &vaultv1.RevokeSecretShareResponse{}, nil
}

func (f *fakeVault) GetSecretUse(_ context.Context, in *vaultv1.GetSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretUseResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return &vaultv1.GetSecretUseResponse{Use: &vaultv1.SecretUse{Id: in.GetUseId(), SecretId: "secret-1", FieldKey: "password", State: f.state}}, nil
}

type fixture struct {
	svc *Service
	fv  *fakeVault
	st  *memStore
	now time.Time
}

func newFixture(state vaultv1.SecretUseState) *fixture {
	fx := &fixture{fv: &fakeVault{state: state, value: "s3cret <&> value"}, st: newMemStore(), now: time.Unix(1790000000, 0)}
	fx.fv.now = func() time.Time { return time.Unix(1790000000, 0) }
	fx.svc = &Service{Store: fx.st, Vault: fx.fv, PublicURL: "https://sneakers.example.org/", Now: func() time.Time { return fx.now }, Log: log.Nop()}
	return fx
}

var ada = &vaultv1.ActorContext{UserId: "user-ada"}

func (fx *fixture) create(t *testing.T) (Link, string) {
	t.Helper()
	l, err := fx.svc.Create(context.Background(), CreateParams{Actor: ada, SecretID: "secret-1", FieldKey: "password", TTL: time.Hour})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	u, err := url.Parse(l.URL)
	if err != nil || u.Host != "sneakers.example.org" || !strings.HasPrefix(u.Path, "/share/") {
		t.Fatalf("link url %q", l.URL)
	}
	return l, strings.TrimPrefix(u.Path, "/share/")
}

func (fx *fixture) do(method, token string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	fx.svc.Handler().ServeHTTP(rec, httptest.NewRequest(method, "/share/"+token, nil))
	return rec
}

const approved = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED

func TestCreateAsksTheVaultWithAHashAndKeepsNoToken(t *testing.T) {
	fx := newFixture(approved)
	l, token := fx.create(t)
	p := fx.fv.prepared
	sum := sha256.Sum256([]byte(strings.SplitN(token, ".", 2)[1]))
	if !p.GetReveal() || p.GetShareHash() != hex.EncodeToString(sum[:]) || p.GetShareTtlSeconds() != 3600 ||
		p.GetSecretId() != "secret-1" || p.GetFieldKey() != "password" || p.GetActor().GetUserId() != "user-ada" {
		t.Fatalf("prepare request = %+v", p)
	}
	if strings.Contains(fx.st.dump(), token) {
		t.Fatal("the store must hold no token")
	}
	if strings.Contains(fx.st.dump(), "s3cret") {
		t.Fatal("the store must hold no value")
	}
	if l.ID != "use-1" || l.State != StateReady || l.ExpiresAtUnix == 0 {
		t.Fatalf("link = %+v", l)
	}
	if len(token) < 40 {
		t.Fatalf("token %q is too short", token)
	}
}

func TestCreateSaysWhenTheOwnersApprovalIsNeeded(t *testing.T) {
	fx := newFixture(vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	if l, _ := fx.create(t); l.State != StateAwaitingApproval {
		t.Fatalf("state %q, want awaiting approval", l.State)
	}
}

func TestCreateRefusals(t *testing.T) {
	fx := newFixture(approved)
	fx.svc.PublicURL = ""
	if _, err := fx.svc.Create(context.Background(), CreateParams{Actor: ada, SecretID: "s", FieldKey: "f", TTL: time.Hour}); err != ErrOff {
		t.Fatalf("no public url: %v, want ErrOff", err)
	}
	fx.svc.PublicURL = "https://sneakers.example.org"
	for _, ttl := range []time.Duration{30 * time.Second, 8 * 24 * time.Hour, -time.Hour} {
		if _, err := fx.svc.Create(context.Background(), CreateParams{Actor: ada, SecretID: "s", FieldKey: "f", TTL: ttl}); err != ErrTTL {
			t.Errorf("ttl %v: %v, want ErrTTL", ttl, err)
		}
	}
	if l, err := fx.svc.Create(context.Background(), CreateParams{Actor: ada, SecretID: "s", FieldKey: "f"}); err != nil || l.ExpiresAtUnix == 0 {
		t.Fatalf("no ttl means the default: %v %v", l, err)
	}
	fx.fv.prepErr = status.Error(codes.PermissionDenied, "no access")
	before := fx.st.dump()
	if _, err := fx.svc.Create(context.Background(), CreateParams{Actor: ada, SecretID: "s", FieldKey: "f", TTL: time.Hour}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a vault refusal must pass through: %v", err)
	}
	if fx.st.dump() != before {
		t.Fatalf("a refused create must store nothing new: %s", fx.st.dump())
	}
}

func TestAPreviewFetchNeverBurnsTheView(t *testing.T) {
	fx := newFixture(approved)
	_, token := fx.create(t)
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodGet} {
		rec := fx.do(method, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: %d", method, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "s3cret") {
			t.Fatal("a preview must not show the value")
		}
		h := rec.Header()
		if h.Get("Cache-Control") != "no-store" || h.Get("X-Robots-Tag") != "noindex, nofollow" ||
			h.Get("Referrer-Policy") != "no-referrer" || !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'none'") {
			t.Fatalf("headers %v", h)
		}
	}
	if fx.fv.redeems != 0 {
		t.Fatalf("a preview reached the vault %d times", fx.fv.redeems)
	}
	if !strings.Contains(fx.do(http.MethodGet, token).Body.String(), `method="post"`) {
		t.Fatal("the page must offer a button that posts")
	}
}

func TestThePostShowsTheValueOnceEscapedAndThenNeverAgain(t *testing.T) {
	fx := newFixture(approved)
	_, token := fx.create(t)
	rec := fx.do(http.MethodPost, token)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "s3cret &lt;&amp;&gt; value") {
		t.Fatalf("view: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("the value page must not be cached")
	}
	again := fx.do(http.MethodPost, token)
	if again.Code != http.StatusGone || strings.Contains(again.Body.String(), "s3cret") {
		t.Fatalf("second view: %d %s", again.Code, again.Body.String())
	}
	if g := fx.do(http.MethodGet, token); g.Code != http.StatusGone {
		t.Fatalf("the page after the view: %d, want 410", g.Code)
	}
}

func TestAnUnapprovedShareWaitsWithoutBurning(t *testing.T) {
	fx := newFixture(vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	_, token := fx.create(t)
	rec := fx.do(http.MethodPost, token)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "approv") || strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("pending: %d %s", rec.Code, rec.Body.String())
	}
	fx.fv.state = approved
	if rec := fx.do(http.MethodPost, token); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("after approval: %d", rec.Code)
	}
}

func TestDeniedExpiredAndUnknownLinksAreGone(t *testing.T) {
	fx := newFixture(vaultv1.SecretUseState_SECRET_USE_STATE_DENIED)
	_, token := fx.create(t)
	if rec := fx.do(http.MethodPost, token); rec.Code != http.StatusGone {
		t.Fatalf("denied: %d", rec.Code)
	}
	for name, tok := range map[string]string{"unknown": "use-9." + strings.Repeat("a", 43), "malformed": "nonsense", "wrong secret": strings.SplitN(token, ".", 2)[0] + "." + strings.Repeat("b", 43)} {
		rec := fx.do(http.MethodPost, tok)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusGone {
			t.Errorf("%s: %d", name, rec.Code)
		}
		if g := fx.do(http.MethodGet, tok); g.Code != http.StatusNotFound && g.Code != http.StatusGone {
			t.Errorf("%s GET: %d", name, g.Code)
		}
	}
	fx2 := newFixture(approved)
	_, tok2 := fx2.create(t)
	fx2.now = fx2.now.Add(2 * time.Hour)
	if rec := fx2.do(http.MethodGet, tok2); rec.Code != http.StatusGone {
		t.Fatalf("expired page: %d, want 410", rec.Code)
	}
	if rec := fx2.do(http.MethodPost, tok2); rec.Code != http.StatusGone || fx2.fv.redeems != 0 {
		t.Fatalf("expired post: %d, vault calls %d", rec.Code, fx2.fv.redeems)
	}
}

func TestOtherMethodsAreRefused(t *testing.T) {
	fx := newFixture(approved)
	_, token := fx.create(t)
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if rec := fx.do(m, token); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD, POST" {
			t.Errorf("%s: %d allow %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

func TestRevokeEndsTheLinkAndOnlyTheCreatorCan(t *testing.T) {
	fx := newFixture(approved)
	l, token := fx.create(t)
	if err := fx.svc.Revoke(context.Background(), &vaultv1.ActorContext{UserId: "user-bob"}, l.ID); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another person: %v", err)
	}
	if rec := fx.do(http.MethodGet, token); rec.Code != http.StatusOK {
		t.Fatalf("a refused revoke must leave the link working: %d", rec.Code)
	}
	if err := fx.svc.Revoke(context.Background(), ada, l.ID); err != nil {
		t.Fatal(err)
	}
	if fx.fv.revokedBy != "user-ada" {
		t.Fatal("the vault must be told")
	}
	if rec := fx.do(http.MethodGet, token); rec.Code != http.StatusGone {
		t.Fatalf("a revoked link: %d, want 410", rec.Code)
	}
	if rec := fx.do(http.MethodPost, token); rec.Code != http.StatusGone || strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatalf("a revoked link must not open: %d", rec.Code)
	}
}

func TestListShowsTheCreatorsOwnLinksWithNoUrl(t *testing.T) {
	fx := newFixture(vaultv1.SecretUseState_SECRET_USE_STATE_PENDING)
	fx.create(t)
	got, err := fx.svc.List(context.Background(), ada)
	if err != nil || len(got) != 1 || got[0].ID != "use-1" || got[0].URL != "" || got[0].State != StateAwaitingApproval || got[0].SecretID != "secret-1" {
		t.Fatalf("list = %+v, %v", got, err)
	}
	if other, _ := fx.svc.List(context.Background(), &vaultv1.ActorContext{UserId: "user-bob"}); len(other) != 0 {
		t.Fatalf("another person sees %d links", len(other))
	}
	fx.fv.state = approved
	if got, _ := fx.svc.List(context.Background(), ada); got[0].State != StateReady {
		t.Fatalf("after approval: %+v", got)
	}
}
