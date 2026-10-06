// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/maintenance"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var btgNow = time.Unix(1_800_000_000, 0)

type btgIdentity struct {
	identityv1.IdentityServiceClient
	calls int
}

func (f *btgIdentity) VerifyTotp(_ context.Context, in *identityv1.VerifyTotpRequest, _ ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error) {
	f.calls++
	return &identityv1.VerifyTotpResponse{Ok: in.GetCode() == "123456"}, nil
}

func (f *btgIdentity) ResolveUserLabels(_ context.Context, in *identityv1.ResolveUserLabelsRequest, _ ...grpc.CallOption) (*identityv1.ResolveUserLabelsResponse, error) {
	out := &identityv1.ResolveUserLabelsResponse{}
	for _, id := range in.GetIds() {
		if id == "u-admin" {
			out.Labels = append(out.Labels, &identityv1.UserLabel{Id: id, Name: "Ada Admin"})
		}
	}
	return out, nil
}

type btgVault struct {
	vaultv1.VaultServiceClient
	openErr  error
	open     *vaultv1.OpenBreakGlassSessionRequest
	get      *vaultv1.GetBreakGlassSessionRequest
	list     *vaultv1.ListBreakGlassItemsRequest
	closeReq *vaultv1.CloseBreakGlassSessionRequest
	sessions *vaultv1.ListBreakGlassSessionsRequest
	reveal   *vaultv1.BreakGlassSecretRequest
}

func btgSessionPB() *vaultv1.BreakGlassSession {
	return &vaultv1.BreakGlassSession{
		Id: "bgs-1", ActorUserId: "u-admin", Reason: "outage",
		OpenedAtUnix: btgNow.Unix(), ExpiresAtUnix: btgNow.Add(15 * time.Minute).Unix(),
	}
}

func (f *btgVault) OpenBreakGlassSession(_ context.Context, in *vaultv1.OpenBreakGlassSessionRequest, _ ...grpc.CallOption) (*vaultv1.OpenBreakGlassSessionResponse, error) {
	f.open = in
	if f.openErr != nil {
		return nil, f.openErr
	}
	return &vaultv1.OpenBreakGlassSessionResponse{Session: btgSessionPB()}, nil
}

func (f *btgVault) GetBreakGlassSession(_ context.Context, in *vaultv1.GetBreakGlassSessionRequest, _ ...grpc.CallOption) (*vaultv1.GetBreakGlassSessionResponse, error) {
	f.get = in
	return &vaultv1.GetBreakGlassSessionResponse{Session: btgSessionPB()}, nil
}

func (f *btgVault) ListBreakGlassItems(_ context.Context, in *vaultv1.ListBreakGlassItemsRequest, _ ...grpc.CallOption) (*vaultv1.ListBreakGlassItemsResponse, error) {
	f.list = in
	return &vaultv1.ListBreakGlassItemsResponse{
		Folders: []*vaultv1.Folder{{Id: "f-personal-bob", Name: "Personal", Scope: vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL, OwnerUserId: "u-bob"}},
		Secrets: []*vaultv1.Secret{{Id: "s-1", Name: "bob-laptop", FolderId: "f-personal-bob", TypeId: "type-password", CanRead: true}},
	}, nil
}

func (f *btgVault) CloseBreakGlassSession(_ context.Context, in *vaultv1.CloseBreakGlassSessionRequest, _ ...grpc.CallOption) (*vaultv1.CloseBreakGlassSessionResponse, error) {
	f.closeReq = in
	s := btgSessionPB()
	s.EndedAtUnix, s.EndReason = btgNow.Add(time.Minute).Unix(), "exit"
	return &vaultv1.CloseBreakGlassSessionResponse{Session: s}, nil
}

func (f *btgVault) ListBreakGlassSessions(_ context.Context, in *vaultv1.ListBreakGlassSessionsRequest, _ ...grpc.CallOption) (*vaultv1.ListBreakGlassSessionsResponse, error) {
	f.sessions = in
	s := btgSessionPB()
	s.EndedAtUnix, s.EndReason = btgNow.Add(time.Minute).Unix(), "exit"
	s.Reveals = []*vaultv1.BreakGlassReveal{{
		EventId: "bg-1", SecretId: "s-1", SecretName: "bob-laptop", RevealedAtUnix: btgNow.Add(30 * time.Second).Unix(),
		OwnerNotified: true,
	}}
	return &vaultv1.ListBreakGlassSessionsResponse{Sessions: []*vaultv1.BreakGlassSession{s}}, nil
}

func (f *btgVault) BreakGlassSecret(_ context.Context, in *vaultv1.BreakGlassSecretRequest, _ ...grpc.CallOption) (*vaultv1.BreakGlassSecretResponse, error) {
	f.reveal = in
	return &vaultv1.BreakGlassSecretResponse{Fields: map[string]string{"password": "example-value"}}, nil
}

// btgCaller decides who the request comes from.
type btgCaller func(ctx context.Context) context.Context

func btgWebAdmin(ctx context.Context) context.Context {
	ctx = WithActor(ctx, "u-admin")
	ctx = WithActorInfo(ctx, true, false, nil)
	return WithSessionRef(ctx, "ref-web-1")
}

func newBTGClient(id *btgIdentity, v *btgVault, caller btgCaller) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: id, Vault: v, Now: func() time.Time { return btgNow }}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(caller(r.Context())))
	}))
}

func btgErrors(t *testing.T, c *gqlclient.Client, query string) []breakGlassErr {
	t.Helper()
	resp, err := c.RawPost(query)
	if err != nil {
		t.Fatal(err)
	}
	var errs []breakGlassErr
	if len(resp.Errors) > 0 {
		if err := json.Unmarshal(resp.Errors, &errs); err != nil {
			t.Fatalf("errors = %s (%v)", resp.Errors, err)
		}
	}
	return errs
}

const btgOpen = `mutation { openBreakGlassSession(reason: "outage", code: "123456") { id actorUserId reason openedAt expiresAt endedAt endReason } }`

func TestOpenBreakGlassSessionVerifiesTheCodeThenOpens(t *testing.T) {
	id, v := &btgIdentity{}, &btgVault{}
	var resp struct {
		OpenBreakGlassSession struct {
			ID, ActorUserID, Reason, OpenedAt, ExpiresAt string
			EndedAt, EndReason                           *string
		}
	}
	newBTGClient(id, v, btgWebAdmin).MustPost(btgOpen, &resp)
	got := resp.OpenBreakGlassSession
	if got.ID != "bgs-1" || got.OpenedAt != "2027-01-15T08:00:00Z" || got.ExpiresAt != "2027-01-15T08:15:00Z" || got.EndedAt != nil || got.EndReason != nil {
		t.Fatalf("session = %+v", got)
	}
	a := v.open.GetActor()
	if v.open.GetReason() != "outage" || a.GetUserId() != "u-admin" || !a.GetIsSiteAdmin() || a.GetSessionRef() != "ref-web-1" {
		t.Fatalf("open request = %+v", v.open)
	}
	if a.GetMfaVerifiedAtUnix() != btgNow.Unix() {
		t.Fatalf("mfa_verified_at_unix = %d, want the code just proved", a.GetMfaVerifiedAtUnix())
	}
}

func TestOpenBreakGlassSessionRefusesABadCode(t *testing.T) {
	for _, code := range []string{"", "000000"} {
		id, v := &btgIdentity{}, &btgVault{}
		errs := btgErrors(t, newBTGClient(id, v, btgWebAdmin), `mutation { openBreakGlassSession(reason: "outage", code: "`+code+`") { id } }`)
		if len(errs) != 1 || errs[0].Extensions.Reason != "BREAK_GLASS_CODE_INVALID" {
			t.Fatalf("code %q: errors = %+v", code, errs)
		}
		if v.open != nil {
			t.Fatalf("code %q: a refused code must never reach the vault", code)
		}
	}
}

func TestOpenBreakGlassSessionPassesTheVaultStepUpRefusal(t *testing.T) {
	st, _ := status.New(codes.PermissionDenied, "confirm your MFA again to break glass").
		WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: "STEP_UP_REQUIRED"})
	v := &btgVault{openErr: st.Err()}
	errs := btgErrors(t, newBTGClient(&btgIdentity{}, v, btgWebAdmin), btgOpen)
	if len(errs) != 1 || errs[0].Extensions.Reason != "STEP_UP_REQUIRED" || errs[0].Extensions.Domain != "sneakers.vault" {
		t.Fatalf("errors = %+v", errs)
	}
}

func TestBreakGlassBrowseIsRefusedOutsideAWebAdminSession(t *testing.T) {
	cases := map[string]struct {
		caller btgCaller
		reason string
	}{
		"not an admin": {func(ctx context.Context) context.Context {
			return WithSessionRef(WithActorInfo(WithActor(ctx, "u-bob"), false, false, nil), "ref-web-1")
		}, "BREAK_GLASS_NOT_ADMIN"},
		"personal token": {func(ctx context.Context) context.Context {
			return WithUserTokenActor(WithActorInfo(WithActor(ctx, "u-admin"), true, false, nil), "u-admin", "tok-1", nil)
		}, "BREAK_GLASS_WEB_ONLY"},
		"service account": {func(ctx context.Context) context.Context {
			return WithMachineActor(ctx, "sa-1", nil)
		}, "BREAK_GLASS_WEB_ONLY"},
		"no web session": {func(ctx context.Context) context.Context {
			return WithActorInfo(WithActor(ctx, "u-admin"), true, false, nil)
		}, "BREAK_GLASS_WEB_ONLY"},
	}
	ops := []string{
		btgOpen,
		`mutation { closeBreakGlassSession(id: "bgs-1") { id } }`,
		`query { breakGlassBrowse(sessionId: "bgs-1") { folders { id } } }`,
		`query { breakGlassSessions { id } }`,
		`mutation { breakGlassSecret(secretId: "s-1", reason: "", code: "123456", sessionId: "bgs-1") { key } }`,
	}
	for name, tc := range cases {
		for _, op := range ops {
			id, v := &btgIdentity{}, &btgVault{}
			errs := btgErrors(t, newBTGClient(id, v, tc.caller), op)
			if len(errs) != 1 || errs[0].Extensions.Reason != tc.reason || errs[0].Extensions.Code != "PERMISSION_DENIED" {
				t.Fatalf("%s %s: errors = %+v", name, op, errs)
			}
			if v.open != nil || v.list != nil || v.closeReq != nil || v.sessions != nil || v.reveal != nil || id.calls != 0 {
				t.Fatalf("%s %s: a refused caller must reach neither identity nor the vault", name, op)
			}
		}
	}
}

func TestBreakGlassSessionQueryIsNullForNonAdmins(t *testing.T) {
	v := &btgVault{}
	var resp struct{ BreakGlassSession *struct{ ID string } }
	nonAdmin := func(ctx context.Context) context.Context {
		return WithSessionRef(WithActorInfo(WithActor(ctx, "u-bob"), false, false, nil), "ref-web-1")
	}
	newBTGClient(&btgIdentity{}, v, nonAdmin).MustPost(`query { breakGlassSession { id } }`, &resp)
	if resp.BreakGlassSession != nil || v.get != nil {
		t.Fatalf("non-admin: session = %+v, vault asked = %v", resp.BreakGlassSession, v.get != nil)
	}
	newBTGClient(&btgIdentity{}, v, btgWebAdmin).MustPost(`query { breakGlassSession { id } }`, &resp)
	if resp.BreakGlassSession == nil || resp.BreakGlassSession.ID != "bgs-1" || v.get.GetActor().GetSessionRef() != "ref-web-1" {
		t.Fatalf("admin: session = %+v", resp.BreakGlassSession)
	}
}

func TestBreakGlassBrowseListsFoldersAndSecrets(t *testing.T) {
	v := &btgVault{}
	var resp struct {
		BreakGlassBrowse struct {
			Folders []struct {
				ID, Scope   string
				OwnerUserID *string
				CanManage   bool
			}
			Secrets []struct {
				ID, Name, FolderID string
				CanRead            *bool
			}
		}
	}
	newBTGClient(&btgIdentity{}, v, btgWebAdmin).MustPost(
		`query { breakGlassBrowse(sessionId: "bgs-1", folderId: "f-personal-bob") { folders { id scope ownerUserId canManage } secrets { id name folderId canRead } } }`, &resp)
	if v.list.GetSessionId() != "bgs-1" || v.list.GetFolderId() != "f-personal-bob" || v.list.GetActor().GetSessionRef() != "ref-web-1" {
		t.Fatalf("list request = %+v", v.list)
	}
	b := resp.BreakGlassBrowse
	if len(b.Folders) != 1 || b.Folders[0].ID != "f-personal-bob" || b.Folders[0].Scope != "personal" || b.Folders[0].CanManage {
		t.Fatalf("folders = %+v", b.Folders)
	}
	if len(b.Secrets) != 1 || b.Secrets[0].Name != "bob-laptop" || b.Secrets[0].CanRead == nil || !*b.Secrets[0].CanRead {
		t.Fatalf("secrets = %+v", b.Secrets)
	}
}

func TestBreakGlassSecretInASessionCarriesTheSession(t *testing.T) {
	v := &btgVault{}
	var resp struct{ BreakGlassSecret []struct{ Key, Value string } }
	newBTGClient(&btgIdentity{}, v, btgWebAdmin).MustPost(
		`mutation { breakGlassSecret(secretId: "s-1", reason: "", code: "123456", sessionId: "bgs-1") { key value } }`, &resp)
	if v.reveal.GetSessionId() != "bgs-1" || v.reveal.GetActor().GetSessionRef() != "ref-web-1" {
		t.Fatalf("reveal request = %+v", v.reveal)
	}
	if len(resp.BreakGlassSecret) != 1 || resp.BreakGlassSecret[0].Value != "example-value" {
		t.Fatalf("fields = %+v", resp.BreakGlassSecret)
	}
}

func TestCloseBreakGlassSession(t *testing.T) {
	v := &btgVault{}
	var resp struct {
		CloseBreakGlassSession struct{ EndedAt, EndReason *string }
	}
	newBTGClient(&btgIdentity{}, v, btgWebAdmin).MustPost(`mutation { closeBreakGlassSession(id: "bgs-1") { endedAt endReason } }`, &resp)
	if v.closeReq.GetSessionId() != "bgs-1" || v.closeReq.GetActor().GetSessionRef() != "ref-web-1" {
		t.Fatalf("close request = %+v", v.closeReq)
	}
	got := resp.CloseBreakGlassSession
	if got.EndReason == nil || *got.EndReason != "exit" || got.EndedAt == nil || *got.EndedAt != "2027-01-15T08:01:00Z" {
		t.Fatalf("closed = %+v", got)
	}
}

func TestBreakGlassSessionsGroupTheRevealsForTheAuditLog(t *testing.T) {
	v := &btgVault{}
	var resp struct {
		BreakGlassSessions []struct {
			ID, ActorName, OpenedAt string
			EndReason               *string
			Reveals                 []struct {
				SecretID, SecretName, RevealedAt string
				OwnerNotified                    bool
			}
		}
	}
	newBTGClient(&btgIdentity{}, v, btgWebAdmin).MustPost(
		`query { breakGlassSessions(limit: 10) { id actorName openedAt endReason reveals { secretId secretName revealedAt ownerNotified } } }`, &resp)
	if v.sessions.GetLimit() != 10 {
		t.Fatalf("limit = %d", v.sessions.GetLimit())
	}
	if len(resp.BreakGlassSessions) != 1 {
		t.Fatalf("sessions = %+v", resp.BreakGlassSessions)
	}
	s := resp.BreakGlassSessions[0]
	if s.ActorName != "Ada Admin" || s.EndReason == nil || *s.EndReason != "exit" || len(s.Reveals) != 1 {
		t.Fatalf("session = %+v", s)
	}
	if r := s.Reveals[0]; r.SecretID != "s-1" || r.SecretName != "bob-laptop" || r.RevealedAt != "2027-01-15T08:00:30Z" || !r.OwnerNotified {
		t.Fatalf("reveal = %+v", r)
	}
}

// An admin can always leave break-glass, even in read-only maintenance; a new
// session can't be opened then.
func TestBreakGlassExitStaysOpenInMaintenance(t *testing.T) {
	mode := maintenance.New(true, nil)
	v := &btgVault{}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: &btgIdentity{}, Vault: v, Now: func() time.Time { return btgNow }}}))
	h.AddTransport(transport.POST{})
	h.Use(maintenance.Guard{Mode: mode, Allowed: maintenance.HumanAllowed})
	h.SetErrorPresenter(gqlerr.Present)
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(btgWebAdmin(r.Context())))
	}))
	var resp struct{ CloseBreakGlassSession struct{ ID string } }
	c.MustPost(`mutation { closeBreakGlassSession(id: "bgs-1") { id } }`, &resp)
	if v.closeReq == nil {
		t.Fatal("exit must reach the vault in maintenance")
	}
	errs := btgErrors(t, c, btgOpen)
	if len(errs) != 1 || errs[0].Extensions.Reason != maintenance.Reason || v.open != nil {
		t.Fatalf("open in maintenance: %+v", errs)
	}
}
