// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// approvalVault records the approval calls the gateway makes; the vault's
// own decisions are tested in the vault.
type approvalVault struct {
	vaultv1.VaultServiceClient
	confirms   []*vaultv1.ConfirmSecretUseRequest
	confirmErr map[string]error
	prepares   []*vaultv1.PrepareSecretUseRequest
	redeems    []*vaultv1.RedeemSecretUseRequest
	toDecide   []*vaultv1.SecretUse
	approval   *vaultv1.SetSecretTokenApprovalRequest
	decideErr  error
}

func (f *approvalVault) ConfirmSecretUse(_ context.Context, in *vaultv1.ConfirmSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.ConfirmSecretUseResponse, error) {
	f.confirms = append(f.confirms, in)
	if err := f.confirmErr[in.GetUseId()]; err != nil {
		return nil, err
	}
	return &vaultv1.ConfirmSecretUseResponse{Use: &vaultv1.SecretUse{Id: in.GetUseId(), State: vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED}}, nil
}

func (f *approvalVault) PrepareSecretUse(_ context.Context, in *vaultv1.PrepareSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.PrepareSecretUseResponse, error) {
	f.prepares = append(f.prepares, in)
	return &vaultv1.PrepareSecretUseResponse{Use: &vaultv1.SecretUse{
		Id: "use-web", SecretName: "domain-admin", FieldKey: in.GetFieldKey(), Reveal: true, UserId: in.GetActor().GetUserId(),
		RunId: in.GetRunId(), State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, Confirm: true,
	}}, nil
}

func (f *approvalVault) RedeemSecretUse(_ context.Context, in *vaultv1.RedeemSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.RedeemSecretUseResponse, error) {
	f.redeems = append(f.redeems, in)
	return &vaultv1.RedeemSecretUseResponse{Use: &vaultv1.SecretUse{Id: in.GetUseId()}, Value: "s3cret"}, nil
}

func (f *approvalVault) ListSecretUsesToDecide(_ context.Context, _ *vaultv1.ListSecretUsesToDecideRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretUsesToDecideResponse, error) {
	return &vaultv1.ListSecretUsesToDecideResponse{Uses: f.toDecide}, nil
}

func (f *approvalVault) SetSecretTokenApproval(_ context.Context, in *vaultv1.SetSecretTokenApprovalRequest, _ ...grpc.CallOption) (*vaultv1.SetSecretTokenApprovalResponse, error) {
	f.approval = in
	return &vaultv1.SetSecretTokenApprovalResponse{Secret: &vaultv1.Secret{
		Id: in.GetSecretId(), RequireTokenApproval: in.GetRequired(), AlwaysRequireApproval: in.GetAlways(),
	}}, nil
}

func (f *approvalVault) DecideSecretUse(_ context.Context, in *vaultv1.DecideSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.DecideSecretUseResponse, error) {
	if f.decideErr != nil {
		return nil, f.decideErr
	}
	return &vaultv1.DecideSecretUseResponse{Use: &vaultv1.SecretUse{Id: in.GetUseId(), State: vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED}}, nil
}

func (f *approvalVault) GetSecretUse(_ context.Context, in *vaultv1.GetSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretUseResponse, error) {
	return &vaultv1.GetSecretUseResponse{Use: &vaultv1.SecretUse{Id: in.GetUseId(), State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING}}, nil
}

type approvalIdentity struct {
	batchIdentity
	users     []*identityv1.User
	usersErr  error
	listCalls int
}

func (f *approvalIdentity) ListUsers(_ context.Context, _ *identityv1.ListUsersRequest, _ ...grpc.CallOption) (*identityv1.ListUsersResponse, error) {
	f.listCalls++
	if f.usersErr != nil {
		return nil, f.usersErr
	}
	return &identityv1.ListUsersResponse{Users: f.users}, nil
}

func (f *approvalIdentity) ResolveUserLabels(_ context.Context, in *identityv1.ResolveUserLabelsRequest, _ ...grpc.CallOption) (*identityv1.ResolveUserLabelsResponse, error) {
	out := &identityv1.ResolveUserLabelsResponse{}
	for _, id := range in.GetIds() {
		out.Labels = append(out.Labels, &identityv1.UserLabel{Id: id, Name: "Name of " + id})
	}
	return out, nil
}

func directory() []*identityv1.User {
	return []*identityv1.User{
		{Id: "u-ada", Subject: "k-ada"},
		{Id: "u-bob", Subject: "k-bob"},
		{Id: "u-gone", Subject: "k-gone", DisabledAtUnix: 1700000000},
		{Id: "u-new"},
	}
}

func newApprovalClient(fv *approvalVault, fi *approvalIdentity, mfaAt time.Time) *gqlclient.Client {
	clock := func() time.Time { return time.Unix(batchNow, 0) }
	r := &Resolver{
		Vault: fv, Identity: fi, MFAMaxAge: 30 * time.Minute, Now: clock,
		ActiveUsers: &ActiveUsers{Identity: fi, Now: clock},
	}
	h := handler.New(NewExecutableSchema(Config{Resolvers: r}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := WithActorInfo(WithActor(req.Context(), "u-ada"), false, false, nil)
		if !mfaAt.IsZero() {
			ctx = WithMFAVerifiedAt(ctx, mfaAt)
		}
		h.ServeHTTP(w, req.WithContext(ctx))
	}))
}

type confirmResult struct {
	ConfirmSecretUses struct{ Outcomes []batchOutcome }
}

func TestConfirmSecretUsesChecksTheFactorOnceAndSendsTheActivePeople(t *testing.T) {
	fv := &approvalVault{}
	fi := &approvalIdentity{users: directory()}
	var resp confirmResult
	newApprovalClient(fv, fi, time.Time{}).MustPost(`mutation { confirmSecretUses(ids:["use-1","use-2"], factor:{kind:"totp", code:"123456"}) { outcomes { id decided reason use { id state } } } }`, &resp)
	if fi.totpCalls != 1 || len(fv.confirms) != 2 {
		t.Fatalf("factor checks = %d, confirms = %d; want 1 and 2", fi.totpCalls, len(fv.confirms))
	}
	if fi.listCalls != 1 {
		t.Fatalf("identity listings = %d, want 1 for the batch", fi.listCalls)
	}
	for _, c := range fv.confirms {
		if got := c.GetActiveUsers().GetUserIds(); !slices.Equal(got, []string{"u-ada", "u-bob"}) {
			t.Fatalf("active users = %v, want the enabled, adopted people only", got)
		}
		if c.GetActor().GetMfaVerifiedAtUnix() != batchNow {
			t.Fatalf("actor MFA time = %d, want the factor just proved", c.GetActor().GetMfaVerifiedAtUnix())
		}
	}
	for _, o := range resp.ConfirmSecretUses.Outcomes {
		if !o.Decided || o.Use.State != "APPROVED" {
			t.Fatalf("outcome = %+v", o)
		}
	}
}

func TestConfirmSecretUsesNeedsAFactorOrAFreshSession(t *testing.T) {
	fv := &approvalVault{}
	fi := &approvalIdentity{users: directory()}
	got := postBatchErr(t, newApprovalClient(fv, fi, time.Time{}), `mutation { confirmSecretUses(ids:["use-1"]) { outcomes { id } } }`)
	if got.Extensions.Reason != "STEP_UP_REQUIRED" || len(fv.confirms) != 0 {
		t.Fatalf("no factor: %+v, confirms %d", got, len(fv.confirms))
	}
	var resp confirmResult
	newApprovalClient(fv, fi, time.Unix(batchNow-29*60, 0)).MustPost(`mutation { confirmSecretUses(ids:["use-1"]) { outcomes { id decided } } }`, &resp)
	if len(fv.confirms) != 1 || fi.totpCalls != 0 {
		t.Fatalf("a session step-up 29 minutes ago must cover it: confirms %d, factor checks %d", len(fv.confirms), fi.totpCalls)
	}
}

func TestConfirmSecretUsesReportsWhenSomeoneElseDecides(t *testing.T) {
	other, _ := status.New(codes.FailedPrecondition, "an owner or approver of this secret decides this use").
		WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: "OTHER_APPROVER"})
	fv := &approvalVault{confirmErr: map[string]error{"use-2": other.Err()}}
	var resp confirmResult
	newApprovalClient(fv, &approvalIdentity{users: directory()}, time.Unix(batchNow, 0)).
		MustPost(`mutation { confirmSecretUses(ids:["use-1","use-2"]) { outcomes { id decided reason } } }`, &resp)
	o := resp.ConfirmSecretUses.Outcomes
	if !o[0].Decided || o[1].Decided || o[1].Reason == nil || *o[1].Reason != "OTHER_APPROVER" {
		t.Fatalf("outcomes = %+v", o)
	}
}

func TestDecideSecretUsesNamesASelfApproval(t *testing.T) {
	self, _ := status.New(codes.PermissionDenied, "you can't approve your own request").
		WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: "SELF_APPROVAL"})
	fv := &approvalVault{decideErr: self.Err()}
	var resp batchResult
	newApprovalClient(fv, &approvalIdentity{}, time.Unix(batchNow, 0)).
		MustPost(decideQuery([]string{"use-1"}, "APPROVE", ""), &resp)
	if r := resp.DecideSecretUses.Outcomes[0].Reason; r == nil || *r != "SELF_APPROVAL" {
		t.Fatalf("outcome = %+v", resp.DecideSecretUses.Outcomes[0])
	}
}

func TestAWebRevealGoesThroughAUse(t *testing.T) {
	fv := &approvalVault{}
	fi := &approvalIdentity{users: directory()}
	c := newApprovalClient(fv, fi, time.Unix(batchNow, 0))
	var prep struct {
		PrepareSecretReveal struct {
			ID, State, RequestedBy string
			Confirm                bool
		}
	}
	c.MustPost(`mutation { prepareSecretReveal(secretId:"s-1", fieldKey:"password", runId:"web-1") { id state requestedBy confirm } }`, &prep)
	p := fv.prepares[0]
	if !p.GetReveal() || p.GetRunId() != "web-1" || p.GetActor().GetUserId() != "u-ada" || len(p.GetActiveUsers().GetUserIds()) != 2 {
		t.Fatalf("prepare = %+v", p)
	}
	if prep.PrepareSecretReveal.State != "PENDING" || !prep.PrepareSecretReveal.Confirm {
		t.Fatalf("prepared = %+v", prep)
	}
	var red struct{ RedeemSecretReveal string }
	c.MustPost(`mutation { redeemSecretReveal(id:"use-web") }`, &red)
	if red.RedeemSecretReveal != "s3cret" || fv.redeems[0].GetActor().GetUserId() != "u-ada" {
		t.Fatalf("redeem = %q, %+v", red.RedeemSecretReveal, fv.redeems)
	}
}

func TestSecretUsesToDecideNamesTheRequesters(t *testing.T) {
	fv := &approvalVault{toDecide: []*vaultv1.SecretUse{
		{Id: "use-b", UserId: "u-bob", SecretName: "domain-admin", State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING},
		{Id: "use-mine", UserId: "u-ada", State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING},
	}}
	var resp struct {
		SecretUsesToDecide []struct{ ID, RequestedBy string }
	}
	newApprovalClient(fv, &approvalIdentity{}, time.Time{}).MustPost(`query { secretUsesToDecide { id requestedBy } }`, &resp)
	if len(resp.SecretUsesToDecide) != 1 || resp.SecretUsesToDecide[0].RequestedBy != "Name of u-bob" {
		t.Fatalf("queue = %+v, want only bob's use, named", resp.SecretUsesToDecide)
	}
}

func TestSetSecretTokenApprovalSetsAlwaysApprove(t *testing.T) {
	fv := &approvalVault{}
	var resp struct {
		SetSecretTokenApproval struct{ RequireTokenApproval, AlwaysRequireApproval bool }
	}
	newApprovalClient(fv, &approvalIdentity{}, time.Time{}).MustPost(`mutation { setSecretTokenApproval(secretId:"s-1", required:true, always:true) { requireTokenApproval alwaysRequireApproval } }`, &resp)
	if !fv.approval.GetAlways() || !resp.SetSecretTokenApproval.AlwaysRequireApproval {
		t.Fatalf("set = %+v resp = %+v", fv.approval, resp)
	}
}

func TestActiveUsersCachesAndFailsToUnknown(t *testing.T) {
	now := time.Unix(batchNow, 0)
	fi := &approvalIdentity{users: directory()}
	a := &ActiveUsers{Identity: fi, Now: func() time.Time { return now }}
	_ = a.Get(context.Background())
	_ = a.Get(context.Background())
	if fi.listCalls != 1 {
		t.Fatalf("identity listings = %d, want 1 inside the cache window", fi.listCalls)
	}
	now = now.Add(activeUsersTTL)
	fi.usersErr = errors.New("identity down")
	if got := a.Get(context.Background()); got != nil {
		t.Fatalf("identity down: got %v, want nil (unknown)", got)
	}
	var none *ActiveUsers
	if none.Get(context.Background()) != nil {
		t.Fatal("no lister: want nil")
	}
}
