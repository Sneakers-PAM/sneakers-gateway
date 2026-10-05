// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// batchVault keeps uses the way vault does for these calls: DecideSecretUse
// refuses an unknown id, another owner's use and a use that isn't pending,
// and expires a pending use past its deadline first.
type batchVault struct {
	vaultv1.VaultServiceClient
	now       int64
	uses      map[string]*vaultv1.SecretUse
	decideErr map[string]error
	decided   []*vaultv1.DecideSecretUseRequest
	lastList  *vaultv1.ListPendingSecretUsesRequest
	listUses  []*vaultv1.SecretUse
}

func (f *batchVault) live(id string) (*vaultv1.SecretUse, bool) {
	u, ok := f.uses[id]
	if ok && u.GetState() == vaultv1.SecretUseState_SECRET_USE_STATE_PENDING && f.now >= u.GetExpiresAtUnix() {
		u.State = vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED
	}
	return u, ok
}

func (f *batchVault) DecideSecretUse(_ context.Context, in *vaultv1.DecideSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.DecideSecretUseResponse, error) {
	f.decided = append(f.decided, in)
	if err := f.decideErr[in.GetUseId()]; err != nil {
		return nil, err
	}
	u, ok := f.live(in.GetUseId())
	switch {
	case !ok:
		return nil, status.Error(codes.NotFound, "secret use not found")
	case u.GetUserId() != in.GetActor().GetUserId():
		return nil, status.Error(codes.PermissionDenied, "only the token's owner can decide this use")
	case u.GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING:
		return nil, status.Errorf(codes.FailedPrecondition, "secret use is %s", u.GetState())
	}
	u.State = vaultv1.SecretUseState_SECRET_USE_STATE_DENIED
	if in.GetApprove() {
		u.State = vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED
	}
	return &vaultv1.DecideSecretUseResponse{Use: proto.Clone(u).(*vaultv1.SecretUse)}, nil
}

func (f *batchVault) GetSecretUse(_ context.Context, in *vaultv1.GetSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretUseResponse, error) {
	u, ok := f.live(in.GetUseId())
	if !ok || u.GetUserId() != in.GetActor().GetUserId() {
		return nil, status.Error(codes.NotFound, "secret use not found")
	}
	return &vaultv1.GetSecretUseResponse{Use: u}, nil
}

func (f *batchVault) ListPendingSecretUses(_ context.Context, in *vaultv1.ListPendingSecretUsesRequest, _ ...grpc.CallOption) (*vaultv1.ListPendingSecretUsesResponse, error) {
	f.lastList = in
	return &vaultv1.ListPendingSecretUsesResponse{Uses: f.listUses}, nil
}

type batchIdentity struct {
	identityv1.IdentityServiceClient
	totpCalls int
	tokens    []*identityv1.UserToken
	tokensErr error
}

func (f *batchIdentity) VerifyTotp(_ context.Context, in *identityv1.VerifyTotpRequest, _ ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error) {
	f.totpCalls++
	return &identityv1.VerifyTotpResponse{Ok: in.GetCode() == "123456"}, nil
}

func (f *batchIdentity) ListUserTokens(_ context.Context, in *identityv1.ListUserTokensRequest, _ ...grpc.CallOption) (*identityv1.ListUserTokensResponse, error) {
	if f.tokensErr != nil {
		return nil, f.tokensErr
	}
	return &identityv1.ListUserTokensResponse{Tokens: f.tokens}, nil
}

const batchNow = 1790000000

func pendingUse(id, owner string) *vaultv1.SecretUse {
	return &vaultv1.SecretUse{
		Id: id, SecretId: "s-" + id, SecretName: "router-admin", FieldKey: "password", UserId: owner, TokenId: "utok-1",
		Argv: []string{"ssh", "admin@router-01"}, ClientLabel: "Sneakers MCP", RunId: "run_a", Purpose: "rotate the router",
		State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, ExpiresAtUnix: batchNow + 300,
	}
}

func newBatchVault(uses ...*vaultv1.SecretUse) *batchVault {
	fv := &batchVault{now: batchNow, uses: map[string]*vaultv1.SecretUse{}, decideErr: map[string]error{}}
	for _, u := range uses {
		fv.uses[u.GetId()] = u
	}
	return fv
}

// newBatchClient signs in u-ada; mfaAt is when the session last proved a
// factor (zero for never). The clock is fixed at batchNow.
func newBatchClient(fv *batchVault, fi *batchIdentity, mfaAt time.Time) *gqlclient.Client {
	r := &Resolver{Vault: fv, Identity: fi, MFAMaxAge: 5 * time.Minute, Now: func() time.Time { return time.Unix(batchNow, 0) }}
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

type batchOutcome struct {
	ID      string
	Decided bool
	Reason  *string
	Use     *struct{ ID, State string }
}

type batchResult struct {
	DecideSecretUses struct{ Outcomes []batchOutcome }
}

func idList(ids ...string) string {
	q := make([]string, len(ids))
	for i, id := range ids {
		q[i] = fmt.Sprintf("%q", id)
	}
	return "[" + strings.Join(q, ",") + "]"
}

func decideQuery(ids []string, decision, factor string) string {
	f := ""
	if factor != "" {
		f = `, factor:{kind:"totp", code:"` + factor + `"}`
	}
	return `mutation { decideSecretUses(ids:` + idList(ids...) + `, decision:` + decision + f + `) { outcomes { id decided reason use { id state } } } }`
}

// postBatchErr posts a query that must fail as a whole and returns its one error.
func postBatchErr(t *testing.T, c *gqlclient.Client, query string) breakGlassErr {
	t.Helper()
	resp, err := c.RawPost(query)
	if err != nil {
		t.Fatal(err)
	}
	var errs []breakGlassErr
	if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
		t.Fatalf("errors = %s (%v)", resp.Errors, err)
	}
	return errs[0]
}

func TestDecideSecretUsesChecksTheFactorOnceForTheWholeBatch(t *testing.T) {
	fv := newBatchVault(pendingUse("use-1", "u-ada"), pendingUse("use-2", "u-ada"), pendingUse("use-3", "u-ada"))
	fi := &batchIdentity{}
	var resp batchResult
	newBatchClient(fv, fi, time.Time{}).MustPost(decideQuery([]string{"use-1", "use-2", "use-3"}, "APPROVE", "123456"), &resp)
	if fi.totpCalls != 1 {
		t.Fatalf("factor checks = %d, want 1", fi.totpCalls)
	}
	if len(fv.decided) != 3 {
		t.Fatalf("vault decides = %d, want 3", len(fv.decided))
	}
	for i, want := range []string{"use-1", "use-2", "use-3"} {
		d := fv.decided[i]
		if d.GetUseId() != want || !d.GetApprove() || d.GetActor().GetUserId() != "u-ada" {
			t.Fatalf("decide %d = %+v", i, d)
		}
		o := resp.DecideSecretUses.Outcomes[i]
		if o.ID != want || !o.Decided || o.Reason != nil || o.Use == nil || o.Use.State != "APPROVED" {
			t.Fatalf("outcome %d = %+v", i, o)
		}
	}
}

func TestDecideSecretUsesDecidesTheRestWhenSomeAreRefused(t *testing.T) {
	expired := pendingUse("use-old", "u-ada")
	expired.ExpiresAtUnix = batchNow - 1
	decided := pendingUse("use-done", "u-ada")
	decided.State = vaultv1.SecretUseState_SECRET_USE_STATE_DENIED
	fv := newBatchVault(pendingUse("use-1", "u-ada"), expired, pendingUse("use-bob", "u-bob"), decided, pendingUse("use-2", "u-ada"),
		pendingUse("use-down", "u-ada"), pendingUse("use-odd", "u-ada"))
	fv.decideErr["use-down"] = status.Error(codes.Unavailable, "vault is restarting")
	fv.decideErr["use-odd"] = status.Error(codes.Internal, "store secret use: disk full")
	ids := []string{"use-1", "use-old", "use-bob", "use-done", "use-missing", "use-down", "use-odd", "use-2"}
	var resp batchResult
	newBatchClient(fv, &batchIdentity{}, time.Time{}).MustPost(decideQuery(ids, "APPROVE", "123456"), &resp)

	want := []string{"", "EXPIRED", "NOT_PERMITTED", "ALREADY_DECIDED", "NOT_FOUND", "UNAVAILABLE", "UNAVAILABLE", ""}
	if len(resp.DecideSecretUses.Outcomes) != len(ids) {
		t.Fatalf("outcomes = %+v", resp.DecideSecretUses.Outcomes)
	}
	for i, o := range resp.DecideSecretUses.Outcomes {
		if o.ID != ids[i] {
			t.Fatalf("outcome %d id = %q, want %q", i, o.ID, ids[i])
		}
		if want[i] == "" {
			if !o.Decided || o.Reason != nil || o.Use == nil || o.Use.State != "APPROVED" {
				t.Fatalf("outcome %d = %+v, want decided", i, o)
			}
			continue
		}
		if o.Decided || o.Use != nil || o.Reason == nil || *o.Reason != want[i] {
			t.Fatalf("outcome %d = %+v, want refused %s", i, o, want[i])
		}
	}
	if len(fv.decided) != len(ids) {
		t.Fatalf("every item must go through vault DecideSecretUse: %d of %d", len(fv.decided), len(ids))
	}
	if fv.uses["use-bob"].GetState() != vaultv1.SecretUseState_SECRET_USE_STATE_PENDING {
		t.Fatal("another owner's use must stay pending")
	}
}

func TestDecideSecretUsesReusesAFreshSessionFactor(t *testing.T) {
	fv := newBatchVault(pendingUse("use-1", "u-ada"), pendingUse("use-2", "u-ada"))
	fi := &batchIdentity{}
	var resp batchResult
	newBatchClient(fv, fi, time.Unix(batchNow, 0).Add(-4*time.Minute)).MustPost(decideQuery([]string{"use-1", "use-2"}, "APPROVE", ""), &resp)
	if fi.totpCalls != 0 || len(fv.decided) != 2 || !resp.DecideSecretUses.Outcomes[1].Decided {
		t.Fatalf("factor checks = %d decides = %d resp = %+v", fi.totpCalls, len(fv.decided), resp)
	}
}

func TestDecideSecretUsesNeedsAStepUpOnceTheWindowCloses(t *testing.T) {
	for name, mfaAt := range map[string]time.Time{
		"stale": time.Unix(batchNow, 0).Add(-6 * time.Minute),
		"never": {},
	} {
		t.Run(name, func(t *testing.T) {
			fv := newBatchVault(pendingUse("use-1", "u-ada"))
			ge := postBatchErr(t, newBatchClient(fv, &batchIdentity{}, mfaAt), decideQuery([]string{"use-1"}, "APPROVE", ""))
			if ge.Extensions.Code != "FAILED_PRECONDITION" || ge.Extensions.Reason != "STEP_UP_REQUIRED" || ge.Extensions.Domain != "sneakers.gateway" {
				t.Fatalf("extensions = %+v", ge.Extensions)
			}
			if len(fv.decided) != 0 {
				t.Fatal("nothing may be decided without a fresh factor")
			}
		})
	}
}

func TestDecideSecretUsesRefusesAWrongFactorAndDecidesNothing(t *testing.T) {
	fv := newBatchVault(pendingUse("use-1", "u-ada"))
	fresh := time.Unix(batchNow, 0).Add(-time.Minute)
	ge := postBatchErr(t, newBatchClient(fv, &batchIdentity{}, fresh), decideQuery([]string{"use-1"}, "APPROVE", "000000"))
	if ge.Extensions.Code != "UNAUTHENTICATED" || ge.Extensions.Reason != "FACTOR_NOT_ACCEPTED" || ge.Extensions.Domain != "sneakers.gateway" {
		t.Fatalf("extensions = %+v", ge.Extensions)
	}
	if len(fv.decided) != 0 {
		t.Fatal("nothing may be decided after a wrong factor")
	}
}

func TestDecideSecretUsesDeniesWithoutAFactor(t *testing.T) {
	fv := newBatchVault(pendingUse("use-1", "u-ada"), pendingUse("use-2", "u-ada"))
	fi := &batchIdentity{}
	var resp batchResult
	newBatchClient(fv, fi, time.Time{}).MustPost(decideQuery([]string{"use-1", "use-2"}, "DENY", ""), &resp)
	if fi.totpCalls != 0 || len(fv.decided) != 2 || fv.decided[0].GetApprove() || resp.DecideSecretUses.Outcomes[0].Use.State != "DENIED" {
		t.Fatalf("factor checks = %d decides = %+v resp = %+v", fi.totpCalls, fv.decided, resp)
	}
}

func TestDecideSecretUsesRefusesAnEmptyOrOversizedBatchFirst(t *testing.T) {
	many := make([]string, 21)
	for i := range many {
		many[i] = fmt.Sprintf("use-%d", i)
	}
	for name, ids := range map[string][]string{"none": {}, "21": many} {
		t.Run(name, func(t *testing.T) {
			fv := newBatchVault()
			fi := &batchIdentity{}
			ge := postBatchErr(t, newBatchClient(fv, fi, time.Time{}), decideQuery(ids, "APPROVE", "123456"))
			if ge.Extensions.Code != "INVALID_ARGUMENT" || ge.Extensions.Reason != "BATCH_SIZE_INVALID" || ge.Extensions.Domain != "sneakers.gateway" {
				t.Fatalf("extensions = %+v", ge.Extensions)
			}
			if fi.totpCalls != 0 || len(fv.decided) != 0 {
				t.Fatalf("factor checks = %d decides = %d, want none", fi.totpCalls, len(fv.decided))
			}
		})
	}
}

func TestDecideSecretUsesDecidesADuplicateOnce(t *testing.T) {
	ids := []string{"use-1", "use-2", "use-1"}
	for i := 3; i <= 20; i++ {
		ids = append(ids, "use-2")
	}
	fv := newBatchVault(pendingUse("use-1", "u-ada"), pendingUse("use-2", "u-ada"))
	var resp batchResult
	newBatchClient(fv, &batchIdentity{}, time.Time{}).MustPost(decideQuery(append(ids, "use-1"), "APPROVE", "123456"), &resp)
	if len(fv.decided) != 2 || len(resp.DecideSecretUses.Outcomes) != 2 || resp.DecideSecretUses.Outcomes[0].ID != "use-1" || resp.DecideSecretUses.Outcomes[1].ID != "use-2" {
		t.Fatalf("decides = %d outcomes = %+v", len(fv.decided), resp.DecideSecretUses.Outcomes)
	}
}

func TestDecideSecretUsesNeedsASignedInUser(t *testing.T) {
	fv := newBatchVault(pendingUse("use-1", "u-ada"))
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Identity: &batchIdentity{}}}))
	h.AddTransport(transport.POST{})
	var resp map[string]any
	if err := gqlclient.New(h).Post(decideQuery([]string{"use-1"}, "DENY", ""), &resp); err == nil || len(fv.decided) != 0 {
		t.Fatal("a caller with no session must be refused")
	}
}

type runResult struct {
	SecretUseRun struct {
		RunID             string
		MfaFreshUntilUnix int
		Uses              []struct {
			ID, RunID, Purpose, Requester, SecretName, FieldKey string
			Argv                                                []string
			Reveal                                              bool
			ExpiresAtUnix                                       int
		}
	}
}

const runQuery = `query { secretUseRun(runId:"run_a") { runId mfaFreshUntilUnix uses { id runId purpose requester secretName fieldKey argv reveal expiresAtUnix } } }`

func TestSecretUseRunListsTheCallersPendingUsesOfTheRun(t *testing.T) {
	fv := newBatchVault()
	other := pendingUse("use-bob", "u-bob")
	reveal := pendingUse("use-2", "u-ada")
	reveal.TokenId, reveal.ClientLabel, reveal.Reveal, reveal.Argv = "utok-gone", "Sneakers MCP", true, nil
	fv.listUses = []*vaultv1.SecretUse{pendingUse("use-1", "u-ada"), other, reveal}
	fi := &batchIdentity{tokens: []*identityv1.UserToken{{Id: "utok-1", UserId: "u-ada", Label: "laptop agent"}}}
	mfaAt := time.Unix(batchNow, 0).Add(-time.Minute)
	var resp runResult
	newBatchClient(fv, fi, mfaAt).MustPost(runQuery, &resp)

	if fv.lastList.GetRunId() != "run_a" || fv.lastList.GetActor().GetUserId() != "u-ada" {
		t.Fatalf("list request = %+v", fv.lastList)
	}
	got := resp.SecretUseRun
	if got.RunID != "run_a" || len(got.Uses) != 2 {
		t.Fatalf("run = %+v", got)
	}
	if got.MfaFreshUntilUnix != int(mfaAt.Add(5*time.Minute).Unix()) {
		t.Fatalf("mfaFreshUntilUnix = %d", got.MfaFreshUntilUnix)
	}
	u := got.Uses[0]
	if u.ID != "use-1" || u.RunID != "run_a" || u.Purpose != "rotate the router" || u.Requester != "laptop agent" || len(u.Argv) != 2 {
		t.Fatalf("use 0 = %+v", u)
	}
	if r := got.Uses[1]; r.ID != "use-2" || r.Requester != "Sneakers MCP" || !r.Reveal {
		t.Fatalf("use 1 = %+v, want the client label for an unknown token", r)
	}
}

func TestSecretUseRunReportsNoWindowForAStaleFactor(t *testing.T) {
	fv := newBatchVault()
	var resp runResult
	newBatchClient(fv, &batchIdentity{}, time.Unix(batchNow, 0).Add(-6*time.Minute)).MustPost(runQuery, &resp)
	if resp.SecretUseRun.MfaFreshUntilUnix != 0 || resp.SecretUseRun.Uses == nil {
		t.Fatalf("run = %+v", resp.SecretUseRun)
	}
}

func TestSecretUseRunFallsBackToTheClientLabelWhenIdentityFails(t *testing.T) {
	fv := newBatchVault()
	fv.listUses = []*vaultv1.SecretUse{pendingUse("use-1", "u-ada")}
	var resp runResult
	newBatchClient(fv, &batchIdentity{tokensErr: status.Error(codes.Unavailable, "identity down")}, time.Time{}).MustPost(runQuery, &resp)
	if len(resp.SecretUseRun.Uses) != 1 || resp.SecretUseRun.Uses[0].Requester != "Sneakers MCP" {
		t.Fatalf("run = %+v", resp.SecretUseRun)
	}
}

func TestPendingSecretUsesNameTheRequestingToken(t *testing.T) {
	fv := newBatchVault()
	fv.listUses = []*vaultv1.SecretUse{pendingUse("use-1", "u-ada")}
	fi := &batchIdentity{tokens: []*identityv1.UserToken{{Id: "utok-1", UserId: "u-ada", Label: "laptop agent"}}}
	var resp struct {
		PendingSecretUses []struct{ Requester, RunID, Purpose string }
	}
	newBatchClient(fv, fi, time.Time{}).MustPost(`query { pendingSecretUses { requester runId purpose } }`, &resp)
	if len(resp.PendingSecretUses) != 1 || resp.PendingSecretUses[0] != (struct{ Requester, RunID, Purpose string }{"laptop agent", "run_a", "rotate the router"}) {
		t.Fatalf("pending = %+v", resp.PendingSecretUses)
	}
}
