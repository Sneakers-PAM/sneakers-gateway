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
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stepUpVault records the actor and requests of the calls the step-up work
// touches, and can refuse a reveal with the vault's step-up reason.
type stepUpVault struct {
	vaultv1.VaultServiceClient
	actor       *vaultv1.ActorContext
	revealErr   error
	ruleset     *vaultv1.SetFolderRulesetRequest
	stepUpReq   *vaultv1.SetFolderRevealStepUpRequest
	settingsReq *vaultv1.UpdateSecuritySettingsRequest
}

func (f *stepUpVault) RevealSecretField(_ context.Context, req *vaultv1.RevealSecretFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	f.actor = req.GetActor()
	if f.revealErr != nil {
		return nil, f.revealErr
	}
	return &vaultv1.RevealSecretFieldResponse{Value: "v"}, nil
}

func (f *stepUpVault) SetFolderRuleset(_ context.Context, req *vaultv1.SetFolderRulesetRequest, _ ...grpc.CallOption) (*vaultv1.SetFolderRulesetResponse, error) {
	f.ruleset = req
	return &vaultv1.SetFolderRulesetResponse{}, nil
}

func (f *stepUpVault) GetFolderRuleset(context.Context, *vaultv1.GetFolderRulesetRequest, ...grpc.CallOption) (*vaultv1.GetFolderRulesetResponse, error) {
	return &vaultv1.GetFolderRulesetResponse{Rules: f.ruleset.GetRules()}, nil
}

func (f *stepUpVault) ListFolders(context.Context, *vaultv1.ListFoldersRequest, ...grpc.CallOption) (*vaultv1.ListFoldersResponse, error) {
	return &vaultv1.ListFoldersResponse{Folders: []*vaultv1.Folder{{Id: "f1", Name: "Ops", RevealStepUp: vaultv1.StepUpMode_STEP_UP_MODE_REQUIRE}}}, nil
}

func (f *stepUpVault) SetFolderRevealStepUp(_ context.Context, req *vaultv1.SetFolderRevealStepUpRequest, _ ...grpc.CallOption) (*vaultv1.SetFolderRevealStepUpResponse, error) {
	f.stepUpReq = req
	f.actor = req.GetActor()
	return &vaultv1.SetFolderRevealStepUpResponse{Folder: &vaultv1.Folder{Id: req.GetFolderId(), Name: "Ops", RevealStepUp: req.GetMode()}}, nil
}

func (f *stepUpVault) UpdateSecuritySettings(_ context.Context, req *vaultv1.UpdateSecuritySettingsRequest, _ ...grpc.CallOption) (*vaultv1.UpdateSecuritySettingsResponse, error) {
	f.settingsReq = req
	return &vaultv1.UpdateSecuritySettingsResponse{Settings: &vaultv1.SecuritySettings{RequireMfaForReveal: req.GetRequireMfaForReveal()}}, nil
}

// recordingWorkflow records the actor it's given on check-out.
type recordingWorkflow struct {
	workflowv1.WorkflowServiceClient
	actor *workflowv1.ActorContext
}

func (f *recordingWorkflow) CheckoutSecret(_ context.Context, req *workflowv1.CheckoutSecretRequest, _ ...grpc.CallOption) (*workflowv1.CheckoutSecretResponse, error) {
	f.actor = req.GetActor()
	return &workflowv1.CheckoutSecretResponse{Lease: &workflowv1.Lease{Id: "l1"}}, nil
}

func (f *recordingWorkflow) CheckinSecret(_ context.Context, req *workflowv1.CheckinSecretRequest, _ ...grpc.CallOption) (*workflowv1.CheckinSecretResponse, error) {
	f.actor = req.GetActor()
	return &workflowv1.CheckinSecretResponse{}, nil
}

// stepUpClient serves the human schema as the session gate would: the actor,
// its authz attributes and the session's MFA time on the context.
func stepUpClient(fv vaultv1.VaultServiceClient, wf workflowv1.WorkflowServiceClient, mfaAt time.Time) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Workflow: wf}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActor(r.Context(), "u-1")
		ctx = WithActorInfo(ctx, true, false, []string{"ops"})
		if !mfaAt.IsZero() {
			ctx = WithMFAVerifiedAt(ctx, mfaAt)
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func TestRevealCarriesTheSessionMFATime(t *testing.T) {
	at := time.Unix(1790000000, 0)
	fv := &stepUpVault{}
	var resp map[string]any
	stepUpClient(fv, nil, at).MustPost(`mutation { revealSecretField(id: "s1", fieldKey: "password") }`, &resp)
	if fv.actor.GetMfaVerifiedAtUnix() != at.Unix() {
		t.Fatalf("mfa_verified_at_unix = %d, want %d", fv.actor.GetMfaVerifiedAtUnix(), at.Unix())
	}
}

func TestRevealWithoutMFATimeSendsZero(t *testing.T) {
	fv := &stepUpVault{}
	var resp map[string]any
	stepUpClient(fv, nil, time.Time{}).MustPost(`mutation { revealSecretField(id: "s1", fieldKey: "password") }`, &resp)
	if fv.actor.GetMfaVerifiedAtUnix() != 0 {
		t.Fatalf("mfa_verified_at_unix = %d, want 0", fv.actor.GetMfaVerifiedAtUnix())
	}
}

// A stale MFA reaches the client as the vault's stable step-up reason.
func TestStaleMFARevealAnswersStepUpRequired(t *testing.T) {
	st, err := status.New(codes.FailedPrecondition, "a fresh second factor is required").WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: "STEP_UP_REQUIRED"})
	if err != nil {
		t.Fatal(err)
	}
	fv := &stepUpVault{revealErr: st.Err()}
	resp, err := stepUpClient(fv, nil, time.Now().Add(-time.Hour)).RawPost(`mutation { revealSecretField(id: "s1", fieldKey: "password") }`)
	if err != nil {
		t.Fatal(err)
	}
	var errs []gqlErr
	if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
		t.Fatalf("errors = %s", resp.Errors)
	}
	if errs[0].Extensions.Code != "FAILED_PRECONDITION" || errs[0].Extensions.Reason != "STEP_UP_REQUIRED" {
		t.Fatalf("extensions = %+v", errs[0].Extensions)
	}
}

func TestCheckoutCarriesTheFullActor(t *testing.T) {
	at := time.Unix(1790000000, 0)
	wf := &recordingWorkflow{}
	var resp map[string]any
	c := stepUpClient(nil, wf, at)
	c.MustPost(`mutation { checkoutSecret(secretId: "s1") { id } }`, &resp)
	a := wf.actor
	if a.GetUserId() != "u-1" || !a.GetIsSiteAdmin() || a.GetIsRoot() || len(a.GetGroupNames()) != 1 || a.GetGroupNames()[0] != "ops" || a.GetMfaVerifiedAtUnix() != at.Unix() {
		t.Fatalf("check-out actor = %+v", a)
	}
	wf.actor = nil
	c.MustPost(`mutation { checkinSecret(secretId: "s1") }`, &resp)
	if wf.actor.GetMfaVerifiedAtUnix() != at.Unix() || !wf.actor.GetIsSiteAdmin() {
		t.Fatalf("check-in actor = %+v", wf.actor)
	}
}

func TestGroupRuleSendsTheGroupID(t *testing.T) {
	fv := &stepUpVault{}
	var resp struct {
		SetFolderRuleset struct {
			Rules []struct{ SubjectID *string }
		}
	}
	stepUpClient(fv, nil, time.Time{}).MustPost(`mutation { setFolderRuleset(folderId: "f1", owners: [], rules: [{subjectKind: group, subjectName: "Ops", subjectId: "g-1", grants: [{action: R, value: allow}]}]) { rules { subjectId } } }`, &resp)
	if got := fv.ruleset.GetRules()[0].GetSubjectId(); got != "g-1" {
		t.Fatalf("subject_id = %q", got)
	}
	if r := resp.SetFolderRuleset.Rules; len(r) != 1 || r[0].SubjectID == nil || *r[0].SubjectID != "g-1" {
		t.Fatalf("rules = %+v", r)
	}
}

func TestSetFolderRevealStepUp(t *testing.T) {
	for gql, want := range map[string]vaultv1.StepUpMode{
		"inherit": vaultv1.StepUpMode_STEP_UP_MODE_UNSPECIFIED,
		"require": vaultv1.StepUpMode_STEP_UP_MODE_REQUIRE,
		"off":     vaultv1.StepUpMode_STEP_UP_MODE_OFF,
	} {
		fv := &stepUpVault{}
		var resp struct {
			SetFolderRevealStepUp struct{ ID, RevealStepUp string }
		}
		stepUpClient(fv, nil, time.Time{}).MustPost(`mutation { setFolderRevealStepUp(folderId: "f1", mode: `+gql+`) { id revealStepUp } }`, &resp)
		if fv.stepUpReq.GetFolderId() != "f1" || fv.stepUpReq.GetMode() != want || fv.actor.GetUserId() != "u-1" {
			t.Fatalf("%s: request = %+v", gql, fv.stepUpReq)
		}
		if resp.SetFolderRevealStepUp.RevealStepUp != gql {
			t.Fatalf("%s: revealStepUp = %q", gql, resp.SetFolderRevealStepUp.RevealStepUp)
		}
	}
}

func TestFolderShowsItsRevealStepUp(t *testing.T) {
	var resp struct {
		Folders []struct{ RevealStepUp string }
	}
	stepUpClient(&stepUpVault{}, nil, time.Time{}).MustPost(`{ folders { revealStepUp } }`, &resp)
	if len(resp.Folders) != 1 || resp.Folders[0].RevealStepUp != "require" {
		t.Fatalf("folders = %+v", resp.Folders)
	}
}

func TestSecuritySettingsRequireMfaForReveal(t *testing.T) {
	fv := &stepUpVault{}
	var resp struct {
		UpdateSecuritySettings struct{ RequireMfaForReveal bool }
	}
	stepUpClient(fv, nil, time.Time{}).MustPost(`mutation { updateSecuritySettings(input: {requireMfaForReveal: true}) { requireMfaForReveal } }`, &resp)
	if fv.settingsReq.RequireMfaForReveal == nil || !*fv.settingsReq.RequireMfaForReveal || !resp.UpdateSecuritySettings.RequireMfaForReveal {
		t.Fatalf("request = %+v, resp = %+v", fv.settingsReq, resp)
	}
}
