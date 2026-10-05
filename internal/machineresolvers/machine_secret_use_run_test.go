// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type runVault struct {
	vaultv1.VaultServiceClient
	lastPrepare *vaultv1.PrepareSecretUseRequest
	prepareErr  error
	lastList    *vaultv1.ListPendingSecretUsesRequest
}

func (f *runVault) PrepareSecretUse(_ context.Context, in *vaultv1.PrepareSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.PrepareSecretUseResponse, error) {
	f.lastPrepare = in
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	u := proto.Clone(preparedUse).(*vaultv1.SecretUse)
	u.RunId, u.Purpose = in.GetRunId(), in.GetPurpose()
	return &vaultv1.PrepareSecretUseResponse{Use: u}, nil
}

func (f *runVault) ListPendingSecretUses(_ context.Context, in *vaultv1.ListPendingSecretUsesRequest, _ ...grpc.CallOption) (*vaultv1.ListPendingSecretUsesResponse, error) {
	f.lastList = in
	u := proto.Clone(preparedUse).(*vaultv1.SecretUse)
	u.RunId = in.GetRunId()
	return &vaultv1.ListPendingSecretUsesResponse{Uses: []*vaultv1.SecretUse{u}}, nil
}

func newRunClient(fv *runVault, runLinks bool) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, PublicURL: "https://sneakers.example.org/", ApprovalRunLinks: runLinks}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)))
	}))
}

type preparedRun struct {
	PrepareSecretUse struct{ ID, RunID, ApprovalURL string }
}

const prepareInRun = `mutation { prepareSecretUse(secretId:"s1", fieldKey:"password", argv:["ssh","admin@router-01"], runId:"run_a", purpose:"rotate the router") { id runId approvalUrl } }`

func TestPrepareSecretUsePassesTheRunAndPurposeToVault(t *testing.T) {
	fv := &runVault{}
	var resp preparedRun
	newRunClient(fv, false).MustPost(prepareInRun, &resp)
	if fv.lastPrepare.GetRunId() != "run_a" || fv.lastPrepare.GetPurpose() != "rotate the router" {
		t.Fatalf("prepare request = %+v", fv.lastPrepare)
	}
	if resp.PrepareSecretUse.RunID != "run_a" {
		t.Fatalf("use = %+v", resp.PrepareSecretUse)
	}
}

func TestApprovalURLOpensTheRunPageOnlyWithTheFlag(t *testing.T) {
	cases := []struct {
		name     string
		runLinks bool
		query    string
		want     string
	}{
		{"flag off", false, prepareInRun, "https://sneakers.example.org/approvals"},
		{"flag on", true, prepareInRun, "https://sneakers.example.org/approvals/run/run_a"},
		{"flag on, no run", true, `mutation { prepareSecretUse(secretId:"s1", fieldKey:"password", argv:["ssh","admin@router-01"]) { id runId approvalUrl } }`, "https://sneakers.example.org/approvals"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp preparedRun
			newRunClient(&runVault{}, tc.runLinks).MustPost(tc.query, &resp)
			if resp.PrepareSecretUse.ApprovalURL != tc.want {
				t.Fatalf("approvalUrl = %q, want %q", resp.PrepareSecretUse.ApprovalURL, tc.want)
			}
		})
	}
}

func TestPrepareSecretUseGivesAnInvalidRequestAStableReason(t *testing.T) {
	fv := &runVault{prepareErr: status.Error(codes.InvalidArgument, "purpose must be plain text of at most 200 characters")}
	resp, err := newRunClient(fv, false).RawPost(prepareInRun)
	if err != nil {
		t.Fatal(err)
	}
	var errs []struct {
		Message    string
		Extensions struct{ Code, Reason, Domain string }
	}
	if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
		t.Fatalf("errors = %s (%v)", resp.Errors, err)
	}
	e := errs[0]
	if e.Extensions.Code != "INVALID_ARGUMENT" || e.Extensions.Reason != "SECRET_USE_REQUEST_INVALID" || e.Extensions.Domain != "sneakers.gateway" {
		t.Fatalf("extensions = %+v", e.Extensions)
	}
	if e.Message != fv.prepareErr.Error() {
		t.Fatalf("message = %q, want vault's %q", e.Message, fv.prepareErr.Error())
	}
}

func TestPrepareSecretUsePassesOtherRefusalsThroughUnchanged(t *testing.T) {
	fv := &runVault{prepareErr: status.Error(codes.PermissionDenied, "not permitted to use this secret")}
	resp, err := newRunClient(fv, false).RawPost(prepareInRun)
	if err != nil {
		t.Fatal(err)
	}
	var errs []struct {
		Extensions struct{ Code, Reason string }
	}
	if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 || errs[0].Extensions.Code != "PERMISSION_DENIED" || errs[0].Extensions.Reason != "" {
		t.Fatalf("errors = %s (%v)", resp.Errors, err)
	}
}

func TestSecretUseRunListsTheTokensPendingUsesOfTheRun(t *testing.T) {
	fv := &runVault{}
	var resp struct {
		SecretUseRun []struct{ ID, RunID, ApprovalURL string }
	}
	newRunClient(fv, true).MustPost(`query { secretUseRun(runId:"run_a") { id runId approvalUrl } }`, &resp)
	a := fv.lastList.GetActor()
	if fv.lastList.GetRunId() != "run_a" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_USER_TOKEN || a.GetTokenId() != "utok-1" {
		t.Fatalf("list request = %+v", fv.lastList)
	}
	if len(resp.SecretUseRun) != 1 || resp.SecretUseRun[0].RunID != "run_a" || resp.SecretUseRun[0].ApprovalURL != "https://sneakers.example.org/approvals/run/run_a" {
		t.Fatalf("run = %+v", resp.SecretUseRun)
	}
}
