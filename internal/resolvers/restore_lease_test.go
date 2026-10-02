// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

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

// leaseWorkflow answers GetActiveLease with lease (nil means none) or err.
type leaseWorkflow struct {
	workflowv1.WorkflowServiceClient
	lease *workflowv1.Lease
	err   error
	asked string
}

func (f *leaseWorkflow) GetActiveLease(_ context.Context, in *workflowv1.GetActiveLeaseRequest, _ ...grpc.CallOption) (*workflowv1.GetActiveLeaseResponse, error) {
	f.asked = in.GetSecretId()
	if f.err != nil {
		return nil, f.err
	}
	return &workflowv1.GetActiveLeaseResponse{Lease: f.lease}, nil
}

func restoreClient(fv vaultv1.VaultServiceClient, wf workflowv1.WorkflowServiceClient) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Workflow: wf}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActorRecovery(WithActorInfo(WithActor(r.Context(), "u-1"), false, false, nil), true)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

const restoreMutation = `mutation { restoreSecretVersion(secretId: "s1", versionNo: 3) { id } }`

func restoreErrors(t *testing.T, c *gqlclient.Client) []gqlErr {
	t.Helper()
	resp, err := c.RawPost(restoreMutation)
	if err != nil {
		t.Fatal(err)
	}
	var errs []gqlErr
	if len(resp.Errors) > 0 {
		if err := json.Unmarshal(resp.Errors, &errs); err != nil {
			t.Fatal(err)
		}
	}
	return errs
}

// The vault can't see leases, so the gateway refuses a restore while someone
// holds one, the same way checkoutSecret refuses, and never calls the vault.
func TestRestoreRefusedWhileCheckedOut(t *testing.T) {
	fv := &recoveryVault{}
	wf := &leaseWorkflow{lease: &workflowv1.Lease{Id: "l-1", SecretId: "s1", UserId: "u-2"}}
	errs := restoreErrors(t, restoreClient(fv, wf))
	if len(errs) != 1 {
		t.Fatalf("errors = %+v", errs)
	}
	e := errs[0].Extensions
	if e.Code != "FAILED_PRECONDITION" || e.Reason != "CHECKOUT_LEASE_HELD" || e.Metadata["holder_user_id"] != "u-2" {
		t.Fatalf("extensions = %+v", e)
	}
	if wf.asked != "s1" || fv.restoreReq != nil {
		t.Fatalf("asked %q, vault request %+v", wf.asked, fv.restoreReq)
	}
}

func TestRestoreRunsWithoutALease(t *testing.T) {
	fv := &recoveryVault{}
	if errs := restoreErrors(t, restoreClient(fv, &leaseWorkflow{})); len(errs) != 0 {
		t.Fatalf("errors = %+v", errs)
	}
	if fv.restoreReq.GetSecretId() != "s1" {
		t.Fatalf("vault request = %+v", fv.restoreReq)
	}
}

// A returned lease no longer holds the secret.
func TestRestoreIgnoresAReturnedLease(t *testing.T) {
	fv := &recoveryVault{}
	wf := &leaseWorkflow{lease: &workflowv1.Lease{Id: "l-1", UserId: "u-2", Returned: true}}
	if errs := restoreErrors(t, restoreClient(fv, wf)); len(errs) != 0 {
		t.Fatalf("errors = %+v", errs)
	}
}

// If the lease can't be checked, the restore doesn't run unchecked.
func TestRestoreRefusedWhenTheLeaseCheckFails(t *testing.T) {
	fv := &recoveryVault{}
	errs := restoreErrors(t, restoreClient(fv, &leaseWorkflow{err: status.Error(codes.Unavailable, "workflow down")}))
	if len(errs) != 1 || errs[0].Extensions.Code != "UNAVAILABLE" || fv.restoreReq != nil {
		t.Fatalf("errors = %+v, vault request = %+v", errs, fv.restoreReq)
	}
	errs = restoreErrors(t, restoreClient(fv, &leaseWorkflow{err: errors.New("broken")}))
	if len(errs) != 1 || fv.restoreReq != nil {
		t.Fatalf("errors = %+v, vault request = %+v", errs, fv.restoreReq)
	}
}

func TestRestoreRotationRefusalReachesTheClient(t *testing.T) {
	st, err := status.New(codes.FailedPrecondition, "the secret is rotating").WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: "ROTATION_IN_PROGRESS"})
	if err != nil {
		t.Fatal(err)
	}
	errs := restoreErrors(t, restoreClient(&recoveryVault{err: st.Err()}, &leaseWorkflow{}))
	if len(errs) != 1 || errs[0].Extensions.Code != "FAILED_PRECONDITION" || errs[0].Extensions.Reason != "ROTATION_IN_PROGRESS" {
		t.Fatalf("errors = %+v", errs)
	}
}

type rotateVault struct {
	vaultv1.VaultServiceClient
	enqueued *vaultv1.EnqueueRotationRequest
}

func (f *rotateVault) EnqueueRotation(_ context.Context, in *vaultv1.EnqueueRotationRequest, _ ...grpc.CallOption) (*vaultv1.EnqueueRotationResponse, error) {
	f.enqueued = in
	return &vaultv1.EnqueueRotationResponse{}, nil
}

func rotateErrors(t *testing.T, fv vaultv1.VaultServiceClient, wf workflowv1.WorkflowServiceClient) []gqlErr {
	t.Helper()
	resp, err := restoreClient(fv, wf).RawPost(`mutation { rotateSecret(secretId: "s1") }`)
	if err != nil {
		t.Fatal(err)
	}
	var errs []gqlErr
	if len(resp.Errors) > 0 {
		if err := json.Unmarshal(resp.Errors, &errs); err != nil {
			t.Fatal(err)
		}
	}
	return errs
}

func TestRotateRefusedWhileCheckedOut(t *testing.T) {
	fv := &rotateVault{}
	errs := rotateErrors(t, fv, &leaseWorkflow{lease: &workflowv1.Lease{Id: "l-1", UserId: "u-2"}})
	if len(errs) != 1 || errs[0].Extensions.Reason != "CHECKOUT_LEASE_HELD" || errs[0].Extensions.Metadata["holder_user_id"] != "u-2" || fv.enqueued != nil {
		t.Fatalf("errors = %+v, enqueued = %+v", errs, fv.enqueued)
	}
}

// A manual rotation doesn't run when the lease can't be checked: it would
// invalidate a holder's credential.
func TestRotateRefusedWhenTheLeaseCheckFails(t *testing.T) {
	fv := &rotateVault{}
	errs := rotateErrors(t, fv, &leaseWorkflow{err: status.Error(codes.Unavailable, "workflow down")})
	if len(errs) != 1 || errs[0].Extensions.Code != "UNAVAILABLE" || fv.enqueued != nil {
		t.Fatalf("errors = %+v, enqueued = %+v", errs, fv.enqueued)
	}
}

func TestRotateRunsWithoutALease(t *testing.T) {
	fv := &rotateVault{}
	if errs := rotateErrors(t, fv, &leaseWorkflow{}); len(errs) != 0 {
		t.Fatalf("errors = %+v", errs)
	}
	if fv.enqueued.GetSecretId() != "s1" || fv.enqueued.GetReason() != "manual" {
		t.Fatalf("enqueued = %+v", fv.enqueued)
	}
}
