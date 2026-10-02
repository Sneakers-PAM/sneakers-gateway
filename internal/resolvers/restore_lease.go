// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"fmt"

	workflowv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/workflow/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// refuseWhileCheckedOut refuses a restore while someone holds a lease on the
// secret, with the same CHECKOUT_LEASE_HELD refusal checkoutSecret gives. The
// vault can't see leases, and a restore would replace the value the holder is
// using. A failed lookup refuses too, so the restore never runs unchecked.
func (r *mutationResolver) refuseWhileCheckedOut(ctx context.Context, secretID string) error {
	resp, err := r.Workflow.GetActiveLease(ctx, &workflowv1.GetActiveLeaseRequest{SecretId: secretID})
	if err != nil {
		if _, ok := status.FromError(err); ok {
			return err
		}
		return status.Error(codes.Unavailable, fmt.Sprintf("checking the secret's lease: %v", err))
	}
	l := resp.GetLease()
	if l.GetId() == "" || l.GetReturned() {
		return nil
	}
	st, _ := status.New(codes.FailedPrecondition, "cannot restore a version while the secret is checked out").
		WithDetails(&errdetails.ErrorInfo{
			Domain:   "sneakers.workflow",
			Reason:   "CHECKOUT_LEASE_HELD",
			Metadata: map[string]string{"holder_user_id": l.GetUserId()},
		})
	return st.Err()
}
