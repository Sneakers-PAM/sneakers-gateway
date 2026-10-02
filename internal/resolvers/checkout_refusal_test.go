// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	workflowv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/workflow/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// refusingWorkflow refuses check-out and check-in with the error it's given.
type refusingWorkflow struct {
	workflowv1.WorkflowServiceClient
	err error
}

func (f *refusingWorkflow) CheckoutSecret(context.Context, *workflowv1.CheckoutSecretRequest, ...grpc.CallOption) (*workflowv1.CheckoutSecretResponse, error) {
	return nil, f.err
}

func (f *refusingWorkflow) CheckinSecret(context.Context, *workflowv1.CheckinSecretRequest, ...grpc.CallOption) (*workflowv1.CheckinSecretResponse, error) {
	return nil, f.err
}

func workflowRefusal(t *testing.T, c codes.Code, msg, reason string, md map[string]string) error {
	t.Helper()
	st, err := status.New(c, msg).WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.workflow", Reason: reason, Metadata: md})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

type gqlErr struct {
	Message    string `json:"message"`
	Extensions struct {
		Code     string            `json:"code"`
		Reason   string            `json:"reason"`
		Metadata map[string]string `json:"metadata"`
	} `json:"extensions"`
}

func postRefused(t *testing.T, wf workflowv1.WorkflowServiceClient, query string) gqlErr {
	t.Helper()
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Workflow: wf}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "u-1")))
	}))
	resp, err := c.RawPost(query)
	if err != nil {
		t.Fatal(err)
	}
	var errs []gqlErr
	if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
		t.Fatalf("errors = %s (%v)", resp.Errors, err)
	}
	return errs[0]
}

func TestCheckoutRefusalsReachTheClientWithTheirReason(t *testing.T) {
	cases := []struct {
		code   codes.Code
		reason string
		md     map[string]string
		want   string
	}{
		{codes.PermissionDenied, "CHECKOUT_NO_ACCESS", nil, "PERMISSION_DENIED"},
		{codes.FailedPrecondition, "CHECKOUT_TYPE_DISABLED", nil, "FAILED_PRECONDITION"},
		{codes.FailedPrecondition, "CHECKOUT_LEASE_HELD", map[string]string{"holder_user_id": "u-2"}, "FAILED_PRECONDITION"},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			wf := &refusingWorkflow{err: workflowRefusal(t, tc.code, "check-out refused", tc.reason, tc.md)}
			ge := postRefused(t, wf, `mutation { checkoutSecret(secretId: "s-1") { id } }`)
			if ge.Extensions.Code != tc.want || ge.Extensions.Reason != tc.reason {
				t.Fatalf("extensions = %+v", ge.Extensions)
			}
			if ge.Message != wf.err.Error() {
				t.Fatalf("message = %q, want %q", ge.Message, wf.err.Error())
			}
			if tc.md != nil && ge.Extensions.Metadata["holder_user_id"] != "u-2" {
				t.Fatalf("metadata = %v", ge.Extensions.Metadata)
			}
		})
	}
}

func TestCheckinRefusalReachesTheClientWithItsReason(t *testing.T) {
	wf := &refusingWorkflow{err: workflowRefusal(t, codes.PermissionDenied, "only the lease holder can check in", "CHECKIN_NOT_HOLDER", nil)}
	ge := postRefused(t, wf, `mutation { checkinSecret(secretId: "s-1") }`)
	if ge.Extensions.Code != "PERMISSION_DENIED" || ge.Extensions.Reason != "CHECKIN_NOT_HOLDER" {
		t.Fatalf("extensions = %+v", ge.Extensions)
	}
}
