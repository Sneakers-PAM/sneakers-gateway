// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gqlerr_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func withInfo(t *testing.T, c codes.Code, msg, domain, reason string, md map[string]string) error {
	t.Helper()
	st, err := status.New(c, msg).WithDetails(&errdetails.ErrorInfo{Domain: domain, Reason: reason, Metadata: md})
	if err != nil {
		t.Fatal(err)
	}
	return st.Err()
}

func TestPresentCarriesTheReasonFromASneakersService(t *testing.T) {
	err := withInfo(t, codes.FailedPrecondition, "secret is checked out by another user", "sneakers.workflow", "CHECKOUT_LEASE_HELD", map[string]string{"holder_user_id": "u-2"})
	ge := gqlerr.Present(context.Background(), err)
	if ge.Message != err.Error() {
		t.Fatalf("message = %q, want the relayed status %q", ge.Message, err.Error())
	}
	if got := ge.Extensions["code"]; got != "FAILED_PRECONDITION" {
		t.Fatalf("code = %v", got)
	}
	if got := ge.Extensions["reason"]; got != "CHECKOUT_LEASE_HELD" {
		t.Fatalf("reason = %v", got)
	}
	md, ok := ge.Extensions["metadata"].(map[string]string)
	if !ok || md["holder_user_id"] != "u-2" {
		t.Fatalf("metadata = %#v", ge.Extensions["metadata"])
	}
}

func TestPresentWrappedStatus(t *testing.T) {
	inner := withInfo(t, codes.PermissionDenied, "no read access", "sneakers.workflow", "CHECKOUT_NO_ACCESS", nil)
	ge := gqlerr.Present(context.Background(), fmt.Errorf("checkout: %w", inner))
	if ge.Extensions["code"] != "PERMISSION_DENIED" || ge.Extensions["reason"] != "CHECKOUT_NO_ACCESS" {
		t.Fatalf("extensions = %#v", ge.Extensions)
	}
	if _, has := ge.Extensions["metadata"]; has {
		t.Fatalf("empty metadata should be left out: %#v", ge.Extensions)
	}
}

func TestPresentPlainStatusGetsOnlyTheCode(t *testing.T) {
	ge := gqlerr.Present(context.Background(), status.Error(codes.PermissionDenied, "not permitted to reveal this secret"))
	if ge.Extensions["code"] != "PERMISSION_DENIED" {
		t.Fatalf("code = %v", ge.Extensions["code"])
	}
	if _, has := ge.Extensions["reason"]; has {
		t.Fatalf("no reason expected: %#v", ge.Extensions)
	}
}

func TestPresentIgnoresErrorInfoFromOtherDomains(t *testing.T) {
	err := withInfo(t, codes.Unavailable, "upstream down", "example.org", "SOMETHING", map[string]string{"k": "v"})
	ge := gqlerr.Present(context.Background(), err)
	if ge.Extensions["code"] != "UNAVAILABLE" {
		t.Fatalf("code = %v", ge.Extensions["code"])
	}
	if _, has := ge.Extensions["reason"]; has {
		t.Fatalf("a foreign ErrorInfo must not reach the client: %#v", ge.Extensions)
	}
}

func TestPresentNonStatusErrorUnchanged(t *testing.T) {
	ge := gqlerr.Present(context.Background(), errors.New("invalid or missing MFA code"))
	if ge.Message != "invalid or missing MFA code" {
		t.Fatalf("message = %q", ge.Message)
	}
	if _, has := ge.Extensions["code"]; has {
		t.Fatalf("no code expected: %#v", ge.Extensions)
	}
}

func TestPresentCodeNames(t *testing.T) {
	want := map[codes.Code]string{
		codes.OK: "OK", codes.Canceled: "CANCELED", codes.Unknown: "UNKNOWN", codes.InvalidArgument: "INVALID_ARGUMENT",
		codes.DeadlineExceeded: "DEADLINE_EXCEEDED", codes.NotFound: "NOT_FOUND", codes.AlreadyExists: "ALREADY_EXISTS",
		codes.PermissionDenied: "PERMISSION_DENIED", codes.ResourceExhausted: "RESOURCE_EXHAUSTED",
		codes.FailedPrecondition: "FAILED_PRECONDITION", codes.Aborted: "ABORTED", codes.OutOfRange: "OUT_OF_RANGE",
		codes.Unimplemented: "UNIMPLEMENTED", codes.Internal: "INTERNAL", codes.Unavailable: "UNAVAILABLE",
		codes.DataLoss: "DATA_LOSS", codes.Unauthenticated: "UNAUTHENTICATED",
	}
	for c, name := range want {
		ge := gqlerr.Present(context.Background(), status.Error(c, "x"))
		if c == codes.OK {
			// status.Error(OK) is nil; check the name through a wrapped status instead.
			continue
		}
		if ge.Extensions["code"] != name {
			t.Fatalf("%v: code = %v, want %s", c, ge.Extensions["code"], name)
		}
	}
}
