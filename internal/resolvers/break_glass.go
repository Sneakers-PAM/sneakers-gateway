// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errBreakGlassCodeInvalid refuses a break glass whose MFA code is wrong,
// missing or expired. Identity can't tell those apart (VerifyTotp answers
// ok=false for all of them), so neither does the reason.
func errBreakGlassCodeInvalid() error {
	st, _ := status.New(codes.Unauthenticated, "invalid or missing MFA code").
		WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.gateway", Reason: "BREAK_GLASS_CODE_INVALID"})
	return st.Err()
}
