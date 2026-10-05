// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package gqlerr presents backend refusals to GraphQL clients with stable
// codes. A gRPC status from a backend keeps its message (clients already read
// "rpc error: code = <Code> desc = <text>") and gains extensions: code, the
// canonical gRPC code name (FAILED_PRECONDITION), and, when a Sneakers service
// attached a google.rpc.ErrorInfo, reason (its stable reason, such as
// CHECKOUT_LEASE_HELD), its domain (sneakers.workflow) and metadata. Every
// error, coded or not, also carries traceId, the request's trace id, so a
// copied diagnostic can be matched to the logs.
package gqlerr

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/99designs/gqlgen/graphql"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sneakersDomain prefixes the ErrorInfo domains whose reasons reach the client
// (sneakers.vault, sneakers.workflow and so on). Details from anything else
// stay server-side.
const sneakersDomain = "sneakers."

// Present is a gqlgen error presenter.
func Present(ctx context.Context, err error) *gqlerror.Error {
	ge := graphql.DefaultErrorPresenter(ctx, err)
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		if ge.Extensions == nil {
			ge.Extensions = map[string]any{}
		}
		ge.Extensions["traceId"] = sc.TraceID().String()
	}
	var gs interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &gs) {
		return ge
	}
	st := gs.GRPCStatus()
	if ge.Extensions == nil {
		ge.Extensions = map[string]any{}
	}
	ge.Extensions["code"] = codeName(st.Code())
	for _, d := range st.Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok || !strings.HasPrefix(info.GetDomain(), sneakersDomain) || info.GetReason() == "" {
			continue
		}
		ge.Extensions["reason"] = info.GetReason()
		ge.Extensions["domain"] = info.GetDomain()
		if len(info.GetMetadata()) > 0 {
			ge.Extensions["metadata"] = info.GetMetadata()
		}
		break
	}
	return ge
}

// codeName turns a gRPC code's Go name (FailedPrecondition) into its canonical
// google.rpc.Code name (FAILED_PRECONDITION).
func codeName(c codes.Code) string {
	name := c.String()
	var b strings.Builder
	for i, r := range name {
		if i > 0 && unicode.IsUpper(r) && !unicode.IsUpper(rune(name[i-1])) {
			b.WriteByte('_')
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}
