// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package gqllog logs every GraphQL response that carries errors, so a failed
// call leaves a gateway log line and not only a vault one.
package gqllog

import (
	"context"
	"errors"
	"time"

	"github.com/99designs/gqlgen/graphql"
	log "github.com/Bugs5382/go-log"
	"github.com/rs/zerolog"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrorLog is a gqlgen extension. Logger, when set, supplies a zerolog logger
// per request; otherwise lines go to Log, trace-correlated through its Ctx
// method (nil discards them). Actor returns the caller's opaque id (a user or
// principal id, never a token).
type ErrorLog struct {
	Logger func(context.Context) zerolog.Logger
	Log    log.Logger
	Actor  func(context.Context) string
}

var (
	_ graphql.HandlerExtension    = ErrorLog{}
	_ graphql.ResponseInterceptor = ErrorLog{}
)

// clientCodes are the caller's own mistakes or refusals: worth a warning, not
// an alert.
var clientCodes = map[codes.Code]bool{
	codes.InvalidArgument: true, codes.NotFound: true, codes.AlreadyExists: true, codes.PermissionDenied: true,
	codes.FailedPrecondition: true, codes.ResourceExhausted: true, codes.Unauthenticated: true, codes.OutOfRange: true,
	codes.Canceled: true,
}

func (ErrorLog) ExtensionName() string                   { return "ErrorLog" }
func (ErrorLog) Validate(graphql.ExecutableSchema) error { return nil }

func (e ErrorLog) InterceptResponse(ctx context.Context, next graphql.ResponseHandler) *graphql.Response {
	start := time.Now()
	resp := next(ctx)
	if resp == nil || len(resp.Errors) == 0 {
		return resp
	}
	op := ""
	if graphql.HasOperationContext(ctx) {
		op = graphql.GetOperationContext(ctx).OperationName
	}
	actor := ""
	if e.Actor != nil {
		actor = e.Actor(ctx)
	}
	for _, ge := range resp.Errors {
		code, client := classify(ge)
		e.emit(ctx, client, op, ge.Path.String(), code, actor, time.Since(start))
	}
	return resp
}

// emit writes one error line. Both paths log the same fields, with the
// duration in milliseconds as zerolog's Dur renders it.
func (e ErrorLog) emit(ctx context.Context, client bool, op, path, code, actor string, d time.Duration) {
	if e.Logger != nil {
		l := e.Logger(ctx)
		ev := l.Error()
		if client {
			ev = l.Warn()
		}
		ev.Str("operation", op).Str("path", path).Str("code", code).Str("actor", actor).
			Dur("duration", d).Msg("graphql error")
		return
	}
	l := e.Log
	if l == nil {
		l = log.Nop()
	}
	l = l.Ctx(ctx)
	fields := []log.Field{log.F("operation", op), log.F("path", path), log.F("code", code), log.F("actor", actor),
		log.F("duration", float64(d)/float64(time.Millisecond))}
	if client {
		l.Warn("graphql error", fields...)
		return
	}
	l.Error(nil, "graphql error", fields...)
}

func classify(ge *gqlerror.Error) (string, bool) {
	if ge.Err == nil {
		if c, ok := ge.Extensions["code"].(string); ok {
			return c, true
		}
		return "GRAPHQL_ERROR", true
	}
	var gs interface{ GRPCStatus() *status.Status }
	if !errors.As(ge.Err, &gs) {
		return codes.Unknown.String(), false
	}
	c := gs.GRPCStatus().Code()
	return c.String(), clientCodes[c]
}
