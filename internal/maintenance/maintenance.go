// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package maintenance holds the gateway's read-only maintenance mode. While
// it's on, every GraphQL mutation is refused with the reason
// MAINTENANCE_READONLY, except the few that only read (reveals, a certificate
// export) or belong to signing in (a step-up code or passkey challenge) and
// the notification inbox, which isn't durable data. Queries and the /auth
// sign-in routes keep working.
//
// The mode is on when MAINTENANCE_READONLY is set, or while the appliance
// ConfigMap says maintenance is on (see internal/appliance).
package maintenance

import (
	"context"
	"slices"

	"github.com/99designs/gqlgen/graphql"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Reason is the stable reason a refused mutation carries in its GraphQL
// error's extensions, with Domain as its domain.
const (
	Reason = "MAINTENANCE_READONLY"
	Domain = "sneakers.gateway"
)

// message is the refusal every client sees.
const message = "Sneakers is in read-only maintenance: changes are refused until it ends; reads and sign-in still work"

// HumanAllowed are the /graphql mutations that stay open in maintenance.
var HumanAllowed = []string{
	"revealSecretField",
	"revealSecretVersionField",
	"exportCertificate",
	"sendMfaEmailCode",
	"beginMfaPasskey",
	"markNotificationRead",
	"markAllNotificationsRead",
}

// MachineAllowed are the /machine/graphql mutations that stay open in
// maintenance.
var MachineAllowed = []string{
	"revealSecretFieldForPrincipal",
}

// Source reports the maintenance state from outside the process, such as the
// appliance ConfigMap. reason may be empty.
type Source func() (on bool, reason string)

// Mode is the current maintenance state. A nil *Mode is always off.
type Mode struct {
	forced bool
	source Source
}

// New returns a Mode that is on when forced is true (MAINTENANCE_READONLY) or
// while source reports it on. source may be nil.
func New(forced bool, source Source) *Mode {
	return &Mode{forced: forced, source: source}
}

// State reports whether read-only maintenance is on, and why when it's known.
func (m *Mode) State() (readOnly bool, reason string) {
	if m == nil {
		return false, ""
	}
	if m.source != nil {
		if on, r := m.source(); on {
			return true, r
		}
	}
	return m.forced, ""
}

// Refusal is the error a refused mutation returns: FAILED_PRECONDITION with
// a google.rpc.ErrorInfo, so the error presenter adds the reason and domain.
func Refusal() error {
	st, err := status.New(codes.FailedPrecondition, message).WithDetails(&errdetails.ErrorInfo{Reason: Reason, Domain: Domain})
	if err != nil {
		return status.Error(codes.FailedPrecondition, message)
	}
	return st.Err()
}

// Guard is a gqlgen extension that refuses the top-level mutation fields not
// in Allowed while Mode is on.
type Guard struct {
	Mode    *Mode
	Allowed []string
}

var (
	_ graphql.HandlerExtension = Guard{}
	_ graphql.FieldInterceptor = Guard{}
)

func (Guard) ExtensionName() string                   { return "MaintenanceGuard" }
func (Guard) Validate(graphql.ExecutableSchema) error { return nil }

func (g Guard) InterceptField(ctx context.Context, next graphql.Resolver) (any, error) {
	fc := graphql.GetFieldContext(ctx)
	if fc == nil || fc.Object != "Mutation" || fc.Field.Field == nil {
		return next(ctx)
	}
	if on, _ := g.Mode.State(); !on || slices.Contains(g.Allowed, fc.Field.Name) {
		return next(ctx)
	}
	return nil, Refusal()
}
