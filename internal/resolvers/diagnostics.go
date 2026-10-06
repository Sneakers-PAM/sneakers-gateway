// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"strings"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// diagnostics answers the diagnostics query: the caller as identity knows
// them (id, username and roles only) plus the collector's cached report.
func (r *Resolver) diagnostics(ctx context.Context) (*Diagnostics, error) {
	actorID := actorFrom(ctx)
	if actorID == "" {
		return nil, status.Error(codes.Unauthenticated, "sign in to read diagnostics")
	}
	actor := &DiagnosticsActor{ID: actorID, Roles: []string{}}
	if r.Identity != nil {
		if resp, err := r.Identity.GetUser(ctx, &identityv1.GetUserRequest{Id: actorID}); err == nil {
			actor.Username = resp.GetUser().GetUsername()
			if roles := resp.GetUser().GetRoles(); roles != nil {
				actor.Roles = roles
			}
		}
	}
	var rep diag.Report
	if r.Diag != nil {
		rep = r.Diag.Report(ctx)
	} else {
		rep = diag.Report{GeneratedAt: time.Now().UTC(), Gateway: diag.Component{Name: "gateway", Version: diag.Unknown, Status: diag.StatusOK}}
	}
	out := &Diagnostics{
		GeneratedAt: rep.GeneratedAt.Format(time.RFC3339),
		TraceID:     traceID(ctx),
		Actor:       actor,
		PublicURL:   rep.PublicURL,
		Gateway:     componentOf(rep.Gateway),
		Services:    componentsOf(rep.Services),
		ThirdParty:  componentsOf(rep.ThirdParty),
	}
	if rep.Appliance != "" {
		out.Appliance = &rep.Appliance
	}
	return out, nil
}

func componentsOf(cs []diag.Component) []*ComponentVersion {
	out := make([]*ComponentVersion, 0, len(cs))
	for _, c := range cs {
		out = append(out, componentOf(c))
	}
	return out
}

func componentOf(c diag.Component) *ComponentVersion {
	v := &ComponentVersion{Name: c.Name, Status: ComponentStatus(c.Status), Dependencies: dependenciesOf(c.Dependencies)}
	if c.Version != "" {
		v.Version = &c.Version
	}
	if c.Commit != "" {
		v.Commit = &c.Commit
	}
	if c.LastContactAt != "" {
		v.LastContactAt = &c.LastContactAt
	}
	return v
}

// dependenciesOf keeps nil as null: a component that reported no readiness
// shows no dependency list, not an empty one.
func dependenciesOf(ds []diag.Dependency) []*DependencyState {
	if ds == nil {
		return nil
	}
	out := make([]*DependencyState, 0, len(ds))
	for _, d := range ds {
		s := &DependencyState{Name: d.Name, State: DependencyHealth(strings.ToUpper(d.State)), Required: d.Required}
		if d.Error != "" {
			s.Error = &d.Error
		}
		if d.Version != "" {
			s.Version = &d.Version
		}
		out = append(out, s)
	}
	return out
}

func traceID(ctx context.Context) string {
	if sc := trace.SpanContextFromContext(ctx); sc.HasTraceID() {
		return sc.TraceID().String()
	}
	return ""
}
