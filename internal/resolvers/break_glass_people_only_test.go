// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
)

func newPeopleOnlyClient(id *btgIdentity, v *btgVault, a *tofuAudit, caller btgCaller) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: id, Vault: v, Audit: a}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(caller(r.Context())))
	}))
}

func btgWebUser(ctx context.Context) context.Context {
	return WithSessionRef(WithActorInfo(WithActor(ctx, "u-bob"), false, false, nil), "ref-web-2")
}

// A plain break-glass reveal (no browse session) is for a person in their
// own signed-in web session too: an agent's personal token, a service
// account or a caller with no web session is refused before the code check,
// and the refusal is audited.
func TestPlainBreakGlassSecretIsRefusedToAgentsAndTokens(t *testing.T) {
	callers := map[string]struct {
		caller btgCaller
		actor  string
		kind   string
	}{
		"personal token": {func(ctx context.Context) context.Context {
			return WithUserTokenActor(WithActorInfo(WithActor(ctx, "u-admin"), true, false, nil), "u-admin", "tok-1", nil)
		}, "u-admin", "user_token"},
		"service account": {func(ctx context.Context) context.Context {
			return WithMachineActor(ctx, "sa-1", nil)
		}, "sa-1", "service_account"},
		"no web session": {func(ctx context.Context) context.Context {
			return WithActorInfo(WithActor(ctx, "u-admin"), true, false, nil)
		}, "u-admin", "no_web_session"},
	}
	for name, tc := range callers {
		t.Run(name, func(t *testing.T) {
			id, v, a := &btgIdentity{}, &btgVault{}, &tofuAudit{}
			errs := btgErrors(t, newPeopleOnlyClient(id, v, a, tc.caller),
				`mutation { breakGlassSecret(secretId: "s-1", reason: "outage", code: "123456") { key } }`)
			if len(errs) != 1 || errs[0].Extensions.Code != "PERMISSION_DENIED" || errs[0].Extensions.Reason != "BREAK_GLASS_WEB_ONLY" {
				t.Fatalf("errors = %+v", errs)
			}
			if !strings.Contains(errs[0].Message, "agents and tokens can't use it") {
				t.Fatalf("message = %q", errs[0].Message)
			}
			if v.reveal != nil || id.calls != 0 {
				t.Fatal("a refused caller must reach neither identity nor the vault")
			}
			wantBreakGlassDenied(t, a, tc.actor, tc.kind)
		})
	}
}

func wantBreakGlassDenied(t *testing.T, a *tofuAudit, actor, kind string) {
	t.Helper()
	if len(a.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(a.events))
	}
	ev := a.events[0]
	if ev.GetAction() != "break_glass.denied" || ev.GetActorUserId() != actor || ev.GetSubject() != "s-1" {
		t.Fatalf("audit event = %+v", ev)
	}
	attrs := ev.GetAttributes()
	if attrs["method"] != "breakGlassSecret" || attrs["reason"] != "BREAK_GLASS_WEB_ONLY" || attrs["caller"] != kind {
		t.Fatalf("audit attributes = %v", attrs)
	}
}

// Opening a browse session is refused to the same callers, and audited.
func TestOpenBreakGlassSessionRefusalIsAudited(t *testing.T) {
	id, v, a := &btgIdentity{}, &btgVault{}, &tofuAudit{}
	tokenCaller := func(ctx context.Context) context.Context {
		return WithUserTokenActor(WithActorInfo(WithActor(ctx, "u-admin"), true, false, nil), "u-admin", "tok-1", nil)
	}
	errs := btgErrors(t, newPeopleOnlyClient(id, v, a, tokenCaller), btgOpen)
	if len(errs) != 1 || errs[0].Extensions.Reason != "BREAK_GLASS_WEB_ONLY" || v.open != nil {
		t.Fatalf("errors = %+v", errs)
	}
	if len(a.events) != 1 || a.events[0].GetAction() != "break_glass.denied" ||
		a.events[0].GetAttributes()["method"] != "openBreakGlassSession" {
		t.Fatalf("audit events = %+v", a.events)
	}
}

// A person in their own web session may still break glass on a secret they
// can read without being a site admin; the vault gets the session reference.
func TestPlainBreakGlassSecretCarriesTheWebSession(t *testing.T) {
	id, v, a := &btgIdentity{}, &btgVault{}, &tofuAudit{}
	var resp struct {
		BreakGlassSecret []struct{ Key, Value string }
	}
	newPeopleOnlyClient(id, v, a, btgWebUser).MustPost(
		`mutation { breakGlassSecret(secretId: "s-1", reason: "outage", code: "123456") { key value } }`, &resp)
	got := v.reveal.GetActor()
	if got.GetUserId() != "u-bob" || got.GetSessionRef() != "ref-web-2" {
		t.Fatalf("vault actor = %+v", got)
	}
	if len(a.events) != 0 {
		t.Fatalf("an allowed reveal records no gateway refusal: %+v", a.events)
	}
}
