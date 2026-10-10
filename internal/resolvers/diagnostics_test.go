// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/diag"
	"google.golang.org/grpc"
)

type diagIdentity struct {
	identityv1.IdentityServiceClient
	asked string
}

func (f *diagIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	f.asked = in.GetId()
	return &identityv1.GetUserResponse{User: &identityv1.User{
		Id: in.GetId(), Username: "morgan", Email: "morgan@example.org", Name: "Morgan Example", Roles: []string{"user", "site-admin"},
	}}, nil
}

func newDiagClient(fi identityv1.IdentityServiceClient, c *diag.Collector, actor string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: fi, Diag: c}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	}))
}

const diagQuery = `{ diagnostics { generatedAt traceId publicUrl appliance
  actor { id username roles }
  gateway { name version commit status }
  services { name version commit status }
  thirdParty { name version commit status } } }`

func TestDiagnostics_ReportsTheCallerAndComponents(t *testing.T) {
	fi := &diagIdentity{}
	c := &diag.Collector{
		Gateway:   diag.Component{Name: "gateway", Version: "v0.1.0", Commit: "abc", Status: diag.StatusOK},
		PublicURL: "https://pam.example.org/",
		Services: []diag.Probe{
			func(context.Context) diag.Component {
				return diag.Component{Name: "vault", Version: "v0.1.0", Commit: "def", Status: diag.StatusOK}
			},
			diag.NotConfigured("connector"),
		},
	}
	var resp struct {
		Diagnostics struct {
			GeneratedAt, TraceID string
			PublicURL            string
			Appliance            *string
			Actor                struct {
				ID, Username string
				Roles        []string
			}
			Gateway  struct{ Name, Version, Commit, Status string }
			Services []struct {
				Name            string
				Version, Commit *string
				Status          string
			}
			ThirdParty []struct {
				Name            string
				Version, Commit *string
				Status          string
			}
		}
	}
	newDiagClient(fi, c, "u-morgan").MustPost(diagQuery, &resp)
	d := resp.Diagnostics
	if fi.asked != "u-morgan" || d.Actor.ID != "u-morgan" || d.Actor.Username != "morgan" || strings.Join(d.Actor.Roles, ",") != "user,site-admin" {
		t.Fatalf("actor = %+v (identity asked for %q)", d.Actor, fi.asked)
	}
	if d.PublicURL != "https://pam.example.org" || d.Appliance != nil {
		t.Fatalf("publicUrl/appliance = %q/%v", d.PublicURL, d.Appliance)
	}
	if d.Gateway.Version != "v0.1.0" || d.Gateway.Status != "OK" {
		t.Fatalf("gateway = %+v", d.Gateway)
	}
	if len(d.Services) != 2 || d.Services[1].Status != "NOT_CONFIGURED" || d.Services[1].Version != nil {
		t.Fatalf("services = %+v", d.Services)
	}
}

func TestDiagnostics_NeverCarriesTheCallersOtherDetails(t *testing.T) {
	var raw map[string]any
	c := &diag.Collector{Gateway: diag.Component{Name: "gateway", Status: diag.StatusOK}}
	newDiagClient(&diagIdentity{}, c, "u-morgan").MustPost(diagQuery, &raw)
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ToLower(string(b))
	for _, bad := range []string{"morgan@example.org", "morgan example"} {
		if strings.Contains(body, bad) {
			t.Fatalf("diagnostics carry %q: %s", bad, body)
		}
	}
}

func TestDiagnostics_RefusedWithoutAnActor(t *testing.T) {
	var resp map[string]any
	err := newDiagClient(&diagIdentity{}, &diag.Collector{}, "").Post(diagQuery, &resp)
	if err == nil || !strings.Contains(err.Error(), "Unauthenticated") {
		t.Fatalf("err = %v, want an Unauthenticated refusal", err)
	}
}

func TestDiagnostics_CarriesDependencyStates(t *testing.T) {
	c := &diag.Collector{
		Gateway: diag.Component{Name: "gateway", Status: diag.StatusOK},
		GatewayDependencies: func(context.Context) []diag.Dependency {
			return []diag.Dependency{{Name: "valkey", State: diag.DepDown, Required: true, Error: "refused"}}
		},
		Services: []diag.Probe{
			func(context.Context) diag.Component {
				return diag.Component{Name: "vault", Status: diag.StatusOK, Dependencies: []diag.Dependency{
					{Name: "postgres", State: diag.DepOK, Required: true, Version: "17.11"},
					{Name: "audit", State: diag.DepDegraded, Error: "unavailable"},
				}}
			},
			diag.NotConfigured("connector"),
		},
	}
	type dep struct {
		Name, State    string
		Required       bool
		Error, Version *string
	}
	var resp struct {
		Diagnostics struct {
			Gateway  struct{ Dependencies []dep }
			Services []struct{ Dependencies []dep }
		}
	}
	newDiagClient(&diagIdentity{}, c, "u-morgan").MustPost(`{ diagnostics {
  gateway { dependencies { name state required error version } }
  services { dependencies { name state required error version } } } }`, &resp)
	d := resp.Diagnostics
	if len(d.Gateway.Dependencies) != 1 || d.Gateway.Dependencies[0].State != "DOWN" || *d.Gateway.Dependencies[0].Error != "refused" {
		t.Fatalf("gateway dependencies = %+v", d.Gateway.Dependencies)
	}
	v := d.Services[0].Dependencies
	if len(v) != 2 || v[0].State != "OK" || v[0].Error != nil || *v[0].Version != "17.11" || v[1].State != "DEGRADED" || v[1].Required {
		t.Fatalf("vault dependencies = %+v", v)
	}
	if d.Services[1].Dependencies != nil {
		t.Fatalf("connector dependencies = %+v, want null", d.Services[1].Dependencies)
	}
}

type diagIdentityUser struct {
	identityv1.IdentityServiceClient
	user *identityv1.User
}

func (f *diagIdentityUser) GetUser(_ context.Context, _ *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	return &identityv1.GetUserResponse{User: f.user}, nil
}

func diagActorUsername(t *testing.T, user *identityv1.User) string {
	t.Helper()
	c := &diag.Collector{Gateway: diag.Component{Name: "gateway", Status: diag.StatusOK}}
	var resp struct {
		Diagnostics struct {
			Actor struct{ Username string }
		}
	}
	newDiagClient(&diagIdentityUser{user: user}, c, "u-morgan").MustPost(`{ diagnostics { actor { username } } }`, &resp)
	return resp.Diagnostics.Actor.Username
}

func TestDiagnostics_ActorUsernameFallsBackToNameWhenUsernameIsEmpty(t *testing.T) {
	got := diagActorUsername(t, &identityv1.User{Id: "u-morgan", Name: "Morgan Example"})
	if got != "Morgan Example" {
		t.Fatalf("username = %q, want the display name", got)
	}
}

func TestDiagnostics_ActorUsernameFallsBackToIDWhenUsernameAndNameAreEmpty(t *testing.T) {
	got := diagActorUsername(t, &identityv1.User{Id: "u-morgan"})
	if got != "u-morgan" {
		t.Fatalf("username = %q, want the account id", got)
	}
}

func TestDiagnostics_CarriesTheProductAndTheBox(t *testing.T) {
	c := &diag.Collector{
		Gateway:        diag.Component{Name: "gateway", Status: diag.StatusOK},
		ProductVersion: "0.1.0",
		Appliance:      "0.1.0-m",
		Box:            &diag.Box{BaseOS: "0.1.0-m", BaseWeb: "0.1.0-m", FQDN: "box1.example.org"},
	}
	type box struct{ BaseOS, BaseWeb, Fqdn string }
	var resp struct {
		Diagnostics struct {
			ProductVersion *string
			Appliance      *string
			Box            *box
		}
	}
	const q = `{ diagnostics { productVersion appliance box { baseOS baseWeb fqdn } } }`
	newDiagClient(&diagIdentity{}, c, "u-morgan").MustPost(q, &resp)
	d := resp.Diagnostics
	if d.ProductVersion == nil || *d.ProductVersion != "0.1.0" || d.Appliance == nil || *d.Appliance != "0.1.0-m" {
		t.Fatalf("product/appliance = %v/%v", d.ProductVersion, d.Appliance)
	}
	if d.Box == nil || *d.Box != (box{BaseOS: "0.1.0-m", BaseWeb: "0.1.0-m", Fqdn: "box1.example.org"}) {
		t.Fatalf("box = %+v", d.Box)
	}

	resp.Diagnostics.ProductVersion, resp.Diagnostics.Box = nil, nil
	newDiagClient(&diagIdentity{}, &diag.Collector{Gateway: diag.Component{Name: "gateway", Status: diag.StatusOK}}, "u-morgan").MustPost(q, &resp)
	if resp.Diagnostics.ProductVersion != nil || resp.Diagnostics.Box != nil {
		t.Fatalf("product/box off the appliance = %v/%+v, want null", resp.Diagnostics.ProductVersion, resp.Diagnostics.Box)
	}
}
