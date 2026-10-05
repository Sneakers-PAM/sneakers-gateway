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
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/grpc"
)

// breakGlassIdentity accepts only the codes in valid. Identity answers ok=false
// for a wrong code and for one outside the TOTP window alike.
type breakGlassIdentity struct {
	identityv1.IdentityServiceClient
	valid map[string]bool
	calls int
}

func (f *breakGlassIdentity) VerifyTotp(_ context.Context, in *identityv1.VerifyTotpRequest, _ ...grpc.CallOption) (*identityv1.VerifyTotpResponse, error) {
	f.calls++
	return &identityv1.VerifyTotpResponse{Ok: f.valid[in.GetCode()]}, nil
}

type breakGlassVault struct {
	vaultv1.VaultServiceClient
	last *vaultv1.BreakGlassSecretRequest
}

func (f *breakGlassVault) BreakGlassSecret(_ context.Context, in *vaultv1.BreakGlassSecretRequest, _ ...grpc.CallOption) (*vaultv1.BreakGlassSecretResponse, error) {
	f.last = in
	return &vaultv1.BreakGlassSecretResponse{Fields: map[string]string{"password": "example-value"}}, nil
}

type breakGlassErr struct {
	Message    string `json:"message"`
	Extensions struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
		Domain string `json:"domain"`
	} `json:"extensions"`
}

func newBreakGlassClient(id *breakGlassIdentity, v *breakGlassVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: id, Vault: v}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "u-ada")))
	}))
}

func TestARefusedBreakGlassCodeHasAStableReason(t *testing.T) {
	cases := []struct {
		name         string
		code         string
		wantIdentity int
	}{
		{"wrong", "000000", 1},
		{"missing", "", 0},
		{"expired", "111111", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := &breakGlassIdentity{valid: map[string]bool{"123456": true}}
			v := &breakGlassVault{}
			c := newBreakGlassClient(id, v)
			resp, err := c.RawPost(`mutation($code: String!) { breakGlassSecret(secretId: "s-1", reason: "outage", code: $code) { key } }`,
				gqlclient.Var("code", tc.code))
			if err != nil {
				t.Fatal(err)
			}
			var errs []breakGlassErr
			if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
				t.Fatalf("errors = %s (%v)", resp.Errors, err)
			}
			ext := errs[0].Extensions
			if ext.Code != "UNAUTHENTICATED" || ext.Reason != "BREAK_GLASS_CODE_INVALID" || ext.Domain != "sneakers.gateway" {
				t.Fatalf("extensions = %+v", ext)
			}
			if v.last != nil {
				t.Fatal("a refused code must never reach the vault")
			}
			if id.calls != tc.wantIdentity {
				t.Fatalf("identity calls = %d, want %d", id.calls, tc.wantIdentity)
			}
		})
	}
}

func TestACorrectBreakGlassCodeRevealsTheFields(t *testing.T) {
	id := &breakGlassIdentity{valid: map[string]bool{"123456": true}}
	v := &breakGlassVault{}
	var resp struct {
		BreakGlassSecret []struct{ Key, Value string }
	}
	newBreakGlassClient(id, v).MustPost(`mutation { breakGlassSecret(secretId: "s-1", reason: "outage", code: "123456") { key value } }`, &resp)
	if v.last.GetSecretId() != "s-1" || v.last.GetReason() != "outage" || v.last.GetActor().GetUserId() != "u-ada" {
		t.Fatalf("vault request = %+v", v.last)
	}
	if len(resp.BreakGlassSecret) != 1 || resp.BreakGlassSecret[0].Key != "password" || resp.BreakGlassSecret[0].Value != "example-value" {
		t.Fatalf("fields = %+v", resp.BreakGlassSecret)
	}
}
