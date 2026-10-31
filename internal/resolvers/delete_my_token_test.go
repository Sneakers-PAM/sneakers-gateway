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
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type deleteTokenIdentity struct {
	identityv1.IdentityServiceClient
	last *identityv1.DeleteUserTokenRequest
	err  error
}

func (f *deleteTokenIdentity) DeleteUserToken(_ context.Context, in *identityv1.DeleteUserTokenRequest, _ ...grpc.CallOption) (*identityv1.DeleteUserTokenResponse, error) {
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	return &identityv1.DeleteUserTokenResponse{}, nil
}

func deleteTokenClient(fi *deleteTokenIdentity, actor string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Identity: fi}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	}))
}

func TestDeleteMyTokenDeletesAsTheCaller(t *testing.T) {
	fi := &deleteTokenIdentity{}
	var resp struct{ DeleteMyToken bool }
	deleteTokenClient(fi, "u-ada").MustPost(`mutation { deleteMyToken(id:"utok-1") }`, &resp)
	if !resp.DeleteMyToken {
		t.Fatal("deleteMyToken = false, want true")
	}
	if fi.last.GetId() != "utok-1" || fi.last.GetUserId() != "u-ada" || fi.last.GetActingUserId() != "u-ada" {
		t.Fatalf("delete req = %+v", fi.last)
	}
}

func TestDeleteMyTokenNeedsASignedInCaller(t *testing.T) {
	fi := &deleteTokenIdentity{}
	var resp map[string]any
	if err := deleteTokenClient(fi, "").Post(`mutation { deleteMyToken(id:"utok-1") }`, &resp); err == nil {
		t.Fatal("deleteMyToken without a session must fail")
	}
	if fi.last != nil {
		t.Fatalf("identity must not be called without a caller, got %+v", fi.last)
	}
}

func TestDeleteMyTokenPassesIdentityRefusalsThrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
		text string
	}{
		{"active token", status.Error(codes.FailedPrecondition, "token is not revoked"), "FAILED_PRECONDITION", "token is not revoked"},
		{"someone else's or a missing token", status.Error(codes.NotFound, "token not found"), "NOT_FOUND", "token not found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := deleteTokenClient(&deleteTokenIdentity{err: tc.err}, "u-ada").RawPost(`mutation { deleteMyToken(id:"utok-1") }`)
			if err != nil {
				t.Fatal(err)
			}
			var errs []gqlErr
			if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
				t.Fatalf("errors = %s", resp.Errors)
			}
			if errs[0].Extensions.Code != tc.code || !strings.Contains(string(resp.Errors), tc.text) {
				t.Fatalf("errors = %s, want code %s and text %q", resp.Errors, tc.code, tc.text)
			}
		})
	}
}
