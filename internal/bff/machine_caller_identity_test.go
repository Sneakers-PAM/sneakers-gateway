// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

func callerIdentityOf(h *Handler, bearer string) (username, email string, ran bool) {
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		username, email = resolvers.CallerIdentity(r.Context())
	})
	req := httptest.NewRequest(http.MethodPost, "/machine/graphql", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	h.MachineActor(next).ServeHTTP(httptest.NewRecorder(), req)
	return username, email, ran
}

func TestMachineActor_UserTokenCarriesItsOwnersUsernameAndEmail(t *testing.T) {
	fid := &fakeIdentity{verifyUserTokenResp: &identityv1.VerifyUserTokenResponse{
		Valid: true, TokenId: "utok-1",
		User: &identityv1.User{Id: "user-ada", Username: "ada", Email: "ada.lovelace@example.org"},
	}}
	username, email, ran := callerIdentityOf(&Handler{Identity: fid}, "snk_u_abc")
	if !ran || username != "ada" || email != "ada.lovelace@example.org" {
		t.Fatalf("ran=%v username=%q email=%q", ran, username, email)
	}
}
