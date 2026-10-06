// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"slices"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

type listIdentity struct {
	identityv1.IdentityServiceClient
	users []*identityv1.User
}

func (f *listIdentity) ListUsers(_ context.Context, _ *identityv1.ListUsersRequest, _ ...grpc.CallOption) (*identityv1.ListUsersResponse, error) {
	return &identityv1.ListUsersResponse{Users: f.users}, nil
}

type confirmUseVault struct{ useVault }

func (f *confirmUseVault) PrepareSecretUse(_ context.Context, in *vaultv1.PrepareSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.PrepareSecretUseResponse, error) {
	f.lastPrepare = in
	return &vaultv1.PrepareSecretUseResponse{Use: &vaultv1.SecretUse{
		Id: "use-1", SecretName: "domain-admin", State: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING, Confirm: true,
	}}, nil
}

func TestPrepareSecretUseSendsTheActivePeopleAndShowsAConfirmation(t *testing.T) {
	fv := &confirmUseVault{}
	users := &resolvers.ActiveUsers{Identity: &listIdentity{users: []*identityv1.User{{Id: "u-ada", Subject: "k-ada"}}}}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, PublicURL: "https://sneakers.example.org", ActiveUsers: users}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)))
	}))
	var resp struct{ PrepareSecretUse struct{ Confirm bool } }
	c.MustPost(`mutation { prepareSecretUse(secretId:"s1", fieldKey:"password", reveal:true) { confirm } }`, &resp)
	if got := fv.lastPrepare.GetActiveUsers().GetUserIds(); !slices.Equal(got, []string{"u-ada"}) {
		t.Fatalf("active users = %v", got)
	}
	if !resp.PrepareSecretUse.Confirm {
		t.Fatal("confirm not passed through")
	}
}
