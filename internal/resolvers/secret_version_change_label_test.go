// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// changeLabelIdentity is a no-op identity fake: the resolver falls back to
// the raw id when nothing resolves, which is all this test needs.
type changeLabelIdentity struct {
	identityv1.IdentityServiceClient
}

func (changeLabelIdentity) ResolveUserLabels(_ context.Context, _ *identityv1.ResolveUserLabelsRequest, _ ...grpc.CallOption) (*identityv1.ResolveUserLabelsResponse, error) {
	return &identityv1.ResolveUserLabelsResponse{}, nil
}

// SecretVersion.changeLabel (sneakers-vault#165) carries vault's own
// description of a type change through unchanged, so the web's version
// history shows it instead of the generic "Changed: <field>".
type fakeVersionVault struct {
	vaultv1.VaultServiceClient
	versions []*vaultv1.SecretVersion
}

func (f *fakeVersionVault) ListSecretVersions(_ context.Context, _ *vaultv1.ListSecretVersionsRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretVersionsResponse, error) {
	return &vaultv1.ListSecretVersionsResponse{Versions: f.versions}, nil
}

func TestSecretVersions_ChangeLabel(t *testing.T) {
	const label = "Type changed: Password -> Password Account (SSH); added host; fields carried over: username, password"
	fv := &fakeVersionVault{versions: []*vaultv1.SecretVersion{
		{VersionNo: 2, CreatedBy: "u1", ChangedFieldKeys: []string{"host"}, ChangeLabel: label},
		{VersionNo: 1, CreatedBy: "u1", FieldKeys: []string{"username", "password"}},
	}}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Identity: changeLabelIdentity{}}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-morgan")))
	}))
	var resp struct {
		SecretVersions []struct {
			VersionNo   int
			ChangeLabel *string
		}
	}
	c.MustPost(`{ secretVersions(secretId: "s1") { versionNo changeLabel } }`, &resp)
	if len(resp.SecretVersions) != 2 {
		t.Fatalf("got %d versions, want 2", len(resp.SecretVersions))
	}
	got := resp.SecretVersions[0].ChangeLabel
	if got == nil || *got != label {
		t.Fatalf("version 2 changeLabel = %v, want %q", got, label)
	}
	if resp.SecretVersions[1].ChangeLabel != nil {
		t.Fatalf("version 1 changeLabel = %v, want nil", *resp.SecretVersions[1].ChangeLabel)
	}
}
