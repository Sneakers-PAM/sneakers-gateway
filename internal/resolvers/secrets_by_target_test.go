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
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// fakeSecretsByTargetVault serves ListSecretsByTarget, recording the
// target_id it was asked for so a test can confirm it was forwarded as is.
type fakeSecretsByTargetVault struct {
	vaultv1.VaultServiceClient
	secrets  []*vaultv1.Secret
	lastReq  *vaultv1.ListSecretsByTargetRequest
	callback func(*vaultv1.ListSecretsByTargetRequest)
}

func (f *fakeSecretsByTargetVault) ListSecretsByTarget(_ context.Context, req *vaultv1.ListSecretsByTargetRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretsByTargetResponse, error) {
	f.lastReq = req
	if f.callback != nil {
		f.callback(req)
	}
	return &vaultv1.ListSecretsByTargetResponse{Secrets: f.secrets}, nil
}

// TestSecretsByTargetForwardsTargetIdAndResults is #168's target page:
// "every secret attached to this target" — the gateway bridges straight to
// the vault's ListSecretsByTarget, forwarding target_id and the actor, and
// passing can_read through unchanged for a locked-but-visible result.
func TestSecretsByTargetForwardsTargetIdAndResults(t *testing.T) {
	fv := &fakeSecretsByTargetVault{secrets: []*vaultv1.Secret{
		{Id: "s-open", Name: "open", FolderId: "f", CanRead: true},
		{Id: "s-locked", Name: "locked", FolderId: "f"},
	}}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-morgan")))
	}))

	var resp struct {
		SecretsByTarget []struct {
			ID      string
			CanRead *bool
		}
	}
	c.MustPost(`{ secretsByTarget(targetId: "target-1") { id canRead } }`, &resp)

	if fv.lastReq.GetTargetId() != "target-1" {
		t.Fatalf("target_id forwarded = %q, want target-1", fv.lastReq.GetTargetId())
	}
	if fv.lastReq.GetActor().GetUserId() != "user-morgan" {
		t.Fatalf("actor forwarded = %+v, want user-morgan", fv.lastReq.GetActor())
	}
	got := map[string]*bool{}
	for _, s := range resp.SecretsByTarget {
		got[s.ID] = s.CanRead
	}
	if got["s-open"] == nil || !*got["s-open"] || got["s-locked"] == nil || *got["s-locked"] {
		t.Fatalf("secretsByTarget canRead = %v", got)
	}
}
