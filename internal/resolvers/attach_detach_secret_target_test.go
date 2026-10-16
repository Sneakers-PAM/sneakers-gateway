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

// attachDetachTargetVault is a fake VaultServiceClient for the human
// attachSecretTarget/detachSecretTarget mutations (#168).
type attachDetachTargetVault struct {
	vaultv1.VaultServiceClient
	lastAttach *vaultv1.AttachSecretTargetRequest
	lastDetach *vaultv1.DetachSecretTargetRequest
}

func (f *attachDetachTargetVault) AttachSecretTarget(_ context.Context, in *vaultv1.AttachSecretTargetRequest, _ ...grpc.CallOption) (*vaultv1.AttachSecretTargetResponse, error) {
	f.lastAttach = in
	return &vaultv1.AttachSecretTargetResponse{Secret: &vaultv1.Secret{
		Id: in.GetSecretId(), Name: "claude ssh key", TargetId: "t1", TargetIds: []string{"t1", in.GetTargetId()},
	}}, nil
}

func (f *attachDetachTargetVault) DetachSecretTarget(_ context.Context, in *vaultv1.DetachSecretTargetRequest, _ ...grpc.CallOption) (*vaultv1.DetachSecretTargetResponse, error) {
	f.lastDetach = in
	return &vaultv1.DetachSecretTargetResponse{Secret: &vaultv1.Secret{
		Id: in.GetSecretId(), Name: "claude ssh key", TargetId: "t1", TargetIds: []string{"t1"},
	}}, nil
}

func newAttachDetachTargetClient(fv *attachDetachTargetVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-carol")))
	}))
}

// TestAttachDetachSecretTarget_BridgesToVault proves the human mutations are
// a thin bridge to vault, carrying the full targetIds list back.
func TestAttachDetachSecretTarget_BridgesToVault(t *testing.T) {
	fv := &attachDetachTargetVault{}
	c := newAttachDetachTargetClient(fv)
	var resp struct {
		AttachSecretTarget struct {
			ID        string
			TargetIds []string
		}
	}
	c.MustPost(`mutation { attachSecretTarget(secretId:"s1", targetId:"t2") { id targetIds } }`, &resp)
	if fv.lastAttach.GetSecretId() != "s1" || fv.lastAttach.GetTargetId() != "t2" {
		t.Fatalf("attach request = %+v", fv.lastAttach)
	}
	if len(resp.AttachSecretTarget.TargetIds) != 2 {
		t.Fatalf("want 2 target ids, got %+v", resp.AttachSecretTarget.TargetIds)
	}

	var detachResp struct {
		DetachSecretTarget struct {
			ID        string
			TargetIds []string
		}
	}
	c.MustPost(`mutation { detachSecretTarget(secretId:"s1", targetId:"t2") { id targetIds } }`, &detachResp)
	if fv.lastDetach.GetSecretId() != "s1" || fv.lastDetach.GetTargetId() != "t2" {
		t.Fatalf("detach request = %+v", fv.lastDetach)
	}
	if len(detachResp.DetachSecretTarget.TargetIds) != 1 {
		t.Fatalf("want 1 target id after detach, got %+v", detachResp.DetachSecretTarget.TargetIds)
	}
}
