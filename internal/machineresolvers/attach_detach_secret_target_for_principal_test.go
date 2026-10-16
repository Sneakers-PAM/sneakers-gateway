// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"google.golang.org/grpc"
)

// attachDetachForPrincipalVault is a fake VaultServiceClient for #168's
// attach/detach-one-target machine mutations.
type attachDetachForPrincipalVault struct {
	vaultv1.VaultServiceClient
	lastAttach *vaultv1.AttachSecretTargetForPrincipalRequest
	lastDetach *vaultv1.DetachSecretTargetForPrincipalRequest
}

func (f *attachDetachForPrincipalVault) AttachSecretTargetForPrincipal(_ context.Context, in *vaultv1.AttachSecretTargetForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.AttachSecretTargetForPrincipalResponse, error) {
	f.lastAttach = in
	return &vaultv1.AttachSecretTargetForPrincipalResponse{Secret: &vaultv1.Secret{
		Id: in.GetSecretId(), Name: "svc-account", TargetId: "t1", TargetIds: []string{"t1", in.GetTargetId()},
	}}, nil
}

func (f *attachDetachForPrincipalVault) DetachSecretTargetForPrincipal(_ context.Context, in *vaultv1.DetachSecretTargetForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.DetachSecretTargetForPrincipalResponse, error) {
	f.lastDetach = in
	return &vaultv1.DetachSecretTargetForPrincipalResponse{Secret: &vaultv1.Secret{
		Id: in.GetSecretId(), Name: "svc-account", TargetId: "t1", TargetIds: []string{"t1"},
	}}, nil
}

func newAttachDetachForPrincipalClient(fv *attachDetachForPrincipalVault) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)))
	}))
}

// TestAttachDetachSecretTargetForPrincipal_BridgesToVault proves the
// attach/detach mutations are a thin bridge to vault, never replacing the
// whole target list (unlike setSecretTargetForPrincipal).
func TestAttachDetachSecretTargetForPrincipal_BridgesToVault(t *testing.T) {
	fv := &attachDetachForPrincipalVault{}
	c := newAttachDetachForPrincipalClient(fv)
	var resp struct {
		AttachSecretTargetForPrincipal struct {
			ID        string
			TargetIds []string
		}
	}
	c.MustPost(`mutation { attachSecretTargetForPrincipal(secretId:"s1", targetId:"t2") { id targetIds } }`, &resp)
	if fv.lastAttach.GetSecretId() != "s1" || fv.lastAttach.GetTargetId() != "t2" {
		t.Fatalf("attach request = %+v", fv.lastAttach)
	}
	if len(resp.AttachSecretTargetForPrincipal.TargetIds) != 2 {
		t.Fatalf("want 2 target ids, got %+v", resp.AttachSecretTargetForPrincipal.TargetIds)
	}

	var detachResp struct {
		DetachSecretTargetForPrincipal struct {
			ID        string
			TargetIds []string
		}
	}
	c.MustPost(`mutation { detachSecretTargetForPrincipal(secretId:"s1", targetId:"t2") { id targetIds } }`, &detachResp)
	if fv.lastDetach.GetSecretId() != "s1" || fv.lastDetach.GetTargetId() != "t2" {
		t.Fatalf("detach request = %+v", fv.lastDetach)
	}
	if len(detachResp.DetachSecretTargetForPrincipal.TargetIds) != 1 {
		t.Fatalf("want 1 target id after detach, got %+v", detachResp.DetachSecretTargetForPrincipal.TargetIds)
	}
}
