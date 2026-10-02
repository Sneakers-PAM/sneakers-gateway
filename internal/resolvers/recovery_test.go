// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type recoveryVault struct {
	vaultv1.VaultServiceClient
	actor      *vaultv1.ActorContext
	restoreReq *vaultv1.RestoreSecretVersionRequest
	err        error
}

func (f *recoveryVault) RevealSecretVersionField(_ context.Context, req *vaultv1.RevealSecretVersionFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretVersionFieldResponse, error) {
	f.actor = req.GetActor()
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.RevealSecretVersionFieldResponse{Value: "old"}, nil
}

func (f *recoveryVault) RestoreSecretVersion(_ context.Context, req *vaultv1.RestoreSecretVersionRequest, _ ...grpc.CallOption) (*vaultv1.RestoreSecretVersionResponse, error) {
	f.actor = req.GetActor()
	f.restoreReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &vaultv1.RestoreSecretVersionResponse{Secret: &vaultv1.Secret{Id: req.GetSecretId(), Name: "db"}}, nil
}

func recoveryClient(fv vaultv1.VaultServiceClient, recovery bool) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Workflow: &leaseWorkflow{}}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActorInfo(WithActor(r.Context(), "u-1"), false, false, nil)
		ctx = WithActorRecovery(ctx, recovery)
		ctx = WithMFAVerifiedAt(ctx, time.Unix(1790000000, 0))
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

func TestPriorVersionRevealCarriesTheRecoveryRole(t *testing.T) {
	for _, recovery := range []bool{true, false} {
		fv := &recoveryVault{}
		var resp map[string]any
		recoveryClient(fv, recovery).MustPost(`mutation { revealSecretVersionField(secretId: "s1", versionNo: 2, fieldKey: "password") }`, &resp)
		if fv.actor.GetIsRecovery() != recovery || fv.actor.GetMfaVerifiedAtUnix() != 1790000000 {
			t.Fatalf("recovery=%v: actor = %+v", recovery, fv.actor)
		}
	}
}

func TestRestoreSecretVersion(t *testing.T) {
	fv := &recoveryVault{}
	var resp struct {
		RestoreSecretVersion struct{ ID, Name string }
	}
	recoveryClient(fv, true).MustPost(`mutation { restoreSecretVersion(secretId: "s1", versionNo: 3) { id name } }`, &resp)
	if fv.restoreReq.GetSecretId() != "s1" || fv.restoreReq.GetVersionNo() != 3 || !fv.actor.GetIsRecovery() || fv.actor.GetUserId() != "u-1" {
		t.Fatalf("request = %+v", fv.restoreReq)
	}
	if resp.RestoreSecretVersion.ID != "s1" {
		t.Fatalf("resp = %+v", resp)
	}
}

// The vault refuses a reader without the role; the reason reaches the client.
func TestRestoreRefusalReachesTheClient(t *testing.T) {
	st, err := status.New(codes.PermissionDenied, "the recovery role is required").WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: "RECOVERY_ROLE_REQUIRED"})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := recoveryClient(&recoveryVault{err: st.Err()}, false).RawPost(`mutation { restoreSecretVersion(secretId: "s1", versionNo: 3) { id } }`)
	if err != nil {
		t.Fatal(err)
	}
	var errs []gqlErr
	if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 || errs[0].Extensions.Reason != "RECOVERY_ROLE_REQUIRED" {
		t.Fatalf("errors = %s", resp.Errors)
	}
}
