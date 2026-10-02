// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

func (f *targetVault) RequestHeartbeatForPrincipal(_ context.Context, in *vaultv1.RequestHeartbeatForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.RequestHeartbeatForPrincipalResponse, error) {
	f.lastRequest = in
	return &vaultv1.RequestHeartbeatForPrincipalResponse{RequestedAtUnix: 1790000000}, nil
}

func (f *targetVault) GetHeartbeatStatusForPrincipal(_ context.Context, in *vaultv1.GetHeartbeatStatusForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.GetHeartbeatStatusForPrincipalResponse, error) {
	return &vaultv1.GetHeartbeatStatusForPrincipalResponse{
		Result: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED, CheckedAtUnix: 1790000030, Detail: "LDAP bind: invalid credentials",
	}, nil
}

func TestRequestSecretCheckForwardsTheToken(t *testing.T) {
	fv := &targetVault{}
	var resp struct{ RequestSecretCheck int }
	newTargetClient(fv).MustPost(`mutation { requestSecretCheck(secretId:"s1") }`, &resp)
	if fv.lastRequest.GetSecretId() != "s1" || fv.lastRequest.GetActor().GetTokenId() != "utok-1" || resp.RequestSecretCheck != 1790000000 {
		t.Fatalf("req = %+v resp = %+v", fv.lastRequest, resp)
	}
}

func TestSecretCheckStatusMapsTheResult(t *testing.T) {
	var resp struct {
		SecretCheckStatus struct {
			Result, Detail string
			CheckedAtUnix  int
			Pending        bool
		}
	}
	newTargetClient(&targetVault{}).MustPost(`{ secretCheckStatus(secretId:"s1") { result detail checkedAtUnix pending } }`, &resp)
	if got := resp.SecretCheckStatus; got.Result != "FAILED" || got.Detail != "LDAP bind: invalid credentials" || got.CheckedAtUnix != 1790000030 || got.Pending {
		t.Fatalf("status = %+v", got)
	}
}
