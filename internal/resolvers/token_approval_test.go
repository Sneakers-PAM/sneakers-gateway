// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

func (f *useAdminVault) SetSecretTokenApproval(_ context.Context, in *vaultv1.SetSecretTokenApprovalRequest, _ ...grpc.CallOption) (*vaultv1.SetSecretTokenApprovalResponse, error) {
	f.lastApproval = in
	return &vaultv1.SetSecretTokenApprovalResponse{Secret: &vaultv1.Secret{Id: in.GetSecretId(), RequireTokenApproval: in.GetRequired()}}, nil
}

func TestSetSecretTokenApprovalForwardsThePerson(t *testing.T) {
	fv := &useAdminVault{}
	var resp struct {
		SetSecretTokenApproval struct {
			ID                   string
			RequireTokenApproval bool
		}
	}
	newUseAdminClient(fv, "u-ada").MustPost(`mutation { setSecretTokenApproval(secretId:"s1", required:true) { id requireTokenApproval } }`, &resp)
	if fv.lastApproval.GetActor().GetUserId() != "u-ada" || !fv.lastApproval.GetRequired() || !resp.SetSecretTokenApproval.RequireTokenApproval {
		t.Fatalf("req = %+v resp = %+v", fv.lastApproval, resp)
	}
}

func TestUseGrantAllowRevealRoundTrips(t *testing.T) {
	fv := &useAdminVault{}
	totpOK = true
	var resp struct{ CreateUseGrant struct{ AllowReveal bool } }
	newUseAdminClient(fv, "u-ada").MustPost(`mutation { createUseGrant(input:{tokenId:"utok-1", secretIds:["s1"], programs:[], allowReveal:true, expiresAtUnix:1790028800}, factor:{kind:"totp", code:"123456"}) { allowReveal } }`, &resp)
	if !fv.lastCreate.GetGrant().GetAllowReveal() || !resp.CreateUseGrant.AllowReveal {
		t.Fatalf("grant = %+v resp = %+v", fv.lastCreate.GetGrant(), resp)
	}
}
