// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

// createSecretForPrincipal's heartbeatBlockedReason (sneakers-vault#162)
// carries vault's principal view through unchanged, so an agent's create
// result can say "heartbeat available: switch it on" or name what's missing.

func TestCreateSecretForPrincipal_HeartbeatBlockedReason(t *testing.T) {
	fv := &fakePrincipalVault{createResp: &vaultv1.CreateSecretForPrincipalResponse{
		Secret: &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key", HeartbeatBlockedReason: "no pinned host key"},
	}}
	c := newPrincipalClient(fv, "sa-42", "")
	var resp struct {
		CreateSecretForPrincipal struct{ HeartbeatBlockedReason *string }
	}
	c.MustPost(`mutation { createSecretForPrincipal(folderId: "f1", typeId: "type-ssh-key", name: "svc", fields: []) { heartbeatBlockedReason } }`, &resp)
	got := resp.CreateSecretForPrincipal.HeartbeatBlockedReason
	if got == nil || *got != "no pinned host key" {
		t.Fatalf("heartbeatBlockedReason = %v, want \"no pinned host key\"", got)
	}
}

func TestCreateSecretForPrincipal_HeartbeatBlockedReasonEmptyWhenReady(t *testing.T) {
	fv := &fakePrincipalVault{createResp: &vaultv1.CreateSecretForPrincipalResponse{
		Secret: &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key", HeartbeatEnabled: true},
	}}
	c := newPrincipalClient(fv, "sa-42", "")
	var resp struct {
		CreateSecretForPrincipal struct{ HeartbeatBlockedReason *string }
	}
	c.MustPost(`mutation { createSecretForPrincipal(folderId: "f1", typeId: "type-ssh-key", name: "svc", fields: []) { heartbeatBlockedReason } }`, &resp)
	if resp.CreateSecretForPrincipal.HeartbeatBlockedReason != nil {
		t.Fatalf("heartbeatBlockedReason = %v, want nil when vault sent none", *resp.CreateSecretForPrincipal.HeartbeatBlockedReason)
	}
}
