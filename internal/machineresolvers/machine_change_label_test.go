// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

// changeSecretTypeForPrincipal's changeLabel (sneakers-vault#165) carries
// vault's own description of the type change through unchanged, so the
// MCP's retype tool can report it instead of a generic "Changed: <field>".

func TestChangeSecretTypeForPrincipal_ChangeLabel(t *testing.T) {
	const label = "Type changed: Password -> Password Account (SSH); added host; fields carried over: username, password"
	fv := &fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{
		Secret:      &vaultv1.Secret{Id: "s1", TypeId: "type-unix-ssh"},
		ChangeLabel: label,
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		ChangeSecretTypeForPrincipal struct{ ChangeLabel *string }
	}
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-unix-ssh") { changeLabel } }`, &resp)
	got := resp.ChangeSecretTypeForPrincipal.ChangeLabel
	if got == nil || *got != label {
		t.Fatalf("changeLabel = %v, want %q", got, label)
	}
}

func TestChangeSecretTypeForPrincipal_ChangeLabelEmptyForAPlainUpdate(t *testing.T) {
	fv := &fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{
		Secret: &vaultv1.Secret{Id: "s1", TypeId: "type-unix-ssh"},
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		ChangeSecretTypeForPrincipal struct{ ChangeLabel *string }
	}
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-unix-ssh") { changeLabel } }`, &resp)
	if resp.ChangeSecretTypeForPrincipal.ChangeLabel != nil {
		t.Fatalf("changeLabel = %v, want nil when vault sent none", *resp.ChangeSecretTypeForPrincipal.ChangeLabel)
	}
}
