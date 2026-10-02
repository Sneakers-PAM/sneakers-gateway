// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

func TestSecretTypes_MapsSensitive(t *testing.T) {
	fv := &listVault{typesResp: &vaultv1.ListSecretTypesResponse{Types: []*vaultv1.SecretType{
		{Id: "type-password", Name: "Password", Fields: []*vaultv1.SecretFieldDef{
			{Key: "username", Kind: vaultv1.FieldKind_FIELD_KIND_TEXT},
			{Key: "password", Kind: vaultv1.FieldKind_FIELD_KIND_PASSWORD, Sensitive: true},
		}},
	}}}
	var resp struct {
		SecretTypes []struct {
			Fields []struct {
				Key       string
				Sensitive bool
			}
		}
	}
	newListClient(fv).MustPost(`query { secretTypes { fields { key sensitive } } }`, &resp)

	f := resp.SecretTypes[0].Fields
	if len(f) != 2 || f[0].Key != "username" || f[0].Sensitive || f[1].Key != "password" || !f[1].Sensitive {
		t.Fatalf("sensitive mapped wrong: %+v", f)
	}
}
