// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

func TestConnectionCarriesTheKdcPort(t *testing.T) {
	port := 1088
	if got := protoConnInput(ConnectionInput{Name: "AD", Protocol: "ldap", KdcPort: &port}); got.GetKdcPort() != 1088 {
		t.Fatalf("input kdc_port = %d, want 1088", got.GetKdcPort())
	}
	got := gqlConnection(&vaultv1.Connection{Id: "c1", KdcPort: 1088})
	if got.KdcPort == nil || *got.KdcPort != 1088 {
		t.Fatalf("output kdcPort = %v, want 1088", got.KdcPort)
	}
}
