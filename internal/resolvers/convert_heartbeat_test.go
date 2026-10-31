// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

func TestHeartbeatGQLKeepsAnUntrustedCertificateApart(t *testing.T) {
	got := heartbeatGQL(vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNTRUSTED_CERTIFICATE)
	if got == nil || *got != HeartbeatResultUntrustedCertificate {
		t.Fatalf("got %v, want untrustedCertificate", got)
	}
}

func TestSecretCarriesTheHeartbeatReason(t *testing.T) {
	const reason = "untrusted certificate: the certificate for dc01.example.org expired"
	got := gqlSecret(&vaultv1.Secret{
		Id: "s1", LastHeartbeatResult: vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNTRUSTED_CERTIFICATE, LastHeartbeatDetail: reason,
	})
	if got.LastHeartbeatDetail == nil || *got.LastHeartbeatDetail != reason {
		t.Fatalf("detail = %v", got.LastHeartbeatDetail)
	}
}
