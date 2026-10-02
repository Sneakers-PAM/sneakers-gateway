// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

func TestActorAttrs_RecoveryRole(t *testing.T) {
	for roles, want := range map[string]bool{"recovery": true, "user": false, "site-admin": false} {
		got, err := actorAttrsFrom(&identityv1.ResolveUserContextResponse{User: &identityv1.User{Id: "usr-42"}, Roles: []string{roles}})
		if err != nil {
			t.Fatal(err)
		}
		if got.recovery != want {
			t.Fatalf("roles %q: recovery = %v", roles, got.recovery)
		}
	}
}
