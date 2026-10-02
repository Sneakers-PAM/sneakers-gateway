// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package apperr

import "testing"

func TestRegistry_HasSSOCodes(t *testing.T) {
	for _, code := range []int{2215, 2216, 2217, 2218} {
		if _, ok := Registry[code]; !ok {
			t.Fatalf("Registry missing SSO code %d", code)
		}
	}
	// Reserved — must NOT be defined.
	for _, code := range []int{2219, 2220} {
		if _, ok := Registry[code]; ok {
			t.Fatalf("code %d is reserved and must not be defined here", code)
		}
	}
}
