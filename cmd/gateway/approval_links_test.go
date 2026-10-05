// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestApprovalRunLinksIsOffUnlessSetToTrue(t *testing.T) {
	for raw, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, " TRUE ": true, "1": true} {
		got, err := approvalRunLinks(raw)
		if err != nil || got != want {
			t.Fatalf("approvalRunLinks(%q) = %v, %v; want %v", raw, got, err, want)
		}
	}
}

func TestApprovalRunLinksRefusesAValueThatIsNotABoolean(t *testing.T) {
	if _, err := approvalRunLinks("yes please"); err == nil {
		t.Fatal("a typo must stop the gateway rather than guess")
	}
}
