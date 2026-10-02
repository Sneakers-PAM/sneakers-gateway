// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestPolisClientSecret(t *testing.T) {
	cases := []struct {
		mode, secret string
		want         string
		wantErr      bool
	}{
		{"real", "", "", true},
		{"real", "dummy", "", true},
		{"real", " dummy\n", "", true},
		{"real", "verifier-value\n", "verifier-value", false},
		{"noauth", "", "dummy", false},
		{"noauth", "verifier-value", "verifier-value", false},
	}
	for _, c := range cases {
		got, err := polisClientSecret(c.mode, envOf(map[string]string{"POLIS_CLIENT_SECRET": c.secret}))
		if (err != nil) != c.wantErr {
			t.Fatalf("%s %q: err = %v, wantErr %v", c.mode, c.secret, err, c.wantErr)
		}
		if err == nil && got != c.want {
			t.Fatalf("%s %q: secret = %q, want %q", c.mode, c.secret, got, c.want)
		}
	}
}
