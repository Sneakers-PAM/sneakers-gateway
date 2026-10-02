// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestCookieSecure(t *testing.T) {
	cases := []struct {
		authMode, raw string
		want          bool
		wantErr       bool
	}{
		{"real", "", true, false},
		{"real", "true", true, false},
		{"real", "1", true, false},
		{"real", "TRUE", true, false},
		{"real", " true ", true, false},
		{"real", "false", false, false},
		{"real", "0", false, false},
		{"real", "False", false, false},
		{"real", "yes", false, true},
		{"real", "on", false, true},
		{"noauth", "", false, false},
		{"noauth", "true", false, false},
		{"noauth", "false", false, false},
		{"noauth", "bogus", false, true},
		{"", "", true, false},
		{"", "false", false, false},
	}
	for _, c := range cases {
		got, err := cookieSecure(c.authMode, c.raw)
		if (err != nil) != c.wantErr {
			t.Fatalf("cookieSecure(%q, %q) err = %v; wantErr %v", c.authMode, c.raw, err, c.wantErr)
		}
		if err == nil && got != c.want {
			t.Fatalf("cookieSecure(%q, %q) = %v; want %v", c.authMode, c.raw, got, c.want)
		}
	}
}
