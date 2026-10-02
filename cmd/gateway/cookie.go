// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// cookieSecure decides the Secure flag for every cookie the BFF sets. It is on
// unless AUTH_MODE=noauth (plain-http dev) or COOKIE_SECURE is explicitly
// false. A value strconv.ParseBool rejects is an error rather than a guess, so
// a typo can never quietly ship session cookies over plain http.
func cookieSecure(authMode, raw string) (bool, error) {
	v := strings.TrimSpace(raw)
	explicit := true
	if v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("COOKIE_SECURE=%q is not a boolean (use true or false)", raw)
		}
		explicit = b
	}
	if authMode == "noauth" {
		return false, nil
	}
	return explicit, nil
}
