// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// approvalRunLinks reads APPROVAL_RUN_LINKS: off unless set to a true value.
// A value strconv.ParseBool rejects is an error rather than a guess.
func approvalRunLinks(raw string) (bool, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(strings.ToLower(v))
	if err != nil {
		return false, fmt.Errorf("APPROVAL_RUN_LINKS=%q is not a boolean (use true or false)", raw)
	}
	return b, nil
}
