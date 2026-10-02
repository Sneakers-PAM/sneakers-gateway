// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package apperr

import (
	"testing"

	goapperr "github.com/Bugs5382/go-apperr"
)

func TestRegistry_ValidGoApperrRegistry(t *testing.T) {
	entries := make([]goapperr.Entry, 0, len(Registry))
	for code, cause := range Registry {
		entries = append(entries, goapperr.Entry{Code: code, Title: "gateway", Cause: cause})
	}
	if _, err := goapperr.NewRegistry(entries, goapperr.WithService(2), goapperr.WithCodeDigits(4)); err != nil {
		t.Fatalf("Registry is not a valid service-2, four-digit go-apperr registry: %v", err)
	}
}
