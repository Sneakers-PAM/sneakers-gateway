// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"strings"
)

// polisDevSecret is Ory Polis's documented development client secret.
const polisDevSecret = "dummy"

var errPolisDevSecret = errors.New("POLIS_CLIENT_SECRET is unset or the development value \"dummy\": with AUTH_MODE=real and SSO on, set it (from a Secret) to the CLIENT_SECRET_VERIFIER Polis runs with")

// polisClientSecret is the client secret for the SSO code exchange, from
// POLIS_CLIENT_SECRET, trimmed. AUTH_MODE=real refuses the development value
// and an unset one; local development falls back to it.
func polisClientSecret(authMode string, getenv func(string) string) (string, error) {
	s := strings.TrimSpace(getenv("POLIS_CLIENT_SECRET"))
	if authMode == "real" {
		if s == "" || s == polisDevSecret {
			return "", errPolisDevSecret
		}
		return s, nil
	}
	if s == "" {
		return polisDevSecret, nil
	}
	return s, nil
}
