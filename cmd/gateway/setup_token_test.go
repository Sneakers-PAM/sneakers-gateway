// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestLogSetupTokenNeverLogsTheValue(t *testing.T) {
	var buf bytes.Buffer
	logSetupToken(zerolog.New(&buf).Level(zerolog.TraceLevel), "s3tup-t0ken-value\n")
	out := buf.String()
	if strings.Contains(out, "s3tup-t0ken-value") {
		t.Fatalf("the setup token reached the log: %s", out)
	}
	if !strings.Contains(out, "SETUP_TOKEN configured") {
		t.Fatalf("missing the configured line: %s", out)
	}
	if strings.Contains(out, "setup_token") {
		t.Fatalf("the log carries a setup_token field: %s", out)
	}
}

func TestLogSetupTokenUnsetWarns(t *testing.T) {
	for _, tok := range []string{"", " \n"} {
		var buf bytes.Buffer
		logSetupToken(zerolog.New(&buf), tok)
		if !strings.Contains(buf.String(), "SETUP_TOKEN not set") {
			t.Fatalf("token %q: missing the not-set warning: %s", tok, buf.String())
		}
	}
}
