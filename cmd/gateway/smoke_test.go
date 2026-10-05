// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type smokeBody struct {
	OK     bool `json:"ok"`
	Checks []struct {
		Name  string `json:"name"`
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	} `json:"checks"`
}

func runSmoke(t *testing.T, checks []smokeCheck, method string) (int, smokeBody, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	smokeHandler(checks, log.Nop()).ServeHTTP(rec, httptest.NewRequest(method, "/smoke", nil))
	var b smokeBody
	_ = json.Unmarshal(rec.Body.Bytes(), &b)
	return rec.Code, b, rec.Body.String()
}

func ok(context.Context) error { return nil }

func TestSmokePassesWhenEveryReadSucceeds(t *testing.T) {
	code, b, _ := runSmoke(t, []smokeCheck{{"identity", ok}, {"vault", ok}}, http.MethodGet)
	if code != http.StatusOK || !b.OK || len(b.Checks) != 2 || !b.Checks[0].OK || !b.Checks[1].OK {
		t.Fatalf("code %d body %+v", code, b)
	}
}

func TestSmokeNamesTheFailedReadWithoutItsText(t *testing.T) {
	failing := func(context.Context) error {
		return status.Error(codes.Unavailable, "dial tcp 192.0.2.7:9091: connection refused")
	}
	code, b, raw := runSmoke(t, []smokeCheck{{"identity", ok}, {"vault", failing}}, http.MethodGet)
	if code != http.StatusServiceUnavailable || b.OK {
		t.Fatalf("code %d body %+v", code, b)
	}
	if b.Checks[1].Name != "vault" || b.Checks[1].OK || b.Checks[1].Error != "unavailable" {
		t.Fatalf("vault check = %+v", b.Checks[1])
	}
	if strings.Contains(raw, "192.0.2.7") {
		t.Fatalf("the answer leaks error text: %s", raw)
	}
}

func TestSmokeClassifiesAPlainError(t *testing.T) {
	_, b, _ := runSmoke(t, []smokeCheck{{"vault", func(context.Context) error { return errors.New("boom") }}}, http.MethodGet)
	if b.Checks[0].Error != "error" {
		t.Fatalf("error class = %q, want error", b.Checks[0].Error)
	}
}

func TestSmokeIsGetOnly(t *testing.T) {
	if code, _, _ := runSmoke(t, []smokeCheck{{"vault", ok}}, http.MethodPost); code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /smoke = %d, want 405", code)
	}
}

func TestSmokeReadsTheCoreServices(t *testing.T) {
	checks := smokeChecks(nil, nil, diagServices{}, nil)
	var names []string
	for _, c := range checks {
		names = append(names, c.name)
	}
	if got := strings.Join(names, ","); got != "identity,vault,workflow,audit" {
		t.Fatalf("checks = %s", got)
	}
	if err := checks[2].run(context.Background()); err == nil {
		t.Fatal("an undialled workflow passed the smoke")
	}
	if n := len(smokeChecks(nil, nil, diagServices{}, ok)); n != 5 {
		t.Fatalf("with a session store: %d checks, want 5", n)
	}
}
