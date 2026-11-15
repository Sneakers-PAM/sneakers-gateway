// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	log "github.com/Bugs5382/go-log"
)

func getRelease(t *testing.T, version, method string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	releaseHandler(version, log.Nop()).ServeHTTP(rec, httptest.NewRequest(method, "/.well-known/sneakers", nil))
	return rec
}

func TestReleaseDocumentCarriesProductVersionAndLevel(t *testing.T) {
	rec := getRelease(t, "v0.1.0", http.MethodGet)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got["product"] != "sneakers-pam" || got["version"] != "v0.1.0" || got["apiLevel"] != float64(apiLevel) {
		t.Fatalf("body %v", got)
	}
	if h := rec.Header().Get("Sneakers-Version"); h != "v0.1.0" {
		t.Fatalf("Sneakers-Version %q", h)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Fatalf("cache control %q", cc)
	}
}

func TestReleaseDocumentSaysSoWhenNoReleaseIsConfigured(t *testing.T) {
	rec := getRelease(t, "", http.MethodGet)
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if v, present := got["version"]; !present || v != nil {
		t.Fatalf("version should be null, body %v", got)
	}
	if rec.Header().Get("Sneakers-Version") != "" {
		t.Fatal("no version header without a release")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("an unset release must not be cached: %q", rec.Header().Get("Cache-Control"))
	}
}

func TestReleaseDocumentAnswersHeadAndRefusesWrites(t *testing.T) {
	if rec := getRelease(t, "v0.1.0", http.MethodHead); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD: code %d body %q", rec.Code, rec.Body.String())
	}
	rec := getRelease(t, "v0.1.0", http.MethodPost)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST: code %d allow %q", rec.Code, rec.Header().Get("Allow"))
	}
}
