// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	mtls "github.com/Bugs5382/go-mtls"
)

func providerFor(t *testing.T, env map[string]string) *mtls.Provider {
	t.Helper()
	p, err := loadMTLS(envOf(env))
	if err != nil || p == nil {
		t.Fatalf("loadMTLS = %v, %v", p, err)
	}
	return p
}

// startMachineListener serves the machine listener on a free port and returns its host:port.
func startMachineListener(t *testing.T, serverEnv map[string]string, next http.Handler) string {
	t.Helper()
	srv := newMachineServer("127.0.0.1:0", providerFor(t, serverEnv), next)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(lis, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return lis.Addr().String()
}

func echoPath() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "served "+r.URL.Path) })
}

func TestMachineListenerServesOnlyTheMachineAPIAndReadiness(t *testing.T) {
	pki := newTestPKI(t)
	addr := startMachineListener(t, pki.leaf(t, "gateway", 2), echoPath())
	client := providerFor(t, pki.leaf(t, "mcp", 3)).HTTPClient()
	client.Timeout = 5 * time.Second

	for path, want := range map[string]int{
		"/machine/graphql": http.StatusOK,
		"/readyz":          http.StatusOK,
		"/graphql":         http.StatusNotFound,
		"/auth/login":      http.StatusNotFound,
		"/setup/bootstrap": http.StatusNotFound,
		"/share/abc":       http.StatusNotFound,
		"/machine/other":   http.StatusNotFound,
		"/oauth2/token":    http.StatusNotFound,
	} {
		resp, err := client.Get("https://" + addr + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Errorf("%s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestMachineListenerRefusesACallerWithoutAClientCertificate(t *testing.T) {
	pki := newTestPKI(t)
	addr := startMachineListener(t, pki.leaf(t, "gateway", 2), echoPath())
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: providerFor(t, pki.leaf(t, "x", 4)).ClientConfig().RootCAs, MinVersion: tls.VersionTLS13}}
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	if resp, err := client.Get("https://" + addr + "/machine/graphql"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a caller with no client certificate must be refused in the handshake")
	}
}

func TestMachineListenerRefusesPlaintext(t *testing.T) {
	pki := newTestPKI(t)
	addr := startMachineListener(t, pki.leaf(t, "gateway", 2), echoPath())
	client := &http.Client{Timeout: 5 * time.Second}
	if resp, err := client.Get("http://" + addr + "/machine/graphql"); err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("plaintext must not reach the machine API")
		}
	}
}

func TestMachineListenerRefusesACallerSignedByAnotherCA(t *testing.T) {
	pki := newTestPKI(t)
	addr := startMachineListener(t, pki.leaf(t, "gateway", 2), echoPath())
	other := newTestPKI(t)
	client := providerFor(t, other.leaf(t, "mcp", 3)).HTTPClient()
	client.Timeout = 5 * time.Second
	if resp, err := client.Get("https://" + addr + "/machine/graphql"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a certificate from another CA must be refused")
	}
}

func TestMachineAllowlistKeepsTheBearerPathBehindTheSameHandler(t *testing.T) {
	rec := httptest.NewRecorder()
	onlyMachinePaths(echoPath()).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/machine/graphql", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "served /machine/graphql" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}
