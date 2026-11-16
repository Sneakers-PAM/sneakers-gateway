// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"time"

	mtls "github.com/Bugs5382/go-mtls"
)

// onlyMachinePaths lets through the machine API and readiness and answers 404
// to everything else, so the mutual-TLS port never serves the people's
// /graphql, the login and setup routes or share links. The match is exact:
// anything else, however it is spelled, is refused.
func onlyMachinePaths(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/machine/graphql", "/readyz":
			next.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// newMachineServer is the second listener, mutual TLS only: a caller must
// present a certificate the cluster CA signed, then the same bearer-token
// checks as on the edge port apply. Serve it with ServeTLS("", "").
func newMachineServer(addr string, prov *mtls.Provider, next http.Handler) *http.Server {
	srv := prov.HTTPServer(addr, onlyMachinePaths(next))
	srv.ReadHeaderTimeout = 10 * time.Second
	return srv
}
