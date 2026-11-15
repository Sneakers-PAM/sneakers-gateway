// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"

	log "github.com/Bugs5382/go-log"
)

// apiLevel is the gateway's API level, published for the mobile apps. Raise
// it when the apps' calls change in a way an older app can't follow.
const apiLevel = 1

// releaseDocument is the whole public release document: it carries nothing
// beyond the product, the release and the API level. Version is null when no
// release is configured, so a caller never mistakes a guess for a release.
type releaseDocument struct {
	Product  string  `json:"product"`
	Version  *string `json:"version"`
	APILevel int     `json:"apiLevel"`
}

// releaseHandler serves GET /.well-known/sneakers, outside the session gate,
// so an app learns which release a server runs before anyone signs in.
func releaseHandler(version string, lg log.Logger) http.Handler {
	doc := releaseDocument{Product: "sneakers-pam", APILevel: apiLevel}
	if version != "" {
		doc.Version = &version
	}
	body, err := json.Marshal(doc)
	if err != nil {
		lg.Error(err, "release document: marshal")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if version != "" {
			w.Header().Set("Sneakers-Version", version)
			w.Header().Set("Cache-Control", "public, max-age=60")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
		lg.Ctx(r.Context()).Debug("release document served", log.F("method", r.Method), log.F("release_configured", version != ""))
	})
}
