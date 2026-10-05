// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package setup serves the unauthenticated first-run endpoints (mounted outside
// the auth/session middleware, like /livez and /readyz): GET /setup/state and POST
// /setup/bootstrap. The bootstrap write is guarded by SETUP_TOKEN here and the
// no-root invariant in identity.
package setup

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/bff"
)

// Handlers holds the unauthenticated /setup/* HTTP handlers.
type Handlers struct {
	identity   identityv1.IdentityServiceClient
	vault      vaultv1.VaultServiceClient
	setupToken string
	ssoProv    *bff.JacksonProvisioner // nil disables SSO provisioning
	// Log receives the handlers' error lines, trace-correlated per request.
	// nil discards them.
	Log log.Logger
}

func (h *Handlers) logger() log.Logger {
	if h.Log == nil {
		return log.Nop()
	}
	return h.Log
}

// New returns a Handlers wired to identity + vault and guarded by setupToken.
// Surrounding whitespace is trimmed from setupToken (a Secret made from a file
// usually ends in a newline); a blank token leaves setup disabled. ssoProv may
// be nil (SSO provisioning disabled, e.g. POLIS_ADMIN_URL unset).
func New(identity identityv1.IdentityServiceClient, vault vaultv1.VaultServiceClient, setupToken string, ssoProv *bff.JacksonProvisioner) *Handlers {
	return &Handlers{identity: identity, vault: vault, setupToken: strings.TrimSpace(setupToken), ssoProv: ssoProv}
}

// tokenMatches compares the submitted token, trimmed like the configured one,
// in constant time.
func (h *Handlers) tokenMatches(submitted string) bool {
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(submitted)), []byte(h.setupToken)) == 1
}

// StateHandler returns an http.HandlerFunc for GET /setup/state.
// Calls identity.GetSetupState and returns {"needsSetup": bool}.
func (h *Handlers) StateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp, err := h.identity.GetSetupState(r.Context(), &identityv1.GetSetupStateRequest{})
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			h.logger().Ctx(r.Context()).Error(err, "setup: GetSetupState failed")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "setup state unavailable"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"needsSetup": resp.GetNeedsSetup()})
	}
}

// BootstrapHandler returns an http.HandlerFunc for POST /setup/bootstrap.
// Expects JSON {setupToken, username, email, password, name}. Guards with
// SETUP_TOKEN (503 if unconfigured, 403 on mismatch) then delegates to
// identity.BootstrapRoot. Maps identity gRPC codes: FailedPrecondition→409,
// InvalidArgument→400, Unavailable→503, other→502. Success→200 {"userId": ...}.
func (h *Handlers) BootstrapHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if h.setupToken == "" {
			writeErr(w, http.StatusServiceUnavailable, "setup is not enabled (no SETUP_TOKEN configured)")
			return
		}
		var body struct {
			SetupToken string `json:"setupToken"`
			Username   string `json:"username"`
			Email      string `json:"email"`
			Password   string `json:"password"`
			Name       string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !h.tokenMatches(body.SetupToken) {
			writeErr(w, http.StatusForbidden, "invalid setup token")
			return
		}
		resp, err := h.identity.BootstrapRoot(r.Context(), &identityv1.BootstrapRootRequest{
			Username: body.Username,
			Email:    body.Email,
			Password: body.Password,
			Name:     body.Name,
		})
		if err != nil {
			h.logger().Ctx(r.Context()).Error(err, "setup: BootstrapRoot failed", log.F("code", status.Code(err).String()))
			switch status.Code(err) {
			case codes.FailedPrecondition:
				writeErr(w, http.StatusConflict, "already set up")
			case codes.InvalidArgument:
				writeErr(w, http.StatusBadRequest, "username, email, and password are required")
			case codes.Unavailable:
				writeErr(w, http.StatusServiceUnavailable, "identity service unavailable")
			default:
				writeErr(w, http.StatusBadGateway, "bootstrap failed")
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"userId": resp.GetUser().GetId()})
	}
}

// SeedHandler returns an http.HandlerFunc for POST /setup/seed. Expects JSON
// {setupToken, userId}. Guards with SETUP_TOKEN (503 if unconfigured, 403 on
// mismatch), then calls vault.SeedBuiltins with an admin actor to install the
// built-in baseline (types/folders/policies/connections) into the fresh, empty
// vault. userId is required: the id /setup/bootstrap returned, the admin the
// seed acts as and whose personal folder is created (400 without it). Idempotent — safe to retry.
// Success → 200 {"types", "connections", "folders"} (totals present after seed).
func (h *Handlers) SeedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if h.setupToken == "" {
			writeErr(w, http.StatusServiceUnavailable, "setup is not enabled (no SETUP_TOKEN configured)")
			return
		}
		var body struct {
			SetupToken string `json:"setupToken"`
			UserID     string `json:"userId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if !h.tokenMatches(body.SetupToken) {
			writeErr(w, http.StatusForbidden, "invalid setup token")
			return
		}
		// The setup actor is the bootstrap admin, a human site admin and root:
		// SeedBuiltins is a privileged, gated install, and its personal folder is
		// created for that user.
		userID := strings.TrimSpace(body.UserID)
		if userID == "" {
			writeErr(w, http.StatusBadRequest, "userId is required: pass the id /setup/bootstrap returned")
			return
		}
		resp, err := h.vault.SeedBuiltins(r.Context(), &vaultv1.SeedBuiltinsRequest{
			Actor: &vaultv1.ActorContext{UserId: userID, IsRoot: true, IsSiteAdmin: true},
		})
		if err != nil {
			h.logger().Ctx(r.Context()).Error(err, "setup: SeedBuiltins failed", log.F("code", status.Code(err).String()))
			switch status.Code(err) {
			case codes.Unavailable:
				writeErr(w, http.StatusServiceUnavailable, "vault service unavailable")
			default:
				writeErr(w, http.StatusBadGateway, "seeding built-ins failed")
			}
			return
		}
		if h.ssoProv != nil {
			if err := h.ssoProv.EnsureConnection(r.Context()); err != nil {
				writeErr(w, http.StatusBadGateway, "seed ok but SSO connection provisioning failed: "+err.Error())
				return
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"types":       resp.GetTypes(),
			"connections": resp.GetConnections(),
			"folders":     resp.GetFolders(),
		})
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": msg})
}
