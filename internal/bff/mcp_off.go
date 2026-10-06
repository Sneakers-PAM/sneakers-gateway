// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import "net/http"

// CodeMCPDisabled is the refusal while the MCP is off (MCP_ENABLED=false):
// every MCP agent token on the machine API and every OAuth route that mints
// one. An MCP agent token is a personal token identity records with
// client_kind mcp (minted by the OAuth flow below), or a Hydra
// client-credentials JWT, which the gateway accepts only for the MCP
// audience.
const CodeMCPDisabled = "MCP_DISABLED"

// ClientKindMCP is the client_kind of personal tokens minted for MCP clients.
const ClientKindMCP = "mcp"

const mcpDisabledMessage = "MCP is turned off on this appliance (setting mcp.enabled)"

func writeMCPDisabled(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": CodeMCPDisabled, "message": mcpDisabledMessage})
}

// MCPOff answers the OAuth routes (/oauth2/* and the authorization-server
// metadata) while the MCP is off, so no new agent token can be minted.
func MCPOff() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeMCPDisabled(w) })
}

// CodeMachineAPIDisabled is the refusal while the machine API is off
// (MACHINE_API_ENABLED=false): personal tokens other than MCP agent tokens,
// and service-account API tokens. MCP agent tokens follow the MCP switch.
const CodeMachineAPIDisabled = "MACHINE_API_DISABLED"

const machineAPIDisabledMessage = "The machine API is turned off on this install (setting MACHINE_API_ENABLED)"

func writeMachineAPIDisabled(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": CodeMachineAPIDisabled, "message": machineAPIDisabledMessage})
}
