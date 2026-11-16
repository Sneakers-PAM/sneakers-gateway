// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const (
	// maxMcpTools and maxMcpToolNameLen bound the list an admin sends. The MCP
	// server has two dozen tools with short names, so these are generous; they
	// only keep a settings write from growing without limit.
	maxMcpTools       = 100
	maxMcpToolNameLen = 64
)

// cleanMcpTools turns the names an admin sent into the list the vault stores:
// trimmed, with blanks and repeats dropped and the first-seen order kept. The
// gateway does not check the names against the MCP server's tool list, which
// it does not own: the MCP server ignores a name it doesn't know, with a
// warning. A name with a control character, a name over maxMcpToolNameLen
// characters or more than maxMcpTools names is refused.
func cleanMcpTools(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if len([]rune(name)) > maxMcpToolNameLen {
			return nil, fmt.Errorf("an MCP tool name is longer than %d characters", maxMcpToolNameLen)
		}
		if strings.ContainsFunc(name, unicode.IsControl) {
			return nil, errors.New("an MCP tool name has a control character")
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) > maxMcpTools {
		return nil, fmt.Errorf("more than %d MCP tool names", maxMcpTools)
	}
	return out, nil
}

// mcpToolNames is the list as the schema's non-null list: never nil.
func mcpToolNames(names []string) []string {
	if names == nil {
		return []string{}
	}
	return names
}
