// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// corsPolicy decides which browser origins may call the gateway with
// credentials. Only an exact match on the allow-list gets CORS headers; any
// other origin gets none, so the browser keeps the response from it.
type corsPolicy struct {
	allowed map[string]bool
	// reflectAny is the local-development fallback: AUTH_MODE=noauth with no
	// list set echoes any origin, so a dev UI on another port keeps working.
	reflectAny bool
}

// newCORSPolicy builds the policy from CORS_ALLOWED_ORIGINS, a comma-separated
// list of origins (scheme://host[:port]). An entry that isn't a plain http or
// https origin, or a wildcard, is an error so a typo can't open the gateway
// to every site.
func newCORSPolicy(authMode, raw string) (*corsPolicy, error) {
	p := &corsPolicy{allowed: map[string]bool{}}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		origin, err := normaliseOrigin(entry)
		if err != nil {
			return nil, fmt.Errorf("CORS_ALLOWED_ORIGINS entry %q: %w", entry, err)
		}
		p.allowed[origin] = true
	}
	p.reflectAny = authMode == "noauth" && len(p.allowed) == 0
	return p, nil
}

func normaliseOrigin(entry string) (string, error) {
	if entry == "*" {
		return "", fmt.Errorf("a wildcard can't be used with credentials; list each origin")
	}
	u, err := url.Parse(entry)
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("must be scheme://host[:port] only")
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// origins lists the allow-list for the start-up log.
func (p *corsPolicy) origins() []string {
	out := make([]string, 0, len(p.allowed))
	for o := range p.allowed {
		out = append(out, o)
	}
	return out
}

func (p *corsPolicy) allows(origin string) bool {
	if p.reflectAny {
		return true
	}
	return p.allowed[strings.ToLower(origin)]
}

// wrap sets the CORS headers for an allowed origin and answers its preflight.
// A preflight from any other origin is refused with 403; an OPTIONS request
// with no Origin isn't a preflight and gets a bare 204.
func (p *corsPolicy) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		h := w.Header()
		allowed := false
		if origin != "" {
			h.Add("Vary", "Origin")
			allowed = p.allows(origin)
		}
		if allowed {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			if origin != "" && !allowed {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if allowed {
				h.Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
				// Authorization is allowed for the machine bearer-auth path
				// (/machine/graphql): a preflighted cross-origin machine client
				// sends its API token in this header.
				h.Set("Access-Control-Allow-Headers", "Content-Type,X-Dev-User,X-CSRF-Token,Authorization")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
