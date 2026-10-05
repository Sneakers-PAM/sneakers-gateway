// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package diag gathers the build and version facts the diagnostics query
// returns: the gateway's own build, each Sneakers-PAM service's version and
// commit (read from its health check's response headers), and the versions of
// the third-party services the gateway can reach.
//
// Only a component's name, version, commit and status ever leave this
// package. Addresses, URLs, credentials, error text and response bodies stay
// inside the probes, and every version string is checked against a strict
// pattern before it's kept.
package diag

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"slices"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
)

// CacheTTL is how long a report is reused before the probes run again.
const CacheTTL = 30 * time.Second

// probeTimeout bounds each probe; collectTimeout bounds one whole collection.
const (
	probeTimeout   = 1500 * time.Millisecond
	collectTimeout = 3 * time.Second
)

// The response headers a Sneakers-PAM service's health check carries.
const (
	HeaderVersion   = "sneakers-version"
	HeaderCommit    = "sneakers-commit"
	HeaderDepPrefix = "sneakers-dep-"
	// HeaderHealth carries the service's readiness report as JSON.
	HeaderHealth = "sneakers-health"
)

// The dependency states a service reports.
const (
	DepOK       = "ok"
	DepDegraded = "degraded"
	DepDown     = "down"
)

// Dependency is one of a component's dependencies as its readiness reports
// it. Only fixed tokens and clean versions are kept.
type Dependency struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Required bool   `json:"required"`
	Error    string `json:"error,omitempty"`
	Version  string `json:"version,omitempty"`
}

// Status is a component's state as the diagnostics see it.
type Status string

// The component states.
const (
	StatusOK            Status = "OK"
	StatusUnavailable   Status = "UNAVAILABLE"
	StatusNotConfigured Status = "NOT_CONFIGURED"
)

// Unknown is the version or commit of a component that answered without one.
const Unknown = "unknown"

// Component is one component's entry in a report.
type Component struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Status  Status `json:"status"`
	// Dependencies is the component's readiness by dependency; nil when it
	// didn't report one.
	Dependencies []Dependency `json:"dependencies,omitempty"`
	// deps holds the dependency versions a service reported (sneakers-dep-*
	// headers), keyed by dependency name. Never serialised.
	deps map[string]string
}

// Probe reads one component. It never fails: an unreachable component comes
// back with StatusUnavailable.
type Probe func(ctx context.Context) Component

// Report is what the diagnostics query returns.
type Report struct {
	GeneratedAt time.Time   `json:"generatedAt"`
	PublicURL   string      `json:"publicUrl"`
	Appliance   string      `json:"appliance"`
	Gateway     Component   `json:"gateway"`
	Services    []Component `json:"services"`
	ThirdParty  []Component `json:"thirdParty"`
}

// sharedDeps are the dependencies the services report on the gateway's
// behalf, so the gateway needs no database or broker credentials. expected
// says whether one is always in use (unreported means unavailable) or only
// when a service reports it (unreported means not configured).
var sharedDeps = []struct {
	name     string
	expected bool
}{
	{"postgres", true},
	{"rabbitmq", false},
}

// Collector assembles reports and caches them for CacheTTL.
type Collector struct {
	Gateway    Component
	PublicURL  string
	Appliance  string
	Services   []Probe
	ThirdParty []Probe
	// GatewayDependencies gives the gateway's own readiness by dependency.
	GatewayDependencies func(context.Context) []Dependency
	Now                 func() time.Time
	// Log gets one debug line per collection; nil logs nothing.
	Log log.Logger

	mu     sync.Mutex
	cached *Report
	at     time.Time
}

// Report returns the cached report, or collects a new one when the cache is
// older than CacheTTL. Concurrent callers share one collection.
func (c *Collector) Report(ctx context.Context) Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.cached != nil && now.Sub(c.at) < CacheTTL {
		c.trace(ctx, "diagnostics: cached report", log.F("age_ms", now.Sub(c.at).Milliseconds()))
		return *c.cached
	}
	started := time.Now()
	r := c.collect(context.WithoutCancel(ctx), now)
	c.cached, c.at = &r, now
	if c.Log != nil {
		var down []string
		for _, comp := range append(slices.Clone(r.Services), r.ThirdParty...) {
			if comp.Status == StatusUnavailable {
				down = append(down, comp.Name)
			}
		}
		c.Log.Ctx(ctx).Debug("diagnostics: collected", log.F("ms", time.Since(started).Milliseconds()), log.F("unavailable", down))
	}
	return r
}

func (c *Collector) trace(ctx context.Context, msg string, fields ...log.Field) {
	if c.Log != nil {
		log.Trace(c.Log.Ctx(ctx), msg, fields...)
	}
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Collector) collect(ctx context.Context, now time.Time) Report {
	ctx, cancel := context.WithTimeout(ctx, collectTimeout)
	defer cancel()
	services := runAll(ctx, c.Services)
	third := runAll(ctx, c.ThirdParty)
	for _, d := range sharedDeps {
		third = append(third, depEntries(services, d.name, d.expected)...)
	}
	gw := c.Gateway
	gw.Version, gw.Commit = clean(gw.Version), clean(gw.Commit)
	if c.GatewayDependencies != nil {
		gw.Dependencies = c.GatewayDependencies(ctx)
	}
	return Report{
		GeneratedAt: now.UTC(),
		PublicURL:   origin(c.PublicURL),
		Appliance:   cleanOptional(c.Appliance),
		Gateway:     gw,
		Services:    services,
		ThirdParty:  third,
	}
}

// runAll runs the probes in parallel, keeping their order.
func runAll(ctx context.Context, probes []Probe) []Component {
	out := make([]Component, len(probes))
	var wg sync.WaitGroup
	for i, p := range probes {
		wg.Go(func() {
			pctx, cancel := context.WithTimeout(ctx, probeTimeout)
			defer cancel()
			comp := p(pctx)
			comp.Version, comp.Commit = clean(comp.Version), clean(comp.Commit)
			if comp.Status == StatusUnavailable || comp.Status == StatusNotConfigured {
				comp.Version, comp.Commit = "", ""
			}
			out[i] = comp
		})
	}
	wg.Wait()
	return out
}

// depEntries turns the services' reports of one dependency into entries: one
// per distinct version, so services that disagree are all shown.
func depEntries(services []Component, name string, expected bool) []Component {
	var versions []string
	for _, s := range services {
		if v := cleanOptional(s.deps[name]); v != "" && !slices.Contains(versions, v) {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		if expected {
			return []Component{{Name: name, Version: Unknown, Status: StatusUnavailable}}
		}
		return []Component{{Name: name, Status: StatusNotConfigured}}
	}
	out := make([]Component, 0, len(versions))
	for _, v := range versions {
		out = append(out, Component{Name: name, Version: v, Status: StatusOK})
	}
	return out
}

// versionPattern is what a version or commit may look like: a tag, a semver,
// a short or full SHA. Anything else (spaces, markup, URLs, multi-line text)
// is dropped rather than echoed.
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// clean returns s when it looks like a version, and Unknown otherwise.
func clean(s string) string {
	if v := cleanOptional(s); v != "" {
		return v
	}
	return Unknown
}

// cleanOptional returns s when it looks like a version, and "" otherwise.
func cleanOptional(s string) string {
	if versionPattern.MatchString(s) {
		return s
	}
	return ""
}

var (
	depNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	depStates      = []string{DepOK, DepDegraded, DepDown}
	depErrors      = []string{"timeout", "refused", "unavailable", "unauthenticated", "error"}
)

// parseDependencies reads a sneakers-health header. Entries with a name or
// state outside the allow-list are dropped, an error that isn't a known class
// becomes "error", and a version that isn't clean is left out. A header that
// isn't JSON gives nil.
func parseDependencies(raw string) []Dependency {
	var h struct {
		Dependencies []Dependency `json:"dependencies"`
	}
	if raw == "" || json.Unmarshal([]byte(raw), &h) != nil {
		return nil
	}
	out := []Dependency{}
	for _, d := range h.Dependencies {
		if !depNamePattern.MatchString(d.Name) || !slices.Contains(depStates, d.State) {
			continue
		}
		e := ""
		if d.State != DepOK {
			e = "error"
			if slices.Contains(depErrors, d.Error) {
				e = d.Error
			}
		}
		out = append(out, Dependency{Name: d.Name, State: d.State, Required: d.Required, Error: e, Version: cleanOptional(d.Version)})
	}
	return out
}

// origin reduces a configured public URL to its scheme and host, dropping any
// credentials, path, query and fragment.
func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
