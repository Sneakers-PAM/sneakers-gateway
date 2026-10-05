// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package health is the gateway's readiness and liveness. Readiness follows
// the dependencies the gateway can't serve without (required) and reports the
// rest as degraded; liveness checks the process only, so an outage never
// restarts the gateway. Results are cached for CacheTTL so probes don't load
// the dependencies, and only fixed tokens leave the package: a dependency's
// name, its state and an error class, never the error text.
package health

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// CacheTTL is how long a set of check results is reused.
const CacheTTL = 5 * time.Second

// DefaultTimeout bounds each dependency check.
const DefaultTimeout = time.Second

// The states of a dependency and of the whole report.
const (
	StateOK       = "ok"
	StateDegraded = "degraded"
	StateDown     = "down"
)

// The error classes a failed check is reported as.
const (
	ClassTimeout         = "timeout"
	ClassRefused         = "refused"
	ClassUnavailable     = "unavailable"
	ClassUnauthenticated = "unauthenticated"
	ClassError           = "error"
)

// Dep is one dependency. Check must be cheap; it runs with the checker's
// timeout. Version, when set, gives the dependency's version for the report.
type Dep struct {
	Name     string
	Required bool
	Check    func(context.Context) error
	Version  func() string
}

// DepState is one dependency's entry in a report.
type DepState struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	Required  bool   `json:"required"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checkedAt,omitempty"`
	Version   string `json:"version,omitempty"`
}

// Report is the readiness answer, the body of /readyz.
type Report struct {
	Status       string     `json:"status"`
	Dependencies []DepState `json:"dependencies,omitempty"`
}

// Checker runs the dependency checks and caches the result.
type Checker struct {
	Deps    []Dep
	Timeout time.Duration
	Now     func() time.Time
	// Log gets one line per dependency state change; nil logs nothing.
	Log log.Logger

	mu     sync.Mutex
	cached *Report
	at     time.Time
	last   map[string]string
}

// Report returns the cached result, or checks every dependency again when it
// is older than CacheTTL. Concurrent callers share one run.
func (c *Checker) Report(ctx context.Context) Report {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.cached != nil && now.Sub(c.at) < CacheTTL {
		return *c.cached
	}
	r := c.run(context.WithoutCancel(ctx), now)
	c.cached, c.at = &r, now
	return r
}

func (c *Checker) run(ctx context.Context, now time.Time) Report {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	errs := make([]error, len(c.Deps))
	var wg sync.WaitGroup
	for i, d := range c.Deps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			errs[i] = d.Check(cctx)
		}()
	}
	wg.Wait()

	r := Report{Status: StateOK, Dependencies: make([]DepState, 0, len(c.Deps))}
	for i, d := range c.Deps {
		s := DepState{Name: d.Name, State: StateOK, Required: d.Required, CheckedAt: now.UTC().Format(time.RFC3339)}
		if d.Version != nil {
			s.Version = d.Version()
		}
		if errs[i] != nil {
			s.Error = Classify(errs[i])
			s.State = StateDegraded
			if d.Required {
				s.State = StateDown
			}
		}
		switch {
		case s.State == StateDown:
			r.Status = StateDown
		case s.State == StateDegraded && r.Status == StateOK:
			r.Status = StateDegraded
		}
		c.logChange(ctx, s)
		r.Dependencies = append(r.Dependencies, s)
	}
	return r
}

func (c *Checker) logChange(ctx context.Context, s DepState) {
	if c.last == nil {
		c.last = map[string]string{}
	}
	prev, seen := c.last[s.Name]
	c.last[s.Name] = s.State
	if c.Log == nil || prev == s.State || (!seen && s.State == StateOK) {
		return
	}
	fields := []log.Field{log.F("dependency", s.Name), log.F("required", s.Required), log.F("state", s.State)}
	if s.State == StateOK {
		c.Log.Ctx(ctx).Info("health: dependency recovered", fields...)
		return
	}
	c.Log.Ctx(ctx).Warn("health: dependency failing", append(fields, log.F("error_class", s.Error))...)
}

func (c *Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Readyz answers 200 while every required dependency is up (ok or degraded)
// and 503 while one is down; the body is the Report.
func (c *Checker) Readyz() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rep := c.Report(r.Context())
		code := http.StatusOK
		if rep.Status == StateDown {
			code = http.StatusServiceUnavailable
		}
		writeJSON(w, code, rep)
	})
}

// Livez answers 200 whenever the process can answer; it checks nothing.
func (c *Checker) Livez() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, Report{Status: StateOK})
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// StatusError is an HTTP check's non-success answer.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return "status " + strconv.Itoa(e.Code) }

// Classify reduces a check's error to one of the fixed classes, so no error
// text (with its addresses or credentials) is ever reported.
func Classify(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return ClassTimeout
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return ClassRefused
	}
	var se *StatusError
	if errors.As(err, &se) {
		if se.Code == http.StatusUnauthorized || se.Code == http.StatusForbidden {
			return ClassUnauthenticated
		}
		return ClassError
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.DeadlineExceeded:
			return ClassTimeout
		case codes.Unavailable:
			return ClassUnavailable
		case codes.Unauthenticated, codes.PermissionDenied:
			return ClassUnauthenticated
		}
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return ClassTimeout
		}
		return ClassUnavailable
	}
	return ClassError
}

// errNotServing is a peer that answered its health check as not ready.
var errNotServing = status.Error(codes.Unavailable, "not serving")

// GRPC checks a peer through its standard health check (readiness).
func GRPC(conn grpc.ClientConnInterface) func(context.Context) error {
	return func(ctx context.Context) error {
		resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
		if err != nil {
			return err
		}
		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			return errNotServing
		}
		return nil
	}
}

// HTTP checks that a GET of url answers 2xx.
func HTTP(client *http.Client, url string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return &StatusError{Code: resp.StatusCode}
		}
		return nil
	}
}
