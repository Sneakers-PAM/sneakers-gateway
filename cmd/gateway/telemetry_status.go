// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/Bugs5382/go-buildinfo/grpcbuildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/telemetry"
	"google.golang.org/grpc"
)

// A workload's export state on /telemetry-status.
const (
	telemetrySending = "sending"
	telemetryIssue   = "issue"
	telemetryOff     = "off"
	telemetryUnknown = "unknown"
)

// telemetrySources is what the rollup reads. A nil connection reads unknown.
type telemetrySources struct {
	services  diagServices
	connector grpc.ClientConnInterface
	// gateway is the gateway's own checker.
	gateway *health.Checker
	// mcpHealthURL is MCP_HEALTH_URL. Empty reads off.
	mcpHealthURL string
}

// startTelemetryStatus keeps each workload's state in a go-buildinfo checker,
// refreshed in the background like the gateway's own: the route only reads
// the last results, so a peer that hangs never holds it. A state other than
// sending is the check's error class, so nothing but a class reaches the
// answer.
func startTelemetryStatus(ctx context.Context, lg log.Logger, s telemetrySources, opts ...health.Option) (*health.Checker, error) {
	httpc := &http.Client{Timeout: checkTimeout}
	workloads := []struct {
		name string
		read func(context.Context) string
	}{
		{"identity", peerTelemetry("identity", s.services.identity, lg)},
		{"vault", peerTelemetry("vault", s.services.vault, lg)},
		{"workflow", peerTelemetry("workflow", s.services.workflow, lg)},
		{"audit", peerTelemetry("audit", s.services.audit, lg)},
		{"notify", peerTelemetry("notify", s.services.notify, lg)},
		{"connector", peerTelemetry("connector", s.connector, lg)},
		{"sshbroker", peerTelemetry("sshbroker", s.services.sshbroker, lg)},
		{"gateway", gatewayTelemetry(s.gateway)},
		{"mcp", mcpTelemetry(httpc, s.mcpHealthURL, lg)},
	}
	deps := make([]health.Dependency, 0, len(workloads))
	for _, w := range workloads {
		deps = append(deps, health.Dependency{Name: w.name, Check: telemetryCheck(w.name, w.read, lg)})
	}
	return startChecker(ctx, log.Nop(), deps, opts...)
}

func telemetryCheck(name string, read func(context.Context) string, lg log.Logger) func(context.Context) error {
	var last atomic.Value
	return func(ctx context.Context) error {
		state := read(ctx)
		if prev := last.Swap(state); prev != state {
			lg.Debug("telemetry state changed", log.F("workload", name), log.F("to", state))
		}
		if state == telemetrySending {
			return nil
		}
		return health.Classify(errors.New(state), state)
	}
}

// peerTelemetry reads a service's otlp dependency from its health check's
// headers. A peer that answers NOT_SERVING still reports; one that can't be
// read is unknown.
func peerTelemetry(name string, conn grpc.ClientConnInterface, lg log.Logger) func(context.Context) string {
	return func(ctx context.Context) string {
		if conn == nil {
			return telemetryUnknown
		}
		r, err := grpcbuildinfo.Read(ctx, conn, headerPrefix)
		if err != nil {
			lg.Debug("telemetry status: peer not read", log.F("workload", name), log.F("class", classOf(err)))
			return telemetryUnknown
		}
		return otlpState(r.Remote)
	}
}

func otlpState(r health.Remote) string {
	d, ok := r.Dependencies[telemetry.DependencyName]
	if !ok {
		return telemetryOff
	}
	switch d.State {
	case health.StateOK:
		return telemetrySending
	case health.StateDegraded, health.StateDown:
		return telemetryIssue
	}
	return telemetryUnknown
}

func gatewayTelemetry(c *health.Checker) func(context.Context) string {
	return func(ctx context.Context) string {
		if c == nil {
			return telemetryUnknown
		}
		for _, d := range c.Report(ctx).Dependencies {
			switch {
			case d.Name != telemetry.DependencyName:
			case d.Error == health.ClassPending:
				return telemetryUnknown
			case d.State == health.StateOK:
				return telemetrySending
			default:
				return telemetryIssue
			}
		}
		return telemetryOff
	}
}

// mcpTelemetry reads the MCP server's otlp dependency from its /readyz
// headers. MCP_HEALTH_URL names the server's /livez, which carries no
// dependencies, so only its origin is used. /readyz answers 503 with the same
// headers, so the status doesn't decide; a failing answer with no headers at
// all isn't a report.
func mcpTelemetry(client *http.Client, healthURL string, lg log.Logger) func(context.Context) string {
	headers, err := health.NewHeaders(headerPrefix)
	return func(ctx context.Context) string {
		if healthURL == "" {
			return telemetryOff
		}
		if err != nil {
			return telemetryUnknown
		}
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint(originOf(healthURL), "/readyz"), nil) // #nosec G704 -- operator configuration plus a fixed path, never request input
		if rerr != nil {
			return telemetryUnknown
		}
		resp, rerr := client.Do(req) // #nosec G704 -- see above
		if rerr != nil {
			lg.Debug("telemetry status: peer not read", log.F("workload", "mcp"), log.F("class", classOf(rerr)))
			return telemetryUnknown
		}
		_ = resp.Body.Close()
		r := headers.Parse(resp.Header)
		if resp.StatusCode != http.StatusOK && len(r.Headers) == 0 {
			return telemetryUnknown
		}
		return otlpState(r)
	}
}

type telemetryEntry struct {
	Name      string `json:"name"`
	State     string `json:"state"`
	CheckedAt string `json:"checkedAt,omitempty"`
}

// telemetryStatusHandler serves GET /telemetry-status from the rollup's last
// results. It always answers 200: the read reports states, and none of them
// is a failure of the gateway.
func telemetryStatusHandler(c *health.Checker, lg log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		report := c.Report(r.Context())
		out := make([]telemetryEntry, 0, len(report.Dependencies))
		for _, d := range report.Dependencies {
			e := telemetryEntry{Name: d.Name, State: telemetryStateOf(d)}
			if !d.CheckedAt.IsZero() {
				e.CheckedAt = d.CheckedAt.UTC().Format(time.RFC3339)
			}
			out = append(out, e)
		}
		lg.Ctx(r.Context()).Debug("telemetry status read", log.F("count", len(out)))
		writeSmoke(w, http.StatusOK, map[string]any{"services": out})
	})
}

// telemetryStateOf turns a rollup entry back into its state. Any other class
// (a check that timed out or hasn't run) is unknown.
func telemetryStateOf(d health.DependencyReport) string {
	switch d.Error {
	case "":
		return telemetrySending
	case telemetryIssue, telemetryOff:
		return d.Error
	}
	return telemetryUnknown
}
