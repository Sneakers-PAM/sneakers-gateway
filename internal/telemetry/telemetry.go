// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry holds the gateway's OTLP export settings: the switches
// read from the environment, the filters on exported logs, the optional otlp
// health dependency and the handler for export errors.
package telemetry

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	otelapi "go.opentelemetry.io/otel"
	"google.golang.org/grpc/status"
)

// DependencyName is the health dependency that reports export state.
const DependencyName = "otlp"

// errorLogWindow limits export error lines: a collector that stays down fails
// every batch, and each line is itself exported while logs are on.
const errorLogWindow = time.Minute

// Config is the telemetry part of the environment.
type Config struct {
	// Endpoint is OTEL_EXPORTER_OTLP_ENDPOINT. Empty means no export.
	Endpoint string
	// InsecureSkipVerify skips the collector's certificate check. go-otel
	// keeps logs off while it's on.
	InsecureSkipVerify bool
	// Logs turns log export on.
	Logs bool
}

// FromEnv reads the telemetry settings. The two switches are on for the exact
// value "true" only.
func FromEnv(getenv func(string) string) Config {
	return Config{
		Endpoint:           getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		InsecureSkipVerify: getenv("OTLP_INSECURE_SKIP_VERIFY") == "true",
		Logs:               getenv("OTLP_LOGS_ENABLED") == "true",
	}
}

// AllowedLogFields are the log fields that may leave the process. Each holds
// an id, a count, a duration, a class, a state or a short enum. Free text,
// addresses and names stay off it: error, reason, host, port, path, target,
// operation (a client chooses it), issuer, the *_url and *_origins fields, the
// backend address fields, folder, requested_folder, matched, identity, the
// fingerprints and the time fields. A new log field exports nothing until
// it's added here.
var AllowedLogFields = []string{
	// ids
	"actor", "actor_user_id", "caller", "client_id", "connection_id", "run_id",
	"secret_id", "session_id", "target_id", "token_id", "use_id", "user_id",
	// counts
	"confirmed", "count", "decided", "folders", "host_keys", "refused", "secrets",
	// durations
	"age_ms", "current", "dur", "duration", "duration_ms", "fallback", "ms", "session_ttl",
	// classes, states and short enums
	"action", "auth_mode", "check", "class", "client_kind", "code", "decision",
	"dependency", "error_class", "from", "method", "ok", "outcome", "required",
	"route", "rule", "sso_reason", "state", "status", "step", "to", "workload",
	// switches
	"appliance_configmap", "approval_run_links", "cookie_secure", "hydra_enabled",
	"machine_api_enabled", "maintenance_readonly", "mcp_clients", "mcp_enabled",
}

// tokenPattern is the shape of a Sneakers token.
var tokenPattern = regexp.MustCompile(`\bsnk_[A-Za-z0-9_\-]+`)

// Options are the go-otel options for this configuration.
func (c Config) Options() []otel.Option {
	return []otel.Option{
		otel.WithInsecureSkipVerify(c.InsecureSkipVerify),
		otel.WithLogs(c.Logs),
		otel.WithLogAllowFields(AllowedLogFields...),
		otel.WithLogRedactPatterns(tokenPattern),
	}
}

// LogOutput is the writer for go-log's WithOutput: stdout plus the export
// writer with logs on, nil with them off, which leaves the logger as it was.
// go-otel's writer discards everything until Init, so the logger can be built
// first.
func (c Config) LogOutput() io.Writer {
	if !c.Logs {
		return nil
	}
	return io.MultiWriter(os.Stdout, otel.LogWriter())
}

var errExportFailing = errors.New("otlp export failing")

// OTLPDependency is the optional otlp health dependency, registered only when
// there's an endpoint. It fails while the last export of a signal failed, so
// a collector that's down degrades the gateway and never makes it not ready.
func OTLPDependency(c Config) (health.Dependency, bool) {
	if c.Endpoint == "" {
		return health.Dependency{}, false
	}
	return health.Dependency{Name: DependencyName, Check: func(context.Context) error {
		s := otel.ExportState()
		if failing(s.Traces) || failing(s.Metrics) || s.Logs.Disabled == "" && failing(s.Logs) {
			return errExportFailing
		}
		return nil
	}}, true
}

func failing(s otel.SignalStatus) bool { return s.LastErrorAt.After(s.LastSuccess) }

// SetErrorHandler sends OpenTelemetry's errors through lg instead of stderr.
// An export error's text names the endpoint and can carry its headers, so
// only the gRPC code is logged, at most once per errorLogWindow.
func SetErrorHandler(lg log.Logger) {
	var last atomic.Int64
	otelapi.SetErrorHandler(otelapi.ErrorHandlerFunc(func(err error) {
		now := time.Now().UnixNano()
		prev := last.Load()
		if prev != 0 && now-prev < int64(errorLogWindow) || !last.CompareAndSwap(prev, now) {
			return
		}
		lg.Warn("telemetry export failed", log.F("code", status.Code(err).String()))
	}))
}
