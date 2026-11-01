// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/telemetry"
	otelapi "go.opentelemetry.io/otel"
	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// collector is an in-process OTLP collector that keeps what logs it receives
// and answers traces with traceErr.
type collector struct {
	collectlogs.UnimplementedLogsServiceServer
	collecttrace.UnimplementedTraceServiceServer
	traceErr error

	mu      sync.Mutex
	records []string
}

func (c *collector) Export(_ context.Context, r *collectlogs.ExportLogsServiceRequest) (*collectlogs.ExportLogsServiceResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, r.String())
	return &collectlogs.ExportLogsServiceResponse{}, nil
}

func (c *collector) received() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.records, "\n")
}

type traceService struct {
	collecttrace.UnimplementedTraceServiceServer
	c *collector
}

func (s traceService) Export(context.Context, *collecttrace.ExportTraceServiceRequest) (*collecttrace.ExportTraceServiceResponse, error) {
	return &collecttrace.ExportTraceServiceResponse{}, s.c.traceErr
}

func startCollector(t *testing.T, c *collector) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	collectlogs.RegisterLogsServiceServer(s, c)
	collecttrace.RegisterTraceServiceServer(s, traceService{c: c})
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return "http://" + lis.Addr().String()
}

func getenv(vars map[string]string) func(string) string {
	return func(k string) string { return vars[k] }
}

func TestFromEnv_OnlyTrueTurnsASwitchOn(t *testing.T) {
	for _, v := range []string{"", "1", "TRUE", "yes", " true"} {
		c := telemetry.FromEnv(getenv(map[string]string{"OTLP_LOGS_ENABLED": v, "OTLP_INSECURE_SKIP_VERIFY": v}))
		if c.Logs || c.InsecureSkipVerify {
			t.Fatalf("%q turned a switch on: %+v", v, c)
		}
	}
	c := telemetry.FromEnv(getenv(map[string]string{"OTLP_LOGS_ENABLED": "true", "OTLP_INSECURE_SKIP_VERIFY": "true", "OTEL_EXPORTER_OTLP_ENDPOINT": "https://collector.example.org:4317"}))
	if !c.Logs || !c.InsecureSkipVerify || c.Endpoint != "https://collector.example.org:4317" {
		t.Fatalf("config = %+v", c)
	}
}

func TestLogOutput_UnsetLeavesTheLoggerAlone(t *testing.T) {
	if w := (telemetry.Config{}).LogOutput(); w != nil {
		t.Fatalf("logs off gave an output: %v", w)
	}
}

func TestLogOutput_KeepsStdout(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	out := telemetry.Config{Logs: true}.LogOutput()
	os.Stdout = stdout
	if _, err := out.Write([]byte("{\"level\":\"info\",\"message\":\"m\"}\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	got, _ := io.ReadAll(r)
	if !bytes.Contains(got, []byte(`"message":"m"`)) {
		t.Fatalf("stdout got %q", got)
	}
}

func TestOTLPDependency_OnlyWithAnEndpoint(t *testing.T) {
	if _, ok := telemetry.OTLPDependency(telemetry.Config{}); ok {
		t.Fatal("a dependency with no endpoint")
	}
	d, ok := telemetry.OTLPDependency(telemetry.Config{Endpoint: "http://collector.example.org:4317"})
	if !ok || d.Name != "otlp" || d.Required || d.Check == nil {
		t.Fatalf("dependency = %+v, %v", d, ok)
	}
}

func TestOTLPDependency_AFailingCollectorFailsTheOptionalCheck(t *testing.T) {
	c := &collector{traceErr: status.Error(codes.PermissionDenied, "collector.example.org refused")}
	endpoint := startCollector(t, c)
	shutdown, err := otel.Init(context.Background(), "gateway", endpoint)
	if err != nil {
		t.Fatal(err)
	}
	cfg := telemetry.Config{Endpoint: endpoint}
	d, _ := telemetry.OTLPDependency(cfg)
	if err := d.Check(context.Background()); err != nil {
		t.Fatalf("before any export: %v", err)
	}
	_, span := otelapi.Tracer("test").Start(context.Background(), "span")
	span.End()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = shutdown(ctx)

	err = d.Check(context.Background())
	if err == nil {
		t.Fatal("a failing collector passed the check")
	}
	if strings.Contains(err.Error(), "collector.example.org") || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("the check carries export text: %v", err)
	}
}

func TestExportedLogs_OnlyTheAllowedFieldsLeave(t *testing.T) {
	const canary = "canary-7f3a9c1e"
	c := &collector{}
	endpoint := startCollector(t, c)
	cfg := telemetry.Config{Endpoint: endpoint, Logs: true}
	// The logger is built first, as main builds it: the writer is a no-op
	// until Init.
	lg := log.NewLoggerWithOptions("gateway", log.WithOutput(cfg.LogOutput()))
	lg.Info("before init", log.F("user_id", "early-line"))
	shutdown, err := otel.InitWithOptions(context.Background(), "gateway", endpoint, cfg.Options()...)
	if err != nil {
		t.Fatal(err)
	}
	lg.Warn("smoke read failed",
		log.F("user_id", "01J0000000000000000000USER"),
		log.F("count", 3),
		log.F("error", canary),
		log.F("host", canary),
		log.F("path", canary),
		log.F("reason", canary),
		log.F("operation", canary),
		log.F("not_on_the_list", canary),
		log.F("code", "snk_"+canary))
	lg.Debug("below the floor", log.F("user_id", "debug-line"))
	// main's start-up logger: the same writer, in zerolog's API.
	startup := log.Ctx(context.Background()) //nolint:staticcheck // as main gets it
	startup.Info().Str("auth_mode", "zerolog-line").Msg("start-up line")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	got := c.received()
	if !strings.Contains(got, "smoke read failed") || !strings.Contains(got, "01J0000000000000000000USER") || !strings.Contains(got, "zerolog-line") {
		t.Fatalf("the allowed line didn't arrive: %q", got)
	}
	for _, bad := range []string{canary, "debug-line", "early-line"} {
		if strings.Contains(got, bad) {
			t.Fatalf("%q reached the collector: %s", bad, got)
		}
	}
}

func TestErrorHandler_AfterInitReplacesTheFilters(t *testing.T) {
	var buf bytes.Buffer
	lg := log.NewLoggerWithOptions("gateway", log.WithOutput(&buf))
	cfg := telemetry.Config{}
	shutdown, err := otel.InitWithOptions(context.Background(), "gateway", "", cfg.Options()...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = shutdown(context.Background()) }()
	telemetry.SetErrorHandler(lg)
	t.Cleanup(func() { otelapi.SetErrorHandler(otelapi.ErrorHandlerFunc(func(error) {})) })

	otelapi.Handle(status.Error(codes.Unavailable, "dial collector.example.org"))
	if got := buf.String(); !strings.Contains(got, "telemetry export failed") || strings.Contains(got, "collector.example.org") {
		t.Fatalf("log = %q", got)
	}
}

func TestAllowedLogFields_HoldNoFreeText(t *testing.T) {
	for _, f := range []string{"error", "host", "port", "path", "target", "reason", "operation", "method", "outcome", "issuer", "otlp", "oauth_public_url", "allowed_origins", "folder", "requested_folder", "identity", "matched"} {
		if slices.Contains(telemetry.AllowedLogFields, f) {
			t.Fatalf("%q can hold free text or an address and is on the list", f)
		}
	}
}

func TestErrorHandler_LogsTheCodeNotTheText(t *testing.T) {
	var buf bytes.Buffer
	lg := log.NewLoggerWithOptions("gateway", log.WithOutput(&buf))
	telemetry.SetErrorHandler(lg)
	t.Cleanup(func() { otelapi.SetErrorHandler(otelapi.ErrorHandlerFunc(func(error) {})) })

	wrapped := errors.Join(errors.New("traces export: https://user:pw@collector.example.org:4317 x-api-key=abc"), status.Error(codes.Unavailable, "dial collector.example.org"))
	otelapi.Handle(wrapped)
	otelapi.Handle(wrapped) // a second failure inside the window writes nothing

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %q", lines)
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &line); err != nil {
		t.Fatal(err)
	}
	if line["code"] != "Unavailable" {
		t.Fatalf("line = %v", line)
	}
	for _, bad := range []string{"collector.example.org", "x-api-key", "pw@"} {
		if strings.Contains(lines[0], bad) {
			t.Fatalf("%q in %s", bad, lines[0])
		}
	}
}
