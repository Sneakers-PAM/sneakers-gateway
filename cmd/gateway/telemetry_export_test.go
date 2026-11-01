// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/telemetry"
	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	collectlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectmetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collecttrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

const exportCanary = "canary-7f3a9c1e"

// exportCollector is an in-process OTLP collector for all three signals.
type exportCollector struct {
	mu     sync.Mutex
	traces []*collecttrace.ExportTraceServiceRequest
	all    []string
}

func (c *exportCollector) keep(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.all = append(c.all, s)
}

func (c *exportCollector) received() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.all, "\n")
}

type traceSink struct {
	collecttrace.UnimplementedTraceServiceServer
	c *exportCollector
}

func (s traceSink) Export(_ context.Context, r *collecttrace.ExportTraceServiceRequest) (*collecttrace.ExportTraceServiceResponse, error) {
	s.c.keep(r.String())
	s.c.mu.Lock()
	defer s.c.mu.Unlock()
	s.c.traces = append(s.c.traces, r)
	return &collecttrace.ExportTraceServiceResponse{}, nil
}

type metricSink struct {
	collectmetrics.UnimplementedMetricsServiceServer
	c *exportCollector
}

func (s metricSink) Export(_ context.Context, r *collectmetrics.ExportMetricsServiceRequest) (*collectmetrics.ExportMetricsServiceResponse, error) {
	s.c.keep(r.String())
	return &collectmetrics.ExportMetricsServiceResponse{}, nil
}

type logSink struct {
	collectlogs.UnimplementedLogsServiceServer
	c *exportCollector
}

func (s logSink) Export(_ context.Context, r *collectlogs.ExportLogsServiceRequest) (*collectlogs.ExportLogsServiceResponse, error) {
	s.c.keep(r.String())
	return &collectlogs.ExportLogsServiceResponse{}, nil
}

// spans lists the exported span names, attribute keys and link count, and
// fails on a span that joined the outside trace.
func (c *exportCollector) spans(t *testing.T, outsideTrace string) (names, attrs []string, links int) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range c.traces {
		for _, rs := range r.GetResourceSpans() {
			for _, ss := range rs.GetScopeSpans() {
				for _, s := range ss.GetSpans() {
					names = append(names, s.GetName())
					if hex.EncodeToString(s.GetTraceId()) == outsideTrace {
						t.Errorf("an outside traceparent parented span %q", s.GetName())
					}
					links += len(s.GetLinks())
					for _, a := range s.GetAttributes() {
						attrs = append(attrs, a.GetKey())
					}
				}
			}
		}
	}
	return names, attrs, links
}

func listen(t *testing.T, s *grpc.Server) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return lis.Addr().String()
}

// startBackend is a gRPC peer whose every method fails with text holding the
// canary, as a backend echoing a secret would.
func startBackend(t *testing.T, seen *metadata.MD) string {
	t.Helper()
	s := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, st grpc.ServerStream) error {
		*seen, _ = metadata.FromIncomingContext(st.Context())
		return status.Error(grpccodes.NotFound, exportCanary)
	}))
	return listen(t, s)
}

// canaryHandler puts the canary everywhere a handler can, then calls a backend
// that answers with it.
func canaryHandler(t *testing.T, cc *grpc.ClientConn) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanFromContext(r.Context())
		span.RecordError(errors.New(exportCanary))
		span.SetStatus(codes.Error, exportCanary)
		span.SetAttributes(attribute.String("canary.attr", exportCanary))
		if b := baggage.FromContext(r.Context()); b.Len() != 0 {
			t.Errorf("baggage came in: %v", b)
		}
		var out emptypb.Empty
		if err := cc.Invoke(r.Context(), "/sneakers.vault.v1.VaultService/GetSecret", &emptypb.Empty{}, &out); err == nil {
			t.Error("the backend should refuse")
		}
		if err := cc.Invoke(r.Context(), "/sneakers.vault.v1."+exportCanary+"/Get", &emptypb.Empty{}, &out); err == nil {
			t.Error("the backend should refuse")
		}
		_, inner := otelapi.Tracer("test").Start(r.Context(), "SELECT "+exportCanary)
		inner.End()
		w.WriteHeader(http.StatusOK)
	}
}

// TestExport_RealRequestsLeakNothing sends real requests through the gateway's
// own handler stack and reads what an OTLP collector receives. The canary is in
// a span status, an exception, a span name, a metric attribute, a resource
// attribute, tracestate, baggage and a client-chosen method.
func TestExport_RealRequestsLeakNothing(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.canary="+exportCanary)

	c := &exportCollector{}
	col := grpc.NewServer()
	collecttrace.RegisterTraceServiceServer(col, traceSink{c: c})
	collectmetrics.RegisterMetricsServiceServer(col, metricSink{c: c})
	collectlogs.RegisterLogsServiceServer(col, logSink{c: c})
	endpoint := listen(t, col)

	var backendMD metadata.MD
	backend := startBackend(t, &backendMD)
	cc, err := grpc.NewClient(backend,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otel.GRPCClientStatsHandler()))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cc.Close() }()

	cfg := telemetry.Config{Endpoint: endpoint, Logs: true}
	lg := log.NewLoggerWithOptions(serviceName, log.WithOutput(cfg.LogOutput()))
	shutdown, err := otel.InitWithOptions(context.Background(), serviceName, endpoint, cfg.Options()...)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/graphql", canaryHandler(t, cc))
	srv := httptest.NewServer(instrument(lg, mux))
	defer srv.Close()

	const outsideTrace = "0af7651916cd43dd8448eb211c80319c"
	send := func(method, path string) {
		t.Helper()
		req, err := http.NewRequest(method, srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("traceparent", "00-"+outsideTrace+"-b7ad6b7169203331-01")
		req.Header.Set("tracestate", "vendor="+exportCanary)
		req.Header.Set("baggage", "user="+exportCanary)
		req.Header.Set("User-Agent", exportCanary)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	send(http.MethodPost, "/graphql")
	send(http.MethodGet, "/"+exportCanary)
	send(strings.ToUpper(exportCanary), "/graphql?q="+exportCanary)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatal(err)
	}

	got := c.received()
	for _, bad := range []string{exportCanary, strings.ToUpper(exportCanary), "exception", "user_agent", "url.path", "url.full", "client.address", "server.address"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q reached the collector", bad)
		}
	}
	if backendMD.Get("baggage") != nil {
		t.Errorf("baggage went downstream: %v", backendMD.Get("baggage"))
	}

	names, attrs, links := c.spans(t, outsideTrace)
	slices.Sort(attrs)
	t.Logf("span names %q, attributes %q, links %d", names, slices.Compact(attrs), links)
	for _, want := range []string{"POST /graphql", "sneakers.vault.v1.VaultService/GetSecret"} {
		if !slices.Contains(names, want) {
			t.Errorf("span %q didn't arrive: %q", want, names)
		}
	}
	if !strings.Contains(got, "http.request.method") || !strings.Contains(got, "rpc.method") {
		t.Errorf("the allowed attributes didn't arrive: %s", got)
	}
}
