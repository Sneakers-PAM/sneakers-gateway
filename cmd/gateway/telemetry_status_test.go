// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/grpcbuildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

const peerErrorText = "dial tcp 192.0.2.7:9091: connection refused"

func pass(context.Context) error { return nil }
func fail(context.Context) error { return errors.New("collector down") }

// otlpChecker is a checker with an otlp dependency running check. A nil check
// gives a checker with no otlp dependency.
func otlpChecker(t *testing.T, check func(context.Context) error) *health.Checker {
	t.Helper()
	deps := []health.Dependency{{Name: "postgres", Check: pass}}
	if check != nil {
		deps = append(deps, health.Dependency{Name: "otlp", Check: check})
	}
	return testChecker(t, deps...)
}

// peerConn dials an in-process gRPC service that reports through go-buildinfo
// exactly as the Sneakers-PAM services do. intercept, when set, runs ahead of
// it, to refuse or hold the health call.
func peerConn(t *testing.T, c *health.Checker, intercept grpc.UnaryServerInterceptor) grpc.ClientConnInterface {
	t.Helper()
	hs := grpchealth.NewServer()
	opts := []grpcbuildinfo.Option{grpcbuildinfo.WithPrefix(headerPrefix), grpcbuildinfo.WithHealthServer(hs)}
	if c != nil {
		opts = append(opts, grpcbuildinfo.WithChecker(c))
	}
	bi, err := grpcbuildinfo.New(opts...)
	if err != nil {
		t.Fatal(err)
	}
	chain := []grpc.UnaryServerInterceptor{bi.UnaryServerInterceptor()}
	if intercept != nil {
		chain = append([]grpc.UnaryServerInterceptor{intercept}, chain...)
	}
	s := grpc.NewServer(grpc.ChainUnaryInterceptor(chain...))
	healthpb.RegisterHealthServer(s, hs)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return dial(t, lis.Addr().String())
}

func dial(t *testing.T, addr string) grpc.ClientConnInterface {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// mcpServer serves go-buildinfo's /readyz and /livez, as the MCP server does.
func mcpServer(t *testing.T, c *health.Checker) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if err := mountHealth(mux, c); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

type telemetryBody struct {
	Services []struct {
		Name      string `json:"name"`
		State     string `json:"state"`
		CheckedAt string `json:"checkedAt"`
	} `json:"services"`
}

// readStatus starts the rollup over sources, polling the route until every
// entry has been checked at least once.
func readStatus(t *testing.T, s telemetrySources) (telemetryBody, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := startTelemetryStatus(ctx, log.Nop(), s, health.WithTTL(50*time.Millisecond), health.WithTimeout(200*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	h := telemetryStatusHandler(c, log.Nop())
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/telemetry-status", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		var b telemetryBody
		if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		done := len(b.Services) > 0
		for _, e := range b.Services {
			done = done && e.CheckedAt != ""
		}
		if done {
			return b, rec.Body.String()
		}
		if time.Now().After(deadline) {
			t.Fatalf("never fully checked: %s", rec.Body)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func stateOf(t *testing.T, b telemetryBody, name string) string {
	t.Helper()
	for _, e := range b.Services {
		if e.Name == name {
			return e.State
		}
	}
	t.Fatalf("%s isn't in the answer: %+v", name, b)
	return ""
}

func TestTelemetryStatus_ListsEveryWorkloadInOrder(t *testing.T) {
	b, _ := readStatus(t, telemetrySources{})
	var names []string
	for _, e := range b.Services {
		names = append(names, e.Name)
		if _, err := time.Parse(time.RFC3339, e.CheckedAt); err != nil {
			t.Fatalf("%s checkedAt = %q", e.Name, e.CheckedAt)
		}
	}
	want := "identity,vault,workflow,audit,notify,connector,sshbroker,gateway,mcp"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("names = %s", got)
	}
}

func TestTelemetryStatus_ReadsAPeersOTLPDependency(t *testing.T) {
	b, _ := readStatus(t, telemetrySources{services: diagServices{
		identity: peerConn(t, otlpChecker(t, pass), nil),
		vault:    peerConn(t, otlpChecker(t, fail), nil),
		workflow: peerConn(t, otlpChecker(t, nil), nil),
		audit:    peerConn(t, nil, nil),
	}})
	for name, want := range map[string]string{"identity": "sending", "vault": "issue", "workflow": "off", "audit": "off"} {
		if got := stateOf(t, b, name); got != want {
			t.Errorf("%s = %s, want %s", name, got, want)
		}
	}
}

func TestTelemetryStatus_APeerThatIsNotServingStillReports(t *testing.T) {
	c := testChecker(t,
		health.Dependency{Name: "postgres", Required: true, Check: fail},
		health.Dependency{Name: "otlp", Check: pass})
	b, _ := readStatus(t, telemetrySources{services: diagServices{identity: peerConn(t, c, nil)}})
	if got := stateOf(t, b, "identity"); got != "sending" {
		t.Fatalf("identity = %s, want sending", got)
	}
}

func TestTelemetryStatus_APeerItCantReadIsUnknownWithoutItsText(t *testing.T) {
	refuse := func(context.Context, any, *grpc.UnaryServerInfo, grpc.UnaryHandler) (any, error) {
		return nil, status.Error(codes.PermissionDenied, peerErrorText)
	}
	hang := func(ctx context.Context, _ any, _ *grpc.UnaryServerInfo, _ grpc.UnaryHandler) (any, error) {
		<-ctx.Done()
		return nil, status.Error(codes.Unavailable, peerErrorText)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := lis.Addr().String()
	_ = lis.Close()

	start := time.Now()
	b, raw := readStatus(t, telemetrySources{services: diagServices{
		identity: peerConn(t, otlpChecker(t, pass), refuse),
		vault:    peerConn(t, otlpChecker(t, pass), hang),
		workflow: dial(t, closed),
		audit:    peerConn(t, otlpChecker(t, pass), nil),
	}})
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("a hanging peer held the read for %v", took)
	}
	for _, name := range []string{"identity", "vault", "workflow", "notify"} {
		if got := stateOf(t, b, name); got != "unknown" {
			t.Errorf("%s = %s, want unknown", name, got)
		}
	}
	if got := stateOf(t, b, "audit"); got != "sending" {
		t.Errorf("audit = %s, want sending", got)
	}
	if strings.Contains(raw, "192.0.2.7") || strings.Contains(raw, "refused") || strings.Contains(raw, "127.0.0.1") {
		t.Fatalf("the answer carries peer text: %s", raw)
	}
}

func TestTelemetryStatus_ConnectorThatCantBeCalledYetIsUnknown(t *testing.T) {
	if got := stateOf(t, first(readStatus(t, telemetrySources{})), "connector"); got != "unknown" {
		t.Fatalf("no address: connector = %s", got)
	}
	denied := func(context.Context, any, *grpc.UnaryServerInfo, grpc.UnaryHandler) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "caller not allowed")
	}
	if got := stateOf(t, first(readStatus(t, telemetrySources{connector: peerConn(t, otlpChecker(t, pass), denied)})), "connector"); got != "unknown" {
		t.Fatalf("refused: connector = %s", got)
	}
	if got := stateOf(t, first(readStatus(t, telemetrySources{connector: peerConn(t, otlpChecker(t, pass), nil)})), "connector"); got != "sending" {
		t.Fatalf("reachable: connector = %s", got)
	}
}

func first(b telemetryBody, _ string) telemetryBody { return b }

func TestTelemetryStatus_MCP(t *testing.T) {
	readMCP := func(url string) string {
		return stateOf(t, first(readStatus(t, telemetrySources{mcpHealthURL: url})), "mcp")
	}
	if got := readMCP(""); got != "off" {
		t.Errorf("no url: mcp = %s, want off", got)
	}
	// MCP_HEALTH_URL names /livez, whose report has no dependencies; the state
	// comes from /readyz on the same host.
	sending := mcpServer(t, otlpChecker(t, pass))
	if got := readMCP(sending.URL + "/livez"); got != "sending" {
		t.Errorf("otlp ok: mcp = %s, want sending", got)
	}
	failing := mcpServer(t, otlpChecker(t, fail))
	if got := readMCP(failing.URL + "/livez"); got != "issue" {
		t.Errorf("otlp failing: mcp = %s, want issue", got)
	}
	noOTLP := mcpServer(t, otlpChecker(t, nil))
	if got := readMCP(noOTLP.URL + "/livez"); got != "off" {
		t.Errorf("no otlp: mcp = %s, want off", got)
	}
	notReady := mcpServer(t, testChecker(t,
		health.Dependency{Name: "gateway", Required: true, Check: fail},
		health.Dependency{Name: "otlp", Check: pass}))
	if got := readMCP(notReady.URL + "/livez"); got != "sending" {
		t.Errorf("not ready: mcp = %s, want sending", got)
	}
	stranger := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(stranger.Close)
	if got := readMCP(stranger.URL + "/livez"); got != "unknown" {
		t.Errorf("an answer that isn't a report: mcp = %s, want unknown", got)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	if got := readMCP(gone.URL + "/livez"); got != "unknown" {
		t.Errorf("unreachable: mcp = %s, want unknown", got)
	}
}

func TestTelemetryStatus_Gateway(t *testing.T) {
	for want, c := range map[string]*health.Checker{
		"sending": otlpChecker(t, pass),
		"issue":   otlpChecker(t, fail),
		"off":     otlpChecker(t, nil),
	} {
		if got := stateOf(t, first(readStatus(t, telemetrySources{gateway: c})), "gateway"); got != want {
			t.Errorf("gateway = %s, want %s", got, want)
		}
	}
}

func TestTelemetryStatus_IsGetOnlyAndNeverCached(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := startTelemetryStatus(ctx, log.Nop(), telemetrySources{})
	if err != nil {
		t.Fatal(err)
	}
	h := telemetryStatusHandler(c, log.Nop())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/telemetry-status", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/telemetry-status", nil))
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers = %v", rec.Header())
	}
}

func TestHealthDeps_OTLPOnlyWithAnEndpoint(t *testing.T) {
	if _, ok := depsOf(healthDeps(func(string) string { return "" }, "noauth", diagServices{}, nil))["otlp"]; ok {
		t.Fatal("otlp registered with no endpoint")
	}
	deps := healthDeps(func(k string) string {
		if k == "OTEL_EXPORTER_OTLP_ENDPOINT" {
			return "http://collector.example.org:4317"
		}
		return ""
	}, "noauth", diagServices{}, nil)
	if required, ok := depsOf(deps)["otlp"]; !ok || required {
		t.Fatalf("otlp = required %v, registered %v", required, ok)
	}
}

func TestFailingOTLPDegradesAndKeepsTheGatewayReady(t *testing.T) {
	mux := routes(t, testChecker(t, health.Dependency{Name: "otlp", Check: fail}))
	code, r, hdr, _ := get(t, mux, "/readyz")
	if code != http.StatusOK || r.Status != health.StateDegraded {
		t.Fatalf("code %d status %s", code, r.Status)
	}
	if hdr.Get("Sneakers-Depstate-otlp") != "degraded" {
		t.Fatalf("headers = %v", hdr)
	}
}
