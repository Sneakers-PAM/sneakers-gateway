// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// healthServer serves the gRPC health service with the given response headers
// on every Check, the way a Sneakers service reports its build.
func healthServer(t *testing.T, headers ...string) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		if len(headers) > 0 {
			_ = grpc.SetHeader(ctx, metadata.Pairs(headers...))
		}
		return h(ctx, req)
	}))
	healthpb.RegisterHealthServer(s, health.NewServer())
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// deadConn is a client for an address nothing listens on.
func deadConn(t *testing.T) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().String()
	_ = lis.Close()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func find(cs []Component, name string) Component {
	for _, c := range cs {
		if c.Name == name {
			return c
		}
	}
	return Component{}
}

func TestGRPCHealth_ReadsBuildHeaders(t *testing.T) {
	conn := healthServer(t, HeaderVersion, "v0.1.0", HeaderCommit, "abc123", HeaderDepPrefix+"postgres", "16.4")
	got := GRPCHealth("vault", conn)(context.Background())
	if got.Status != StatusOK || got.Version != "v0.1.0" || got.Commit != "abc123" {
		t.Fatalf("got %+v, want OK v0.1.0 abc123", got)
	}
	if got.deps["postgres"] != "16.4" {
		t.Fatalf("postgres dep = %q, want 16.4", got.deps["postgres"])
	}
}

func TestGRPCHealth_UnreachableAndUnstamped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if got := GRPCHealth("audit", deadConn(t))(ctx); got.Status != StatusUnavailable || got.Version != "" {
		t.Fatalf("dead service: got %+v, want UNAVAILABLE with no version", got)
	}
	if got := GRPCHealth("notify", healthServer(t))(context.Background()); got.Status != StatusOK || got.Version != "unknown" {
		t.Fatalf("service without build headers: got %+v, want OK and version unknown", got)
	}
	if got := GRPCHealth("connector", nil)(context.Background()); got.Status != StatusNotConfigured {
		t.Fatalf("nil conn: got %+v, want NOT_CONFIGURED", got)
	}
}

func TestHTTPVersion_ReadsField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"version":"v1.3.1","commit":"feedbeef"}`))
	}))
	defer srv.Close()
	got := HTTPVersion("kratos", srv.Client(), srv.URL+"/admin/version")(context.Background())
	if got.Status != StatusOK || got.Version != "v1.3.1" || got.Commit != "feedbeef" {
		t.Fatalf("got %+v", got)
	}
	if got := HTTPVersion("hydra", srv.Client(), srv.URL+"/nope")(context.Background()); got.Status != StatusUnavailable {
		t.Fatalf("404: got %+v, want UNAVAILABLE", got)
	}
	if got := HTTPVersion("polis", srv.Client(), "")(context.Background()); got.Status != StatusNotConfigured {
		t.Fatalf("no URL: got %+v, want NOT_CONFIGURED", got)
	}
}

func TestValkey_ParsesInfo(t *testing.T) {
	info := "# Server\r\nredis_version:7.2.4\r\nvalkey_version:8.1.1\r\nos:Linux\r\n"
	got := Valkey(func(context.Context) (string, error) { return info, nil })(context.Background())
	if got.Status != StatusOK || got.Version != "8.1.1" {
		t.Fatalf("got %+v, want valkey 8.1.1", got)
	}
	got = Valkey(func(context.Context) (string, error) { return "redis_version:7.2.4\r\n", nil })(context.Background())
	if got.Version != "7.2.4" {
		t.Fatalf("redis-only INFO: got %+v, want 7.2.4", got)
	}
	got = Valkey(func(context.Context) (string, error) {
		return "", errors.New("dial tcp valkey.example.test:6379: refused")
	})(context.Background())
	if got.Status != StatusUnavailable || got.Version != "" {
		t.Fatalf("error: got %+v, want UNAVAILABLE", got)
	}
	if got := Valkey(nil)(context.Background()); got.Status != StatusNotConfigured {
		t.Fatalf("nil: got %+v, want NOT_CONFIGURED", got)
	}
}

func TestCollector_ReportAndCache(t *testing.T) {
	var calls atomic.Int32
	vault := func(context.Context) Component {
		calls.Add(1)
		return Component{Name: "vault", Version: "v0.1.0", Commit: "abc", Status: StatusOK, deps: map[string]string{"postgres": "16.4"}}
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	c := &Collector{
		Gateway:   Component{Name: "gateway", Version: "v0.1.0", Commit: "def", Status: StatusOK},
		PublicURL: "https://pam.example.org/some/path?x=1",
		Appliance: "v0.1.0",
		Services:  []Probe{vault},
		Now:       func() time.Time { return now },
	}
	r := c.Report(context.Background())
	if r.PublicURL != "https://pam.example.org" {
		t.Errorf("public URL = %q, want the origin only", r.PublicURL)
	}
	if r.Appliance != "v0.1.0" || r.Gateway.Version != "v0.1.0" {
		t.Errorf("appliance/gateway = %q/%q", r.Appliance, r.Gateway.Version)
	}
	if pg := find(r.ThirdParty, "postgres"); pg.Version != "16.4" || pg.Status != StatusOK {
		t.Errorf("postgres = %+v, want 16.4 from the vault's headers", pg)
	}
	if rb := find(r.ThirdParty, "rabbitmq"); rb.Status != StatusNotConfigured {
		t.Errorf("rabbitmq = %+v, want NOT_CONFIGURED when no service reports a broker", rb)
	}
	c.Report(context.Background())
	if calls.Load() != 1 {
		t.Fatalf("probe ran %d times within the cache window, want 1", calls.Load())
	}
	now = now.Add(CacheTTL + time.Second)
	c.Report(context.Background())
	if calls.Load() != 2 {
		t.Fatalf("probe ran %d times after the cache window, want 2", calls.Load())
	}
}

func TestCollector_NoPostgresReported(t *testing.T) {
	c := &Collector{Services: []Probe{func(context.Context) Component { return Component{Name: "audit", Status: StatusUnavailable} }}}
	if pg := find(c.Report(context.Background()).ThirdParty, "postgres"); pg.Status != StatusUnavailable || pg.Version != "unknown" {
		t.Fatalf("postgres = %+v, want UNAVAILABLE and unknown when no service reports it", pg)
	}
}

// TestReport_NeverCarriesCredentialsOrHosts is the redaction proof: probes
// whose configuration and answers hold credentials, internal hosts and
// arbitrary text still yield a report with none of it.
func TestReport_NeverCarriesCredentialsOrHosts(t *testing.T) {
	const secret = "hunter2-SECRET-VALUE"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"v1 ` + secret + `","commit":"<script>` + secret + `"}`))
	}))
	defer srv.Close()
	leaky := strings.Replace(srv.URL, "http://", "http://admin:"+secret+"@", 1) + "/version?token=" + secret
	conn := healthServer(t, HeaderVersion, "v0.1.0\n"+secret, HeaderCommit, strings.Repeat("a", 200))
	c := &Collector{
		Gateway:   Component{Name: "gateway", Version: "v0.1.0", Status: StatusOK},
		PublicURL: "https://user:" + secret + "@pam.example.org/?session=" + secret,
		Appliance: "v0.1.0; " + secret,
		Services:  []Probe{GRPCHealth("vault", conn)},
		ThirdParty: []Probe{
			HTTPVersion("hydra", srv.Client(), leaky),
			Valkey(func(context.Context) (string, error) {
				return "", errors.New("NOAUTH redis://default:" + secret + "@valkey.internal.example:6379")
			}),
			HTTPVersion("polis", srv.Client(), "http://polis.internal.example:1/api/health?apiKey="+secret),
		},
	}
	b, err := json.Marshal(c.Report(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	for _, bad := range []string{secret, "admin:", "internal.example", "127.0.0.1", "session=", "token=", "<script>", "NOAUTH"} {
		if strings.Contains(out, bad) {
			t.Errorf("report contains %q: %s", bad, out)
		}
	}
	if !strings.Contains(out, `"publicUrl":"https://pam.example.org"`) {
		t.Errorf("report lost the public origin: %s", out)
	}
}

func TestKubernetes_ReadsGitVersionWithToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" || r.Header.Get("Authorization") != "Bearer sa-token" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"major":"1","minor":"33","gitVersion":"v1.33.4+k0s"}`))
	}))
	defer srv.Close()
	got := kubernetes(srv.Client(), srv.URL, func() string { return "sa-token" })(context.Background())
	if got.Status != StatusOK || got.Version != "v1.33.4+k0s" || got.Name != "kubernetes" {
		t.Fatalf("got %+v, want kubernetes v1.33.4+k0s", got)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if got := InCluster()(context.Background()); got.Status != StatusNotConfigured {
		t.Fatalf("outside a cluster: got %+v, want NOT_CONFIGURED", got)
	}
}

func TestGRPCHealth_ReadsDependencyStates(t *testing.T) {
	hdr := `{"status":"degraded","dependencies":[` +
		`{"name":"postgres","state":"ok","required":true,"checkedAt":"2026-10-05T12:00:00Z","version":"17.11"},` +
		`{"name":"audit","state":"degraded","required":false,"error":"unavailable"},` +
		`{"name":"evil host.example.test","state":"ok"},` +
		`{"name":"valkey","state":"exploded","required":true},` +
		`{"name":"kratos","state":"down","required":true,"error":"dial tcp kratos.example.test: hunter2","version":"<b>v1</b>"}]}`
	got := GRPCHealth("vault", healthServer(t, HeaderVersion, "v0.1.0", HeaderHealth, hdr))(context.Background())
	want := []Dependency{
		{Name: "postgres", State: DepOK, Required: true, Version: "17.11"},
		{Name: "audit", State: DepDegraded, Error: "unavailable"},
		{Name: "kratos", State: DepDown, Required: true, Error: "error"},
	}
	if len(got.Dependencies) != len(want) {
		t.Fatalf("dependencies = %+v, want %+v", got.Dependencies, want)
	}
	for i := range want {
		if got.Dependencies[i] != want[i] {
			t.Fatalf("dependency %d = %+v, want %+v", i, got.Dependencies[i], want[i])
		}
	}
}

func TestGRPCHealth_GarbledOrMissingHealthHeader(t *testing.T) {
	if got := GRPCHealth("vault", healthServer(t, HeaderHealth, "not json hunter2"))(context.Background()); got.Dependencies != nil {
		t.Fatalf("garbled header: %+v", got.Dependencies)
	}
	if got := GRPCHealth("vault", healthServer(t))(context.Background()); got.Dependencies != nil {
		t.Fatalf("no header: %+v", got.Dependencies)
	}
}

func TestGRPCHealth_NotServingIsUnavailableButKeepsItsBuild(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := health.NewServer()
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	s := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderVersion, "v0.1.0", HeaderHealth, `{"status":"down","dependencies":[{"name":"postgres","state":"down","required":true,"error":"refused"}]}`))
		return h(ctx, req)
	}))
	healthpb.RegisterHealthServer(s, hs)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	got := GRPCHealth("vault", conn)(context.Background())
	if got.Status != StatusUnavailable || got.Version != "v0.1.0" || len(got.Dependencies) != 1 || got.Dependencies[0].State != DepDown {
		t.Fatalf("got %+v, want UNAVAILABLE with its build and postgres down", got)
	}
}

func TestCollector_GatewayCarriesItsOwnDependencies(t *testing.T) {
	c := &Collector{
		Gateway: Component{Name: "gateway", Status: StatusOK},
		GatewayDependencies: func(context.Context) []Dependency {
			return []Dependency{{Name: "valkey", State: DepDown, Required: true, Error: "refused"}}
		},
	}
	r := c.Report(context.Background())
	if len(r.Gateway.Dependencies) != 1 || r.Gateway.Dependencies[0].Name != "valkey" {
		t.Fatalf("gateway = %+v", r.Gateway)
	}
}
