// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/bff"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// testTTL is the cache window the tests run with; waiting it out lets the next
// probe run the checks again.
const testTTL = time.Second

const leaked = "redis://valkey.internal.example.test:6379 hunter2"

func testChecker(t *testing.T, deps ...health.Dependency) *health.Checker {
	t.Helper()
	c, err := newChecker(log.Nop(), deps, health.WithTTL(testTTL))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func depsOf(deps []health.Dependency) map[string]bool {
	out := map[string]bool{}
	for _, d := range deps {
		out[d.Name] = d.Required
	}
	return out
}

// readyBody is the /readyz answer.
type readyBody struct {
	Status       health.State              `json:"status"`
	Dependencies []health.DependencyReport `json:"dependencies"`
}

func get(t *testing.T, h http.Handler, path string) (int, readyBody, http.Header, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var r readyBody
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return rec.Code, r, rec.Header(), rec.Body.String()
}

func routes(t *testing.T, c *health.Checker) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	if err := mountHealth(mux, c); err != nil {
		t.Fatal(err)
	}
	return mux
}

func TestHealthDeps_NoauthNeedsOnlyIdentity(t *testing.T) {
	t.Setenv("HYDRA_ENABLED", "")
	want := map[string]bool{"identity": true, "vault": false, "workflow": false, "audit": false, "notify": false, "sshbroker": false}
	if got := depsOf(healthDeps(func(string) string { return "" }, "noauth", diagServices{}, nil)); !mapsEqual(got, want) {
		t.Fatalf("deps = %v, want %v", got, want)
	}
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func TestHealthDeps_RealModeRequiresValkeyAndKratos(t *testing.T) {
	var ready atomic.Bool
	ready.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/ready", "/api/health":
			if !ready.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("HYDRA_ENABLED", "true")
	vars := map[string]string{
		"KRATOS_PUBLIC_URL": srv.URL + "/",
		"HYDRA_JWKS_URL":    srv.URL + "/.well-known/jwks.json",
		"POLIS_PUBLIC_URL":  "https://sso.example.test",
		"POLIS_ISSUER_URL":  srv.URL,
	}
	var valkeyUp atomic.Bool
	valkeyUp.Store(true)
	ping := func(context.Context) error {
		if valkeyUp.Load() {
			return nil
		}
		return errors.New("dial valkey.example.test:6379: refused")
	}
	deps := healthDeps(func(k string) string { return vars[k] }, "real", diagServices{}, ping)
	got := depsOf(deps)
	for name, req := range map[string]bool{"valkey": true, "kratos": true, "identity": true, "hydra": false, "polis": false} {
		if r, ok := got[name]; !ok || r != req {
			t.Fatalf("deps = %v; %s should be present with required=%v", got, name, req)
		}
	}
	// The gRPC peers have no conn here.
	deps = slices.DeleteFunc(deps, func(d health.Dependency) bool {
		return !slices.Contains([]string{"valkey", "kratos", "hydra", "polis"}, d.Name)
	})
	c := testChecker(t, deps...)

	if r := c.Report(context.Background()); r.Status != health.StateOK {
		t.Fatalf("healthy: %+v", r)
	}
	ready.Store(false)
	time.Sleep(testTTL)
	r := c.Report(context.Background())
	if r.Status != health.StateDown || r.Dependencies[2].State != health.StateDegraded || r.Dependencies[3].State != health.StateDegraded {
		t.Fatalf("kratos, hydra and polis not ready: %+v, want down with hydra and polis degraded", r)
	}
	ready.Store(true)
	valkeyUp.Store(false)
	time.Sleep(testTTL)
	if r := c.Report(context.Background()); r.Status != health.StateDown || r.Dependencies[0].Error != health.ClassError {
		t.Fatalf("valkey down: %+v", r)
	}
}

func TestHealthRoutes(t *testing.T) {
	c := testChecker(t, health.Dependency{Name: "valkey", Required: true, Check: func(context.Context) error { return errors.New("refused") }})
	mux := routes(t, c)
	for path, want := range map[string]int{"/livez": 200, "/readyz": 503, "/health": 404} {
		if code, _, _, _ := get(t, mux, path); code != want {
			t.Fatalf("%s = %d, want %d", path, code, want)
		}
	}
}

// TestHealthRoutes_HeaderNames pins the exact header names /readyz and /livez
// carry.
func TestHealthRoutes_HeaderNames(t *testing.T) {
	oldV, oldC := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = oldV, oldC })
	mux := routes(t, testChecker(t, health.Dependency{Name: "identity", Required: true, Check: func(context.Context) error { return nil }}))
	keys := func(h http.Header) []string {
		var out []string
		for k := range h {
			if strings.HasPrefix(k, "Sneakers-") {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return out
	}
	_, _, h, _ := get(t, mux, "/readyz")
	if got, want := keys(h), []string{"Sneakers-Commit", "Sneakers-Depstate-Identity", "Sneakers-Version"}; !slices.Equal(got, want) {
		t.Fatalf("/readyz headers = %v, want %v", got, want)
	}
	if h.Get("Sneakers-Version") != "v9.9.9-test" || h.Get("Sneakers-Commit") != "0123456789abcdef" {
		t.Fatalf("/readyz build = %v", h)
	}
	if _, _, h, _ := get(t, mux, "/livez"); !slices.Equal(keys(h), []string{"Sneakers-Commit", "Sneakers-Version"}) {
		t.Fatalf("/livez headers = %v", keys(h))
	}
}

// toggle is a fake dependency whose failure can be switched mid-test.
type toggle struct {
	mu    sync.Mutex
	err   error
	calls atomic.Int32
}

func (t *toggle) set(err error) { t.mu.Lock(); t.err = err; t.mu.Unlock() }
func (t *toggle) check(context.Context) error {
	t.calls.Add(1)
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.err
}

func expect(t *testing.T, h http.Handler, path string, code int, state health.State) readyBody {
	t.Helper()
	got, r, _, body := get(t, h, path)
	if got != code || (state != "" && r.Status != state) {
		t.Fatalf("%s: got %d %s, want %d %s", path, got, body, code, state)
	}
	return r
}

func TestReadinessFollowsARequiredDependency(t *testing.T) {
	valkey := &toggle{}
	mux := routes(t, testChecker(t, health.Dependency{Name: "valkey", Required: true, Check: valkey.check}))

	expect(t, mux, "/readyz", http.StatusOK, health.StateOK)

	valkey.set(fmt.Errorf("dial %s: %w", leaked, syscall.ECONNREFUSED))
	time.Sleep(testTTL)
	r := expect(t, mux, "/readyz", http.StatusServiceUnavailable, health.StateDown)
	if d := r.Dependencies[0]; d.Name != "valkey" || d.State != health.StateDown || !d.Required || d.Error != "refused" || d.CheckedAt.IsZero() {
		t.Fatalf("dependency = %+v", d)
	}
	if code, _, _, body := get(t, mux, "/livez"); code != http.StatusOK || strings.TrimSpace(body) != `{"status":"ok"}` {
		t.Fatalf("liveness = %d %s", code, body)
	}

	valkey.set(nil)
	expect(t, mux, "/readyz", http.StatusServiceUnavailable, health.StateDown) // still inside the cache window
	time.Sleep(testTTL)
	expect(t, mux, "/readyz", http.StatusOK, health.StateOK)
}

func TestAnOptionalDependencyOnlyDegrades(t *testing.T) {
	audit := &toggle{err: status.Error(codes.Unavailable, "connection refused to "+leaked)}
	mux := routes(t, testChecker(t,
		health.Dependency{Name: "identity", Required: true, Check: (&toggle{}).check},
		health.Dependency{Name: "audit", Check: audit.check},
	))
	r := expect(t, mux, "/readyz", http.StatusOK, health.StateDegraded)
	if d := r.Dependencies[1]; d.State != health.StateDegraded || d.Required || d.Error != "unavailable" {
		t.Fatalf("audit = %+v", d)
	}
}

func TestTheReportNeverCarriesErrorText(t *testing.T) {
	mux := routes(t, testChecker(t,
		health.Dependency{Name: "valkey", Required: true, Check: func(context.Context) error { return errors.New(leaked) }},
		health.Dependency{Name: "kratos", Required: true, Check: func(context.Context) error { return &statusError{code: 403} }},
	))
	_, r, _, body := get(t, mux, "/readyz")
	for _, bad := range []string{"hunter2", "internal.example", "redis://", "6379"} {
		if strings.Contains(body, bad) {
			t.Fatalf("readiness body carries %q: %s", bad, body)
		}
	}
	if r.Dependencies[0].Error != "error" || r.Dependencies[1].Error != "unauthenticated" {
		t.Fatalf("classes = %+v", r.Dependencies)
	}
}

func TestEachCheckIsBoundedByTheTimeout(t *testing.T) {
	c, err := newChecker(log.Nop(), []health.Dependency{{Name: "kratos", Required: true, Check: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}}, health.WithTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	r := c.Report(context.Background())
	if time.Since(started) > time.Second || r.Dependencies[0].Error != "timeout" {
		t.Fatalf("took %v, report %+v", time.Since(started), r)
	}
}

func TestProbesInsideTheWindowShareOneCheck(t *testing.T) {
	dep := &toggle{}
	c := testChecker(t, health.Dependency{Name: "valkey", Required: true, Check: dep.check})
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { c.Report(context.Background()) })
	}
	wg.Wait()
	if n := dep.calls.Load(); n != 1 {
		t.Fatalf("checked %d times, want 1", n)
	}
}

// reportedClass is the error class a readiness report gives check's error.
func reportedClass(t *testing.T, check func(context.Context) error) string {
	t.Helper()
	return testChecker(t, health.Dependency{Name: "dep", Check: check}).Report(context.Background()).Dependencies[0].Error
}

func TestClassify(t *testing.T) {
	cases := map[string]error{
		"":                nil,
		"timeout":         context.DeadlineExceeded,
		"refused":         &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
		"unavailable":     &net.DNSError{Err: "no such host", Name: "kratos.example.test"},
		"unauthenticated": status.Error(codes.PermissionDenied, "no"),
		"error":           &statusError{code: 500},
	}
	for want, err := range cases {
		if got := reportedClass(t, func(context.Context) error { return err }); got != want {
			t.Errorf("class of %v = %q, want %q", err, got, want)
		}
	}
	if got := reportedClass(t, func(context.Context) error { return status.Error(codes.DeadlineExceeded, "x") }); got != "timeout" {
		t.Errorf("grpc deadline = %q", got)
	}
	if got := reportedClass(t, func(context.Context) error { return &statusError{code: 401} }); got != "unauthenticated" {
		t.Errorf("401 = %q", got)
	}
}

func TestGRPCPeerNotServingIsUnavailable(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := grpchealth.NewServer()
	s := grpc.NewServer()
	healthpb.RegisterHealthServer(s, hs)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	check := grpcPeer(conn)
	if err := check(context.Background()); err != nil {
		t.Fatalf("serving peer: %v", err)
	}
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	if got := reportedClass(t, check); got != "unavailable" {
		t.Fatalf("not-serving peer = %q, want unavailable", got)
	}
}

func TestHTTPCheck(t *testing.T) {
	var code atomic.Int32
	code.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(int(code.Load())) }))
	defer srv.Close()
	check := checkHTTP(srv.Client(), srv.URL)
	if err := check(context.Background()); err != nil {
		t.Fatalf("200: %v", err)
	}
	code.Store(http.StatusServiceUnavailable)
	if got := reportedClass(t, check); got != "error" {
		t.Fatalf("503 = %q, want error", got)
	}
}

// TestValkeyReadinessAgainstARealValkey stops a real Valkey mid-test. It runs
// when GATEWAY_TEST_VALKEY_URL and GATEWAY_TEST_VALKEY_CONTAINER name a
// throwaway container published on a fixed port.
func TestValkeyReadinessAgainstARealValkey(t *testing.T) {
	url, name := os.Getenv("GATEWAY_TEST_VALKEY_URL"), os.Getenv("GATEWAY_TEST_VALKEY_CONTAINER")
	if url == "" || name == "" {
		t.Skip("GATEWAY_TEST_VALKEY_URL and GATEWAY_TEST_VALKEY_CONTAINER not set")
	}
	ctx := context.Background()
	rc, err := bff.ParseRedisURL(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	mux := routes(t, testChecker(t, health.Dependency{Name: "valkey", Required: true, Check: func(ctx context.Context) error { return rc.Redis().Ping(ctx).Err() }}))
	docker := func(args ...string) {
		if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
			t.Fatalf("docker %v: %v %s", args, err, out)
		}
	}
	expect(t, mux, "/readyz", 200, "")
	docker("stop", "-t", "1", name)
	t.Cleanup(func() { _ = exec.Command("docker", "start", name).Run() })
	time.Sleep(testTTL)
	if r := expect(t, mux, "/readyz", 503, health.StateDown); r.Dependencies[0].State != health.StateDown {
		t.Fatalf("valkey stopped: %+v, want down", r)
	}
	expect(t, mux, "/livez", 200, "")
	docker("start", name)
	deadline := time.Now().Add(20 * time.Second)
	for {
		time.Sleep(testTTL)
		code, r, _, _ := get(t, mux, "/readyz")
		if code == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("valkey restarted but readiness stayed %d %+v", code, r)
		}
	}
}
