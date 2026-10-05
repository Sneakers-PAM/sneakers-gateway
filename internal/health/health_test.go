// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpchealth "google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

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

type clock struct{ now time.Time }

func (c *clock) Now() time.Time          { return c.now }
func (c *clock) advance(d time.Duration) { c.now = c.now.Add(d) }

func get(t *testing.T, h http.Handler) (int, Report) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var r Report
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return rec.Code, r
}

const leaked = "redis://valkey.internal.example.test:6379 hunter2"

func expect(t *testing.T, h http.Handler, code int, state string) Report {
	t.Helper()
	got, r := get(t, h)
	if got != code || r.Status != state {
		t.Fatalf("got %d %+v, want %d %s", got, r, code, state)
	}
	return r
}

func TestReadinessFollowsARequiredDependency(t *testing.T) {
	valkey := &toggle{}
	clk := &clock{now: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}
	c := &Checker{Deps: []Dep{{Name: "valkey", Required: true, Check: valkey.check}}, Now: clk.Now}

	expect(t, c.Readyz(), http.StatusOK, StateOK)

	valkey.set(fmt.Errorf("dial %s: %w", leaked, syscall.ECONNREFUSED))
	clk.advance(CacheTTL + time.Millisecond)
	r := expect(t, c.Readyz(), http.StatusServiceUnavailable, StateDown)
	want := DepState{Name: "valkey", State: StateDown, Required: true, Error: "refused", CheckedAt: "2026-10-05T12:00:05Z"}
	if r.Dependencies[0] != want {
		t.Fatalf("dependency = %+v, want %+v", r.Dependencies[0], want)
	}
	if live := expect(t, c.Livez(), http.StatusOK, StateOK); len(live.Dependencies) != 0 {
		t.Fatalf("liveness carries dependencies: %+v", live)
	}

	valkey.set(nil)
	expect(t, c.Readyz(), http.StatusServiceUnavailable, StateDown) // still inside the cache window
	clk.advance(CacheTTL + time.Millisecond)
	expect(t, c.Readyz(), http.StatusOK, StateOK)
}

func TestAnOptionalDependencyOnlyDegrades(t *testing.T) {
	audit := &toggle{err: status.Error(codes.Unavailable, "connection refused to "+leaked)}
	c := &Checker{Deps: []Dep{
		{Name: "identity", Required: true, Check: (&toggle{}).check},
		{Name: "audit", Check: audit.check},
	}}
	code, r := get(t, c.Readyz())
	if code != http.StatusOK || r.Status != StateDegraded {
		t.Fatalf("got %d %+v, want 200 degraded", code, r)
	}
	if d := r.Dependencies[1]; d.State != StateDegraded || d.Required || d.Error != "unavailable" {
		t.Fatalf("audit = %+v", d)
	}
}

func TestTheReportNeverCarriesErrorText(t *testing.T) {
	c := &Checker{Deps: []Dep{
		{Name: "valkey", Required: true, Check: func(context.Context) error { return errors.New(leaked) }},
		{Name: "kratos", Required: true, Check: func(context.Context) error { return &StatusError{Code: 403} }},
	}}
	rec := httptest.NewRecorder()
	c.Readyz().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	body := rec.Body.String()
	for _, bad := range []string{"hunter2", "internal.example", "redis://", "6379"} {
		if strings.Contains(body, bad) {
			t.Fatalf("readiness body carries %q: %s", bad, body)
		}
	}
	_, r := get(t, c.Readyz())
	if r.Dependencies[0].Error != "error" || r.Dependencies[1].Error != "unauthenticated" {
		t.Fatalf("classes = %+v", r.Dependencies)
	}
}

func TestEachCheckIsBoundedByTheTimeout(t *testing.T) {
	c := &Checker{Timeout: 20 * time.Millisecond, Deps: []Dep{{Name: "kratos", Required: true, Check: func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}}}}
	started := time.Now()
	r := c.Report(context.Background())
	if time.Since(started) > time.Second || r.Dependencies[0].Error != "timeout" {
		t.Fatalf("took %v, report %+v", time.Since(started), r)
	}
}

func TestProbesInsideTheWindowShareOneCheck(t *testing.T) {
	dep := &toggle{}
	c := &Checker{Deps: []Dep{{Name: "valkey", Required: true, Check: dep.check}}}
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); c.Report(context.Background()) }()
	}
	wg.Wait()
	if n := dep.calls.Load(); n != 1 {
		t.Fatalf("checked %d times, want 1", n)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]error{
		"":                nil,
		"timeout":         context.DeadlineExceeded,
		"refused":         &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED},
		"unavailable":     &net.DNSError{Err: "no such host", Name: "kratos.example.test"},
		"unauthenticated": status.Error(codes.PermissionDenied, "no"),
		"error":           &StatusError{Code: 500},
	}
	for want, err := range cases {
		if got := Classify(err); got != want {
			t.Errorf("Classify(%v) = %q, want %q", err, got, want)
		}
	}
	if got := Classify(status.Error(codes.DeadlineExceeded, "x")); got != "timeout" {
		t.Errorf("grpc deadline = %q", got)
	}
	if got := Classify(&StatusError{Code: 401}); got != "unauthenticated" {
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
	check := GRPC(conn)
	if err := check(context.Background()); err != nil {
		t.Fatalf("serving peer: %v", err)
	}
	hs.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)
	if got := Classify(check(context.Background())); got != ClassUnavailable {
		t.Fatalf("not-serving peer = %q, want unavailable", got)
	}
}

func TestHTTPCheck(t *testing.T) {
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) }))
	defer srv.Close()
	check := HTTP(srv.Client(), srv.URL)
	if err := check(context.Background()); err != nil {
		t.Fatalf("200: %v", err)
	}
	code = http.StatusServiceUnavailable
	if got := Classify(check(context.Background())); got != ClassError {
		t.Fatalf("503 = %q, want error", got)
	}
}
