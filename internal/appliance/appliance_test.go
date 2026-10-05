// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package appliance

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const cmPath = "/api/v1/namespaces/sneakers/configmaps/sneakers-appliance"

// apiServer answers the ConfigMap get with whatever status and body are set.
type apiServer struct {
	status atomic.Int32
	body   atomic.Value
	auth   atomic.Value
}

func newAPIServer(t *testing.T) (*apiServer, *httptest.Server) {
	t.Helper()
	a := &apiServer{}
	a.status.Store(http.StatusOK)
	a.body.Store(`{"kind":"ConfigMap","data":{}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.auth.Store(r.Header.Get("Authorization"))
		if r.Method != http.MethodGet || r.URL.Path != cmPath {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(a.status.Load()))
		_, _ = w.Write([]byte(a.body.Load().(string)))
	}))
	t.Cleanup(srv.Close)
	return a, srv
}

func newWatcher(t *testing.T, srv *httptest.Server) *Watcher {
	t.Helper()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return New(Config{APIServer: srv.URL, Namespace: "sneakers", TokenFile: token, Client: srv.Client()})
}

func TestItReadsTheConfigMapWithTheServiceAccountToken(t *testing.T) {
	a, srv := newAPIServer(t)
	a.body.Store(`{"kind":"ConfigMap","data":{"maintenance":"on","maintenanceReason":"upgrade to 0.2.0"}}`)
	w := newWatcher(t, srv)
	w.Refresh(context.Background())
	if got := a.auth.Load(); got != "Bearer sa-token" {
		t.Fatalf("Authorization = %v, want the trimmed token", got)
	}
	on, reason := w.Maintenance()
	if !on || reason != "upgrade to 0.2.0" {
		t.Fatalf("Maintenance() = %v, %q", on, reason)
	}
	if got := w.Data()["maintenance"]; got != "on" {
		t.Fatalf("Data()[maintenance] = %q", got)
	}
}

func TestAnAbsentConfigMapIsEmpty(t *testing.T) {
	a, srv := newAPIServer(t)
	a.body.Store(`{"data":{"maintenance":"on"}}`)
	w := newWatcher(t, srv)
	w.Refresh(context.Background())
	a.status.Store(http.StatusNotFound)
	a.body.Store(`{"kind":"Status","code":404}`)
	w.Refresh(context.Background())
	if on, _ := w.Maintenance(); on {
		t.Fatal("maintenance still on after the ConfigMap went away")
	}
	if len(w.Data()) != 0 {
		t.Fatalf("Data() = %v, want empty", w.Data())
	}
}

func TestARefusalOrAnErrorKeepsTheLastData(t *testing.T) {
	for _, code := range []int{http.StatusForbidden, http.StatusInternalServerError} {
		a, srv := newAPIServer(t)
		a.body.Store(`{"data":{"maintenance":"on"}}`)
		w := newWatcher(t, srv)
		w.Refresh(context.Background())
		a.status.Store(int32(code))
		a.body.Store(`{"kind":"Status"}`)
		w.Refresh(context.Background())
		if on, _ := w.Maintenance(); !on {
			t.Fatalf("status %d dropped the last maintenance state", code)
		}
	}
}

func TestANilWatcherIsEmpty(t *testing.T) {
	var w *Watcher
	if on, _ := w.Maintenance(); on || len(w.Data()) != 0 {
		t.Fatal("a nil watcher reported data")
	}
}

func TestOutsideKubernetesThereIsNoWatcher(t *testing.T) {
	w, err := FromEnv(func(string) string { return "" }, nil)
	if err != nil || w != nil {
		t.Fatalf("FromEnv() = %v, %v; want nil, nil", w, err)
	}
}

func TestABadPollIntervalIsRefused(t *testing.T) {
	env := map[string]string{"KUBERNETES_SERVICE_HOST": "192.0.2.1", "APPLIANCE_POLL_INTERVAL": "soon"}
	if _, err := FromEnv(func(k string) string { return env[k] }, nil); err == nil {
		t.Fatal("APPLIANCE_POLL_INTERVAL=soon was accepted")
	}
}

func TestSessionsEndedAtIsReadAsATime(t *testing.T) {
	a, srv := newAPIServer(t)
	w := newWatcher(t, srv)
	w.Refresh(context.Background())
	if !w.SessionsEndedAt().IsZero() {
		t.Fatal("a cutoff with no key set")
	}
	a.body.Store(`{"data":{"sessionsEndedAt":"2026-10-05T02:00:00Z"}}`)
	w.Refresh(context.Background())
	if got := w.SessionsEndedAt(); !got.Equal(time.Date(2026, 10, 5, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("SessionsEndedAt() = %v", got)
	}
	a.body.Store(`{"data":{"sessionsEndedAt":"last night"}}`)
	w.Refresh(context.Background())
	if !w.SessionsEndedAt().IsZero() {
		t.Fatal("a value that isn't a time was used as a cutoff")
	}
	var none *Watcher
	if !none.SessionsEndedAt().IsZero() {
		t.Fatal("a nil watcher gave a cutoff")
	}
}
