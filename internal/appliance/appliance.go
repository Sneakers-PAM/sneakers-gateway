// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package appliance reads the sneakers-appliance ConfigMap the appliance's
// platform controller publishes in the install's namespace. The gateway
// makes one get of that one ConfigMap through the Kubernetes API, on a
// timer, with its own service-account token; there is no other edge.
//
// On a plain Kubernetes install the ConfigMap doesn't exist, so the data is
// empty. When the API can't be reached the last data read is kept, so a
// brief API outage doesn't drop the gateway out of maintenance.
package appliance

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
)

// The ConfigMap keys the gateway reads (docs/appliance.md).
const (
	KeyMaintenance       = "maintenance"
	KeyMaintenanceReason = "maintenanceReason"
)

// On is the value a switch key holds when it's on.
const On = "on"

// The in-cluster defaults.
const (
	DefaultName         = "sneakers-appliance"
	DefaultInterval     = 10 * time.Second
	serviceAccountDir   = "/var/run/secrets/kubernetes.io/serviceaccount"
	defaultTokenFile    = serviceAccountDir + "/token"
	defaultCAFile       = serviceAccountDir + "/ca.crt"
	defaultNamespaceDir = serviceAccountDir + "/namespace"
	requestTimeout      = 5 * time.Second
	maxBody             = 1 << 20
)

// Watcher keeps the latest copy of the ConfigMap's data.
type Watcher struct {
	url       string
	tokenFile string
	client    *http.Client
	interval  time.Duration
	log       log.Logger

	mu        sync.RWMutex
	data      map[string]string
	lastState string
}

// Config builds a Watcher. APIServer is the API server's base URL; Client
// must trust its certificate.
type Config struct {
	APIServer string
	Namespace string
	Name      string
	TokenFile string
	Client    *http.Client
	Interval  time.Duration
	Log       log.Logger
}

// New returns a Watcher for cfg. Empty Name and Interval take the defaults.
func New(cfg Config) *Watcher {
	if cfg.Name == "" {
		cfg.Name = DefaultName
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: requestTimeout}
	}
	return &Watcher{
		url: strings.TrimRight(cfg.APIServer, "/") + "/api/v1/namespaces/" + url.PathEscape(cfg.Namespace) +
			"/configmaps/" + url.PathEscape(cfg.Name),
		tokenFile: cfg.TokenFile,
		client:    cfg.Client,
		interval:  cfg.Interval,
		log:       cfg.Log,
		data:      map[string]string{},
	}
}

// FromEnv returns a Watcher for the pod's own namespace, or nil when the
// gateway isn't running in Kubernetes (no KUBERNETES_SERVICE_HOST). The
// settings are APPLIANCE_CONFIGMAP (the name), APPLIANCE_POLL_INTERVAL and
// APPLIANCE_TOKEN_FILE.
func FromEnv(getenv func(string) string, lg log.Logger) (*Watcher, error) {
	host, port := getenv("KUBERNETES_SERVICE_HOST"), getenv("KUBERNETES_SERVICE_PORT")
	if host == "" {
		return nil, nil
	}
	if port == "" {
		port = "443"
	}
	interval := DefaultInterval
	if raw := strings.TrimSpace(getenv("APPLIANCE_POLL_INTERVAL")); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("APPLIANCE_POLL_INTERVAL %q: want a positive duration such as 10s", raw)
		}
		interval = d
	}
	tokenFile := getenv("APPLIANCE_TOKEN_FILE")
	if tokenFile == "" {
		tokenFile = defaultTokenFile
	}
	ns, err := os.ReadFile(defaultNamespaceDir)
	if err != nil {
		return nil, fmt.Errorf("read the pod namespace: %w", err)
	}
	ca, err := os.ReadFile(defaultCAFile)
	if err != nil {
		return nil, fmt.Errorf("read the cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("the cluster CA file holds no certificate")
	}
	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	return New(Config{
		APIServer: "https://" + net.JoinHostPort(host, port),
		Namespace: strings.TrimSpace(string(ns)),
		Name:      getenv("APPLIANCE_CONFIGMAP"),
		TokenFile: tokenFile,
		Client:    client,
		Interval:  interval,
		Log:       lg,
	}), nil
}

// Data returns a copy of the latest ConfigMap data; empty when there is none.
func (w *Watcher) Data() map[string]string {
	out := map[string]string{}
	if w == nil {
		return out
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	for k, v := range w.data {
		out[k] = v
	}
	return out
}

// Get returns one key's value, or "" when it's unset.
func (w *Watcher) Get(key string) string {
	if w == nil {
		return ""
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.data[key]
}

// Maintenance reports the ConfigMap's maintenance state, for maintenance.New.
func (w *Watcher) Maintenance() (bool, string) {
	return w.Get(KeyMaintenance) == On, w.Get(KeyMaintenanceReason)
}

// Run reads the ConfigMap now and then every interval until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	w.Refresh(ctx)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Refresh(ctx)
		}
	}
}

// The outcomes of one read, logged when they change.
const (
	stateFound     = "found"
	stateAbsent    = "absent"
	stateForbidden = "forbidden"
	stateError     = "error"
)

// Refresh reads the ConfigMap once. Found replaces the data; absent clears
// it; a refusal or an error keeps the last data.
func (w *Watcher) Refresh(ctx context.Context) {
	start := time.Now()
	data, state, err := w.read(ctx)
	w.mu.Lock()
	switch state {
	case stateFound:
		w.data = data
	case stateAbsent:
		w.data = map[string]string{}
	}
	changed := state != w.lastState
	w.lastState = state
	maint := w.data[KeyMaintenance]
	w.mu.Unlock()

	fields := []log.Field{log.F("target", w.url), log.F("outcome", state), log.F("maintenance", maint),
		log.F("dur", float64(time.Since(start))/float64(time.Millisecond))}
	if err != nil {
		fields = append(fields, log.F("error", err.Error()))
	}
	if w.log == nil {
		return
	}
	switch {
	case !changed:
		w.log.Debug("appliance configmap read", fields...)
	case state == stateFound || state == stateAbsent:
		w.log.Info("appliance configmap state changed", fields...)
	default:
		w.log.Warn("appliance configmap unreadable, keeping the last data", fields...)
	}
}

func (w *Watcher) read(ctx context.Context) (map[string]string, string, error) {
	token, err := os.ReadFile(w.tokenFile)
	if err != nil {
		return nil, stateError, fmt.Errorf("read the service-account token: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.url, nil)
	if err != nil {
		return nil, stateError, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, stateError, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, stateError, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, stateAbsent, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, stateForbidden, fmt.Errorf("the API server answered %d", resp.StatusCode)
	default:
		return nil, stateError, fmt.Errorf("the API server answered %d", resp.StatusCode)
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(body, &cm); err != nil {
		return nil, stateError, fmt.Errorf("decode the ConfigMap: %w", err)
	}
	if cm.Data == nil {
		cm.Data = map[string]string{}
	}
	return cm.Data, stateFound, nil
}
