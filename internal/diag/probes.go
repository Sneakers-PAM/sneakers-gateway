// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// maxBody caps how much of a version answer is read.
const maxBody = 64 << 10

// GRPCHealth reads a Sneakers-PAM service's build and readiness from its
// health check's response headers. A nil conn means the service isn't
// configured. A service that answers without the headers (an older build) is
// OK with an unknown version and no dependencies; one that answers that it
// isn't serving is unavailable but keeps its build and dependencies.
func GRPCHealth(name string, conn grpc.ClientConnInterface) Probe {
	return func(ctx context.Context) Component {
		if conn == nil {
			return Component{Name: name, Status: StatusNotConfigured}
		}
		var md metadata.MD
		resp, err := healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{}, grpc.Header(&md))
		if err != nil {
			return Component{Name: name, Status: StatusUnavailable}
		}
		c := Component{Name: name, Version: clean(first(md, HeaderVersion)), Commit: clean(first(md, HeaderCommit)), Status: StatusOK}
		if resp.GetStatus() != healthpb.HealthCheckResponse_SERVING {
			c.Status = StatusUnavailable
		}
		c.Dependencies = parseDependencies(first(md, HeaderHealth))
		for k := range md {
			if dep, ok := strings.CutPrefix(k, HeaderDepPrefix); ok {
				if c.deps == nil {
					c.deps = map[string]string{}
				}
				c.deps[dep] = first(md, k)
			}
		}
		return c
	}
}

func first(md metadata.MD, key string) string {
	if v := md.Get(key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// HTTPVersion reads a JSON answer with a "version" (and optional "commit")
// field, the shape Kratos, Hydra, Polis and the MCP server answer with. An
// empty URL means the component isn't configured.
func HTTPVersion(name string, client *http.Client, endpoint string) Probe {
	return func(ctx context.Context) Component {
		if endpoint == "" {
			return Component{Name: name, Status: StatusNotConfigured}
		}
		var body struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
		}
		if !getJSON(ctx, client, endpoint, "", &body) {
			return Component{Name: name, Status: StatusUnavailable}
		}
		return Component{Name: name, Version: body.Version, Commit: body.Commit, Status: StatusOK}
	}
}

// getJSON GETs endpoint and decodes a 200 answer into out, reporting whether
// it worked. The error itself is dropped: it can name hosts and addresses.
func getJSON(ctx context.Context, client *http.Client, endpoint, bearer string, out any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil) // #nosec G704 -- endpoint is operator configuration or the in-cluster API server, plus a fixed path, never request input
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := client.Do(req) // #nosec G704 -- see above
	if err != nil {
		return false
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxBody)).Decode(out) == nil
}

// Valkey reads the server version from INFO server text (valkey_version,
// falling back to redis_version). A nil info means the gateway has no Valkey
// client (AUTH_MODE=noauth).
func Valkey(info func(context.Context) (string, error)) Probe {
	return func(ctx context.Context) Component {
		const name = "valkey"
		if info == nil {
			return Component{Name: name, Status: StatusNotConfigured}
		}
		text, err := info(ctx)
		if err != nil {
			return Component{Name: name, Status: StatusUnavailable}
		}
		fields := map[string]string{}
		sc := bufio.NewScanner(strings.NewReader(text))
		for sc.Scan() {
			if k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), ":"); ok {
				fields[k] = v
			}
		}
		v := fields["valkey_version"]
		if v == "" {
			v = fields["redis_version"]
		}
		return Component{Name: name, Version: v, Status: StatusOK}
	}
}

// NotConfigured is a probe for a component this deployment doesn't use.
func NotConfigured(name string) Probe {
	return func(context.Context) Component { return Component{Name: name, Status: StatusNotConfigured} }
}

// The in-cluster ServiceAccount files.
const (
	saTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- a well-known file path, not a credential
	saCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// InCluster reads the Kubernetes version from the API server's discovery
// endpoint (GET /version), with the pod's ServiceAccount token when one is
// mounted; any authenticated identity may read it by default. Outside a
// cluster, or without the cluster CA, it's not configured.
func InCluster() Probe {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return NotConfigured("kubernetes")
	}
	ca, err := os.ReadFile(saCAFile)
	if err != nil {
		return NotConfigured("kubernetes")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return NotConfigured("kubernetes")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	token := func() string {
		b, err := os.ReadFile(saTokenFile)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return kubernetes(client, "https://"+net.JoinHostPort(host, port), token)
}

func kubernetes(client *http.Client, base string, token func() string) Probe {
	return func(ctx context.Context) Component {
		const name = "kubernetes"
		var body struct {
			GitVersion string `json:"gitVersion"`
		}
		if !getJSON(ctx, client, base+"/version", token(), &body) {
			return Component{Name: name, Status: StatusUnavailable}
		}
		return Component{Name: name, Version: body.GitVersion, Status: StatusOK}
	}
}
