// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package gqllog

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/rs/zerolog"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// server builds a one-field schema whose resolver fails with err (nil = ok).
func server(t *testing.T, err error, buf *bytes.Buffer) *httptest.Server {
	t.Helper()
	schema := gqlparser.MustLoadSchema(&ast.Source{Input: `type Query { secret(id: ID!): String }`})
	h := handler.New(&graphql.ExecutableSchemaMock{
		// Like generated code: resolver errors are added while the response
		// handler runs, which is where the response interceptors see them.
		ExecFunc: func(context.Context) graphql.ResponseHandler {
			ran := false
			return func(ctx context.Context) *graphql.Response {
				if ran {
					return nil
				}
				ran = true
				if err != nil {
					graphql.AddError(graphql.WithPathContext(ctx, graphql.NewPathWithField("secret")), err)
					return &graphql.Response{Data: []byte(`{"secret":null}`)}
				}
				return &graphql.Response{Data: []byte(`{"secret":"x"}`)}
			}
		},
		SchemaFunc:     func() *ast.Schema { return schema },
		ComplexityFunc: func(context.Context, string, string, int, map[string]any) (int, bool) { return 0, false },
	})
	h.AddTransport(transport.POST{})
	h.Use(ErrorLog{
		Logger: func(context.Context) zerolog.Logger { return zerolog.New(buf) },
		Actor:  func(context.Context) string { return "u-ada" },
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, query string, vars map[string]any) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"query": query, "variables": vars, "operationName": "Get"})
	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
}

func entries(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

const query = `query Get($id: ID!) { secret(id: $id) }`

func TestAClientErrorIsLoggedAtWarnWithoutValues(t *testing.T) {
	var buf bytes.Buffer
	post(t, server(t, status.Error(codes.PermissionDenied, "not permitted"), &buf), query, map[string]any{"id": "s3cret-arg"})
	es := entries(t, &buf)
	if len(es) != 1 {
		t.Fatalf("log = %q, want one line", buf.String())
	}
	e := es[0]
	if e["level"] != "warn" || e["code"] != "PermissionDenied" || e["operation"] != "Get" || e["path"] != "secret" || e["actor"] != "u-ada" || e["duration"] == nil {
		t.Fatalf("entry = %v", e)
	}
	if strings.Contains(buf.String(), "s3cret-arg") {
		t.Fatal("a variable value reached the log")
	}
}

func TestAServerErrorIsLoggedAtError(t *testing.T) {
	var buf bytes.Buffer
	post(t, server(t, status.Error(codes.Unavailable, "vault down"), &buf), query, map[string]any{"id": "s1"})
	if es := entries(t, &buf); len(es) != 1 || es[0]["level"] != "error" || es[0]["code"] != "Unavailable" {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestAPlainErrorCountsAsAServerError(t *testing.T) {
	var buf bytes.Buffer
	post(t, server(t, errString("boom"), &buf), query, map[string]any{"id": "s1"})
	if es := entries(t, &buf); len(es) != 1 || es[0]["level"] != "error" || es[0]["code"] != "Unknown" {
		t.Fatalf("log = %q", buf.String())
	}
}

func TestASuccessfulCallLogsNothing(t *testing.T) {
	var buf bytes.Buffer
	post(t, server(t, nil, &buf), query, map[string]any{"id": "s1"})
	if buf.Len() != 0 {
		t.Fatalf("log = %q, want nothing", buf.String())
	}
}

func TestAnInvalidQueryIsLoggedAtWarn(t *testing.T) {
	var buf bytes.Buffer
	post(t, server(t, nil, &buf), `query Get { nope }`, nil)
	if es := entries(t, &buf); len(es) != 1 || es[0]["level"] != "warn" || es[0]["code"] != "GRAPHQL_VALIDATION_FAILED" {
		t.Fatalf("log = %q", buf.String())
	}
}

type errString string

func (e errString) Error() string { return string(e) }
