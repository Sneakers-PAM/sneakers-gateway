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
	log "github.com/Bugs5382/go-log"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestTheNeutralLoggerGetsTheSameFields(t *testing.T) {
	t.Setenv("LOG_FORMAT", "json")
	t.Setenv("LOG_LEVEL", "info")
	var buf bytes.Buffer
	schema := gqlparser.MustLoadSchema(&ast.Source{Input: `type Query { secret(id: ID!): String }`})
	h := handler.New(&graphql.ExecutableSchemaMock{
		ExecFunc: func(context.Context) graphql.ResponseHandler {
			ran := false
			return func(ctx context.Context) *graphql.Response {
				if ran {
					return nil
				}
				ran = true
				graphql.AddError(graphql.WithPathContext(ctx, graphql.NewPathWithField("secret")), status.Error(codes.NotFound, "no such secret"))
				return &graphql.Response{Data: []byte(`{"secret":null}`)}
			}
		},
		SchemaFunc:     func() *ast.Schema { return schema },
		ComplexityFunc: func(context.Context, string, string, int, map[string]any) (int, bool) { return 0, false },
	})
	h.AddTransport(transport.POST{})
	h.Use(ErrorLog{
		Log:   log.NewLoggerWithOptions("gateway", log.WithOutput(&buf)),
		Actor: func(context.Context) string { return "u-ada" },
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	b, _ := json.Marshal(map[string]any{"query": query, "variables": map[string]any{"id": "s3cret-arg"}, "operationName": "Get"})
	resp, err := http.Post(srv.URL, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	var e map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &e); err != nil {
		t.Fatalf("log = %q, want one JSON line: %v", buf.String(), err)
	}
	if e["level"] != "warn" || e["code"] != "NotFound" || e["operation"] != "Get" || e["path"] != "secret" ||
		e["actor"] != "u-ada" || e["service"] != "gateway" {
		t.Fatalf("entry = %v", e)
	}
	if _, ok := e["duration"].(float64); !ok {
		t.Fatalf("duration = %v, want a number of milliseconds", e["duration"])
	}
	if strings.Contains(buf.String(), "s3cret-arg") {
		t.Fatal("a variable value reached the log")
	}
}

func TestANilLogDiscardsLines(t *testing.T) {
	ErrorLog{}.emit(context.Background(), false, "Get", "secret", "Unknown", "u-ada", 0)
}
