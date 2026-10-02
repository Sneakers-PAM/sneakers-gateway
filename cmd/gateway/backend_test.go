// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// bearerVault stands in for a callee with workload authentication on: it
// refuses a call without a bearer token and records the one it got.
type bearerVault struct {
	vaultv1.UnimplementedVaultServiceServer
	got chan string
}

func (v *bearerVault) GetSecuritySettings(ctx context.Context, _ *vaultv1.GetSecuritySettingsRequest) (*vaultv1.GetSecuritySettingsResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	auth := md.Get("authorization")
	if len(auth) != 1 {
		return nil, status.Error(codes.Unauthenticated, "missing workload token")
	}
	v.got <- auth[0]
	return &vaultv1.GetSecuritySettingsResponse{}, nil
}

func startBearerVault(t *testing.T) (string, *bearerVault) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	v := &bearerVault{got: make(chan string, 4)}
	vaultv1.RegisterVaultServiceServer(srv, v)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String(), v
}

func dialVault(t *testing.T, addr string, opts []grpc.DialOption) vaultv1.VaultServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return vaultv1.NewVaultServiceClient(conn)
}

func writeToken(t *testing.T, path, tok string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestBackendDialOptionsSendTheWorkloadTokenOnEveryCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, "first-token")
	opts, err := backendDialOptions("real", envOf(map[string]string{"WORKLOAD_TOKEN_FILE": path}))
	if err != nil {
		t.Fatal(err)
	}
	addr, v := startBearerVault(t)
	c := dialVault(t, addr, opts)
	if _, err := c.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := <-v.got; got != "Bearer first-token" {
		t.Fatalf("authorization = %q", got)
	}
	// The kubelet rotates the projected token in place; the next call sends the new one.
	writeToken(t, path, "rotated-token")
	if _, err := c.GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := <-v.got; got != "Bearer rotated-token" {
		t.Fatalf("authorization after rotation = %q", got)
	}
}

func TestBackendDialOptionsWithoutTokenAreRefusedByTheCallee(t *testing.T) {
	opts, err := backendDialOptions("noauth", envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := startBearerVault(t)
	_, err = dialVault(t, addr, opts).GetSecuritySettings(context.Background(), &vaultv1.GetSecuritySettingsRequest{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("err = %v, want Unauthenticated", err)
	}
}

func TestBackendDialOptionsRealModeNeedsAWorkloadToken(t *testing.T) {
	if _, err := backendDialOptions("real", envOf(nil)); err == nil {
		t.Fatal("real mode without WORKLOAD_TOKEN_FILE must refuse to start")
	}
}

func TestBackendDialOptionsUnreadableTokenFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	for _, mode := range []string{"real", "noauth"} {
		if _, err := backendDialOptions(mode, envOf(map[string]string{"WORKLOAD_TOKEN_FILE": missing})); err == nil {
			t.Fatalf("%s: a set but unreadable WORKLOAD_TOKEN_FILE must fail start-up", mode)
		}
	}
}
