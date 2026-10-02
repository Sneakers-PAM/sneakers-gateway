// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"

	otel "github.com/Bugs5382/go-otel"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/workloadauth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// errNoWorkloadToken stops a real deployment that would call every backend
// without its workload identity, which the backends refuse.
var errNoWorkloadToken = errors.New(workloadauth.EnvTokenFile + " is not set: AUTH_MODE=real needs the gateway's projected service-account token (audience sneakers) to call the backends")

// backendDialOptions are the options for every gRPC client to a backend
// (vault, workflow, identity, audit, notify, SSH broker): plaintext inside the
// cluster, otel client spans, and the gateway's workload token as
// "authorization: Bearer" metadata, re-read from WORKLOAD_TOKEN_FILE on every
// call. Without the variable no token is sent, which only a backend with
// WORKLOAD_AUTH=disabled accepts, so AUTH_MODE=real refuses to start.
func backendDialOptions(authMode string, getenv func(string) string) ([]grpc.DialOption, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(otel.GRPCClientStatsHandler()),
	}
	tokenOpt, ok, err := workloadauth.DialOptionFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	if !ok {
		if authMode == "real" {
			return nil, errNoWorkloadToken
		}
		return opts, nil
	}
	return append(opts, tokenOpt), nil
}
