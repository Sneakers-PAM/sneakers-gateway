// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"google.golang.org/grpc"
)

// sessionRefVault records the actor of every call that hands a person a secret's
// value. The vault refuses these without the web session reference (#151).
type sessionRefVault struct {
	vaultv1.VaultServiceClient
	actors map[string]*vaultv1.ActorContext
}

func (f *sessionRefVault) RevealSecretField(_ context.Context, req *vaultv1.RevealSecretFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretFieldResponse, error) {
	f.actors["reveal"] = req.GetActor()
	return &vaultv1.RevealSecretFieldResponse{Value: "v"}, nil
}

func (f *sessionRefVault) RevealSecretVersionField(_ context.Context, req *vaultv1.RevealSecretVersionFieldRequest, _ ...grpc.CallOption) (*vaultv1.RevealSecretVersionFieldResponse, error) {
	f.actors["version"] = req.GetActor()
	return &vaultv1.RevealSecretVersionFieldResponse{Value: "v"}, nil
}

func (f *sessionRefVault) CopySecret(_ context.Context, req *vaultv1.CopySecretRequest, _ ...grpc.CallOption) (*vaultv1.CopySecretResponse, error) {
	f.actors["copy"] = req.GetActor()
	return &vaultv1.CopySecretResponse{Value: "v"}, nil
}

func (f *sessionRefVault) ExportCertificate(_ context.Context, req *vaultv1.ExportCertificateRequest, _ ...grpc.CallOption) (*vaultv1.ExportCertificateResponse, error) {
	f.actors["export"] = req.GetActor()
	return &vaultv1.ExportCertificateResponse{Filename: "c.pem"}, nil
}

// sessionRefClient serves the human schema as the session gate would, with the
// web session reference on the context unless ref is empty.
func sessionRefClient(fv vaultv1.VaultServiceClient, ref string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActor(r.Context(), "u-1")
		if ref != "" {
			ctx = WithSessionRef(ctx, ref)
		}
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
}

var personRevealMutations = map[string]string{
	"reveal":  `mutation { revealSecretField(id: "s1", fieldKey: "password") }`,
	"version": `mutation { revealSecretVersionField(secretId: "s1", versionNo: 1, fieldKey: "password") }`,
	"copy":    `mutation { copySecret(id: "s1") }`,
	"export":  `mutation { exportCertificate(secretId: "s1", format: "pem") { filename } }`,
}

// Every call that hands a person a value carries the session reference, so the
// vault can tell a signed-in web session from a token (#151).
func TestPersonRevealsCarryTheWebSessionRef(t *testing.T) {
	fv := &sessionRefVault{actors: map[string]*vaultv1.ActorContext{}}
	c := sessionRefClient(fv, "ref-1")
	for name, q := range personRevealMutations {
		var resp map[string]any
		c.MustPost(q, &resp)
		if got := fv.actors[name].GetSessionRef(); got != "ref-1" {
			t.Errorf("%s: session_ref = %q, want ref-1", name, got)
		}
	}
}

// Outside a web session there is no reference to send, and none is invented.
func TestPersonRevealsWithoutAWebSessionSendNoRef(t *testing.T) {
	fv := &sessionRefVault{actors: map[string]*vaultv1.ActorContext{}}
	c := sessionRefClient(fv, "")
	for name, q := range personRevealMutations {
		var resp map[string]any
		c.MustPost(q, &resp)
		if got := fv.actors[name].GetSessionRef(); got != "" {
			t.Errorf("%s: session_ref = %q, want empty", name, got)
		}
	}
}

// The broker hands the actor to the vault when it reveals the key, and the vault
// wants the web session reference there, so the gateway must pass it on.
func TestBrokerActorCarriesTheWebSessionRef(t *testing.T) {
	got := brokerActor(&vaultv1.ActorContext{UserId: "u-1", SessionRef: "ref-1"})
	if got.GetSessionRef() != "ref-1" {
		t.Fatalf("broker actor session_ref = %q, want ref-1", got.GetSessionRef())
	}
}

// Opening an SSH session from a web session sends the broker the session
// reference, so the key reveal at redeem time is a person's own web session.
func TestOpenSSHSessionSendsTheBrokerTheWebSessionRef(t *testing.T) {
	fv := &fakeSSHVault{targetIDs: []string{"target-1"}}
	fb := &fakeSSHBroker{}
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, SSHBroker: fb}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithSessionRef(WithActor(r.Context(), "user-morgan"), "ref-9")
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	var resp map[string]any
	c.MustPost(openSSHSessionMutation, &resp)
	if got := fb.lastReq.GetActor().GetSessionRef(); got != "ref-9" {
		t.Fatalf("CreateSession actor session_ref = %q, want ref-9", got)
	}
}
