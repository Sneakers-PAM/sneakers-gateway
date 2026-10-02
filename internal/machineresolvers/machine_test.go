// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
	"net/http"
)

// fakePrincipalVault embeds the client interface (nil) so it satisfies the
// type; only the three principal ops under test are exercised here — mirrors
// resolver_test.go's fakeVault pattern.
type fakePrincipalVault struct {
	vaultv1.VaultServiceClient

	lastListReq     *vaultv1.ListSecretsForPrincipalRequest
	listResp        *vaultv1.ListSecretsForPrincipalResponse
	lastCreateReq   *vaultv1.CreateSecretForPrincipalRequest
	createResp      *vaultv1.CreateSecretForPrincipalResponse
	lastGenerateReq *vaultv1.GenerateSecretForPrincipalRequest
	generateResp    *vaultv1.GenerateSecretForPrincipalResponse
}

func (f *fakePrincipalVault) ListSecretsForPrincipal(_ context.Context, req *vaultv1.ListSecretsForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretsForPrincipalResponse, error) {
	f.lastListReq = req
	return f.listResp, nil
}

func (f *fakePrincipalVault) CreateSecretForPrincipal(_ context.Context, req *vaultv1.CreateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.CreateSecretForPrincipalResponse, error) {
	f.lastCreateReq = req
	return f.createResp, nil
}

func (f *fakePrincipalVault) GenerateSecretForPrincipal(_ context.Context, req *vaultv1.GenerateSecretForPrincipalRequest, _ ...grpc.CallOption) (*vaultv1.GenerateSecretForPrincipalResponse, error) {
	f.lastGenerateReq = req
	return f.generateResp, nil
}

// newPrincipalClient wires the machine gqlgen handler over the fake vault,
// injecting a fixed machine actor (id + scope) as bff.MachineActor does in
// production — mirrors resolver_test.go's newClient.
func newPrincipalClient(fv *fakePrincipalVault, saID, scope string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(resolvers.WithMachineActor(r.Context(), saID, strings.Fields(scope))))
	})
	return gqlclient.New(wrapped)
}

func TestFindSecretsForPrincipal_ForwardsMachineActorAndReturnsSummaries(t *testing.T) {
	fv := &fakePrincipalVault{
		listResp: &vaultv1.ListSecretsForPrincipalResponse{
			Secrets: []*vaultv1.Secret{
				{Id: "s1", Name: "svc-a", FolderId: "f-ok", TypeId: "type-password", TargetId: "t1"},
			},
		},
	}
	c := newPrincipalClient(fv, "sa-42", "sneakers-secrets")
	var resp struct {
		FindSecretsForPrincipal []struct {
			ID       string
			Name     string
			FolderID string
			TypeID   string
			TargetID *string
		}
	}
	c.MustPost(`query { findSecretsForPrincipal(query: "svc", folderId: "f-ok", typeId: "type-password") { id name folderId typeId targetId } }`, &resp)

	if fv.lastListReq == nil {
		t.Fatal("vault.ListSecretsForPrincipal was not called")
	}
	actor := fv.lastListReq.GetActor()
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT {
		t.Fatalf("actor.PrincipalKind = %v, want SERVICE_ACCOUNT", actor.GetPrincipalKind())
	}
	if actor.GetPrincipalId() != "sa-42" {
		t.Fatalf("actor.PrincipalId = %q, want sa-42", actor.GetPrincipalId())
	}
	if fv.lastListReq.GetQuery() != "svc" || fv.lastListReq.GetFolderId() != "f-ok" || fv.lastListReq.GetTypeId() != "type-password" {
		t.Fatalf("query/folderId/typeId not forwarded: %+v", fv.lastListReq)
	}
	if len(resp.FindSecretsForPrincipal) != 1 {
		t.Fatalf("got %d summaries, want 1", len(resp.FindSecretsForPrincipal))
	}
	got := resp.FindSecretsForPrincipal[0]
	if got.ID != "s1" || got.Name != "svc-a" || got.FolderID != "f-ok" || got.TypeID != "type-password" || got.TargetID == nil || *got.TargetID != "t1" {
		t.Fatalf("summary mapped wrong: %+v", got)
	}
}

func TestFindSecretsForPrincipal_OmittedOptionalArgsForwardEmpty(t *testing.T) {
	fv := &fakePrincipalVault{listResp: &vaultv1.ListSecretsForPrincipalResponse{}}
	c := newPrincipalClient(fv, "sa-1", "")
	var resp struct {
		FindSecretsForPrincipal []struct{ ID string }
	}
	c.MustPost(`query { findSecretsForPrincipal { id } }`, &resp)

	if fv.lastListReq.GetQuery() != "" || fv.lastListReq.GetFolderId() != "" || fv.lastListReq.GetTypeId() != "" {
		t.Fatalf("expected empty optional fields when omitted, got %+v", fv.lastListReq)
	}
	if len(resp.FindSecretsForPrincipal) != 0 {
		t.Fatalf("expected no summaries, got %+v", resp.FindSecretsForPrincipal)
	}
}

func TestCreateSecretForPrincipal_MapsFieldsAndReturnsSummary(t *testing.T) {
	fv := &fakePrincipalVault{
		createResp: &vaultv1.CreateSecretForPrincipalResponse{
			Secret: &vaultv1.Secret{Id: "s2", Name: "svc-a", FolderId: "f-ok", TypeId: "type-password"},
		},
	}
	c := newPrincipalClient(fv, "sa-42", "sneakers-secrets")
	var resp struct {
		CreateSecretForPrincipal struct {
			ID       string
			Name     string
			FolderID string
			TypeID   string
		}
	}
	c.MustPost(`mutation {
		createSecretForPrincipal(folderId: "f-ok", typeId: "type-password", name: "svc-a", fields: [{key: "username", value: "svc-a"}, {key: "password", value: "p"}], targetId: "t1") {
			id name folderId typeId
		}
	}`, &resp)

	if fv.lastCreateReq == nil {
		t.Fatal("vault.CreateSecretForPrincipal was not called")
	}
	actor := fv.lastCreateReq.GetActor()
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT {
		t.Fatalf("actor.PrincipalKind = %v, want SERVICE_ACCOUNT", actor.GetPrincipalKind())
	}
	if actor.GetPrincipalId() != "sa-42" {
		t.Fatalf("actor.PrincipalId = %q, want sa-42", actor.GetPrincipalId())
	}
	if fv.lastCreateReq.GetFolderId() != "f-ok" || fv.lastCreateReq.GetTypeId() != "type-password" || fv.lastCreateReq.GetName() != "svc-a" || fv.lastCreateReq.GetTargetId() != "t1" {
		t.Fatalf("scalar fields not forwarded: %+v", fv.lastCreateReq)
	}
	wantFields := map[string]string{"username": "svc-a", "password": "p"}
	if len(fv.lastCreateReq.GetFields()) != len(wantFields) {
		t.Fatalf("fields = %+v, want %+v", fv.lastCreateReq.GetFields(), wantFields)
	}
	for k, v := range wantFields {
		if fv.lastCreateReq.GetFields()[k] != v {
			t.Fatalf("fields[%q] = %q, want %q", k, fv.lastCreateReq.GetFields()[k], v)
		}
	}
	if resp.CreateSecretForPrincipal.ID != "s2" || resp.CreateSecretForPrincipal.Name != "svc-a" {
		t.Fatalf("summary mapped wrong: %+v", resp.CreateSecretForPrincipal)
	}
}

func TestGenerateSecretForPrincipal_ReturnsGeneratedValueWhenRequested(t *testing.T) {
	fv := &fakePrincipalVault{
		generateResp: &vaultv1.GenerateSecretForPrincipalResponse{
			Secret:         &vaultv1.Secret{Id: "s3", Name: "svc-sql", FolderId: "f-ok", TypeId: "type-active-directory"},
			GeneratedValue: "Gener4ted!",
		},
	}
	c := newPrincipalClient(fv, "sa-42", "sneakers-secrets")
	var resp struct {
		GenerateSecretForPrincipal struct {
			Secret struct {
				ID       string
				FolderID string
			}
			GeneratedValue *string
		}
	}
	c.MustPost(`mutation {
		generateSecretForPrincipal(folderId: "f-ok", typeId: "type-active-directory", name: "svc-sql", fields: [{key: "domain", value: "CORP"}], policyId: "pol-1", targetId: "t2", returnValue: true) {
			secret { id folderId }
			generatedValue
		}
	}`, &resp)

	if fv.lastGenerateReq == nil {
		t.Fatal("vault.GenerateSecretForPrincipal was not called")
	}
	actor := fv.lastGenerateReq.GetActor()
	if actor.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_SERVICE_ACCOUNT {
		t.Fatalf("actor.PrincipalKind = %v, want SERVICE_ACCOUNT", actor.GetPrincipalKind())
	}
	if fv.lastGenerateReq.GetFolderId() != "f-ok" || fv.lastGenerateReq.GetTypeId() != "type-active-directory" ||
		fv.lastGenerateReq.GetName() != "svc-sql" || fv.lastGenerateReq.GetPolicyId() != "pol-1" ||
		fv.lastGenerateReq.GetTargetId() != "t2" || !fv.lastGenerateReq.GetReturnValue() {
		t.Fatalf("scalar fields not forwarded: %+v", fv.lastGenerateReq)
	}
	if len(fv.lastGenerateReq.GetFields()) != 1 || fv.lastGenerateReq.GetFields()["domain"] != "CORP" {
		t.Fatalf("fields not forwarded: %+v", fv.lastGenerateReq.GetFields())
	}
	if resp.GenerateSecretForPrincipal.Secret.ID != "s3" {
		t.Fatalf("summary mapped wrong: %+v", resp.GenerateSecretForPrincipal.Secret)
	}
	if resp.GenerateSecretForPrincipal.GeneratedValue == nil || *resp.GenerateSecretForPrincipal.GeneratedValue != "Gener4ted!" {
		t.Fatalf("generatedValue = %v, want Gener4ted!", resp.GenerateSecretForPrincipal.GeneratedValue)
	}
}

func TestCreateSecretForPrincipal_DuplicateFieldKeyRejectedWithoutCallingVault(t *testing.T) {
	fv := &fakePrincipalVault{
		createResp: &vaultv1.CreateSecretForPrincipalResponse{
			Secret: &vaultv1.Secret{Id: "s2", Name: "svc-a", FolderId: "f-ok", TypeId: "type-password"},
		},
	}
	c := newPrincipalClient(fv, "sa-42", "sneakers-secrets")
	var resp struct {
		CreateSecretForPrincipal struct{ ID string }
	}
	err := c.Post(`mutation {
		createSecretForPrincipal(folderId: "f-ok", typeId: "type-password", name: "svc-a", fields: [{key: "username", value: "svc-a"}, {key: "username", value: "dup"}]) {
			id
		}
	}`, &resp)

	if err == nil {
		t.Fatal("expected an error for duplicate field key, got none")
	}
	if !strings.Contains(err.Error(), "duplicate field key") || !strings.Contains(err.Error(), "username") {
		t.Fatalf("error = %q, want it to mention duplicate field key and the offending key", err.Error())
	}
	if fv.lastCreateReq != nil {
		t.Fatalf("vault.CreateSecretForPrincipal was called, want it skipped on duplicate-key error: %+v", fv.lastCreateReq)
	}
}

func TestGenerateSecretForPrincipal_NoReturnValueOmitsField(t *testing.T) {
	fv := &fakePrincipalVault{
		generateResp: &vaultv1.GenerateSecretForPrincipalResponse{
			Secret: &vaultv1.Secret{Id: "s4", Name: "svc-sql2", FolderId: "f-ok", TypeId: "type-active-directory"},
			// GeneratedValue left empty: ReturnValue was false/omitted.
		},
	}
	c := newPrincipalClient(fv, "sa-42", "sneakers-secrets")
	var resp struct {
		GenerateSecretForPrincipal struct {
			Secret         struct{ ID string }
			GeneratedValue *string
		}
	}
	c.MustPost(`mutation {
		generateSecretForPrincipal(folderId: "f-ok", typeId: "type-active-directory", name: "svc-sql2", fields: []) {
			secret { id }
			generatedValue
		}
	}`, &resp)

	if fv.lastGenerateReq.GetReturnValue() {
		t.Fatalf("expected returnValue to default false when omitted")
	}
	if resp.GenerateSecretForPrincipal.GeneratedValue != nil {
		t.Fatalf("generatedValue = %v, want nil", *resp.GenerateSecretForPrincipal.GeneratedValue)
	}
}
