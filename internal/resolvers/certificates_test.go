// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeCertVault is a minimal vault fake covering only the calls
// importCertificate/exportCertificate makes, recording the last request so
// tests can assert what was forwarded (actor + args).
type fakeCertVault struct {
	vaultv1.VaultServiceClient

	lastImportReq *vaultv1.ImportCertificateRequest
	importResp    *vaultv1.ImportCertificateResponse
	importErr     error

	lastExportReq *vaultv1.ExportCertificateRequest
	exportResp    *vaultv1.ExportCertificateResponse
	exportErr     error

	lastReplaceReq *vaultv1.ReplaceCertificateRequest
	replaceResp    *vaultv1.ReplaceCertificateResponse
	replaceErr     error
}

func (f *fakeCertVault) ImportCertificate(_ context.Context, req *vaultv1.ImportCertificateRequest, _ ...grpc.CallOption) (*vaultv1.ImportCertificateResponse, error) {
	f.lastImportReq = req
	if f.importErr != nil {
		return nil, f.importErr
	}
	return f.importResp, nil
}

func (f *fakeCertVault) ExportCertificate(_ context.Context, req *vaultv1.ExportCertificateRequest, _ ...grpc.CallOption) (*vaultv1.ExportCertificateResponse, error) {
	f.lastExportReq = req
	if f.exportErr != nil {
		return nil, f.exportErr
	}
	return f.exportResp, nil
}

func (f *fakeCertVault) ReplaceCertificate(_ context.Context, req *vaultv1.ReplaceCertificateRequest, _ ...grpc.CallOption) (*vaultv1.ReplaceCertificateResponse, error) {
	f.lastReplaceReq = req
	if f.replaceErr != nil {
		return nil, f.replaceErr
	}
	return f.replaceResp, nil
}

// newCertClient wires the gqlgen handler over a fake vault, injecting a fixed
// no-auth actor (as the HTTP layer does in production) — mirrors newClient in
// resolver_test.go.
func newCertClient(fv *fakeCertVault, actor string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	})
	return gqlclient.New(wrapped)
}

const importCertMutation = `mutation Import($folderId: String!, $name: String!, $fileBase64: String!, $passphrase: String, $alias: String) {
	importCertificate(folderId: $folderId, name: $name, fileBase64: $fileBase64, passphrase: $passphrase, alias: $alias) {
		secret { id name }
		aliases
		meta { subject issuer sans notBefore notAfter serialNumber fingerprintSha256 keyAlgorithm keyBits isCA }
	}
}`

const exportCertMutation = `mutation Export($secretId: String!, $format: String!, $newPassphrase: String) {
	exportCertificate(secretId: $secretId, format: $format, newPassphrase: $newPassphrase) {
		fileBase64
		filename
		contentType
	}
}`

const replaceCertMutation = `mutation Replace($secretId: String!, $fileBase64: String!, $passphrase: String, $alias: String) {
	replaceCertificate(secretId: $secretId, fileBase64: $fileBase64, passphrase: $passphrase, alias: $alias) {
		secret { id name }
		aliases
		meta { subject issuer sans notBefore notAfter serialNumber fingerprintSha256 keyAlgorithm keyBits isCA }
	}
}`

func TestImportCertificateDecodesAndForwardsToVault(t *testing.T) {
	fv := &fakeCertVault{importResp: &vaultv1.ImportCertificateResponse{
		Secret: &vaultv1.Secret{Id: "secret-1", Name: "leaf.example.org", FolderId: "folder-1", TypeId: "type-cert"},
		Meta: &vaultv1.CertMeta{
			Subject: "CN=leaf.example.org", Issuer: "CN=Example CA", Sans: []string{"leaf.example.org"},
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
			SerialNumber: "0a1b2c", FingerprintSha256: "deadbeef", KeyAlgorithm: "RSA", KeyBits: 2048, IsCa: false,
		},
	}}
	c := newCertClient(fv, "user-clarke")

	raw := []byte("fake-pem-bytes")
	b64 := base64.StdEncoding.EncodeToString(raw)

	var resp struct {
		ImportCertificate struct {
			Secret  struct{ ID, Name string }
			Aliases []string
			Meta    struct {
				Subject, Issuer, KeyAlgorithm, SerialNumber, FingerprintSha256, NotBefore, NotAfter string
				Sans                                                                                []string
				KeyBits                                                                             int
				IsCA                                                                                bool
			}
		}
	}
	err := c.Post(importCertMutation, &resp, gqlclient.Var("folderId", "folder-1"), gqlclient.Var("name", "leaf.example.org"),
		gqlclient.Var("fileBase64", b64), gqlclient.Var("passphrase", "sekret"), gqlclient.Var("alias", "leaf"))
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	if fv.lastImportReq == nil {
		t.Fatalf("vault ImportCertificate was never called")
	}
	if fv.lastImportReq.GetActor().GetUserId() != "user-clarke" {
		t.Fatalf("actor = %q, want user-clarke", fv.lastImportReq.GetActor().GetUserId())
	}
	if string(fv.lastImportReq.GetFileBytes()) != string(raw) {
		t.Fatalf("fileBytes = %q, want %q (base64 decode mismatch)", fv.lastImportReq.GetFileBytes(), raw)
	}
	if fv.lastImportReq.GetFolderId() != "folder-1" || fv.lastImportReq.GetName() != "leaf.example.org" {
		t.Fatalf("unexpected folder/name forwarded: %+v", fv.lastImportReq)
	}
	if fv.lastImportReq.GetPassphrase() != "sekret" || fv.lastImportReq.GetAlias() != "leaf" {
		t.Fatalf("unexpected passphrase/alias forwarded: %+v", fv.lastImportReq)
	}

	if resp.ImportCertificate.Secret.ID != "secret-1" {
		t.Fatalf("secret = %+v, want id secret-1", resp.ImportCertificate.Secret)
	}
	if resp.ImportCertificate.Meta.KeyBits != 2048 || resp.ImportCertificate.Meta.KeyAlgorithm != "RSA" {
		t.Fatalf("meta = %+v, want keyBits 2048 / RSA", resp.ImportCertificate.Meta)
	}
	if len(resp.ImportCertificate.Aliases) != 0 {
		t.Fatalf("aliases = %v, want none for a single-entry import", resp.ImportCertificate.Aliases)
	}
}

func TestImportCertificateInvalidBase64ReturnsGraphQLError(t *testing.T) {
	fv := &fakeCertVault{}
	c := newCertClient(fv, "user-clarke")

	var resp struct {
		ImportCertificate struct {
			Aliases []string
		}
	}
	err := c.Post(importCertMutation, &resp, gqlclient.Var("folderId", "folder-1"), gqlclient.Var("name", "leaf"),
		gqlclient.Var("fileBase64", "not-valid-base64!!"), gqlclient.Var("passphrase", (*string)(nil)), gqlclient.Var("alias", (*string)(nil)))
	if err == nil {
		t.Fatalf("expected an error for invalid base64, got none")
	}
	if fv.lastImportReq != nil {
		t.Fatalf("vault must not be called when fileBase64 fails to decode")
	}
}

// TestImportCertificateMultiEntryReturnsAliasesNotError verifies the
// multi-entry container case: the vault returns Aliases populated with
// Secret/Meta left nil and NO gRPC error. That's a normal result, not a
// failure — it must pass straight through with aliases set and secret null.
func TestImportCertificateMultiEntryReturnsAliasesNotError(t *testing.T) {
	fv := &fakeCertVault{importResp: &vaultv1.ImportCertificateResponse{
		Aliases: []string{"leaf-1", "leaf-2", "intermediate-ca"},
	}}
	c := newCertClient(fv, "user-turing")

	raw := base64.StdEncoding.EncodeToString([]byte("fake-pkcs12-bundle"))
	var resp struct {
		ImportCertificate struct {
			Secret  *struct{ ID string }
			Aliases []string
			Meta    *struct{ Subject string }
		}
	}
	err := c.Post(importCertMutation, &resp, gqlclient.Var("folderId", "folder-1"), gqlclient.Var("name", "bundle"),
		gqlclient.Var("fileBase64", raw), gqlclient.Var("passphrase", (*string)(nil)), gqlclient.Var("alias", (*string)(nil)))
	if err != nil {
		t.Fatalf("multi-entry import must not be treated as an error: %v", err)
	}
	if resp.ImportCertificate.Secret != nil {
		t.Fatalf("secret = %+v, want null for a multi-entry container", resp.ImportCertificate.Secret)
	}
	if resp.ImportCertificate.Meta != nil {
		t.Fatalf("meta = %+v, want null for a multi-entry container", resp.ImportCertificate.Meta)
	}
	if len(resp.ImportCertificate.Aliases) != 3 {
		t.Fatalf("aliases = %v, want 3 entries", resp.ImportCertificate.Aliases)
	}
}

func TestImportCertificateVaultDenialPropagates(t *testing.T) {
	fv := &fakeCertVault{importErr: status.Error(codes.PermissionDenied, "not authorized for this folder")}
	c := newCertClient(fv, "user-morgan")

	raw := base64.StdEncoding.EncodeToString([]byte("fake-pem-bytes"))
	var resp struct {
		ImportCertificate struct {
			Aliases []string
		}
	}
	err := c.Post(importCertMutation, &resp, gqlclient.Var("folderId", "folder-1"), gqlclient.Var("name", "leaf"),
		gqlclient.Var("fileBase64", raw), gqlclient.Var("passphrase", (*string)(nil)), gqlclient.Var("alias", (*string)(nil)))
	if err == nil {
		t.Fatalf("expected the vault's PermissionDenied to propagate as a GraphQL error")
	}
	if fv.lastImportReq == nil {
		t.Fatalf("vault should still have been called; the gateway forwards the actor and lets vault-side RACI decide")
	}
}

func TestExportCertificateForwardsAndBase64EncodesBytes(t *testing.T) {
	fileBytes := []byte("fake-pkcs12-container-bytes")
	fv := &fakeCertVault{exportResp: &vaultv1.ExportCertificateResponse{
		FileBytes: fileBytes, Filename: "leaf.p12", ContentType: "application/x-pkcs12",
	}}
	c := newCertClient(fv, "user-hopper")

	var resp struct {
		ExportCertificate struct {
			FileBase64, Filename, ContentType string
		}
	}
	err := c.Post(exportCertMutation, &resp, gqlclient.Var("secretId", "secret-1"), gqlclient.Var("format", "pkcs12"),
		gqlclient.Var("newPassphrase", "newpass"))
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if fv.lastExportReq.GetActor().GetUserId() != "user-hopper" {
		t.Fatalf("actor = %q, want user-hopper", fv.lastExportReq.GetActor().GetUserId())
	}
	if fv.lastExportReq.GetSecretId() != "secret-1" || fv.lastExportReq.GetFormat() != "pkcs12" || fv.lastExportReq.GetNewPassphrase() != "newpass" {
		t.Fatalf("unexpected export request forwarded: %+v", fv.lastExportReq)
	}

	if resp.ExportCertificate.Filename != "leaf.p12" || resp.ExportCertificate.ContentType != "application/x-pkcs12" {
		t.Fatalf("unexpected filename/contentType: %+v", resp.ExportCertificate)
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.ExportCertificate.FileBase64)
	if err != nil {
		t.Fatalf("fileBase64 did not decode: %v", err)
	}
	if string(decoded) != string(fileBytes) {
		t.Fatalf("decoded bytes = %q, want %q", decoded, fileBytes)
	}
}

func TestExportCertificateVaultDenialPropagates(t *testing.T) {
	fv := &fakeCertVault{exportErr: status.Error(codes.PermissionDenied, "reveal not permitted")}
	c := newCertClient(fv, "user-morgan")

	var resp struct {
		ExportCertificate struct{ FileBase64 string }
	}
	err := c.Post(exportCertMutation, &resp, gqlclient.Var("secretId", "secret-1"), gqlclient.Var("format", "pem"),
		gqlclient.Var("newPassphrase", (*string)(nil)))
	if err == nil {
		t.Fatalf("expected the vault's PermissionDenied to propagate as a GraphQL error")
	}
}

func TestReplaceCertificateDecodesAndForwardsToVault(t *testing.T) {
	fv := &fakeCertVault{replaceResp: &vaultv1.ReplaceCertificateResponse{
		Secret: &vaultv1.Secret{Id: "secret-1", Name: "leaf.example.org", FolderId: "folder-1", TypeId: "type-cert"},
		Meta: &vaultv1.CertMeta{
			Subject: "CN=leaf.example.org", Issuer: "CN=Example CA", Sans: []string{"leaf.example.org"},
			NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z",
			SerialNumber: "0a1b2c", FingerprintSha256: "deadbeef", KeyAlgorithm: "RSA", KeyBits: 2048, IsCa: false,
		},
	}}
	c := newCertClient(fv, "user-clarke")

	raw := []byte("fake-pem-bytes")
	b64 := base64.StdEncoding.EncodeToString(raw)

	var resp struct {
		ReplaceCertificate struct {
			Secret  struct{ ID, Name string }
			Aliases []string
			Meta    struct {
				Subject, Issuer, KeyAlgorithm, SerialNumber, FingerprintSha256, NotBefore, NotAfter string
				Sans                                                                                []string
				KeyBits                                                                             int
				IsCA                                                                                bool
			}
		}
	}
	err := c.Post(replaceCertMutation, &resp, gqlclient.Var("secretId", "secret-1"),
		gqlclient.Var("fileBase64", b64), gqlclient.Var("passphrase", "sekret"), gqlclient.Var("alias", "leaf"))
	if err != nil {
		t.Fatalf("replace failed: %v", err)
	}

	if fv.lastReplaceReq == nil {
		t.Fatalf("vault ReplaceCertificate was never called")
	}
	if fv.lastReplaceReq.GetActor().GetUserId() != "user-clarke" {
		t.Fatalf("actor = %q, want user-clarke", fv.lastReplaceReq.GetActor().GetUserId())
	}
	if string(fv.lastReplaceReq.GetFileBytes()) != string(raw) {
		t.Fatalf("fileBytes = %q, want %q (base64 decode mismatch)", fv.lastReplaceReq.GetFileBytes(), raw)
	}
	if fv.lastReplaceReq.GetSecretId() != "secret-1" {
		t.Fatalf("unexpected secretId forwarded: %+v", fv.lastReplaceReq)
	}
	if fv.lastReplaceReq.GetPassphrase() != "sekret" || fv.lastReplaceReq.GetAlias() != "leaf" {
		t.Fatalf("unexpected passphrase/alias forwarded: %+v", fv.lastReplaceReq)
	}

	if resp.ReplaceCertificate.Secret.ID != "secret-1" {
		t.Fatalf("secret = %+v, want id secret-1", resp.ReplaceCertificate.Secret)
	}
	if resp.ReplaceCertificate.Meta.KeyBits != 2048 || resp.ReplaceCertificate.Meta.KeyAlgorithm != "RSA" {
		t.Fatalf("meta = %+v, want keyBits 2048 / RSA", resp.ReplaceCertificate.Meta)
	}
	if len(resp.ReplaceCertificate.Aliases) != 0 {
		t.Fatalf("aliases = %v, want none for a single-entry replace", resp.ReplaceCertificate.Aliases)
	}
}

func TestReplaceCertificateInvalidBase64ReturnsGraphQLError(t *testing.T) {
	fv := &fakeCertVault{}
	c := newCertClient(fv, "user-clarke")

	var resp struct {
		ReplaceCertificate struct {
			Aliases []string
		}
	}
	err := c.Post(replaceCertMutation, &resp, gqlclient.Var("secretId", "secret-1"),
		gqlclient.Var("fileBase64", "not-valid-base64!!"), gqlclient.Var("passphrase", (*string)(nil)), gqlclient.Var("alias", (*string)(nil)))
	if err == nil {
		t.Fatalf("expected an error for invalid base64, got none")
	}
	if fv.lastReplaceReq != nil {
		t.Fatalf("vault must not be called when fileBase64 fails to decode")
	}
}

// TestReplaceCertificateMultiEntryReturnsAliasesNotError verifies the
// multi-entry container case: the vault returns Aliases populated with
// Secret/Meta left nil and NO gRPC error. That's a normal result, not a
// failure — it must pass straight through with aliases set and secret null.
func TestReplaceCertificateMultiEntryReturnsAliasesNotError(t *testing.T) {
	fv := &fakeCertVault{replaceResp: &vaultv1.ReplaceCertificateResponse{
		Aliases: []string{"leaf-1", "leaf-2", "intermediate-ca"},
	}}
	c := newCertClient(fv, "user-turing")

	raw := base64.StdEncoding.EncodeToString([]byte("fake-pkcs12-bundle"))
	var resp struct {
		ReplaceCertificate struct {
			Secret  *struct{ ID string }
			Aliases []string
			Meta    *struct{ Subject string }
		}
	}
	err := c.Post(replaceCertMutation, &resp, gqlclient.Var("secretId", "secret-1"),
		gqlclient.Var("fileBase64", raw), gqlclient.Var("passphrase", (*string)(nil)), gqlclient.Var("alias", (*string)(nil)))
	if err != nil {
		t.Fatalf("multi-entry replace must not be treated as an error: %v", err)
	}
	if resp.ReplaceCertificate.Secret != nil {
		t.Fatalf("secret = %+v, want null for a multi-entry container", resp.ReplaceCertificate.Secret)
	}
	if resp.ReplaceCertificate.Meta != nil {
		t.Fatalf("meta = %+v, want null for a multi-entry container", resp.ReplaceCertificate.Meta)
	}
	if len(resp.ReplaceCertificate.Aliases) != 3 {
		t.Fatalf("aliases = %v, want 3 entries", resp.ReplaceCertificate.Aliases)
	}
}

func TestReplaceCertificateVaultDenialPropagates(t *testing.T) {
	fv := &fakeCertVault{replaceErr: status.Error(codes.PermissionDenied, "not authorized for this secret")}
	c := newCertClient(fv, "user-morgan")

	raw := base64.StdEncoding.EncodeToString([]byte("fake-pem-bytes"))
	var resp struct {
		ReplaceCertificate struct {
			Aliases []string
		}
	}
	err := c.Post(replaceCertMutation, &resp, gqlclient.Var("secretId", "secret-1"),
		gqlclient.Var("fileBase64", raw), gqlclient.Var("passphrase", (*string)(nil)), gqlclient.Var("alias", (*string)(nil)))
	if err == nil {
		t.Fatalf("expected the vault's PermissionDenied to propagate as a GraphQL error")
	}
	if fv.lastReplaceReq == nil {
		t.Fatalf("vault should still have been called; the gateway forwards the actor and lets vault-side RACI decide")
	}
}
