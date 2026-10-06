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
	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAudit serves ListRecords from a fixed, canned set of records.
type fakeAudit struct {
	auditv1.AuditServiceClient
	records []*auditv1.AuditRecord
}

func (f *fakeAudit) ListRecords(context.Context, *auditv1.ListRecordsRequest, ...grpc.CallOption) (*auditv1.ListRecordsResponse, error) {
	return &auditv1.ListRecordsResponse{Records: f.records}, nil
}

// fakeSubjectVault serves the vault calls subject resolution needs: GetSecret
// (per id, deniable), ListFolders and ListTargets.
type fakeSubjectVault struct {
	vaultv1.VaultServiceClient
	secrets       map[string]*vaultv1.Secret // id -> secret; absent = denied/not found
	folders       []*vaultv1.Folder
	targets       []*vaultv1.Target
	getSecretCall int
}

func (f *fakeSubjectVault) GetSecret(_ context.Context, req *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	f.getSecretCall++
	sec, ok := f.secrets[req.GetId()]
	if !ok {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return &vaultv1.GetSecretResponse{Secret: sec}, nil
}

func (f *fakeSubjectVault) ListFolders(context.Context, *vaultv1.ListFoldersRequest, ...grpc.CallOption) (*vaultv1.ListFoldersResponse, error) {
	return &vaultv1.ListFoldersResponse{Folders: f.folders}, nil
}

func (f *fakeSubjectVault) ListTargets(context.Context, *vaultv1.ListTargetsRequest, ...grpc.CallOption) (*vaultv1.ListTargetsResponse, error) {
	return &vaultv1.ListTargetsResponse{Targets: f.targets}, nil
}

// fakeSubjectIdentity serves ResolveUserLabels and ListServiceAccounts.
type fakeSubjectIdentity struct {
	identityv1.IdentityServiceClient
	labels          []*identityv1.UserLabel
	serviceAccounts []*identityv1.ServiceAccount
}

func (f *fakeSubjectIdentity) ResolveUserLabels(context.Context, *identityv1.ResolveUserLabelsRequest, ...grpc.CallOption) (*identityv1.ResolveUserLabelsResponse, error) {
	return &identityv1.ResolveUserLabelsResponse{Labels: f.labels}, nil
}

func (f *fakeSubjectIdentity) ListServiceAccounts(context.Context, *identityv1.ListServiceAccountsRequest, ...grpc.CallOption) (*identityv1.ListServiceAccountsResponse, error) {
	return &identityv1.ListServiceAccountsResponse{ServiceAccounts: f.serviceAccounts}, nil
}

// newAuditClient wires the gqlgen handler over fake audit/vault/identity
// clients, as a site admin (the auditRecords query is admin-only).
func newAuditClient(fa *fakeAudit, fv vaultv1.VaultServiceClient, fi identityv1.IdentityServiceClient) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Audit: fa, Vault: fv, Identity: fi}}))
	h.AddTransport(transport.POST{})
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := WithActor(r.Context(), "user-admin")
		ctx = WithActorInfo(ctx, true, false, nil)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
	return gqlclient.New(wrapped)
}

const auditSubjectQuery = `query {
  auditRecords {
    subject subjectKind subjectId subjectName
  }
}`

// Each known subject kind resolves to its display name through the right
// backend call; an unreadable secret, an unknown-prefix subject and a
// deleted/unlisted folder all come back with no name and no error.
func TestAuditRecordSubjectResolvesByKind(t *testing.T) {
	fa := &fakeAudit{records: []*auditv1.AuditRecord{
		{Seq: 1, ActorUserId: "user-admin", Subject: "secret-1#password"},
		{Seq: 2, ActorUserId: "user-admin", Subject: "secret-missing"},
		{Seq: 3, ActorUserId: "user-admin", Subject: "folder-1"},
		{Seq: 4, ActorUserId: "user-admin", Subject: "folder-deleted"},
		{Seq: 5, ActorUserId: "user-admin", Subject: "target-1"},
		{Seq: 6, ActorUserId: "user-admin", Subject: "user-1"},
		{Seq: 7, ActorUserId: "user-admin", Subject: "sa-1"},
		{Seq: 8, ActorUserId: "user-admin", Subject: "break-glass-9"},
	}}
	fv := &fakeSubjectVault{
		secrets: map[string]*vaultv1.Secret{"secret-1": {Id: "secret-1", Name: "db password"}},
		folders: []*vaultv1.Folder{{Id: "folder-1", Name: "Infra"}},
		targets: []*vaultv1.Target{{Id: "target-1", Name: "dc1"}},
	}
	fi := &fakeSubjectIdentity{
		labels:          []*identityv1.UserLabel{{Id: "user-1", Name: "Morgan"}},
		serviceAccounts: []*identityv1.ServiceAccount{{Id: "sa-1", Name: "ci-bot"}},
	}
	c := newAuditClient(fa, fv, fi)

	var resp struct {
		AuditRecords []struct {
			Subject, SubjectKind, SubjectID string
			SubjectName                     *string
		}
	}
	c.MustPost(auditSubjectQuery, &resp)
	if len(resp.AuditRecords) != 8 {
		t.Fatalf("got %d records, want 8", len(resp.AuditRecords))
	}
	byKind := map[string]struct {
		Subject, SubjectKind, SubjectID string
		SubjectName                     *string
	}{}
	for _, r := range resp.AuditRecords {
		byKind[r.Subject] = r
	}
	cases := []struct {
		subject, wantKind, wantID, wantName string
		wantNil                             bool
	}{
		{"secret-1#password", "secret", "secret-1", "db password", false},
		{"secret-missing", "secret", "secret-missing", "", true},
		{"folder-1", "folder", "folder-1", "Infra", false},
		{"folder-deleted", "folder", "folder-deleted", "", true},
		{"target-1", "target", "target-1", "dc1", false},
		{"user-1", "user", "user-1", "Morgan", false},
		{"sa-1", "service_account", "sa-1", "ci-bot", false},
		{"break-glass-9", "unknown", "break-glass-9", "", true},
	}
	for _, c := range cases {
		got, ok := byKind[c.subject]
		if !ok {
			t.Fatalf("no record for subject %q", c.subject)
		}
		if got.SubjectKind != c.wantKind {
			t.Errorf("%s: subjectKind = %q, want %q", c.subject, got.SubjectKind, c.wantKind)
		}
		if got.SubjectID != c.wantID {
			t.Errorf("%s: subjectId = %q, want %q", c.subject, got.SubjectID, c.wantID)
		}
		if c.wantNil {
			if got.SubjectName != nil {
				t.Errorf("%s: subjectName = %q, want nil", c.subject, *got.SubjectName)
			}
			continue
		}
		if got.SubjectName == nil || *got.SubjectName != c.wantName {
			t.Errorf("%s: subjectName = %v, want %q", c.subject, got.SubjectName, c.wantName)
		}
	}
}

// Two records naming the same secret (one a field-level reveal) resolve with
// one GetSecret call, not two: subject resolution is batched per page.
func TestAuditRecordSubjectResolutionIsBatchedPerPage(t *testing.T) {
	fa := &fakeAudit{records: []*auditv1.AuditRecord{
		{Seq: 1, ActorUserId: "user-admin", Subject: "secret-1"},
		{Seq: 2, ActorUserId: "user-admin", Subject: "secret-1#password"},
	}}
	fv := &fakeSubjectVault{secrets: map[string]*vaultv1.Secret{"secret-1": {Id: "secret-1", Name: "db password"}}}
	c := newAuditClient(fa, fv, &fakeSubjectIdentity{})

	var resp struct {
		AuditRecords []struct {
			Subject, SubjectKind, SubjectID string
			SubjectName                     *string
		}
	}
	c.MustPost(auditSubjectQuery, &resp)
	if fv.getSecretCall != 1 {
		t.Fatalf("GetSecret called %d times, want 1 (deduped across the page)", fv.getSecretCall)
	}
	for _, r := range resp.AuditRecords {
		if r.SubjectName == nil || *r.SubjectName != "db password" {
			t.Errorf("subject %s: subjectName = %v, want \"db password\"", r.Subject, r.SubjectName)
		}
	}
}
