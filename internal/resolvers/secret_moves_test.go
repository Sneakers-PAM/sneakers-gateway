// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"net/http"
	"reflect"
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

type movesVault struct {
	vaultv1.VaultServiceClient
	lastVersions *vaultv1.ListSecretVersionsRequest
	deny         bool
}

func (f *movesVault) ListSecretVersions(_ context.Context, in *vaultv1.ListSecretVersionsRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretVersionsResponse, error) {
	f.lastVersions = in
	if f.deny {
		return nil, status.Error(codes.PermissionDenied, "not permitted to view this secret's history")
	}
	return &vaultv1.ListSecretVersionsResponse{}, nil
}

type movesAudit struct {
	auditv1.AuditServiceClient
	lastList *auditv1.ListRecordsRequest
	records  []*auditv1.AuditRecord
}

func (f *movesAudit) ListRecords(_ context.Context, in *auditv1.ListRecordsRequest, _ ...grpc.CallOption) (*auditv1.ListRecordsResponse, error) {
	f.lastList = in
	return &auditv1.ListRecordsResponse{Records: f.records}, nil
}

type movesIdentity struct {
	identityv1.IdentityServiceClient
}

func (movesIdentity) ResolveUserLabels(_ context.Context, in *identityv1.ResolveUserLabelsRequest, _ ...grpc.CallOption) (*identityv1.ResolveUserLabelsResponse, error) {
	var out []*identityv1.UserLabel
	for _, id := range in.GetIds() {
		if id == "user-ada" {
			out = append(out, &identityv1.UserLabel{Id: id, Name: "Ada Example"})
		}
	}
	return &identityv1.ResolveUserLabelsResponse{Labels: out}, nil
}

func newMovesClient(fv *movesVault, fa *movesAudit, actor string) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Audit: fa, Identity: movesIdentity{}}}))
	h.AddTransport(transport.POST{})
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), actor)))
	}))
}

type secretMoveResult struct {
	MovedBy, MovedByName, MovedAt, FromFolderID, ToFolderID string
}

type secretMovesResp struct {
	SecretMoves []secretMoveResult
}

func TestSecretMovesListsMovesNewestFirst(t *testing.T) {
	fv := &movesVault{}
	fa := &movesAudit{records: []*auditv1.AuditRecord{
		{Seq: 1, Action: "secret.create", ActorUserId: "user-ada", Subject: "s1", OccurredAt: "2026-09-30T18:39:48Z"},
		{Seq: 2, Action: "secret.move", ActorUserId: "user-ada", Subject: "s1", OccurredAt: "2026-09-30T18:45:55Z"},
		{Seq: 3, Action: "secret.update", ActorUserId: "user-ada", Subject: "s1", OccurredAt: "2026-09-30T18:45:56Z"},
		{Seq: 4, Action: "secret.move.approval_required.principal", ActorUserId: "utok-1", Subject: "s1", OccurredAt: "2026-09-30T19:00:00Z",
			Attributes: map[string]string{"from_folder_id": "f-b", "to_folder_id": "f-c"}},
		{Seq: 5, Action: "secret.move.principal", ActorUserId: "utok-1", Subject: "s1", OccurredAt: "2026-09-30T19:10:00Z",
			Attributes: map[string]string{"from_folder_id": "f-a", "to_folder_id": "f-b"}},
		{Seq: 6, Action: "secret.move", ActorUserId: "user-ada", Subject: "s1", OccurredAt: "2026-09-30T19:20:00Z",
			Attributes: map[string]string{"from_folder_id": "f-b", "to_folder_id": "f-a"}},
	}}
	var resp secretMovesResp
	newMovesClient(fv, fa, "user-ada").MustPost(`query { secretMoves(secretId:"s1") { movedBy movedByName movedAt fromFolderId toFolderId } }`, &resp)

	if fv.lastVersions.GetSecretId() != "s1" || fv.lastVersions.GetActor().GetUserId() != "user-ada" {
		t.Fatalf("vault history gate not consulted for the caller: %+v", fv.lastVersions)
	}
	if fa.lastList.GetSubject() != "s1" {
		t.Fatalf("audit subject = %q, want s1", fa.lastList.GetSubject())
	}
	want := secretMovesResp{SecretMoves: []secretMoveResult{
		{MovedBy: "user-ada", MovedByName: "Ada Example", MovedAt: "2026-09-30T19:20:00Z", FromFolderID: "f-b", ToFolderID: "f-a"},
		{MovedBy: "utok-1", MovedByName: "utok-1", MovedAt: "2026-09-30T19:10:00Z", FromFolderID: "f-a", ToFolderID: "f-b"},
		// Recorded before the vault kept folder ids: still a move, folders unknown.
		{MovedBy: "user-ada", MovedByName: "Ada Example", MovedAt: "2026-09-30T18:45:55Z"},
	}}
	if !reflect.DeepEqual(resp, want) {
		t.Errorf("secretMoves = %+v\nwant %+v", resp.SecretMoves, want.SecretMoves)
	}
}

func TestSecretMovesDeniedWithoutHistoryAccess(t *testing.T) {
	fv := &movesVault{deny: true}
	fa := &movesAudit{}
	var resp secretMovesResp
	err := newMovesClient(fv, fa, "user-bob").Post(`query { secretMoves(secretId:"s1") { movedAt } }`, &resp)
	if err == nil {
		t.Fatal("secretMoves returned moves to a caller without history access")
	}
	if fa.lastList != nil {
		t.Error("audit was read before the vault access check passed")
	}
}
