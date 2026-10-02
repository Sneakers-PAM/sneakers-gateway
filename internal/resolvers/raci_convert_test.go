// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// TestGqlRaciRule checks the proto->gql RACI rule conversion: the grants map is
// emitted as an ordered C,I,A,R cell list, dropping blank/unknown values.
func TestGqlRaciRule(t *testing.T) {
	in := &vaultv1.RaciRule{
		Id: "raci-1", FolderId: "f1", Order: 2,
		SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE, SubjectName: "",
		Grants: map[string]string{"R": "allow", "C": "allow", "I": "deny", "X": "allow", "A": ""},
	}
	got := gqlRaciRule(in)
	if got.SubjectKind != SubjectKindEveryone {
		t.Fatalf("subjectKind = %v, want everyone", got.SubjectKind)
	}
	if len(got.Grants) != 3 {
		t.Fatalf("grants len = %d, want 3 (blank A + unknown X dropped)", len(got.Grants))
	}
	// Order must be C, I, R (A blank dropped; canonical C,I,A,R order).
	wantOrder := []RaciAction{RaciActionC, RaciActionI, RaciActionR}
	for i, g := range got.Grants {
		if g.Action != wantOrder[i] {
			t.Errorf("grant[%d].Action = %v, want %v", i, g.Action, wantOrder[i])
		}
	}
}

// TestProtoRaciRuleInput checks the gql->proto direction: only allow/deny cells
// survive into the proto grants map, and subject kind maps back.
func TestProtoRaciRuleInput(t *testing.T) {
	in := &RaciRuleInput{
		SubjectKind: SubjectKindGroup, SubjectName: "Platform Team",
		Grants: []*RaciRuleGrantInput{
			{Action: RaciActionC, Value: RaciGrantAllow},
			{Action: RaciActionR, Value: RaciGrantDeny},
		},
	}
	got := protoRaciRuleInput(in)
	if got.GetSubjectKind() != vaultv1.SubjectKind_SUBJECT_KIND_GROUP {
		t.Fatalf("subjectKind = %v, want group", got.GetSubjectKind())
	}
	if got.GetSubjectName() != "Platform Team" {
		t.Errorf("subjectName = %q", got.GetSubjectName())
	}
	if got.GetGrants()["C"] != "allow" || got.GetGrants()["R"] != "deny" {
		t.Errorf("grants = %v, want C=allow R=deny", got.GetGrants())
	}
}

// TestSubjectKindRoundTrip proves the three-way enum mapping is stable both ways.
func TestSubjectKindRoundTrip(t *testing.T) {
	for _, k := range []SubjectKind{SubjectKindEveryone, SubjectKindGroup, SubjectKindUser} {
		if got := subjectKindGQL(subjectKindProto(k)); got != k {
			t.Errorf("round-trip %v -> %v", k, got)
		}
	}
}

// TestGqlFolderOwners checks the proto->gql folder conversion passes the RACI
// owners list through untouched, alongside the other output-only fields.
func TestGqlFolderOwners(t *testing.T) {
	in := &vaultv1.Folder{
		Id: "f1", Name: "Platform Team", SubtreeSecretCount: 3,
		Owners: []string{"user-a", "user-b"},
	}
	got := gqlFolder(in)
	if len(got.Owners) != 2 || got.Owners[0] != "user-a" || got.Owners[1] != "user-b" {
		t.Errorf("Owners = %v, want [user-a user-b]", got.Owners)
	}
	if got.SubtreeSecretCount == nil || *got.SubtreeSecretCount != 3 {
		t.Errorf("SubtreeSecretCount = %v, want 3", got.SubtreeSecretCount)
	}
}

// TestGqlFolderCanManage checks the proto->gql folder conversion passes the
// vault's authoritative can_manage signal through untouched, in both states.
func TestGqlFolderCanManage(t *testing.T) {
	cases := []struct {
		name string
		in   *vaultv1.Folder
		want bool
	}{
		{"owner", &vaultv1.Folder{Id: "f1", Name: "Platform Team", CanManage: true}, true},
		{"non-owner", &vaultv1.Folder{Id: "f1", Name: "Platform Team", CanManage: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gqlFolder(tc.in)
			if got.CanManage != tc.want {
				t.Errorf("CanManage = %v, want %v", got.CanManage, tc.want)
			}
		})
	}
}

// TestGqlCertMetaHasPrivateKey checks gqlCertMeta carries hasPrivateKey through,
// so the UI can seed the key-bearing export-disable state from the
// import/replace response without a page reload.
func TestGqlCertMetaHasPrivateKey(t *testing.T) {
	cases := []struct {
		name string
		in   *vaultv1.CertMeta
		want bool
	}{
		{"with-key", &vaultv1.CertMeta{Subject: "cn=a", HasPrivateKey: true}, true},
		{"cert-only", &vaultv1.CertMeta{Subject: "cn=a", HasPrivateKey: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gqlCertMeta(tc.in)
			if got.HasPrivateKey != tc.want {
				t.Errorf("HasPrivateKey = %v, want %v", got.HasPrivateKey, tc.want)
			}
		})
	}
}

// TestGqlFolderAccessManageRuleset checks gqlFolderAccess carries ManageRuleset
// through in both directions (true and false), alongside the other RACI flags.
func TestGqlFolderAccessManageRuleset(t *testing.T) {
	cases := []struct {
		name string
		in   *vaultv1.FolderAccess
		want bool
	}{
		{"granted", &vaultv1.FolderAccess{Read: true, ManageRuleset: true}, true},
		{"denied", &vaultv1.FolderAccess{Read: true, ManageRuleset: false}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gqlFolderAccess(tc.in)
			if got.ManageRuleset != tc.want {
				t.Errorf("ManageRuleset = %v, want %v", got.ManageRuleset, tc.want)
			}
			if got.Read != tc.in.GetRead() {
				t.Errorf("Read = %v, want %v", got.Read, tc.in.GetRead())
			}
		})
	}
}

// secretRulesetFake is a minimal fake vault client driving buildSecretRuleset/
// SecretRuleset/MySecretAccess: a secret "s1" living in folder "f1", the
// secret's own rule from GetSecretRuleset, and the folder's own rule (with no
// parent) surfaced as the sole inherited entry.
type secretRulesetFake struct {
	vaultv1.VaultServiceClient
}

func (f *secretRulesetFake) GetSecret(_ context.Context, req *vaultv1.GetSecretRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretResponse, error) {
	return &vaultv1.GetSecretResponse{Secret: &vaultv1.Secret{Id: req.GetId(), FolderId: "f1"}}, nil
}

func (f *secretRulesetFake) ListFolders(_ context.Context, _ *vaultv1.ListFoldersRequest, _ ...grpc.CallOption) (*vaultv1.ListFoldersResponse, error) {
	return &vaultv1.ListFoldersResponse{Folders: []*vaultv1.Folder{
		{Id: "f1", Name: "Platform Team"},
	}}, nil
}

func (f *secretRulesetFake) GetFolderRuleset(_ context.Context, req *vaultv1.GetFolderRulesetRequest, _ ...grpc.CallOption) (*vaultv1.GetFolderRulesetResponse, error) {
	if req.GetFolderId() != "f1" {
		return &vaultv1.GetFolderRulesetResponse{}, nil
	}
	return &vaultv1.GetFolderRulesetResponse{
		Owners: []string{"user-owner"},
		Rules: []*vaultv1.RaciRule{
			{Id: "fr1", FolderId: "f1", SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_GROUP, SubjectName: "Platform Team", Grants: map[string]string{"R": "allow"}},
		},
	}, nil
}

func (f *secretRulesetFake) GetSecretRuleset(_ context.Context, req *vaultv1.GetSecretRulesetRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretRulesetResponse, error) {
	return &vaultv1.GetSecretRulesetResponse{
		Rules: []*vaultv1.RaciRule{
			{Id: "sr1", SubjectKind: vaultv1.SubjectKind_SUBJECT_KIND_USER, SubjectName: "user-clarke", Grants: map[string]string{"C": "deny"}},
		},
	}, nil
}

func (f *secretRulesetFake) GetMySecretAccess(_ context.Context, _ *vaultv1.GetMySecretAccessRequest, _ ...grpc.CallOption) (*vaultv1.GetMySecretAccessResponse, error) {
	return &vaultv1.GetMySecretAccessResponse{Access: &vaultv1.FolderAccess{Read: true, Reveal: false, ManageRuleset: true}}, nil
}

// TestSecretRuleset drives the private buildSecretRuleset helper directly: it
// should return the secret's own rule plus one inherited rule tagged with the
// owning folder (which has no parent, so the ancestor walk adds nothing more).
func TestSecretRuleset(t *testing.T) {
	r := &Resolver{Vault: &secretRulesetFake{}}
	got, err := r.buildSecretRuleset(context.Background(), "s1")
	if err != nil {
		t.Fatalf("buildSecretRuleset error: %v", err)
	}
	if got.SecretID != "s1" {
		t.Errorf("secretId = %q, want s1", got.SecretID)
	}
	if len(got.Rules) != 1 || got.Rules[0].SubjectName != "user-clarke" {
		t.Fatalf("rules = %+v, want 1 rule for user-clarke", got.Rules)
	}
	if len(got.Inherited) != 1 {
		t.Fatalf("inherited = %+v, want 1 entry from folder f1", got.Inherited)
	}
	inh := got.Inherited[0]
	if inh.FromFolderID != "f1" || inh.FromFolderName != "Platform Team" {
		t.Errorf("inherited source = %q/%q, want f1/Platform Team", inh.FromFolderID, inh.FromFolderName)
	}
	if inh.Rule.SubjectName != "Platform Team" {
		t.Errorf("inherited rule subject = %q, want Platform Team", inh.Rule.SubjectName)
	}
}

// TestMySecretAccessResolver drives the query resolver end to end against the
// fake, confirming ManageRuleset and the other flags reach the gql response.
func TestMySecretAccessResolver(t *testing.T) {
	r := &queryResolver{&Resolver{Vault: &secretRulesetFake{}}}
	got, err := r.MySecretAccess(context.Background(), "s1")
	if err != nil {
		t.Fatalf("MySecretAccess error: %v", err)
	}
	if !got.Read || got.Reveal || !got.ManageRuleset {
		t.Errorf("access = %+v, want read=true reveal=false manageRuleset=true", got)
	}
}
