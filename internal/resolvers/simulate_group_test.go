// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"slices"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc"
)

// simGroupIdentity resolves a fixed group membership for whichever userID
// the simulation resolvers ask about, so the test can simulate two
// different users against the same rule.
type simGroupIdentity struct {
	identityv1.IdentityServiceClient
	groupsByUser map[string][]*identityv1.Group
}

func (f *simGroupIdentity) GetUser(_ context.Context, in *identityv1.GetUserRequest, _ ...grpc.CallOption) (*identityv1.GetUserResponse, error) {
	return &identityv1.GetUserResponse{User: &identityv1.User{Id: in.GetId()}}, nil
}

func (f *simGroupIdentity) ListUserGroups(_ context.Context, in *identityv1.ListUserGroupsRequest, _ ...grpc.CallOption) (*identityv1.ListUserGroupsResponse, error) {
	return &identityv1.ListUserGroupsResponse{Groups: f.groupsByUser[in.GetUserId()]}, nil
}

// simGroupIDVault stands in for the vault's RACI simulation: a folder's lone
// draft rule grants read to one GROUP by subject_id, matching the simulated
// user's SimGroupIds alone (never SimGroupNames), the same way vault's own
// authz package matches an id-carrying GROUP rule.
type simGroupIDVault struct {
	vaultv1.VaultServiceClient
	lastReq *vaultv1.SimulateFolderRequest
}

func (f *simGroupIDVault) SimulateFolder(_ context.Context, req *vaultv1.SimulateFolderRequest, _ ...grpc.CallOption) (*vaultv1.SimulateFolderResponse, error) {
	f.lastReq = req
	matched := false
	for _, rule := range req.GetDraftRules() {
		if rule.GetSubjectKind() == vaultv1.SubjectKind_SUBJECT_KIND_GROUP && rule.GetSubjectId() != "" &&
			slices.Contains(req.GetSimGroupIds(), rule.GetSubjectId()) {
			matched = true
		}
	}
	return &vaultv1.SimulateFolderResponse{Decision: &vaultv1.RaciDecision{Read: matched}}, nil
}

// TestSimulateFolderMatchesGroupRuleByID shows the gateway resolves the
// simulated user's directory group ids (not just names) and sends them as
// sim_group_ids, so a draft GROUP rule carrying a subject_id is matched for
// a member of that group and refused for a user in a same-named group with a
// different id.
func TestSimulateFolderMatchesGroupRuleByID(t *testing.T) {
	fv := &simGroupIDVault{}
	fi := &simGroupIdentity{groupsByUser: map[string][]*identityv1.Group{
		"user-member":   {{Id: "grp-ops", Name: "Ops"}},
		"user-outsider": {{Id: "grp-ops-renamed", Name: "Ops"}},
	}}
	r := &queryResolver{&Resolver{Vault: fv, Identity: fi}}
	draftRules := []*RaciRuleInput{{
		SubjectKind: SubjectKindGroup, SubjectName: "Ops", SubjectID: strPtr("grp-ops"),
		Grants: []*RaciRuleGrantInput{{Action: RaciActionR, Value: RaciGrantAllow}},
	}}

	got, err := r.SimulateFolder(context.Background(), "f1", "user-member", draftRules)
	if err != nil {
		t.Fatalf("SimulateFolder (member) error: %v", err)
	}
	if !got.Read {
		t.Errorf("member: read = %v, want true (group id grp-ops matches)", got.Read)
	}
	if !slices.Contains(fv.lastReq.GetSimGroupIds(), "grp-ops") {
		t.Errorf("member: SimGroupIds = %v, want it to contain grp-ops", fv.lastReq.GetSimGroupIds())
	}

	got, err = r.SimulateFolder(context.Background(), "f1", "user-outsider", draftRules)
	if err != nil {
		t.Fatalf("SimulateFolder (outsider) error: %v", err)
	}
	if got.Read {
		t.Errorf("outsider: read = %v, want false (grp-ops-renamed != grp-ops, name alone must not match)", got.Read)
	}
}
