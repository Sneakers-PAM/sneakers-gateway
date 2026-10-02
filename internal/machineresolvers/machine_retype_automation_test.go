// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"context"
	"testing"

	vaultv1 "github.com/Sneakers-PAM/sneakers-vault/gen/go/sneakers/vault/v1"
	"google.golang.org/grpc"
)

// changeSecretTypeForPrincipal reports what the change left the secret's
// rotation, heartbeat and target at, derived from the new type's capabilities
// and the secret vault returns.

type fakeRetypeTypesVault struct {
	fakeMutateVault
	typesCalls int
}

func (f *fakeRetypeTypesVault) ListSecretTypes(_ context.Context, _ *vaultv1.ListSecretTypesRequest, _ ...grpc.CallOption) (*vaultv1.ListSecretTypesResponse, error) {
	f.typesCalls++
	return &vaultv1.ListSecretTypesResponse{Types: []*vaultv1.SecretType{
		{Id: "type-password"},
		{Id: "type-active-directory", Rotation: true, Heartbeat: true, Checkout: true},
		{Id: "type-ssh-key", Heartbeat: true, Checkout: true},
		{Id: "type-unix-ssh"},
		{Id: "type-ssl-cert"},
	}}, nil
}

type automationResult struct {
	ChangeSecretTypeForPrincipal struct {
		Automation struct{ Rotation, Heartbeat, Target string }
	}
}

func retypeAutomation(t *testing.T, sec *vaultv1.Secret) (automationResult, *fakeRetypeTypesVault) {
	t.Helper()
	fv := &fakeRetypeTypesVault{fakeMutateVault: fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{Secret: sec}}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp automationResult
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "`+sec.GetTypeId()+`") {
		automation { rotation heartbeat target } } }`, &resp)
	return resp, fv
}

func TestChangeSecretTypeForPrincipal_Automation(t *testing.T) {
	cases := []struct {
		name                        string
		sec                         *vaultv1.Secret
		rotation, heartbeat, target string
	}{
		{"into AD with a target", &vaultv1.Secret{Id: "s1", TypeId: "type-active-directory", TargetId: "tg1", RotationOptOut: true},
			"OFF", "ON", "ATTACHED"},
		{"into AD without a target", &vaultv1.Secret{Id: "s1", TypeId: "type-active-directory", RotationOptOut: true},
			"OFF", "NO_TARGET", "NONE"},
		{"into AD with heartbeat opted out", &vaultv1.Secret{Id: "s1", TypeId: "type-active-directory", TargetId: "tg1", RotationOptOut: true, HeartbeatOptOut: true},
			"OFF", "OFF", "ATTACHED"},
		{"rotation enabled", &vaultv1.Secret{Id: "s1", TypeId: "type-active-directory", TargetId: "tg1"},
			"ON", "ON", "ATTACHED"},
		{"out to a generic type", &vaultv1.Secret{Id: "s1", TypeId: "type-password"},
			"NONE", "NONE", "NOT_SUPPORTED"},
		{"into the certificate type", &vaultv1.Secret{Id: "s1", TypeId: "type-ssl-cert"},
			"NONE", "NONE", "NOT_SUPPORTED"},
		{"into a connectable type keeps its target", &vaultv1.Secret{Id: "s1", TypeId: "type-unix-ssh", TargetId: "tg1"},
			"NONE", "NONE", "ATTACHED"},
		{"into a heartbeat-only type", &vaultv1.Secret{Id: "s1", TypeId: "type-ssh-key", TargetId: "tg1"},
			"NONE", "ON", "ATTACHED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, _ := retypeAutomation(t, tc.sec)
			got := resp.ChangeSecretTypeForPrincipal.Automation
			if got.Rotation != tc.rotation || got.Heartbeat != tc.heartbeat || got.Target != tc.target {
				t.Fatalf("automation = %+v, want rotation=%s heartbeat=%s target=%s", got, tc.rotation, tc.heartbeat, tc.target)
			}
		})
	}
}

// The type catalog is read only when the caller asks for automation.
func TestChangeSecretTypeForPrincipal_AutomationOnlyReadsTypesWhenAsked(t *testing.T) {
	fv := &fakeRetypeTypesVault{fakeMutateVault: fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{
		Secret: &vaultv1.Secret{Id: "s1", TypeId: "type-password"},
	}}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		ChangeSecretTypeForPrincipal struct{ FieldKeys []string }
	}
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-password") { fieldKeys } }`, &resp)
	if fv.typesCalls != 0 {
		t.Fatalf("ListSecretTypes called %d times without automation selected", fv.typesCalls)
	}
}

func TestChangeSecretTypeForPrincipal_AutomationUnknownTypeIsAnError(t *testing.T) {
	fv := &fakeRetypeTypesVault{fakeMutateVault: fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{
		Secret: &vaultv1.Secret{Id: "s1", TypeId: "type-gone"},
	}}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp automationResult
	if err := c.Post(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-gone") { automation { rotation } } }`, &resp); err == nil {
		t.Fatal("want an error when the new type is not in the catalog")
	}
}

// Keys vault appended to the notes field are passed through, keys only.
func TestChangeSecretTypeForPrincipal_MovedToNotesKeys(t *testing.T) {
	fv := &fakeMutateVault{retypeResp: &vaultv1.ChangeSecretTypeForPrincipalResponse{
		Secret: &vaultv1.Secret{Id: "s1", TypeId: "type-password"}, FieldKeys: []string{"notes", "password", "username"},
		MovedToNotesKeys: []string{"domain", "netbios"}, NotesFieldKey: "notes",
	}}
	c := newPrincipalClient(&fakePrincipalVault{VaultServiceClient: fv}, "sa-7", "")
	var resp struct {
		ChangeSecretTypeForPrincipal struct{ MovedToNotesKeys []string }
	}
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-password") { movedToNotesKeys } }`, &resp)
	if got := resp.ChangeSecretTypeForPrincipal.MovedToNotesKeys; len(got) != 2 || got[0] != "domain" || got[1] != "netbios" {
		t.Fatalf("movedToNotesKeys = %v", got)
	}

	fv.retypeResp = &vaultv1.ChangeSecretTypeForPrincipalResponse{Secret: &vaultv1.Secret{Id: "s1", TypeId: "type-password"}}
	c.MustPost(`mutation { changeSecretTypeForPrincipal(id: "s1", newTypeId: "type-password") { movedToNotesKeys } }`, &resp)
	if resp.ChangeSecretTypeForPrincipal.MovedToNotesKeys == nil {
		t.Fatal("movedToNotesKeys must be a non-null list")
	}
}
