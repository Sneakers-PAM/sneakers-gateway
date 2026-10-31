// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/maintenance"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type typeChangeVault struct {
	vaultv1.VaultServiceClient
	lastChange  *vaultv1.ChangeSecretTypeRequest
	lastPreview *vaultv1.PreviewSecretTypeChangeRequest
	changeResp  *vaultv1.ChangeSecretTypeResponse
	previewResp *vaultv1.PreviewSecretTypeChangeResponse
	err         error
}

func (f *typeChangeVault) ChangeSecretType(_ context.Context, in *vaultv1.ChangeSecretTypeRequest, _ ...grpc.CallOption) (*vaultv1.ChangeSecretTypeResponse, error) {
	f.lastChange = in
	if f.err != nil {
		return nil, f.err
	}
	return f.changeResp, nil
}

func (f *typeChangeVault) PreviewSecretTypeChange(_ context.Context, in *vaultv1.PreviewSecretTypeChangeRequest, _ ...grpc.CallOption) (*vaultv1.PreviewSecretTypeChangeResponse, error) {
	f.lastPreview = in
	if f.err != nil {
		return nil, f.err
	}
	return f.previewResp, nil
}

func newTypeChangeClient(fv *typeChangeVault, mode *maintenance.Mode) *gqlclient.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv, Maintenance: mode}}))
	h.AddTransport(transport.POST{})
	h.Use(maintenance.Guard{Mode: mode, Allowed: maintenance.HumanAllowed})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-clarke")))
	}))
}

const changeTypeMutation = `mutation {
	changeSecretType(
		id: "s1", newTypeId: "type-note",
		fieldMapping: [{from: "password", to: "secret"}],
		fields: [{key: "url", value: "https://example.org"}],
		unmappedFields: refuse
	) {
		secret { id typeId }
		fieldKeys
		movedToNotesKeys
		notesFieldKey
		changeLabel
	}
}`

const previewTypeChangeQuery = `query {
	previewSecretTypeChange(
		id: "s1", newTypeId: "type-note",
		fieldMapping: [{from: "password", to: "secret"}],
		fields: [{key: "url", value: "https://example.org"}],
		unmappedFields: refuse
	) {
		allowed refusalReason refusalMessage
		fieldChanges { fromKey toKey outcome reason }
		missingRequiredKeys notesFieldKey fieldKeys changeLabel
		rotation heartbeat target fromTargetId targetId
	}
}`

type typeChangePreviewResult struct {
	Allowed        bool
	RefusalReason  *string
	RefusalMessage *string
	FieldChanges   []struct {
		FromKey string
		ToKey   *string
		Outcome string
		Reason  *string
	}
	MissingRequiredKeys         []string
	NotesFieldKey               *string
	FieldKeys                   []string
	ChangeLabel                 *string
	Rotation, Heartbeat, Target string
	FromTargetID, TargetID      *string
}

type previewResp struct {
	PreviewSecretTypeChange typeChangePreviewResult
}

func TestChangeSecretTypeForwardsToTheVaultAsThePerson(t *testing.T) {
	fv := &typeChangeVault{changeResp: &vaultv1.ChangeSecretTypeResponse{
		Secret:           &vaultv1.Secret{Id: "s1", TypeId: "type-note"},
		FieldKeys:        []string{"notes", "secret", "url"},
		MovedToNotesKeys: []string{"host"},
		NotesFieldKey:    "notes",
		ChangeLabel:      "Type changed: Login -> Note",
	}}
	var resp struct {
		ChangeSecretType struct {
			Secret struct {
				ID     string
				TypeID string
			}
			FieldKeys        []string
			MovedToNotesKeys []string
			NotesFieldKey    *string
			ChangeLabel      *string
		}
	}
	newTypeChangeClient(fv, nil).MustPost(changeTypeMutation, &resp)

	in := fv.lastChange
	if in.GetActor().GetUserId() != "user-clarke" || in.GetId() != "s1" || in.GetNewTypeId() != "type-note" {
		t.Fatalf("request = %+v", in)
	}
	if !reflect.DeepEqual(in.GetFieldMapping(), map[string]string{"password": "secret"}) {
		t.Fatalf("field_mapping = %v", in.GetFieldMapping())
	}
	if !reflect.DeepEqual(in.GetFields(), map[string]string{"url": "https://example.org"}) {
		t.Fatalf("fields = %v", in.GetFields())
	}
	if in.GetUnmappedFields() != vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE {
		t.Fatalf("unmapped_fields = %v", in.GetUnmappedFields())
	}
	got := resp.ChangeSecretType
	if got.Secret.ID != "s1" || got.Secret.TypeID != "type-note" {
		t.Fatalf("secret = %+v", got.Secret)
	}
	if !reflect.DeepEqual(got.FieldKeys, []string{"notes", "secret", "url"}) || !reflect.DeepEqual(got.MovedToNotesKeys, []string{"host"}) {
		t.Fatalf("keys = %+v", got)
	}
	if got.NotesFieldKey == nil || *got.NotesFieldKey != "notes" || got.ChangeLabel == nil || *got.ChangeLabel != "Type changed: Login -> Note" {
		t.Fatalf("notes/label = %+v", got)
	}
}

func TestChangeSecretTypeLeavesThePolicyToTheVaultWhenUnset(t *testing.T) {
	fv := &typeChangeVault{changeResp: &vaultv1.ChangeSecretTypeResponse{Secret: &vaultv1.Secret{Id: "s1"}}}
	var resp struct {
		ChangeSecretType struct {
			FieldKeys        []string
			MovedToNotesKeys []string
			NotesFieldKey    *string
		}
	}
	newTypeChangeClient(fv, nil).MustPost(`mutation { changeSecretType(id:"s1", newTypeId:"t") { fieldKeys movedToNotesKeys notesFieldKey } }`, &resp)
	if got := fv.lastChange.GetUnmappedFields(); got != vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_UNSPECIFIED {
		t.Fatalf("unmapped_fields = %v", got)
	}
	got := resp.ChangeSecretType
	if got.FieldKeys == nil || got.MovedToNotesKeys == nil || got.NotesFieldKey != nil {
		t.Fatalf("empty results = %+v", got)
	}
}

func TestChangeSecretTypeNotesPolicyReachesTheVault(t *testing.T) {
	fv := &typeChangeVault{changeResp: &vaultv1.ChangeSecretTypeResponse{Secret: &vaultv1.Secret{Id: "s1"}}}
	var resp struct{ ChangeSecretType struct{ FieldKeys []string } }
	newTypeChangeClient(fv, nil).MustPost(`mutation { changeSecretType(id:"s1", newTypeId:"t", unmappedFields: notes) { fieldKeys } }`, &resp)
	if got := fv.lastChange.GetUnmappedFields(); got != vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_NOTES {
		t.Fatalf("unmapped_fields = %v", got)
	}
}

func TestChangeSecretTypeRefusesDuplicateInputsBeforeTheVault(t *testing.T) {
	cases := map[string]string{
		"mapping": `mutation { changeSecretType(id:"s1", newTypeId:"t", fieldMapping:[{from:"a",to:"b"},{from:"a",to:"c"}]) { fieldKeys } }`,
		"field":   `mutation { changeSecretType(id:"s1", newTypeId:"t", fields:[{key:"a",value:"hunter2"},{key:"a",value:"hunter3"}]) { fieldKeys } }`,
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			fv := &typeChangeVault{}
			var resp struct{ ChangeSecretType struct{ FieldKeys []string } }
			err := newTypeChangeClient(fv, nil).Post(q, &resp)
			if err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("err = %v", err)
			}
			if strings.Contains(err.Error(), "hunter") {
				t.Fatalf("a value reached the error: %v", err)
			}
			if fv.lastChange != nil {
				t.Fatal("the duplicate reached the vault")
			}
		})
	}
}

func TestChangeSecretTypePassesVaultRefusalsThroughUnchanged(t *testing.T) {
	cases := []struct {
		reason string
		code   codes.Code
		name   string
		md     map[string]string
	}{
		{"TYPE_CHANGE_UNMAPPED_FIELDS", codes.FailedPrecondition, "FAILED_PRECONDITION", map[string]string{"fields": "host,url"}},
		{"TYPE_CHANGE_LOWERS_PROTECTION", codes.FailedPrecondition, "FAILED_PRECONDITION", map[string]string{"fields": "password"}},
		{"TYPE_CHANGE_NOTES_TOO_LONG", codes.FailedPrecondition, "FAILED_PRECONDITION", map[string]string{"fields": "host"}},
		{"TYPE_CHANGE_INVALID_FIELD", codes.InvalidArgument, "INVALID_ARGUMENT", map[string]string{"fields": "url"}},
		{"TYPE_CHANGE_CERTIFICATE_INVALID", codes.InvalidArgument, "INVALID_ARGUMENT", map[string]string{"fields": "certificate"}},
		{"FIELD_VALUE_REQUIRED", codes.InvalidArgument, "INVALID_ARGUMENT", map[string]string{"field": "password"}},
		{"FIELD_VALUE_NOT_ALLOWED", codes.InvalidArgument, "INVALID_ARGUMENT", map[string]string{"field": "kind", "allowed": "a,b"}},
		{"ROTATION_IN_PROGRESS", codes.FailedPrecondition, "FAILED_PRECONDITION", nil},
		{"RETIRED", codes.FailedPrecondition, "FAILED_PRECONDITION", nil},
	}
	for _, tc := range cases {
		t.Run(tc.reason, func(t *testing.T) {
			st, err := status.New(tc.code, "refused").WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.vault", Reason: tc.reason, Metadata: tc.md})
			if err != nil {
				t.Fatal(err)
			}
			var resp struct{ ChangeSecretType struct{ FieldKeys []string } }
			perr := newTypeChangeClient(&typeChangeVault{err: st.Err()}, nil).Post(changeTypeMutation, &resp)
			if perr == nil {
				t.Fatal("want the refusal")
			}
			var errs []struct {
				Extensions struct {
					Code, Reason, Domain string
					Metadata             map[string]string
				}
			}
			if jerr := json.Unmarshal([]byte(perr.Error()), &errs); jerr != nil || len(errs) == 0 {
				t.Fatalf("unexpected error shape: %v", perr)
			}
			ext := errs[0].Extensions
			if ext.Code != tc.name || ext.Reason != tc.reason || ext.Domain != "sneakers.vault" {
				t.Fatalf("extensions = %+v", ext)
			}
			if len(tc.md) > 0 && !reflect.DeepEqual(ext.Metadata, tc.md) {
				t.Fatalf("metadata = %v, want %v", ext.Metadata, tc.md)
			}
		})
	}
}

func TestPreviewSecretTypeChangeReportsAnAllowedChange(t *testing.T) {
	fv := &typeChangeVault{previewResp: &vaultv1.PreviewSecretTypeChangeResponse{
		Allowed: true,
		FieldChanges: []*vaultv1.SecretTypeChangeField{
			{FromKey: "host", ToKey: "notes", Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_MOVED_TO_NOTES},
			{FromKey: "password", ToKey: "secret", Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_RENAMED},
			{FromKey: "url", ToKey: "url", Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_CARRIED},
		},
		NotesFieldKey: "notes",
		FieldKeys:     []string{"notes", "secret", "url"},
		ChangeLabel:   "Type changed: Login -> Note",
		Rotation:      "none",
		Heartbeat:     "no_target",
		Target:        "detached",
		FromTargetId:  "t1",
	}}
	var resp previewResp
	newTypeChangeClient(fv, nil).MustPost(previewTypeChangeQuery, &resp)

	assertPreviewRequest(t, fv.lastPreview)

	got := resp.PreviewSecretTypeChange
	if !got.Allowed || got.RefusalReason != nil || got.RefusalMessage != nil {
		t.Fatalf("preview = %+v", got)
	}
	assertPreviewOutcomes(t, got)
	if got.NotesFieldKey == nil || *got.NotesFieldKey != "notes" || got.ChangeLabel == nil {
		t.Fatalf("preview = %+v", got)
	}
	if got.Rotation != "none" || got.Heartbeat != "no_target" || got.Target != "detached" {
		t.Fatalf("automation = %+v", got)
	}
	if got.FromTargetID == nil || *got.FromTargetID != "t1" || got.TargetID != nil {
		t.Fatalf("targets = %+v", got)
	}
}

func assertPreviewRequest(t *testing.T, in *vaultv1.PreviewSecretTypeChangeRequest) {
	t.Helper()
	if in.GetActor().GetUserId() != "user-clarke" || in.GetId() != "s1" || in.GetNewTypeId() != "type-note" {
		t.Fatalf("request = %+v", in)
	}
	if !reflect.DeepEqual(in.GetFieldMapping(), map[string]string{"password": "secret"}) ||
		!reflect.DeepEqual(in.GetFields(), map[string]string{"url": "https://example.org"}) ||
		in.GetUnmappedFields() != vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE {
		t.Fatalf("request = %+v", in)
	}
}

func assertPreviewOutcomes(t *testing.T, got typeChangePreviewResult) {
	t.Helper()
	outcomes := make([]string, 0, len(got.FieldChanges))
	for _, c := range got.FieldChanges {
		outcomes = append(outcomes, c.FromKey+":"+*c.ToKey+":"+c.Outcome)
	}
	if want := []string{"host:notes:movedToNotes", "password:secret:renamed", "url:url:carried"}; !reflect.DeepEqual(outcomes, want) {
		t.Fatalf("outcomes = %v, want %v", outcomes, want)
	}
}

func TestPreviewSecretTypeChangeReportsARefusalAsAnAnswer(t *testing.T) {
	fv := &typeChangeVault{previewResp: &vaultv1.PreviewSecretTypeChangeResponse{
		RefusalReason:  "TYPE_CHANGE_LOWERS_PROTECTION",
		RefusalMessage: "password would land in a less protected field",
		FieldChanges: []*vaultv1.SecretTypeChangeField{
			{FromKey: "password", Outcome: vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_BLOCKED, Reason: "TYPE_CHANGE_LOWERS_PROTECTION"},
		},
		MissingRequiredKeys: []string{"secret"},
		Rotation:            "off",
		Heartbeat:           "none",
		Target:              "kept",
		TargetId:            "t1",
	}}
	var resp previewResp
	newTypeChangeClient(fv, nil).MustPost(previewTypeChangeQuery, &resp)

	got := resp.PreviewSecretTypeChange
	if got.Allowed || got.RefusalReason == nil || *got.RefusalReason != "TYPE_CHANGE_LOWERS_PROTECTION" || got.RefusalMessage == nil {
		t.Fatalf("preview = %+v", got)
	}
	if len(got.FieldChanges) != 1 {
		t.Fatalf("field changes = %+v", got.FieldChanges)
	}
	fc := got.FieldChanges[0]
	if fc.Outcome != "blocked" || fc.ToKey != nil || fc.Reason == nil || *fc.Reason != "TYPE_CHANGE_LOWERS_PROTECTION" {
		t.Fatalf("field change = %+v", fc)
	}
	if !reflect.DeepEqual(got.MissingRequiredKeys, []string{"secret"}) {
		t.Fatalf("missing = %v", got.MissingRequiredKeys)
	}
	if got.FieldKeys == nil || len(got.FieldKeys) != 0 {
		t.Fatalf("field keys = %v, want an empty list", got.FieldKeys)
	}
	if got.TargetID == nil || *got.TargetID != "t1" {
		t.Fatalf("target = %+v", got)
	}
}

func TestPreviewSecretTypeChangePassesGRPCErrorsThrough(t *testing.T) {
	want := status.Error(codes.PermissionDenied, "not permitted")
	var resp previewResp
	err := newTypeChangeClient(&typeChangeVault{err: want}, nil).Post(previewTypeChangeQuery, &resp)
	if err == nil || !strings.Contains(err.Error(), "PERMISSION_DENIED") {
		t.Fatalf("err = %v", err)
	}
}

func TestPreviewSecretTypeChangeRefusesDuplicateInputsBeforeTheVault(t *testing.T) {
	fv := &typeChangeVault{}
	var resp previewResp
	err := newTypeChangeClient(fv, nil).Post(`query { previewSecretTypeChange(id:"s1", newTypeId:"t", fieldMapping:[{from:"a",to:"b"},{from:"a",to:"c"}]) { allowed } }`, &resp)
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("err = %v", err)
	}
	if fv.lastPreview != nil {
		t.Fatal("the duplicate reached the vault")
	}
}

func TestMaintenanceRefusesTheTypeChangeButNotItsPreview(t *testing.T) {
	fv := &typeChangeVault{previewResp: &vaultv1.PreviewSecretTypeChangeResponse{Allowed: true, Rotation: "none", Heartbeat: "none", Target: "none"}}
	c := newTypeChangeClient(fv, maintenance.New(true, nil))

	var changed struct{ ChangeSecretType struct{ FieldKeys []string } }
	if got := reason(t, c.Post(changeTypeMutation, &changed)); got != maintenance.Reason {
		t.Fatalf("reason = %q, want %s", got, maintenance.Reason)
	}
	if fv.lastChange != nil {
		t.Fatal("the refused change still reached the vault")
	}

	var resp previewResp
	c.MustPost(previewTypeChangeQuery, &resp)
	if !resp.PreviewSecretTypeChange.Allowed || fv.lastPreview == nil {
		t.Fatalf("preview = %+v", resp.PreviewSecretTypeChange)
	}
}
