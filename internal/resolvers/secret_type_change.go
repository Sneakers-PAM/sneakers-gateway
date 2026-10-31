// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// typeChangeInputs flattens a type change's lists into the vault's maps. A
// repeated key is refused, because a map would otherwise keep only the last
// entry and silently lose a value. The errors name keys, never values.
func typeChangeInputs(fieldMapping []*FieldMappingInput, fields []*KeyValueInput) (mapping, values map[string]string, err error) {
	mapping = make(map[string]string, len(fieldMapping))
	for _, m := range fieldMapping {
		if _, dup := mapping[m.From]; dup {
			return nil, nil, status.Error(codes.InvalidArgument, "duplicate field mapping for key: "+m.From)
		}
		mapping[m.From] = m.To
	}
	values = make(map[string]string, len(fields))
	for _, f := range fields {
		if _, dup := values[f.Key]; dup {
			return nil, nil, status.Error(codes.InvalidArgument, "duplicate field key: "+f.Key)
		}
		values[f.Key] = f.Value
	}
	return mapping, values, nil
}

func unmappedFieldPolicy(p *UnmappedFieldPolicy) vaultv1.UnmappedFieldPolicy {
	if p == nil {
		return vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_UNSPECIFIED
	}
	if *p == UnmappedFieldPolicyRefuse {
		return vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_REFUSE
	}
	return vaultv1.UnmappedFieldPolicy_UNMAPPED_FIELD_POLICY_NOTES
}

func gqlTypeChangedSecret(resp *vaultv1.ChangeSecretTypeResponse) *TypeChangedSecret {
	return &TypeChangedSecret{
		Secret:           gqlSecret(resp.GetSecret()),
		FieldKeys:        nonNilKeys(resp.GetFieldKeys()),
		MovedToNotesKeys: nonNilKeys(resp.GetMovedToNotesKeys()),
		NotesFieldKey:    emptyToNil(resp.GetNotesFieldKey()),
		ChangeLabel:      emptyToNil(resp.GetChangeLabel()),
	}
}

func gqlSecretTypeChangePreview(resp *vaultv1.PreviewSecretTypeChangeResponse) *SecretTypeChangePreview {
	changes := make([]*SecretTypeChangeField, 0, len(resp.GetFieldChanges()))
	for _, c := range resp.GetFieldChanges() {
		changes = append(changes, &SecretTypeChangeField{
			FromKey: c.GetFromKey(),
			ToKey:   emptyToNil(c.GetToKey()),
			Outcome: gqlTypeChangeOutcome(c.GetOutcome()),
			Reason:  emptyToNil(c.GetReason()),
		})
	}
	return &SecretTypeChangePreview{
		Allowed:             resp.GetAllowed(),
		RefusalReason:       emptyToNil(resp.GetRefusalReason()),
		RefusalMessage:      emptyToNil(resp.GetRefusalMessage()),
		FieldChanges:        changes,
		MissingRequiredKeys: nonNilKeys(resp.GetMissingRequiredKeys()),
		NotesFieldKey:       emptyToNil(resp.GetNotesFieldKey()),
		FieldKeys:           nonNilKeys(resp.GetFieldKeys()),
		ChangeLabel:         emptyToNil(resp.GetChangeLabel()),
		Rotation:            resp.GetRotation(),
		Heartbeat:           resp.GetHeartbeat(),
		Target:              resp.GetTarget(),
		FromTargetID:        emptyToNil(resp.GetFromTargetId()),
		TargetID:            emptyToNil(resp.GetTargetId()),
	}
}

// gqlTypeChangeOutcome treats an outcome this gateway doesn't know as blocked,
// so a client never reads an unknown outcome as a safe move.
func gqlTypeChangeOutcome(o vaultv1.SecretTypeChangeFieldOutcome) SecretTypeChangeOutcome {
	switch o {
	case vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_CARRIED:
		return SecretTypeChangeOutcomeCarried
	case vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_RENAMED:
		return SecretTypeChangeOutcomeRenamed
	case vaultv1.SecretTypeChangeFieldOutcome_SECRET_TYPE_CHANGE_FIELD_OUTCOME_MOVED_TO_NOTES:
		return SecretTypeChangeOutcomeMovedToNotes
	default:
		return SecretTypeChangeOutcomeBlocked
	}
}

func nonNilKeys(keys []string) []string {
	if keys == nil {
		return []string{}
	}
	return keys
}
