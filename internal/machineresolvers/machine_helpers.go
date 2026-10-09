// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package machineresolvers helpers kept OUT of machine.resolvers.go on
// purpose: gqlgen's follow-schema rewriter for that file only understands the
// bound Query/Mutation resolver methods and the mutationResolver/
// queryResolver adapter structs — anything else gets swept into a warning
// comment on every regen.
package machineresolvers

import (
	"context"
	"net/url"
	"slices"
	"strings"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/safeconv"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// deref returns the zero value for a nil optional GraphQL scalar argument,
// otherwise the pointed-to value — used for the optional string args
// (query/folderId/typeId/policyId/targetId) gqlgen binds as *string.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// derefBool is deref's bool counterpart, for the optional Boolean args.
func derefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

// fieldMap flattens the GraphQL SecretFieldInput list into the
// map[string]string the vault CreateSecretForPrincipal/
// GenerateSecretForPrincipal requests carry. A repeated key would otherwise
// silently last-write-win and drop a field value, so a duplicate key is
// rejected instead of overwritten.
func fieldMap(fields []*SecretFieldInput) (map[string]string, error) {
	out := make(map[string]string, len(fields))
	for _, f := range fields {
		if f == nil {
			continue
		}
		if _, dup := out[f.Key]; dup {
			return nil, status.Error(codes.InvalidArgument, "duplicate field key: "+f.Key)
		}
		out[f.Key] = f.Value
	}
	return out, nil
}

// mappingMap flattens the changeSecretTypeForPrincipal FieldMappingInput list
// into vault's old-key -> new-key map. A repeated source key is rejected (it
// would otherwise silently last-write-win).
func mappingMap(in []*FieldMappingInput) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for _, m := range in {
		if m == nil {
			continue
		}
		if _, dup := out[m.From]; dup {
			return nil, status.Error(codes.InvalidArgument, "duplicate field mapping for key: "+m.From)
		}
		out[m.From] = m.To
	}
	return out, nil
}

// summaryOf maps a vault Secret (metadata-only) to the GraphQL SecretSummary.
// Never touches field values — the vault Secret proto carries none.
func summaryOf(sec *vaultv1.Secret) *SecretSummary {
	if sec == nil {
		return nil
	}
	out := &SecretSummary{
		ID:              sec.GetId(),
		Name:            sec.GetName(),
		FolderID:        sec.GetFolderId(),
		TypeID:          sec.GetTypeId(),
		RotationOptOut:  sec.GetRotationOptOut(),
		HeartbeatOptOut: sec.GetHeartbeatOptOut(),

		ValueVersion:     int(sec.GetValueVersion()),
		ValueChangedAt:   emptyToNil(sec.GetValueChangedAt()),
		RotationEnabled:  sec.GetRotationEnabled(),
		RotatesOnCheckin: sec.GetRotatesOnCheckin(),
		HeartbeatEnabled: sec.GetHeartbeatEnabled(),
		RotatedAt:        emptyToNil(sec.GetRotatedAt()),
		NextRotationAt:   emptyToNil(sec.GetNextRotationAt()),
	}
	if tid := sec.GetTargetId(); tid != "" {
		out.TargetID = &tid
	}
	if r := sec.GetLastRotationResult(); r != vaultv1.RotationState_ROTATION_STATE_UNSPECIFIED {
		out.LastRotationResult = emptyToNil(strings.TrimPrefix(r.String(), "ROTATION_STATE_"))
	}
	if r := sec.GetLastHeartbeatResult(); r != vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNSPECIFIED {
		out.LastHeartbeatResult = emptyToNil(strings.TrimPrefix(r.String(), "HEARTBEAT_RESULT_"))
	}
	return out
}

// connectableTypeIDs take a target without having heartbeat or rotation.
// Mirrors vault's typeTakesTarget.
var connectableTypeIDs = map[string]bool{"type-ssh-key": true, "type-unix-ssh": true}

// typeChangeAutomationOf derives what a type change left the secret's
// automation and target at, from the new type and the secret vault returned,
// by the rules vault applies.
func typeChangeAutomationOf(t *vaultv1.SecretType, sec *SecretSummary) *TypeChangeAutomation {
	hasTarget := sec.TargetID != nil && *sec.TargetID != ""
	out := &TypeChangeAutomation{Rotation: TypeChangeRotationNone, Heartbeat: TypeChangeHeartbeatNone, Target: TypeChangeTargetNotSupported}
	switch {
	case !t.GetRotation():
	case sec.RotationOptOut:
		out.Rotation = TypeChangeRotationOff
	default:
		out.Rotation = TypeChangeRotationOn
	}
	switch {
	case !t.GetHeartbeat():
	case sec.HeartbeatOptOut:
		out.Heartbeat = TypeChangeHeartbeatOff
	case !hasTarget:
		out.Heartbeat = TypeChangeHeartbeatNoTarget
	default:
		out.Heartbeat = TypeChangeHeartbeatOn
	}
	if t.GetHeartbeat() || t.GetRotation() || connectableTypeIDs[t.GetId()] {
		out.Target = TypeChangeTargetNone
		if hasTarget {
			out.Target = TypeChangeTargetAttached
		}
	}
	return out
}

// summariesOf maps a slice of vault Secrets to GraphQL SecretSummaries,
// preserving order.
func summariesOf(secrets []*vaultv1.Secret) []*SecretSummary {
	out := make([]*SecretSummary, 0, len(secrets))
	for _, sec := range secrets {
		out = append(out, summaryOf(sec))
	}
	return out
}

// emptyToNil turns vault's "unset" sentinel for generated_value (empty
// string, since return_value defaulted to false) into a nil GraphQL optional
// String, so generatedValue is null rather than "" when nothing was returned.
func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// principalFoldersOf maps the principal's visible folders to PrincipalFolders,
// keeping those whose name contains query (case-insensitive) and whose parent
// is parentID, when set. Each path joins names up through visible ancestors;
// a visited set stops the walk on a parent cycle.
func principalFoldersOf(folders []*vaultv1.Folder, query, parentID string) []*PrincipalFolder {
	byID := make(map[string]*vaultv1.Folder, len(folders))
	for _, f := range folders {
		byID[f.GetId()] = f
	}
	q := strings.ToLower(strings.TrimSpace(query))
	out := make([]*PrincipalFolder, 0, len(folders))
	for _, f := range folders {
		if parentID != "" && f.GetParentId() != parentID {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(f.GetName()), q) {
			continue
		}
		out = append(out, principalFolderOf(f, byID))
	}
	return out
}

// visiblePrincipalFolder maps a folder a folder mutation returned, taking its
// entry from the principal's visible tree so the path matches
// foldersForPrincipal. Vault returns only the one folder, so without the
// listing the path is just its name. The mutation has already committed, so a
// failed listing or a missing entry falls back to that name rather than
// reporting an error for a change that happened.
func (r *Resolver) visiblePrincipalFolder(ctx context.Context, f *vaultv1.Folder) *PrincipalFolder {
	list, err := r.Vault.ListFoldersForPrincipal(ctx, &vaultv1.ListFoldersForPrincipalRequest{
		Actor: resolvers.MachineActorOf(ctx),
	})
	if err != nil {
		return principalFolderOf(f, nil)
	}
	for _, pf := range principalFoldersOf(list.GetFolders(), "", "") {
		if pf.ID == f.GetId() {
			return pf
		}
	}
	return principalFolderOf(f, nil)
}

// principalFolderOf maps one folder, joining its path through the ancestors
// present in byID. A nil or empty byID gives a path of the folder's own name.
func principalFolderOf(f *vaultv1.Folder, byID map[string]*vaultv1.Folder) *PrincipalFolder {
	var names []string
	seen := map[string]bool{}
	for cur := f; cur != nil && !seen[cur.GetId()]; cur = byID[cur.GetParentId()] {
		seen[cur.GetId()] = true
		names = append(names, cur.GetName())
	}
	slices.Reverse(names)
	pf := &PrincipalFolder{ID: f.GetId(), Name: f.GetName(), Path: strings.Join(names, "/"), CanAuthor: f.GetCanManage()}
	if pid := f.GetParentId(); pid != "" {
		pf.ParentID = &pid
	}
	return pf
}

// secretTypesOf maps catalog types to summaries. Default values stay behind.
func secretTypesOf(types []*vaultv1.SecretType) []*SecretTypeSummary {
	out := make([]*SecretTypeSummary, 0, len(types))
	for _, t := range types {
		fields := make([]*SecretTypeField, 0, len(t.GetFields()))
		for _, fd := range t.GetFields() {
			fields = append(fields, &SecretTypeField{
				Key: fd.GetKey(), Label: fd.GetLabel(), Required: fd.GetRequired(), Sensitive: fd.GetSensitive(),
				Kind: strings.TrimPrefix(fd.GetKind().String(), "FIELD_KIND_"),
			})
		}
		out = append(out, &SecretTypeSummary{ID: t.GetId(), Name: t.GetName(), Fields: fields})
	}
	return out
}

func (r *Resolver) secretUseOf(u *vaultv1.SecretUse) *SecretUse {
	out := &SecretUse{
		ID: u.GetId(), SecretID: u.GetSecretId(), SecretName: u.GetSecretName(), FieldKey: u.GetFieldKey(),
		Argv: append([]string{}, u.GetArgv()...), State: strings.TrimPrefix(u.GetState().String(), "SECRET_USE_STATE_"),
		ExpiresAtUnix: safeconv.IntFromInt64(u.GetExpiresAtUnix()),
		ApprovalURL:   strings.TrimRight(r.PublicURL, "/") + "/approvals",
		Reveal:        u.GetReveal(),
		Confirm:       u.GetConfirm(),
	}
	if id := u.GetRunId(); id != "" {
		out.RunID = &id
		if r.ApprovalRunLinks {
			out.ApprovalURL += "/run/" + url.PathEscape(id)
		}
	}
	return out
}

// prepareRefusal gives vault's InvalidArgument for a prepare (a bad argv,
// run id or purpose) the stable reason SECRET_USE_REQUEST_INVALID, keeping
// vault's message, which names the field. Other refusals, and one that already
// carries a reason, pass through.
func prepareRefusal(err error) error {
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		return err
	}
	for _, d := range st.Details() {
		if _, ok := d.(*errdetails.ErrorInfo); ok {
			return err
		}
	}
	coded, _ := status.New(codes.InvalidArgument, st.Message()).
		WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.gateway", Reason: "SECRET_USE_REQUEST_INVALID"})
	return coded.Err()
}

func targetOf(t *vaultv1.Target) *MachineTarget {
	return &MachineTarget{
		ID: t.GetId(), Name: t.GetName(), Hostname: t.GetHostname(), Kind: t.GetKind(), Domain: t.GetDomain(),
		Realm: t.GetRealm(), ConnectionID: t.GetConnectionId(), Description: t.GetDescription(),
		OwnerUserID: t.GetOwnerUserId(), SecretCount: int(t.GetSecretCount()),
		SSHHostKeys: append([]string{}, t.GetSshHostKeys()...),
	}
}
