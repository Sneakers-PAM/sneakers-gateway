// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"sort"

	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	workflowv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/workflow/v1"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/safeconv"
)

func gqlUser(u *identityv1.User) *User {
	roles := u.GetRoles()
	if roles == nil {
		roles = []string{}
	}
	return &User{
		ID: u.GetId(), Name: u.GetName(), Username: u.GetUsername(), Email: u.GetEmail(),
		Roles: roles, IsRoot: u.GetIsRoot(), Subject: u.GetSubject(),
		EmailVerified: u.GetEmailVerified(),
		Disabled:      u.GetDisabledAtUnix() != 0,
	}
}

func approvalStatusGQL(s workflowv1.ApprovalStatus) ApprovalStatus {
	switch s {
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_APPROVED:
		return ApprovalStatusApproved
	case workflowv1.ApprovalStatus_APPROVAL_STATUS_DENIED:
		return ApprovalStatusDenied
	default:
		return ApprovalStatusPending
	}
}

func gqlLease(l *workflowv1.Lease) *Lease {
	return &Lease{
		ID: l.GetId(), SecretID: l.GetSecretId(), UserID: l.GetUserId(),
		IssuedAt: l.GetIssuedAt(), ExpiresAt: l.GetExpiresAt(), Returned: boolPtr(l.GetReturned()),
	}
}

func gqlApproval(r *workflowv1.ApprovalRequest) *ApprovalRequest {
	comments := make([]*ApprovalComment, 0, len(r.GetComments()))
	for _, c := range r.GetComments() {
		comments = append(comments, gqlApprovalComment(c))
	}
	return &ApprovalRequest{
		ID: r.GetId(), SecretID: r.GetSecretId(), RequestedByUserID: r.GetRequestedByUserId(),
		Status: approvalStatusGQL(r.GetStatus()), RequestedAt: r.GetRequestedAt(),
		Reason:     strPtr(r.GetReason()),
		ResolvedAt: strPtr(r.GetResolvedAt()), ResolvedByUserID: strPtr(r.GetResolvedByUserId()),
		Comments: comments,
		Kind:     requestKindGQL(r.GetKind()),
		FolderID: r.GetFolderId(), DestParentID: r.GetDestParentId(),
		FolderName: r.GetFolderName(), DestParentName: r.GetDestParentName(),
	}
}

// requestKindGQL maps the workflow request kind to the GraphQL enum; anything
// but folder_move is the default secret_access.
func requestKindGQL(k workflowv1.RequestKind) RequestKind {
	switch k {
	case workflowv1.RequestKind_REQUEST_KIND_FOLDER_MOVE:
		return RequestKindFolderMove
	case workflowv1.RequestKind_REQUEST_KIND_SECRET_MOVE:
		return RequestKindSecretMove
	default:
		return RequestKindSecretAccess
	}
}

// gqlApprovalComment converts a workflow ApprovalComment into its GraphQL
// shape; authorName defaults to the raw author id and is upgraded to a display
// name by enrichApprovalNames (batch identity lookup).
func gqlApprovalComment(c *workflowv1.ApprovalComment) *ApprovalComment {
	return &ApprovalComment{
		ID: c.GetId(), AuthorUserID: c.GetAuthorUserId(), AuthorName: c.GetAuthorUserId(),
		Body: c.GetBody(), CreatedAt: c.GetCreatedAt(),
	}
}

// Conversions between vault proto types and the generated GraphQL models.
// Enums map to the schema's lowercase string values.

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// ---- enums: proto -> gql ----

func fieldKindGQL(k vaultv1.FieldKind) FieldKind {
	switch k {
	case vaultv1.FieldKind_FIELD_KIND_MULTILINE:
		return FieldKindMultiline
	case vaultv1.FieldKind_FIELD_KIND_PASSWORD:
		return FieldKindPassword
	case vaultv1.FieldKind_FIELD_KIND_BOOLEAN:
		return FieldKindBoolean
	case vaultv1.FieldKind_FIELD_KIND_SELECT:
		return FieldKindSelect
	case vaultv1.FieldKind_FIELD_KIND_FILE:
		return FieldKindFile
	case vaultv1.FieldKind_FIELD_KIND_SENSITIVE:
		return FieldKindSensitive
	default:
		return FieldKindText
	}
}

func originGQL(o vaultv1.TypeOrigin) TypeOrigin {
	switch o {
	case vaultv1.TypeOrigin_TYPE_ORIGIN_SYSTEM:
		return TypeOriginSystem
	case vaultv1.TypeOrigin_TYPE_ORIGIN_EXTENSION:
		return TypeOriginExtension
	default:
		return TypeOriginCustom
	}
}

func scopeGQL(s vaultv1.FolderScope) FolderScope {
	switch s {
	case vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL:
		return FolderScopePersonal
	case vaultv1.FolderScope_FOLDER_SCOPE_ROLE:
		return FolderScopeRole
	default:
		return FolderScopeGroup
	}
}

func heartbeatGQL(h vaultv1.HeartbeatResult) *HeartbeatResult {
	var v HeartbeatResult
	switch h {
	case vaultv1.HeartbeatResult_HEARTBEAT_RESULT_OK:
		v = HeartbeatResultOk
	case vaultv1.HeartbeatResult_HEARTBEAT_RESULT_FAILED:
		v = HeartbeatResultFailed
	case vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNKNOWN:
		v = HeartbeatResultUnknown
	case vaultv1.HeartbeatResult_HEARTBEAT_RESULT_UNREACHABLE:
		v = HeartbeatResultUnreachable
	case vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_NOT_PINNED:
		v = HeartbeatResultHostKeyNotPinned
	case vaultv1.HeartbeatResult_HEARTBEAT_RESULT_HOST_KEY_MISMATCH:
		v = HeartbeatResultHostKeyMismatch
	default:
		return nil
	}
	return &v
}

func rotationStateGQL(s vaultv1.RotationState) *RotationState {
	var v RotationState
	switch s {
	case vaultv1.RotationState_ROTATION_STATE_OK:
		v = RotationStateOk
	case vaultv1.RotationState_ROTATION_STATE_FAILED:
		v = RotationStateFailed
	case vaultv1.RotationState_ROTATION_STATE_DEGRADED:
		v = RotationStateDegraded
	case vaultv1.RotationState_ROTATION_STATE_ROTATING:
		v = RotationStateRotating
	default:
		return nil
	}
	return &v
}

func roleGQL(r vaultv1.FolderRole) FolderRole {
	switch r {
	case vaultv1.FolderRole_FOLDER_ROLE_WRITE:
		return FolderRoleWrite
	case vaultv1.FolderRole_FOLDER_ROLE_DELETE:
		return FolderRoleDelete
	case vaultv1.FolderRole_FOLDER_ROLE_BULK:
		return FolderRoleBulk
	case vaultv1.FolderRole_FOLDER_ROLE_OWNER:
		return FolderRoleOwner
	default:
		return FolderRoleRead
	}
}

func subjectKindGQL(k vaultv1.SubjectKind) SubjectKind {
	switch k {
	case vaultv1.SubjectKind_SUBJECT_KIND_USER:
		return SubjectKindUser
	case vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE:
		return SubjectKindEveryone
	default:
		return SubjectKindGroup
	}
}

func enforcementGQL(e vaultv1.PolicyEnforcement) *PolicyEnforcement {
	var v PolicyEnforcement
	switch e {
	case vaultv1.PolicyEnforcement_POLICY_ENFORCEMENT_STRICT:
		v = PolicyEnforcementStrict
	case vaultv1.PolicyEnforcement_POLICY_ENFORCEMENT_LAX:
		v = PolicyEnforcementLax
	default:
		return nil
	}
	return &v
}

// ---- enums: gql -> proto (mutation inputs) ----

func roleProto(r FolderRole) vaultv1.FolderRole {
	switch r {
	case FolderRoleWrite:
		return vaultv1.FolderRole_FOLDER_ROLE_WRITE
	case FolderRoleDelete:
		return vaultv1.FolderRole_FOLDER_ROLE_DELETE
	case FolderRoleBulk:
		return vaultv1.FolderRole_FOLDER_ROLE_BULK
	case FolderRoleOwner:
		return vaultv1.FolderRole_FOLDER_ROLE_OWNER
	default:
		return vaultv1.FolderRole_FOLDER_ROLE_READ
	}
}

func subjectKindProto(k SubjectKind) vaultv1.SubjectKind {
	switch k {
	case SubjectKindUser:
		return vaultv1.SubjectKind_SUBJECT_KIND_USER
	case SubjectKindEveryone:
		return vaultv1.SubjectKind_SUBJECT_KIND_EVERYONE
	default:
		return vaultv1.SubjectKind_SUBJECT_KIND_GROUP
	}
}

// ---- models: proto -> gql ----

func gqlField(f *vaultv1.SecretFieldDef) *SecretFieldDef {
	out := &SecretFieldDef{
		Key: f.GetKey(), Label: f.GetLabel(), Kind: fieldKindGQL(f.GetKind()),
		Options: f.GetOptions(), DefaultValue: strPtr(f.GetDefaultValue()),
		Required: boolPtr(f.GetRequired()), Sensitive: boolPtr(f.GetSensitive()),
		PolicyID: strPtr(f.GetPolicyId()), PolicyEnforcement: enforcementGQL(f.GetPolicyEnforcement()),
		Rotates: boolPtr(f.GetRotates()), SuperSensitive: boolPtr(f.GetSuperSensitive()),
		Pattern: strPtr(f.GetPattern()),
	}
	if f.GetMaxLength() > 0 {
		out.MaxLength = intPtr(int(f.GetMaxLength()))
	}
	return out
}

func gqlType(t *vaultv1.SecretType) *SecretType {
	fields := make([]*SecretFieldDef, 0, len(t.GetFields()))
	for _, f := range t.GetFields() {
		fields = append(fields, gqlField(f))
	}
	return &SecretType{
		ID: t.GetId(), Name: t.GetName(), Fields: fields,
		Heartbeat: boolPtr(t.GetHeartbeat()), Checkout: boolPtr(t.GetCheckout()),
		Origin: originGQL(t.GetOrigin()), Vendor: strPtr(t.GetVendor()),
		Rotation: boolPtr(t.GetRotation()),
	}
}

func gqlCertMeta(m *vaultv1.CertMeta) *CertMeta {
	return &CertMeta{
		Subject: m.GetSubject(), Issuer: m.GetIssuer(), Sans: m.GetSans(),
		NotBefore: m.GetNotBefore(), NotAfter: m.GetNotAfter(),
		SerialNumber: m.GetSerialNumber(), FingerprintSha256: m.GetFingerprintSha256(),
		KeyAlgorithm: m.GetKeyAlgorithm(), KeyBits: int(m.GetKeyBits()), IsCa: m.GetIsCa(),
		HasPrivateKey: m.GetHasPrivateKey(),
	}
}

func gqlFolder(f *vaultv1.Folder) *Folder {
	return &Folder{
		ID: f.GetId(), Name: f.GetName(), ParentID: strPtr(f.GetParentId()),
		Scope: scopeGQL(f.GetScope()), OwnerUserID: strPtr(f.GetOwnerUserId()),
		GroupID: strPtr(f.GetGroupId()), Role: strPtr(f.GetRole()),
		IsMasterPersonal: boolPtr(f.GetIsMasterPersonal()), Order: intPtr(int(f.GetOrder())),
		SubtreeSecretCount: intPtr(int(f.GetSubtreeSecretCount())),
		Owners:             f.GetOwners(),
		CanManage:          f.GetCanManage(),
		RevealStepUp:       stepUpModeGQL(f.GetRevealStepUp()),
	}
}

func stepUpModeGQL(m vaultv1.StepUpMode) StepUpMode {
	switch m {
	case vaultv1.StepUpMode_STEP_UP_MODE_REQUIRE:
		return StepUpModeRequire
	case vaultv1.StepUpMode_STEP_UP_MODE_OFF:
		return StepUpModeOff
	default:
		return StepUpModeInherit
	}
}

func stepUpModeProto(m StepUpMode) vaultv1.StepUpMode {
	switch m {
	case StepUpModeRequire:
		return vaultv1.StepUpMode_STEP_UP_MODE_REQUIRE
	case StepUpModeOff:
		return vaultv1.StepUpMode_STEP_UP_MODE_OFF
	default:
		return vaultv1.StepUpMode_STEP_UP_MODE_UNSPECIFIED
	}
}

func gqlSecret(s *vaultv1.Secret) *Secret {
	return &Secret{
		ID: s.GetId(), Name: s.GetName(), FolderID: s.GetFolderId(), TypeID: s.GetTypeId(),
		TargetID:  strPtr(s.GetTargetId()),
		ExpiresAt: strPtr(s.GetExpiresAt()), LastHeartbeatResult: heartbeatGQL(s.GetLastHeartbeatResult()),
		VerifiedAt: strPtr(s.GetVerifiedAt()),
		Masked:     boolPtr(true), ViewCount: intPtr(int(s.GetViewCount())), LastAccessedAt: strPtr(s.GetLastAccessedAt()),
		Retired: s.GetRetired(), RetiredAt: s.GetRetiredAt(),
		LastRotationResult: rotationStateGQL(s.GetLastRotationResult()), RotatedAt: strPtr(s.GetRotatedAt()),
		RotationIntervalDays: intPtr(int(s.GetRotationIntervalDays())), NextRotationAt: strPtr(s.GetNextRotationAt()),
		RotationOptOut: boolPtr(s.GetRotationOptOut()), HeartbeatOptOut: boolPtr(s.GetHeartbeatOptOut()),
		RequireTokenApproval:  boolPtr(s.GetRequireTokenApproval()),
		AlwaysRequireApproval: boolPtr(s.GetAlwaysRequireApproval()),
	}
}

// gqlSecretWithAccess is gqlSecret plus canRead, for the vault calls that set
// can_read (ListSecretsInFolder and GetSecret).
func gqlSecretWithAccess(s *vaultv1.Secret) *Secret {
	out := gqlSecret(s)
	out.CanRead = boolPtr(s.GetCanRead())
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
func bderef(b *bool) bool { return b != nil && *b }
func ideref(i *int) int32 {
	if i == nil {
		return 0
	}
	return safeconv.Int32(*i)
}

func gqlConnection(c *vaultv1.Connection) *Connection {
	return &Connection{
		ID: c.GetId(), Name: c.GetName(), Protocol: c.GetProtocol(),
		Port: intPtr(int(c.GetPort())), UseTLS: boolPtr(c.GetUseTls()), Description: strPtr(c.GetDescription()),
		TargetCount: int(c.GetTargetCount()),
	}
}
func gqlTarget(t *vaultv1.Target) *Target {
	return &Target{
		ID: t.GetId(), Name: t.GetName(), Hostname: t.GetHostname(),
		Kind: strPtr(t.GetKind()), Domain: strPtr(t.GetDomain()), Realm: strPtr(t.GetRealm()),
		ConnectionID: t.GetConnectionId(), Description: strPtr(t.GetDescription()),
		SecretCount: int(t.GetSecretCount()), OwnerUserID: strPtr(t.GetOwnerUserId()),
		SSHHostKeys: append([]string{}, t.GetSshHostKeys()...),
	}
}
func protoConnInput(in ConnectionInput) *vaultv1.Connection {
	return &vaultv1.Connection{
		Id: deref(in.ID), Name: in.Name, Protocol: in.Protocol,
		Port: ideref(in.Port), UseTls: bderef(in.UseTLS), Description: deref(in.Description),
	}
}
func protoTargetInput(in TargetInput) *vaultv1.Target {
	return &vaultv1.Target{
		Id: deref(in.ID), Name: in.Name, Hostname: in.Hostname,
		Kind: deref(in.Kind), Domain: deref(in.Domain), Realm: deref(in.Realm),
		ConnectionId: in.ConnectionID, Description: deref(in.Description),
		SshHostKeys: in.SSHHostKeys,
	}
}

// int32 pointer (proto optional) <-> int pointer (gql)
func i32ToIntPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}
func intToI32Ptr(p *int) *int32 {
	if p == nil {
		return nil
	}
	v := safeconv.Int32(*p)
	return &v
}

func startClassGQL(s string) *PwStartClass {
	var v PwStartClass
	switch s {
	case "letter":
		v = PwStartClassLetter
	case "digit":
		v = PwStartClassDigit
	case "symbol":
		v = PwStartClassSymbol
	case "any":
		v = PwStartClassAny
	default:
		return nil
	}
	return &v
}
func startClassProto(p *PwStartClass) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func gqlPolicy(p *vaultv1.PasswordPolicy) *PasswordPolicy {
	return &PasswordPolicy{
		ID: p.GetId(), Name: p.GetName(), MinLength: int(p.GetMinLength()),
		MaxLength: i32ToIntPtr(p.MaxLength), RequireUpper: p.GetRequireUpper(),
		RequireLower: p.GetRequireLower(), RequireDigit: p.GetRequireDigit(),
		RequireSymbol: p.GetRequireSymbol(), RotationDays: i32ToIntPtr(p.RotationDays),
		StartClass: startClassGQL(p.GetStartClass()), EndLiteral: strPtr(p.GetEndLiteral()),
		ExcludeChars: strPtr(p.GetExcludeChars()),
		IsDefault:    p.GetIsDefault(), ByTypeFields: int(p.GetByTypeFields()), Deletable: p.GetDeletable(),
	}
}
func protoPolicyInput(in PasswordPolicyInput) *vaultv1.PasswordPolicy {
	return &vaultv1.PasswordPolicy{
		Id: deref(in.ID), Name: in.Name, MinLength: safeconv.Int32(in.MinLength),
		MaxLength: intToI32Ptr(in.MaxLength), RequireUpper: in.RequireUpper,
		RequireLower: in.RequireLower, RequireDigit: in.RequireDigit, RequireSymbol: in.RequireSymbol,
		RotationDays: intToI32Ptr(in.RotationDays), StartClass: startClassProto(in.StartClass),
		EndLiteral: deref(in.EndLiteral), ExcludeChars: deref(in.ExcludeChars),
	}
}
func gqlSettings(s *vaultv1.SecuritySettings) *SecuritySettings {
	return &SecuritySettings{
		DefaultPasswordPolicyID:        strPtr(s.GetDefaultPasswordPolicyId()),
		RequireMfaForSensitiveCheckout: s.GetRequireMfaForSensitiveCheckout(),
		AllowAPIForSensitive:           s.GetAllowApiForSensitive(),
		RequestHistoryRetentionDays:    intPtr(int(s.GetRequestHistoryRetentionDays())),
		SessionTTLSeconds:              intPtr(int(s.GetSessionTtlSeconds())),
		RequireMfaForReveal:            s.GetRequireMfaForReveal(),
	}
}

// ---- inputs: gql -> proto ----

func fieldKindProto(k FieldKind) vaultv1.FieldKind {
	switch k {
	case FieldKindMultiline:
		return vaultv1.FieldKind_FIELD_KIND_MULTILINE
	case FieldKindPassword:
		return vaultv1.FieldKind_FIELD_KIND_PASSWORD
	case FieldKindBoolean:
		return vaultv1.FieldKind_FIELD_KIND_BOOLEAN
	case FieldKindSelect:
		return vaultv1.FieldKind_FIELD_KIND_SELECT
	case FieldKindFile:
		return vaultv1.FieldKind_FIELD_KIND_FILE
	case FieldKindSensitive:
		return vaultv1.FieldKind_FIELD_KIND_SENSITIVE
	default:
		return vaultv1.FieldKind_FIELD_KIND_TEXT
	}
}

func enforcementProto(e *PolicyEnforcement) vaultv1.PolicyEnforcement {
	if e == nil {
		return vaultv1.PolicyEnforcement_POLICY_ENFORCEMENT_UNSPECIFIED
	}
	if *e == PolicyEnforcementStrict {
		return vaultv1.PolicyEnforcement_POLICY_ENFORCEMENT_STRICT
	}
	return vaultv1.PolicyEnforcement_POLICY_ENFORCEMENT_LAX
}

func protoFieldInput(f *SecretFieldDefInput) *vaultv1.SecretFieldDef {
	return &vaultv1.SecretFieldDef{
		Key: f.Key, Label: f.Label, Kind: fieldKindProto(f.Kind), Options: f.Options,
		DefaultValue: deref(f.DefaultValue), Required: bderef(f.Required), Sensitive: bderef(f.Sensitive),
		PolicyId: deref(f.PolicyID), PolicyEnforcement: enforcementProto(f.PolicyEnforcement),
		Rotates: bderef(f.Rotates), SuperSensitive: bderef(f.SuperSensitive),
		Pattern: deref(f.Pattern), MaxLength: ideref(f.MaxLength),
	}
}

func protoTypeInput(in SecretTypeInput) *vaultv1.SecretType {
	fields := make([]*vaultv1.SecretFieldDef, 0, len(in.Fields))
	for _, f := range in.Fields {
		fields = append(fields, protoFieldInput(f))
	}
	return &vaultv1.SecretType{Name: in.Name, Fields: fields, Heartbeat: bderef(in.Heartbeat), Checkout: bderef(in.Checkout), Rotation: bderef(in.Rotation)}
}

func gqlRule(r *vaultv1.FolderAccessRule) *FolderAccessRule {
	return &FolderAccessRule{
		ID: r.GetId(), FolderID: r.GetFolderId(), SubjectKind: subjectKindGQL(r.GetSubjectKind()),
		SubjectID: r.GetSubjectId(), Role: roleGQL(r.GetRole()),
	}
}

// ---- firewall-RACI: proto <-> gql --------------------------------------------

// raciActionOrder keeps grant cells in a stable C, I, A, R order (proto grants
// are an unordered map).
var raciActionOrder = []RaciAction{RaciActionC, RaciActionI, RaciActionA, RaciActionR}

// gqlRaciGrants converts a proto grants map ({"C|I|A|R": "allow|deny"}) into the
// ordered gql grant-cell list, skipping blank/unknown values.
func gqlRaciGrants(grants map[string]string) []*RaciRuleGrant {
	out := make([]*RaciRuleGrant, 0, len(grants))
	for _, act := range raciActionOrder {
		v, ok := grants[string(act)]
		if !ok {
			continue
		}
		switch RaciGrant(v) {
		case RaciGrantAllow, RaciGrantDeny:
			out = append(out, &RaciRuleGrant{Action: act, Value: RaciGrant(v)})
		}
	}
	return out
}

func gqlRaciRule(r *vaultv1.RaciRule) *RaciRule {
	return &RaciRule{
		ID: r.GetId(), FolderID: r.GetFolderId(), Order: int(r.GetOrder()),
		SubjectKind: subjectKindGQL(r.GetSubjectKind()), SubjectName: r.GetSubjectName(),
		SubjectID: strPtr(r.GetSubjectId()), Grants: gqlRaciGrants(r.GetGrants()),
	}
}

// protoRaciRuleInput converts one gql rule input into a proto RaciRule (id/order
// are assigned server-side by the vault). Blank/unknown grant values are dropped.
func protoRaciRuleInput(in *RaciRuleInput) *vaultv1.RaciRule {
	grants := make(map[string]string, len(in.Grants))
	for _, g := range in.Grants {
		if g == nil {
			continue
		}
		if g.Value == RaciGrantAllow || g.Value == RaciGrantDeny {
			grants[string(g.Action)] = string(g.Value)
		}
	}
	return &vaultv1.RaciRule{
		SubjectKind: subjectKindProto(in.SubjectKind), SubjectName: in.SubjectName, SubjectId: deref(in.SubjectID), Grants: grants,
	}
}

func gqlFolderAccess(a *vaultv1.FolderAccess) *FolderAccess {
	return &FolderAccess{
		Read: a.GetRead(), Reveal: a.GetReveal(), Manage: a.GetManage(),
		Approve: a.GetApprove(), Informed: a.GetInformed(),
		ManageRuleset: a.GetManageRuleset(),
	}
}

// gqlRaciDecision converts a simulated RACI decision (per-action grant +
// human-readable reason) from the vault's SimulateFolder/SimulateSecret
// response into the gql model.
func gqlRaciDecision(d *vaultv1.RaciDecision) *RaciDecision {
	return &RaciDecision{
		Read: d.GetRead(), ReadReason: d.GetReadReason(),
		Reveal: d.GetReveal(), RevealReason: d.GetRevealReason(),
		Manage: d.GetManage(), ManageReason: d.GetManageReason(),
		Approve: d.GetApprove(), ApproveReason: d.GetApproveReason(),
		Informed: d.GetInformed(), InformedReason: d.GetInformedReason(),
	}
}

// auditTierGQL maps the audit Tier enum to the lowercase string the GraphQL
// schema exposes ("audit" | "activity"), defaulting unknown/unspecified to
// "activity" (the routine tier).
func auditTierGQL(t auditv1.Tier) string {
	switch t {
	case auditv1.Tier_TIER_AUDIT:
		return "audit"
	case auditv1.Tier_TIER_ACTIVITY:
		return "activity"
	default:
		return "activity"
	}
}

// gqlAuditRecord converts an audit-service AuditRecord into its GraphQL shape.
// actorName is the resolved human-readable label (falls back to the actor id
// upstream); attributes are emitted key-sorted for a stable UI ordering.
func gqlAuditRecord(rec *auditv1.AuditRecord, actorName string) *AuditRecord {
	attrs := make([]*AuditAttr, 0, len(rec.GetAttributes()))
	for k, v := range rec.GetAttributes() {
		attrs = append(attrs, &AuditAttr{Key: k, Value: v})
	}
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].Key < attrs[j].Key })
	return &AuditRecord{
		Seq:         safeconv.IntFromUint64(rec.GetSeq()),
		Tier:        auditTierGQL(rec.GetTier()),
		Action:      rec.GetAction(),
		ActorUserID: rec.GetActorUserId(),
		ActorName:   actorName,
		Subject:     rec.GetSubject(),
		GroupID:     rec.GetGroupId(),
		Sensitive:   rec.GetSensitive(),
		Attributes:  attrs,
		OccurredAt:  rec.GetOccurredAt(),
		PrevHash:    rec.GetPrevHash(),
		Hash:        rec.GetHash(),
	}
}

// gqlSecretVersion converts a vault SecretVersion into its GraphQL shape.
// createdByName is the resolved human-readable label (falls back to the raw
// createdBy id upstream); field keys are passed through as-is (already sorted by
// the vault, values never present).
func gqlSecretVersion(v *vaultv1.SecretVersion, createdByName string) *SecretVersion {
	keys := v.GetFieldKeys()
	if keys == nil {
		keys = []string{}
	}
	changed := v.GetChangedFieldKeys()
	if changed == nil {
		changed = []string{}
	}
	return &SecretVersion{
		VersionNo:        int(v.GetVersionNo()),
		CreatedBy:        v.GetCreatedBy(),
		CreatedByName:    createdByName,
		CreatedAt:        v.GetCreatedAt(),
		Active:           v.GetActive(),
		FieldKeys:        keys,
		ChangedFieldKeys: changed,
	}
}

// gqlAuditChain converts the audit-service VerifyChain response into its
// GraphQL shape for the tamper-evidence banner.
func gqlAuditChain(resp *auditv1.VerifyChainResponse) *AuditChainStatus {
	return &AuditChainStatus{
		Valid:       resp.GetValid(),
		BrokenAtSeq: safeconv.IntFromUint64(resp.GetBrokenAtSeq()),
		Length:      safeconv.IntFromUint64(resp.GetLength()),
	}
}

// gqlServiceAccount converts an identity ServiceAccount into its GraphQL
// shape, including the OidcIssuer/OidcSubject/OidcAllowedGroups linkage.
// OidcAllowedGroups is a non-null GraphQL list, so it is never nil
// (unlinked => []). Never carries a token value — ServiceAccount has none;
// see gqlAPIToken/MintApiTokenResult for tokens.
func gqlServiceAccount(sa *identityv1.ServiceAccount) *ServiceAccount {
	return &ServiceAccount{
		ID:                sa.GetId(),
		Name:              sa.GetName(),
		Description:       sa.GetDescription(),
		Disabled:          sa.GetDisabled(),
		CreatedBy:         sa.GetCreatedBy(),
		CreatedAtUnix:     safeconv.IntFromInt64(sa.GetCreatedAtUnix()),
		OidcIssuer:        emptyToNil(sa.GetOidcIssuer()),
		OidcSubject:       emptyToNil(sa.GetOidcSubject()),
		OidcAllowedGroups: append([]string{}, sa.GetOidcAllowedGroups()...),
	}
}

// emptyToNil turns identity's "unset" sentinel for a proto string field
// (empty string — most service accounts are never OIDC-linked) into a nil
// GraphQL optional String, so oidcIssuer/oidcSubject are null rather than ""
// when the service account has no OIDC link.
func emptyToNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// gqlAPIToken converts identity ApiToken metadata into its GraphQL shape.
// Deliberately has no token field to convert — ApiToken is metadata-only on
// the wire (the plaintext token is carried solely by MintApiTokenResponse,
// exactly once, at mint time).
func gqlAPIToken(t *identityv1.ApiToken) *APIToken {
	return &APIToken{
		ID:               t.GetId(),
		ServiceAccountID: t.GetServiceAccountId(),
		Scope:            t.GetScope(),
		ExpiresAtUnix:    safeconv.IntFromInt64(t.GetExpiresAtUnix()),
		RevokedAtUnix:    safeconv.IntFromInt64(t.GetRevokedAtUnix()),
		LastUsedAtUnix:   safeconv.IntFromInt64(t.GetLastUsedAtUnix()),
		CreatedBy:        t.GetCreatedBy(),
	}
}

func gqlUserToken(t *identityv1.UserToken) *UserToken {
	return &UserToken{
		ID: t.GetId(), Label: t.GetLabel(), ClientName: t.GetClientName(),
		CreatedAtUnix:  safeconv.IntFromInt64(t.GetCreatedAtUnix()),
		LastUsedAtUnix: safeconv.IntFromInt64(t.GetLastUsedAtUnix()),
		ExpiresAtUnix:  safeconv.IntFromInt64(t.GetExpiresAtUnix()),
		RevokedAtUnix:  safeconv.IntFromInt64(t.GetRevokedAtUnix()),
	}
}
