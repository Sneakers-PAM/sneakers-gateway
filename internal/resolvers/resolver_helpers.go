// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

// Private resolver helpers, deliberately kept out of schema.resolvers.go.
//
// gqlgen's follow-schema rewriter only understands two things in that file:
// the bound Query/Mutation resolver methods, and the mutationResolver /
// queryResolver adapter structs. Anything else living below those adapters —
// regardless of its name — gets swept into a "would be deleted" warning block
// on every `gqlgen generate`, because the tool has no way to tell a
// deliberate helper apart from orphaned old resolver code once it's in that
// file (see gqlgen's own generated warning: "You have helper methods in this
// file. Move them out to keep these resolver files clean."). Living in this
// separate, non-generated file is what stops the sweep; the non-colliding
// names below are for readability only, since gqlgen does not match on names.

import (
	"context"
	"slices"
	"time"

	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	notifyv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/notify/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/safeconv"
)

// secretStatsPollInterval is how often the secretStats subscription re-reads the
// acting user's rollup from the vault and pushes when it changed. Short enough to
// feel live, cheap enough to run per open dashboard. Kept here (not in the
// generated resolver file) so gqlgen doesn't sweep it into its warning block.
const secretStatsPollInterval = 5 * time.Second

// gqlNotification converts a notify-service Notification into its GraphQL shape.
func gqlNotification(n *notifyv1.Notification) *Notification {
	return &Notification{
		ID: n.GetId(), Action: n.GetAction(), ResourceKind: n.GetResourceKind(),
		ResourceID: n.GetResourceId(), ResourceLabel: n.GetResourceLabel(),
		ActorLabel: n.GetActorLabel(), OccurredAt: n.GetOccurredAt(), Read: n.GetRead(),
	}
}

// buildFolderRuleset assembles a folder's own firewall-RACI ruleset (owners +
// ordered rules) plus the rules/owners it inherits from ancestor folders.
func (r *Resolver) buildFolderRuleset(ctx context.Context, folderID string) (*FolderRuleset, error) {
	own, err := r.Vault.GetFolderRuleset(ctx, &vaultv1.GetFolderRulesetRequest{Actor: actorOf(ctx), FolderId: folderID})
	if err != nil {
		return nil, err
	}
	rules := make([]*RaciRule, 0, len(own.GetRules()))
	for _, rule := range own.GetRules() {
		rules = append(rules, gqlRaciRule(rule))
	}
	return &FolderRuleset{
		FolderID:        folderID,
		Owners:          own.GetOwners(),
		Rules:           rules,
		Inherited:       r.ancestorRaciRules(ctx, folderID),
		InheritedOwners: r.ancestorOwners(ctx, folderID),
	}, nil
}

// ancestorsOf walks the folder chain up from folderID, nearest ancestor first.
func (r *Resolver) ancestorsOf(ctx context.Context, folderID string) []*vaultv1.Folder {
	folders, err := r.Vault.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: actorOf(ctx)})
	if err != nil {
		return nil
	}
	byID := make(map[string]*vaultv1.Folder, len(folders.GetFolders()))
	for _, f := range folders.GetFolders() {
		byID[f.GetId()] = f
	}
	var out []*vaultv1.Folder
	start := byID[folderID]
	for cur := folderParent(byID, start); cur != nil; cur = folderParent(byID, cur) {
		out = append(out, cur)
		if cur.GetParentId() == "" {
			break
		}
	}
	return out
}

// ancestorRaciRules collects the RACI rules inherited from ancestor folders,
// tagged with the ancestor they came from.
func (r *Resolver) ancestorRaciRules(ctx context.Context, folderID string) []*InheritedRaciRule {
	var out []*InheritedRaciRule
	for _, cur := range r.ancestorsOf(ctx, folderID) {
		rs, err := r.Vault.GetFolderRuleset(ctx, &vaultv1.GetFolderRulesetRequest{Actor: actorOf(ctx), FolderId: cur.GetId()})
		if err == nil {
			for _, rule := range rs.GetRules() {
				out = append(out, &InheritedRaciRule{
					Rule: gqlRaciRule(rule), FromFolderID: cur.GetId(), FromFolderName: cur.GetName(),
				})
			}
		}
	}
	return out
}

// ancestorOwners collects the owners inherited from ancestor folders
// (including a personal-folder owner), tagged with the ancestor they came
// from, deduplicated by user id.
func (r *Resolver) ancestorOwners(ctx context.Context, folderID string) []*InheritedOwner {
	var out []*InheritedOwner
	seen := make(map[string]bool)
	for _, cur := range r.ancestorsOf(ctx, folderID) {
		var owners []string
		if rs, err := r.Vault.GetFolderRuleset(ctx, &vaultv1.GetFolderRulesetRequest{Actor: actorOf(ctx), FolderId: cur.GetId()}); err == nil {
			owners = rs.GetOwners()
		}
		if cur.GetScope() == vaultv1.FolderScope_FOLDER_SCOPE_PERSONAL && cur.GetOwnerUserId() != "" {
			owners = append(owners, cur.GetOwnerUserId())
		}
		for _, uid := range owners {
			if uid == "" || seen[uid] {
				continue
			}
			seen[uid] = true
			out = append(out, &InheritedOwner{
				UserID: uid, FromFolderID: cur.GetId(), FromFolderName: cur.GetName(),
			})
		}
	}
	return out
}

// buildSecretRuleset assembles a secret's own ruleset plus the rules it
// inherits from its enclosing folder chain.
func (r *Resolver) buildSecretRuleset(ctx context.Context, secretID string) (*SecretRuleset, error) {
	own, err := r.Vault.GetSecretRuleset(ctx, &vaultv1.GetSecretRulesetRequest{Actor: actorOf(ctx), SecretId: secretID})
	if err != nil {
		return nil, err
	}
	rules := make([]*RaciRule, 0, len(own.GetRules()))
	for _, rule := range own.GetRules() {
		rules = append(rules, gqlRaciRule(rule))
	}
	return &SecretRuleset{
		SecretID:  secretID,
		Rules:     rules,
		Inherited: r.secretFolderInheritedRules(ctx, secretID),
	}, nil
}

// secretFolderInheritedRules returns the RACI rules a secret inherits from
// its own enclosing folder plus that folder's ancestor chain.
func (r *Resolver) secretFolderInheritedRules(ctx context.Context, secretID string) []*InheritedRaciRule {
	sec, err := r.Vault.GetSecret(ctx, &vaultv1.GetSecretRequest{Actor: actorOf(ctx), Id: secretID})
	if err != nil || sec.GetSecret() == nil {
		return nil
	}
	folderID := sec.GetSecret().GetFolderId()
	if folderID == "" {
		return nil
	}
	folderName := ""
	if folders, ferr := r.Vault.ListFolders(ctx, &vaultv1.ListFoldersRequest{Actor: actorOf(ctx)}); ferr == nil {
		for _, f := range folders.GetFolders() {
			if f.GetId() == folderID {
				folderName = f.GetName()
				break
			}
		}
	}
	var out []*InheritedRaciRule
	if fr, ferr := r.Vault.GetFolderRuleset(ctx, &vaultv1.GetFolderRulesetRequest{Actor: actorOf(ctx), FolderId: folderID}); ferr == nil {
		for _, rule := range fr.GetRules() {
			out = append(out, &InheritedRaciRule{
				Rule: gqlRaciRule(rule), FromFolderID: folderID, FromFolderName: folderName,
			})
		}
	}
	return append(out, r.ancestorRaciRules(ctx, folderID)...)
}

// folderParent looks up f's parent in byID, or nil if f has none.
func folderParent(byID map[string]*vaultv1.Folder, f *vaultv1.Folder) *vaultv1.Folder {
	if f == nil || f.GetParentId() == "" {
		return nil
	}
	return byID[f.GetParentId()]
}

// simActorAttrs resolves the site-admin/root attributes and directory group
// membership of userID for the RACI simulation resolvers
// (SimulateFolder/SimulateSecret). Both the group names and ids are
// resolved, so simulation matches a GROUP rule the same way the real actor
// path does, whether the rule carries a subject_id or only a legacy name.
func (r *Resolver) simActorAttrs(ctx context.Context, userID string) (simIsSiteAdmin, simIsRoot bool, groupNames, groupIDs []string, err error) {
	resp, err := r.Identity.GetUser(ctx, &identityv1.GetUserRequest{Id: userID})
	if err != nil {
		return false, false, nil, nil, err
	}
	u := resp.GetUser()
	groupsResp, err := r.Identity.ListUserGroups(ctx, &identityv1.ListUserGroupsRequest{UserId: userID})
	if err != nil {
		return false, false, nil, nil, err
	}
	names := make([]string, 0, len(groupsResp.GetGroups()))
	ids := make([]string, 0, len(groupsResp.GetGroups()))
	for _, g := range groupsResp.GetGroups() {
		names = append(names, g.GetName())
		ids = append(ids, g.GetId())
	}
	return slices.Contains(u.GetRoles(), "site-admin") || slices.Contains(u.GetRoles(), "admin"), u.GetIsRoot(), names, ids, nil
}

// requireAdmin gates a mutation to the acting user being a site-admin or root
// (resolved into the ActorContext by the HTTP layer). Returns PermissionDenied
// otherwise. Used for identity-editing mutations (group membership).
func requireAdmin(ctx context.Context) error {
	a := actorOf(ctx)
	if a.GetIsSiteAdmin() || a.GetIsRoot() {
		return nil
	}
	return status.Error(codes.PermissionDenied, "admin privileges required")
}

// listAuditRecords fetches the audit trail (admin-only) with optional actor and
// subject filters, then resolves each distinct actor id to a human-readable
// label via identity (falling back to the raw id when unresolved).
func (r *Resolver) listAuditRecords(ctx context.Context, actorUserID, subject *string, excludeActions []string, limit *int) ([]*AuditRecord, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	req := &auditv1.ListRecordsRequest{}
	if actorUserID != nil {
		req.ActorUserId = *actorUserID
	}
	if subject != nil {
		req.Subject = *subject
	}
	// Server-side exclusion: dropped before the limit, so it spans the whole chain.
	req.ExcludeActions = excludeActions
	if limit != nil && *limit > 0 {
		req.Limit = safeconv.Uint32(*limit)
	}
	resp, err := r.Audit.ListRecords(ctx, req)
	if err != nil {
		return nil, err
	}
	recs := resp.GetRecords()
	names := r.resolveActorNames(ctx, recs)
	// Newest-first: the audit chain is stored oldest→newest, but the log reads
	// most-recent first.
	out := make([]*AuditRecord, 0, len(recs))
	for i := len(recs) - 1; i >= 0; i-- {
		rec := recs[i]
		name := names[rec.GetActorUserId()]
		if name == "" {
			name = rec.GetActorUserId()
		}
		out = append(out, gqlAuditRecord(rec, name))
	}
	return out, nil
}

// resolveActorNames batch-resolves the distinct actor ids across the given
// audit records to display labels via identity. Best effort: on error it
// returns an empty map and callers fall back to the raw id.
func (r *Resolver) resolveActorNames(ctx context.Context, records []*auditv1.AuditRecord) map[string]string {
	seen := make(map[string]bool)
	ids := make([]string, 0, len(records))
	for _, rec := range records {
		id := rec.GetActorUserId()
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	names := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return names
	}
	resp, err := r.Identity.ResolveUserLabels(ctx, &identityv1.ResolveUserLabelsRequest{Ids: ids})
	if err != nil {
		return names
	}
	for _, l := range resp.GetLabels() {
		names[l.GetId()] = l.GetName()
	}
	return names
}

// resolveCreatedByNames batch-resolves the distinct createdBy ids across the
// given secret versions to display labels via identity. Best effort: on error it
// returns an empty map and callers fall back to the raw id. Mirrors
// resolveActorNames (audit trail) for the value-history surface.
func (r *Resolver) resolveCreatedByNames(ctx context.Context, versions []*vaultv1.SecretVersion) map[string]string {
	seen := make(map[string]bool)
	ids := make([]string, 0, len(versions))
	for _, v := range versions {
		id := v.GetCreatedBy()
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	names := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return names
	}
	resp, err := r.Identity.ResolveUserLabels(ctx, &identityv1.ResolveUserLabelsRequest{Ids: ids})
	if err != nil {
		return names
	}
	for _, l := range resp.GetLabels() {
		names[l.GetId()] = l.GetName()
	}
	return names
}

// enrichApprovalNames resolves the resolvedByUserId of each already-resolved
// approval request to a display name via identity (batch, distinct ids). Best
// effort: on lookup failure the name is simply left unset and the UI falls
// back to the raw id. Requesting-user names are resolved client-side, so only
// the resolver identity is filled here (that's the who/when history surface).
//
//nolint:gocognit // one pass gathers ids from requests and comments, one fills names back
func (r *Resolver) enrichApprovalNames(ctx context.Context, reqs []*ApprovalRequest) {
	seen := make(map[string]bool)
	ids := make([]string, 0, len(reqs))
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		ids = append(ids, id)
	}
	for _, req := range reqs {
		if req.ResolvedByUserID != nil {
			add(*req.ResolvedByUserID)
		}
		// Comment authors share the same batch lookup as the resolver identity.
		for _, c := range req.Comments {
			add(c.AuthorUserID)
		}
	}
	if len(ids) == 0 {
		return
	}
	resp, err := r.Identity.ResolveUserLabels(ctx, &identityv1.ResolveUserLabelsRequest{Ids: ids})
	if err != nil {
		return
	}
	names := make(map[string]string, len(resp.GetLabels()))
	for _, l := range resp.GetLabels() {
		names[l.GetId()] = l.GetName()
	}
	for _, req := range reqs {
		if req.ResolvedByUserID != nil {
			if n := names[*req.ResolvedByUserID]; n != "" {
				nm := n
				req.ResolvedByUserName = &nm
			}
		}
		for _, c := range req.Comments {
			if n := names[c.AuthorUserID]; n != "" {
				c.AuthorName = n
			}
		}
	}
}

// listAuditActions returns the full set of distinct action strings present in
// the chain (admin-only), so the UI can offer the complete "hide actions" list
// rather than only the actions in the fetched window.
func (r *Resolver) listAuditActions(ctx context.Context) ([]string, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := r.Audit.DistinctActions(ctx, &auditv1.DistinctActionsRequest{})
	if err != nil {
		return nil, err
	}
	return resp.GetActions(), nil
}

// verifyAuditChain verifies the audit hash-chain (admin-only) for the
// tamper-evidence banner.
func (r *Resolver) verifyAuditChain(ctx context.Context) (*AuditChainStatus, error) {
	if err := requireAdmin(ctx); err != nil {
		return nil, err
	}
	resp, err := r.Audit.VerifyChain(ctx, &auditv1.VerifyChainRequest{})
	if err != nil {
		return nil, err
	}
	return gqlAuditChain(resp), nil
}
