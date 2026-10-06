// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"slices"
	"time"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/safeconv"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errBreakGlassCodeInvalid refuses a break glass whose MFA code is wrong,
// missing or expired. Identity can't tell those apart (VerifyTotp answers
// ok=false for all of them), so neither does the reason.
func errBreakGlassCodeInvalid() error {
	st, _ := status.New(codes.Unauthenticated, "invalid or missing MFA code").
		WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.gateway", Reason: "BREAK_GLASS_CODE_INVALID"})
	return st.Err()
}

// errBreakGlassWebOnly refuses break-glass browse to anything but a signed-in
// web session: personal tokens, service accounts and callers with no session.
func errBreakGlassWebOnly() error {
	return gatewayError(codes.PermissionDenied, "break-glass is available from the web app only", "BREAK_GLASS_WEB_ONLY")
}

func errBreakGlassNotAdmin() error {
	return gatewayError(codes.PermissionDenied, "break-glass is for site admins", "BREAK_GLASS_NOT_ADMIN")
}

type sessionRefKey struct{}

// WithSessionRef attaches the opaque reference to the signed-in web session
// (set by the session gate; never the session id itself). The vault binds a
// break-glass browse session to it.
func WithSessionRef(ctx context.Context, ref string) context.Context {
	return context.WithValue(ctx, sessionRefKey{}, ref)
}

// SessionRef returns the web session reference, "" outside a web session.
func SessionRef(ctx context.Context) string {
	ref, _ := ctx.Value(sessionRefKey{}).(string)
	return ref
}

// breakGlassActor is the vault actor for a break-glass browse call: a site
// admin or root in a web session, with the session reference. Anyone else is
// refused before identity or the vault is asked.
func breakGlassActor(ctx context.Context) (*vaultv1.ActorContext, error) {
	if _, machine := machineActorFrom(ctx); machine || SessionRef(ctx) == "" || actorFrom(ctx) == "" {
		return nil, errBreakGlassWebOnly()
	}
	a := actorOf(ctx)
	if !a.GetIsSiteAdmin() && !a.GetIsRoot() {
		return nil, errBreakGlassNotAdmin()
	}
	a.SessionRef = SessionRef(ctx)
	return a, nil
}

// verifyBreakGlassCode checks the TOTP code in front of every break-glass
// call; a missing or wrong code never reaches the vault.
func (r *Resolver) verifyBreakGlassCode(ctx context.Context, userID, code string) error {
	if code == "" {
		return errBreakGlassCodeInvalid()
	}
	vr, err := r.Identity.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: userID, Code: code})
	if err != nil {
		return err
	}
	if !vr.GetOk() {
		return errBreakGlassCodeInvalid()
	}
	return nil
}

// breakGlassReveal is breakGlassSecret: the TOTP step-up, then the vault's
// emergency reveal, inside a browse session when sessionID is set.
func (r *Resolver) breakGlassReveal(ctx context.Context, secretID, reason, code string, sessionID *string) ([]*KeyValue, error) {
	actor := actorOf(ctx)
	if sid := deref(sessionID); sid != "" {
		a, err := breakGlassActor(ctx)
		if err != nil {
			return nil, err
		}
		actor = a
	}
	if err := r.verifyBreakGlassCode(ctx, actor.GetUserId(), code); err != nil {
		return nil, err
	}
	l := r.logger(ctx).With(log.F("user_id", actor.GetUserId()), log.F("secret_id", secretID), log.F("session_id", deref(sessionID)))
	resp, err := r.Vault.BreakGlassSecret(ctx, &vaultv1.BreakGlassSecretRequest{
		Actor: actor, SecretId: secretID, Reason: reason, SessionId: deref(sessionID),
	})
	if err != nil {
		l.Warn("break-glass: reveal refused", log.F("error", err.Error()))
		return nil, err
	}
	l.Info("break-glass: secret revealed")
	out := make([]*KeyValue, 0, len(resp.GetFields()))
	for k, v := range resp.GetFields() {
		out = append(out, &KeyValue{Key: k, Value: v})
	}
	return out, nil
}

func (r *Resolver) openBreakGlassSession(ctx context.Context, reason, code string) (*BreakGlassSession, error) {
	actor, err := breakGlassActor(ctx)
	if err != nil {
		return nil, err
	}
	l := r.logger(ctx).With(log.F("user_id", actor.GetUserId()))
	if err := r.verifyBreakGlassCode(ctx, actor.GetUserId(), code); err != nil {
		l.Warn("break-glass: open refused at the code check")
		return nil, err
	}
	// The code was proved just now, here.
	actor.MfaVerifiedAtUnix = r.now().Unix()
	resp, err := r.Vault.OpenBreakGlassSession(ctx, &vaultv1.OpenBreakGlassSessionRequest{Actor: actor, Reason: reason})
	if err != nil {
		l.Warn("break-glass: open refused", log.F("error", err.Error()))
		return nil, err
	}
	l.Info("break-glass: session opened", log.F("session_id", resp.GetSession().GetId()))
	return gqlBreakGlassSession(resp.GetSession(), ""), nil
}

func (r *Resolver) closeBreakGlassSession(ctx context.Context, id string) (*BreakGlassSession, error) {
	actor, err := breakGlassActor(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.Vault.CloseBreakGlassSession(ctx, &vaultv1.CloseBreakGlassSessionRequest{Actor: actor, SessionId: id})
	if err != nil {
		return nil, err
	}
	r.logger(ctx).Info("break-glass: session closed", log.F("user_id", actor.GetUserId()), log.F("session_id", id))
	return gqlBreakGlassSession(resp.GetSession(), ""), nil
}

// currentBreakGlassSession is the caller's open session, or nil. Anyone who
// can't break glass gets nil without asking the vault, so the web can check
// on every page.
func (r *Resolver) currentBreakGlassSession(ctx context.Context) (*BreakGlassSession, error) {
	actor, refused := breakGlassActor(ctx)
	if refused != nil {
		r.logger(ctx).Debug("break-glass: caller can't break glass, no session", log.F("reason", refused.Error()))
		return nil, nil
	}
	resp, err := r.Vault.GetBreakGlassSession(ctx, &vaultv1.GetBreakGlassSessionRequest{Actor: actor})
	if err != nil {
		return nil, err
	}
	if resp.GetSession() == nil {
		return nil, nil
	}
	return gqlBreakGlassSession(resp.GetSession(), ""), nil
}

func (r *Resolver) breakGlassBrowse(ctx context.Context, sessionID string, folderID *string) (*BreakGlassBrowse, error) {
	actor, err := breakGlassActor(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.Vault.ListBreakGlassItems(ctx, &vaultv1.ListBreakGlassItemsRequest{
		Actor: actor, SessionId: sessionID, FolderId: deref(folderID),
	})
	if err != nil {
		return nil, err
	}
	out := &BreakGlassBrowse{
		Folders: make([]*Folder, 0, len(resp.GetFolders())),
		Secrets: make([]*Secret, 0, len(resp.GetSecrets())),
	}
	for _, f := range resp.GetFolders() {
		out.Folders = append(out.Folders, gqlFolder(f))
	}
	for _, s := range resp.GetSecrets() {
		out.Secrets = append(out.Secrets, gqlSecretWithAccess(s))
	}
	r.logger(ctx).Debug("break-glass: browse listed", log.F("session_id", sessionID),
		log.F("folders", len(out.Folders)), log.F("secrets", len(out.Secrets)))
	return out, nil
}

func (r *Resolver) breakGlassSessions(ctx context.Context, limit *int) ([]*BreakGlassSession, error) {
	actor, err := breakGlassActor(ctx)
	if err != nil {
		return nil, err
	}
	req := &vaultv1.ListBreakGlassSessionsRequest{Actor: actor}
	if limit != nil && *limit > 0 {
		req.Limit = safeconv.Int32(*limit)
	}
	resp, err := r.Vault.ListBreakGlassSessions(ctx, req)
	if err != nil {
		return nil, err
	}
	names := r.resolveUserNames(ctx, resp.GetSessions())
	out := make([]*BreakGlassSession, 0, len(resp.GetSessions()))
	for _, s := range resp.GetSessions() {
		out = append(out, gqlBreakGlassSession(s, names[s.GetActorUserId()]))
	}
	return out, nil
}

// resolveUserNames looks the sessions' actors up in identity, best effort.
func (r *Resolver) resolveUserNames(ctx context.Context, sessions []*vaultv1.BreakGlassSession) map[string]string {
	names := map[string]string{}
	var ids []string
	for _, s := range sessions {
		if id := s.GetActorUserId(); id != "" && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return names
	}
	resp, err := r.Identity.ResolveUserLabels(ctx, &identityv1.ResolveUserLabelsRequest{Ids: ids})
	if err != nil {
		r.logger(ctx).Warn("break-glass: resolve actor names failed", log.F("error", err.Error()))
		return names
	}
	for _, l := range resp.GetLabels() {
		names[l.GetId()] = l.GetName()
	}
	return names
}

func unixRFC3339(sec int64) string { return time.Unix(sec, 0).UTC().Format(time.RFC3339) }

func gqlBreakGlassSession(s *vaultv1.BreakGlassSession, name string) *BreakGlassSession {
	if name == "" {
		name = s.GetActorUserId()
	}
	out := &BreakGlassSession{
		ID: s.GetId(), ActorUserID: s.GetActorUserId(), ActorName: name, Reason: s.GetReason(),
		OpenedAt: unixRFC3339(s.GetOpenedAtUnix()), ExpiresAt: unixRFC3339(s.GetExpiresAtUnix()),
		EndReason: strPtr(s.GetEndReason()), Reveals: make([]*BreakGlassReveal, 0, len(s.GetReveals())),
	}
	if s.GetEndedAtUnix() != 0 {
		out.EndedAt = strPtr(unixRFC3339(s.GetEndedAtUnix()))
	}
	for _, rv := range s.GetReveals() {
		out.Reveals = append(out.Reveals, &BreakGlassReveal{
			EventID: rv.GetEventId(), SecretID: rv.GetSecretId(), SecretName: rv.GetSecretName(),
			RevealedAt: unixRFC3339(rv.GetRevealedAtUnix()), PostRotationScheduled: rv.GetPostRotationScheduled(),
			OwnerNotified: rv.GetOwnerNotified(),
		})
	}
	return out
}
