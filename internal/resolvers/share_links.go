// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"
	"time"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/share"
	"google.golang.org/grpc/codes"
)

// One-time share links: the share package holds the link, the vault the
// approval and the audit. These resolvers are the signed-in person's side.

func sharePerson(ctx context.Context) (*vaultv1.ActorContext, error) {
	if _, machine := machineActorFrom(ctx); machine {
		return nil, gatewayError(codes.PermissionDenied, "share links are made by a signed-in person", "SHARE_NOT_PERSON")
	}
	a := actorOf(ctx)
	if uid := a.GetUserId(); uid == "" || uid == "system" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN {
		return nil, gatewayError(codes.PermissionDenied, "share links are made by a signed-in person", "SHARE_NOT_PERSON")
	}
	return a, nil
}

func (r *Resolver) shareService() (*share.Service, error) {
	if r.Share == nil {
		return nil, gatewayError(codes.FailedPrecondition, "share links are off on this install", "SHARE_LINKS_OFF")
	}
	return r.Share, nil
}

func gqlShareLink(l share.Link) *ShareLink {
	out := &ShareLink{ID: l.ID, SecretID: l.SecretID, FieldKey: l.FieldKey, ExpiresAtUnix: int(l.ExpiresAtUnix), State: l.State}
	if l.URL != "" {
		u := l.URL
		out.URL = &u
	}
	return out
}

func (r *Resolver) createShareLink(ctx context.Context, secretID, fieldKey string, ttlSeconds *int) (*ShareLink, error) {
	actor, err := sharePerson(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := r.shareService()
	if err != nil {
		return nil, err
	}
	var ttl time.Duration
	if ttlSeconds != nil {
		ttl = time.Duration(*ttlSeconds) * time.Second
		if *ttlSeconds == 0 {
			ttl = -1 // an explicit zero is not "unset"
		}
	}
	l, err := svc.Create(ctx, share.CreateParams{Actor: actor, Active: r.ActiveUsers.Get(ctx), SecretID: secretID, FieldKey: fieldKey, TTL: ttl})
	switch {
	case errors.Is(err, share.ErrOff):
		return nil, gatewayError(codes.FailedPrecondition, "share links are off on this install", "SHARE_LINKS_OFF")
	case errors.Is(err, share.ErrTTL):
		return nil, gatewayError(codes.InvalidArgument, "a share link lives from 60 seconds to 7 days", "SHARE_TTL_INVALID")
	case err != nil:
		return nil, err
	}
	return gqlShareLink(l), nil
}

func (r *Resolver) revokeShareLink(ctx context.Context, id string) (bool, error) {
	actor, err := sharePerson(ctx)
	if err != nil {
		return false, err
	}
	svc, err := r.shareService()
	if err != nil {
		return false, err
	}
	if err := svc.Revoke(ctx, actor, id); err != nil {
		return false, err
	}
	return true, nil
}

func (r *Resolver) shareLinks(ctx context.Context) ([]*ShareLink, error) {
	actor, err := sharePerson(ctx)
	if err != nil {
		return nil, err
	}
	svc, err := r.shareService()
	if err != nil {
		return nil, err
	}
	links, err := svc.List(ctx, actor)
	if err != nil {
		return nil, err
	}
	out := make([]*ShareLink, 0, len(links))
	for _, l := range links {
		out = append(out, gqlShareLink(l))
	}
	return out, nil
}
