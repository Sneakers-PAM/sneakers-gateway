// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/Bugs5382/go-log"
)

// vaultReason is the ErrorInfo reason of a vault refusal, or "".
func vaultReason(err error) string {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetDomain() == "sneakers.vault" {
			return info.GetReason()
		}
	}
	return ""
}

// confirmSecretUses lets the signed-in person confirm their own pending uses
// that nobody else can decide, checking the factor once for the task. The
// vault decides each one, with the active people from identity.
func (r *Resolver) confirmSecretUses(ctx context.Context, ids []string, factor *FactorInput) (*DecideSecretUsesResult, error) {
	me, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	ids = distinctIDs(ids)
	if len(ids) == 0 || len(ids) > maxBatchUses {
		return nil, gatewayError(codes.InvalidArgument, "confirm 1 to 20 secret uses at a time", "BATCH_SIZE_INVALID")
	}
	l := r.logger(ctx).With(log.F("user_id", me), log.F("count", len(ids)))
	if err := r.batchFactor(ctx, me, factor); err != nil {
		l.Warn("secret uses: confirmation refused before any use", log.F("error", err.Error()))
		return nil, err
	}
	actor := actorOf(ctx)
	if factor != nil {
		// The factor was proved just now, here.
		actor.MfaVerifiedAtUnix = r.now().Unix()
	}
	users := r.ActiveUsers.Get(ctx)
	out := &DecideSecretUsesResult{Outcomes: make([]*SecretUseOutcome, 0, len(ids))}
	confirmed := 0
	for _, id := range ids {
		resp, err := r.Vault.ConfirmSecretUse(ctx, &vaultv1.ConfirmSecretUseRequest{Actor: actor, UseId: id, ActiveUsers: users})
		if err != nil {
			reason := r.refusalOf(ctx, l, id, err)
			l.Debug("secret uses: confirmation refused", log.F("use_id", id), log.F("reason", string(reason)))
			out.Outcomes = append(out.Outcomes, &SecretUseOutcome{ID: id, Reason: &reason})
			continue
		}
		confirmed++
		out.Outcomes = append(out.Outcomes, &SecretUseOutcome{ID: id, Decided: true, Use: secretUseOf(resp.GetUse())})
	}
	l.Info("secret uses: confirmed", log.F("confirmed", confirmed), log.F("refused", len(ids)-confirmed))
	return out, nil
}

// prepareSecretReveal asks the vault for a web reveal use, for a secret whose
// approval level needs a decision.
func (r *Resolver) prepareSecretReveal(ctx context.Context, secretID, fieldKey string, runID *string) (*SecretUse, error) {
	me, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.Vault.PrepareSecretUse(ctx, &vaultv1.PrepareSecretUseRequest{
		Actor: actorOf(ctx), SecretId: secretID, FieldKey: fieldKey, Reveal: true, ClientLabel: "Sneakers web",
		RunId: deref(runID), ActiveUsers: r.ActiveUsers.Get(ctx),
	})
	if err != nil {
		return nil, err
	}
	u := resp.GetUse()
	r.logger(ctx).Debug("secret uses: web reveal prepared", log.F("user_id", me), log.F("use_id", u.GetId()), log.F("state", u.GetState().String()))
	return secretUseOf(u), nil
}

func (r *Resolver) redeemSecretReveal(ctx context.Context, id string) (string, error) {
	if _, err := signedIn(ctx); err != nil {
		return "", err
	}
	resp, err := r.Vault.RedeemSecretUse(ctx, &vaultv1.RedeemSecretUseRequest{Actor: actorOf(ctx), UseId: id})
	if err != nil {
		return "", err
	}
	return resp.GetValue(), nil
}

// secretUsesToDecide lists the other people's pending uses the caller may
// decide, naming each requester.
func (r *Resolver) secretUsesToDecide(ctx context.Context) ([]*SecretUse, error) {
	me, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.Vault.ListSecretUsesToDecide(ctx, &vaultv1.ListSecretUsesToDecideRequest{Actor: actorOf(ctx)})
	if err != nil {
		return nil, err
	}
	names := r.userNames(ctx, resp.GetUses())
	out := make([]*SecretUse, 0, len(resp.GetUses()))
	for _, u := range resp.GetUses() {
		if u.GetUserId() == me {
			continue
		}
		su := secretUseOf(u)
		if n := names[u.GetUserId()]; n != "" {
			su.RequestedBy = n
		}
		out = append(out, su)
	}
	r.logger(ctx).Debug("secret uses: to decide listed", log.F("user_id", me), log.F("count", len(out)))
	return out, nil
}

// userNames maps the requesters of uses to display names; best effort.
func (r *Resolver) userNames(ctx context.Context, uses []*vaultv1.SecretUse) map[string]string {
	seen := map[string]bool{}
	ids := make([]string, 0, len(uses))
	for _, u := range uses {
		if id := u.GetUserId(); id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	names := make(map[string]string, len(ids))
	if len(ids) == 0 {
		return names
	}
	resp, err := r.Identity.ResolveUserLabels(ctx, &identityv1.ResolveUserLabelsRequest{Ids: ids})
	if err != nil {
		r.logger(ctx).Warn("secret uses: requester names unavailable", log.F("error", err.Error()))
		return names
	}
	for _, l := range resp.GetLabels() {
		names[l.GetId()] = l.GetName()
	}
	return names
}
