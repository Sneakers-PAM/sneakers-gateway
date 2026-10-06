// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "github.com/Bugs5382/go-log"
)

const (
	maxBatchUses = 20
	// defaultMFAMaxAge and mfaClockSkew match bff.DefaultMFAMaxAge and the
	// skew bff allows, so the batch window is the session's step-up window.
	defaultMFAMaxAge = 30 * time.Minute
	mfaClockSkew     = 30 * time.Second
)

// gatewayError is a refusal the gateway makes itself, with a stable reason in
// domain sneakers.gateway that gqlerr passes to the client.
func gatewayError(c codes.Code, msg, reason string) error {
	st, _ := status.New(c, msg).WithDetails(&errdetails.ErrorInfo{Domain: "sneakers.gateway", Reason: reason})
	return st.Err()
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *Resolver) logger(ctx context.Context) log.Logger {
	if r.Log == nil {
		return log.Nop()
	}
	return r.Log.Ctx(ctx)
}

// mfaFreshUntil is when the session's second factor stops covering an
// approval, or zero when it doesn't cover one now.
func (r *Resolver) mfaFreshUntil(ctx context.Context) time.Time {
	at := MFAVerifiedAt(ctx)
	if at.IsZero() {
		return time.Time{}
	}
	maxAge := r.MFAMaxAge
	if maxAge <= 0 {
		maxAge = defaultMFAMaxAge
	}
	// A window under the skew allowance (MFA_MAX_AGE=0) still covers the
	// action retried right after its step-up.
	maxAge = max(maxAge, mfaClockSkew)
	age := r.now().Sub(at)
	if age < -mfaClockSkew || age > maxAge {
		return time.Time{}
	}
	return at.Add(maxAge)
}

// batchFactor checks the factor for a batch approval once: a factor given
// here, else the session's own within MFA_MAX_AGE.
func (r *Resolver) batchFactor(ctx context.Context, userID string, f *FactorInput) error {
	if f == nil {
		if r.mfaFreshUntil(ctx).IsZero() {
			return gatewayError(codes.FailedPrecondition, "a fresh second factor is required", "STEP_UP_REQUIRED")
		}
		return nil
	}
	err := r.requireFactor(ctx, userID, f)
	if errors.Is(err, errFactorNotAccepted) {
		return gatewayError(codes.Unauthenticated, err.Error(), "FACTOR_NOT_ACCEPTED")
	}
	return err
}

func distinctIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func (r *Resolver) decideSecretUses(ctx context.Context, ids []string, decision SecretUseDecision, factor *FactorInput) (*DecideSecretUsesResult, error) {
	me, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	ids = distinctIDs(ids)
	if len(ids) == 0 || len(ids) > maxBatchUses {
		return nil, gatewayError(codes.InvalidArgument, "decide 1 to 20 secret uses at a time", "BATCH_SIZE_INVALID")
	}
	approve := decision == SecretUseDecisionApprove
	l := r.logger(ctx).With(log.F("user_id", me), log.F("decision", string(decision)), log.F("count", len(ids)))
	if approve {
		if err := r.batchFactor(ctx, me, factor); err != nil {
			l.Warn("secret uses: batch refused before any decision", log.F("error", err.Error()))
			return nil, err
		}
	}
	names := r.tokenNames(ctx, me)
	out := &DecideSecretUsesResult{Outcomes: make([]*SecretUseOutcome, 0, len(ids))}
	decided := 0
	// One at a time, in request order, so the audit order matches the request.
	for _, id := range ids {
		o := r.decideOne(ctx, l, id, approve, names)
		if o.Decided {
			decided++
		}
		out.Outcomes = append(out.Outcomes, o)
	}
	l.Info("secret uses: batch decided", log.F("decided", decided), log.F("refused", len(ids)-decided))
	return out, nil
}

func (r *Resolver) decideOne(ctx context.Context, l log.Logger, id string, approve bool, names map[string]string) *SecretUseOutcome {
	resp, err := r.Vault.DecideSecretUse(ctx, &vaultv1.DecideSecretUseRequest{Actor: actorOf(ctx), UseId: id, Approve: approve})
	if err == nil {
		l.Debug("secret uses: decided", log.F("use_id", id), log.F("run_id", resp.GetUse().GetRunId()))
		return &SecretUseOutcome{ID: id, Decided: true, Use: withRequester(secretUseOf(resp.GetUse()), resp.GetUse(), names)}
	}
	reason := r.refusalOf(ctx, l, id, err)
	l.Debug("secret uses: refused", log.F("use_id", id), log.F("reason", string(reason)))
	return &SecretUseOutcome{ID: id, Reason: &reason}
}

// refusalOf maps vault's refusal of one use to a stable reason. Vault answers
// FailedPrecondition for any use that isn't pending, so the use's state says
// whether it expired or was already decided.
func (r *Resolver) refusalOf(ctx context.Context, l log.Logger, id string, err error) SecretUseRefusal {
	switch vaultReason(err) {
	case "SELF_APPROVAL":
		return SecretUseRefusalSelfApproval
	case "OTHER_APPROVER":
		return SecretUseRefusalOtherApprover
	case "NO_APPROVER":
		return SecretUseRefusalNoApprover
	}
	switch status.Code(err) {
	case codes.NotFound:
		return SecretUseRefusalNotFound
	case codes.PermissionDenied:
		return SecretUseRefusalNotPermitted
	case codes.FailedPrecondition:
		got, gerr := r.Vault.GetSecretUse(ctx, &vaultv1.GetSecretUseRequest{Actor: actorOf(ctx), UseId: id})
		if gerr == nil && got.GetUse().GetState() == vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED {
			return SecretUseRefusalExpired
		}
		return SecretUseRefusalAlreadyDecided
	case codes.Unavailable, codes.DeadlineExceeded:
		return SecretUseRefusalUnavailable
	}
	l.Error(err, "secret uses: unexpected vault refusal", log.F("use_id", id), log.F("code", status.Code(err).String()))
	return SecretUseRefusalUnavailable
}

// tokenNames maps the user's token ids to their names, for a use's
// requester. On failure every requester falls back to the client label.
func (r *Resolver) tokenNames(ctx context.Context, userID string) map[string]string {
	start := r.now()
	resp, err := r.Identity.ListUserTokens(ctx, &identityv1.ListUserTokensRequest{UserId: userID})
	if err != nil {
		r.logger(ctx).Warn("secret uses: token names unavailable, showing client labels",
			log.F("user_id", userID), log.F("error", err.Error()), log.F("ms", float64(r.now().Sub(start))/float64(time.Millisecond)))
		return nil
	}
	out := make(map[string]string, len(resp.GetTokens()))
	for _, t := range resp.GetTokens() {
		if t.GetLabel() != "" {
			out[t.GetId()] = t.GetLabel()
		}
	}
	return out
}

func withRequester(out *SecretUse, u *vaultv1.SecretUse, names map[string]string) *SecretUse {
	if n, ok := names[u.GetTokenId()]; ok {
		out.Requester = n
	}
	return out
}

func (r *Resolver) secretUseRun(ctx context.Context, runID string) (*SecretUseRun, error) {
	me, err := signedIn(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := r.Vault.ListPendingSecretUses(ctx, &vaultv1.ListPendingSecretUsesRequest{Actor: actorOf(ctx), RunId: runID})
	if err != nil {
		return nil, err
	}
	names := r.tokenNames(ctx, me)
	out := &SecretUseRun{RunID: runID, Uses: make([]*SecretUse, 0, len(resp.GetUses()))}
	for _, u := range resp.GetUses() {
		// Vault lists the caller's own uses; never show anyone else's.
		if u.GetUserId() != me {
			continue
		}
		out.Uses = append(out.Uses, withRequester(secretUseOf(u), u, names))
	}
	if until := r.mfaFreshUntil(ctx); !until.IsZero() {
		out.MfaFreshUntilUnix = int(until.Unix())
	}
	r.logger(ctx).Debug("secret uses: run listed", log.F("user_id", me), log.F("run_id", runID), log.F("count", len(out.Uses)))
	return out, nil
}
