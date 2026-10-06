// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"errors"
	"strings"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/safeconv"
)

// Matches the bff login purpose so one emailed code serves any factor check.
const mfaEmailPurpose = "login"

var (
	errFactorRequired    = errors.New("a fresh second factor is required")
	errFactorNotAccepted = errors.New("second factor was not accepted")
)

// requireFactor refuses before vault is asked: releasing a secret to a token,
// or pre-approving that, must be the human at the keyboard, not a stolen session.
func (r *Resolver) requireFactor(ctx context.Context, userID string, f *FactorInput) error {
	if f == nil {
		return errFactorRequired
	}
	code, cred, sid := deref(f.Code), deref(f.CredentialJSON), deref(f.WebauthnSessionID)
	var ok bool
	var err error
	switch f.Kind {
	case "totp":
		var resp *identityv1.VerifyTotpResponse
		resp, err = r.Identity.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: userID, Code: code})
		ok = resp.GetOk()
	case "email":
		var resp *identityv1.VerifyEmailOtpResponse
		resp, err = r.Identity.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: userID, Code: code, Purpose: mfaEmailPurpose})
		ok = resp.GetOk()
	case "passkey":
		var resp *identityv1.WebauthnAssertFinishResponse
		resp, err = r.Identity.WebauthnAssertFinish(ctx, &identityv1.WebauthnAssertFinishRequest{UserId: userID, SessionId: sid, CredentialJson: cred})
		ok = resp.GetOk()
	}
	if err != nil {
		return err
	}
	if !ok {
		return errFactorNotAccepted
	}
	return nil
}

func signedIn(ctx context.Context) (string, error) {
	me := actorFrom(ctx)
	if me == "" {
		return "", errors.New("not signed in")
	}
	return me, nil
}

func (r *Resolver) ownsToken(ctx context.Context, userID, tokenID string) (bool, error) {
	resp, err := r.Identity.ListUserTokens(ctx, &identityv1.ListUserTokensRequest{UserId: userID})
	if err != nil {
		return false, err
	}
	for _, t := range resp.GetTokens() {
		if t.GetId() == tokenID && t.GetRevokedAtUnix() == 0 {
			return true, nil
		}
	}
	return false, nil
}

func secretUseOf(u *vaultv1.SecretUse) *SecretUse {
	out := &SecretUse{
		ID: u.GetId(), SecretName: u.GetSecretName(), FieldKey: u.GetFieldKey(),
		Argv: append([]string{}, u.GetArgv()...), ClientLabel: u.GetClientLabel(), Reveal: u.GetReveal(),
		State:         strings.TrimPrefix(u.GetState().String(), "SECRET_USE_STATE_"),
		ExpiresAtUnix: safeconv.IntFromInt64(u.GetExpiresAtUnix()),
		Purpose:       u.GetPurpose(), Requester: u.GetClientLabel(),
		RequestedBy: u.GetUserId(), Confirm: u.GetConfirm(),
	}
	if id := u.GetRunId(); id != "" {
		out.RunID = &id
	}
	return out
}

func useGrantOf(g *vaultv1.UseGrant) *UseGrant {
	out := &UseGrant{
		ID: g.GetId(), TokenID: g.GetTokenId(),
		SecretIds: append([]string{}, g.GetSecretIds()...), FieldKeys: append([]string{}, g.GetFieldKeys()...),
		Programs:      []*UseGrantProgram{},
		ExpiresAtUnix: safeconv.IntFromInt64(g.GetExpiresAtUnix()),
		MaxUses:       int(g.GetMaxUses()), Uses: int(g.GetUses()),
		RevokedAtUnix: safeconv.IntFromInt64(g.GetRevokedAtUnix()),
		AllowReveal:   g.GetAllowReveal(),
	}
	if f := g.GetFolderId(); f != "" {
		out.FolderID = &f
	}
	for _, p := range g.GetPrograms() {
		out.Programs = append(out.Programs, &UseGrantProgram{Program: p.GetProgram(), ArgPattern: p.GetArgPattern()})
	}
	return out
}

func useGrantProto(in UseGrantInput) *vaultv1.UseGrant {
	g := &vaultv1.UseGrant{
		TokenId: in.TokenID, SecretIds: in.SecretIds, FolderId: deref(in.FolderID), FieldKeys: in.FieldKeys,
		ExpiresAtUnix: int64(in.ExpiresAtUnix), AllowReveal: in.AllowReveal != nil && *in.AllowReveal,
	}
	if in.MaxUses != nil {
		g.MaxUses = safeconv.Int32(*in.MaxUses)
	}
	for _, p := range in.Programs {
		g.Programs = append(g.Programs, &vaultv1.UseGrantProgram{Program: p.Program, ArgPattern: p.ArgPattern})
	}
	return g
}
