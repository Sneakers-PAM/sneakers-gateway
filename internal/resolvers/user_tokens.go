// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

func (r *queryResolver) listUserTokens(ctx context.Context, userID string) ([]*UserToken, error) {
	resp, err := r.Identity.ListUserTokens(ctx, &identityv1.ListUserTokensRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	out := make([]*UserToken, 0, len(resp.GetTokens()))
	for _, t := range resp.GetTokens() {
		out = append(out, gqlUserToken(t))
	}
	return out, nil
}
