// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
)

// activeUsersTTL is how long one identity listing serves the vault's "can
// anyone else decide this use" check.
const activeUsersTTL = 30 * time.Second

// ActiveUsers lists the people identity reports as active (not disabled, with
// a login subject), for the vault's approval decisions. It never decides
// anything itself: the vault does, from this list.
type ActiveUsers struct {
	Identity identityv1.IdentityServiceClient
	Log      log.Logger
	Now      func() time.Time

	mu  sync.Mutex
	ids []string
	at  time.Time
}

func (a *ActiveUsers) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Get returns the active people, or nil when identity can't say: the vault
// then never treats the install as single-user.
func (a *ActiveUsers) Get(ctx context.Context) *vaultv1.ActiveUsers {
	if a == nil || a.Identity == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if !a.at.IsZero() && now.Sub(a.at) < activeUsersTTL {
		return &vaultv1.ActiveUsers{UserIds: append([]string(nil), a.ids...)}
	}
	resp, err := a.Identity.ListUsers(ctx, &identityv1.ListUsersRequest{})
	if err != nil {
		if a.Log != nil {
			a.Log.Ctx(ctx).Warn("active users unavailable; approvals treat the install as multi-user", log.F("error", err.Error()))
		}
		return nil
	}
	ids := make([]string, 0, len(resp.GetUsers()))
	for _, u := range resp.GetUsers() {
		if u.GetDisabledAtUnix() == 0 && u.GetSubject() != "" {
			ids = append(ids, u.GetId())
		}
	}
	a.ids, a.at = ids, now
	if a.Log != nil {
		a.Log.Ctx(ctx).Debug("active users listed", log.F("count", len(ids)))
	}
	return &vaultv1.ActiveUsers{UserIds: append([]string(nil), ids...)}
}
