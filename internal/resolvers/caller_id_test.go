// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"testing"
)

func TestCallerIDNamesTheCallerWithoutAToken(t *testing.T) {
	for name, c := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"person":          {WithActor(context.Background(), "u-ada"), "u-ada"},
		"personal token":  {WithUserTokenActor(context.Background(), "u-ada", "utok-1", nil), "u-ada"},
		"service account": {WithMachineActor(context.Background(), "sa-backup", nil), "sa-backup"},
		"anonymous":       {context.Background(), ""},
	} {
		if got := CallerID(c.ctx); got != c.want {
			t.Errorf("%s: CallerID = %q, want %q", name, got, c.want)
		}
	}
}
