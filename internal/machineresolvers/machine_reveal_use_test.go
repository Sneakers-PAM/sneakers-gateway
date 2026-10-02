// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import "testing"

func TestPrepareSecretUseCanAskForARevealWithNoCommand(t *testing.T) {
	fv := &useVault{}
	var resp struct{ PrepareSecretUse struct{ ID string } }
	newUseClient(fv).MustPost(`mutation { prepareSecretUse(secretId:"s1", fieldKey:"password", reveal:true, clientLabel:"Example CLI") { id } }`, &resp)
	if !fv.lastPrepare.GetReveal() || len(fv.lastPrepare.GetArgv()) != 0 {
		t.Fatalf("prepare = %+v, want a reveal with no argv", fv.lastPrepare)
	}
}
