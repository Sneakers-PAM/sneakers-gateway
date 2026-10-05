// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import "github.com/Sneakers-PAM/sneakers-gateway/internal/appliance"

// applianceOf maps the appliance ConfigMap's keys to the appliance query.
// Off the appliance only present (false) is set.
func applianceOf(a ApplianceState) *Appliance {
	if a == nil || !a.Present() {
		return &Appliance{}
	}
	opt := func(key string) *string {
		if v := a.Get(key); v != "" {
			return &v
		}
		return nil
	}
	return &Appliance{
		Present:           true,
		Version:           opt(appliance.KeyVersion),
		ProductState:      opt(appliance.KeyProductState),
		Mcp:               opt(appliance.KeyMCP),
		McpRevokePending:  a.Get(appliance.KeyMCPRevokePending) == "true",
		MachineAPI:        opt(appliance.KeyMachineAPI),
		TLSMode:           opt(appliance.KeyTLSMode),
		TLSNotAfter:       opt(appliance.KeyTLSNotAfter),
		Maintenance:       a.Get(appliance.KeyMaintenance) == appliance.On,
		MaintenanceReason: opt(appliance.KeyMaintenanceReason),
	}
}
