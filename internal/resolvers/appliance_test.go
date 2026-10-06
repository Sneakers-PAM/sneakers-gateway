// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"net/http"
	"testing"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
)

type fakeAppliance struct {
	present bool
	data    map[string]string
}

func (f fakeAppliance) Present() bool         { return f.present }
func (f fakeAppliance) Get(key string) string { return f.data[key] }

type applianceResp struct {
	Appliance struct {
		Present           bool
		Version           *string
		ProductState      *string
		Mcp               *string
		McpRevokePending  bool
		MachineAPI        *string `json:"machineApi"`
		TLSMode           *string `json:"tlsMode"`
		TLSNotAfter       *string `json:"tlsNotAfter"`
		Maintenance       bool
		MaintenanceReason *string
	}
}

const applianceQuery = `{ appliance { present version productState mcp mcpRevokePending machineApi tlsMode tlsNotAfter maintenance maintenanceReason } }`

func queryAppliance(t *testing.T, a ApplianceState) applianceResp {
	t.Helper()
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Appliance: a}}))
	h.AddTransport(transport.POST{})
	c := gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r.WithContext(WithActor(r.Context(), "user-clarke")))
	}))
	var resp applianceResp
	c.MustPost(applianceQuery, &resp)
	return resp
}

func TestTheApplianceFieldReturnsTheConfigMapKeys(t *testing.T) {
	resp := queryAppliance(t, fakeAppliance{present: true, data: map[string]string{
		"version": "0.1.0", "productState": "ok", "mcp": "off", "mcpRevokePending": "true",
		"machineApi": "on", "tlsMode": "self-signed", "tlsNotAfter": "2027-10-05T00:00:00Z",
		"maintenance": "on", "maintenanceReason": "upgrade to 0.2.0",
	}}).Appliance
	if !resp.Present || *resp.Version != "0.1.0" || *resp.ProductState != "ok" || *resp.Mcp != "off" ||
		!resp.McpRevokePending || *resp.MachineAPI != "on" || *resp.TLSMode != "self-signed" ||
		*resp.TLSNotAfter != "2027-10-05T00:00:00Z" || !resp.Maintenance || *resp.MaintenanceReason != "upgrade to 0.2.0" {
		t.Fatalf("appliance = %+v", resp)
	}
}

func TestTheApplianceFieldIsEmptyOffTheAppliance(t *testing.T) {
	for name, a := range map[string]ApplianceState{"absent": fakeAppliance{}, "unwired": nil} {
		resp := queryAppliance(t, a).Appliance
		if resp.Present || resp.Version != nil || resp.Mcp != nil || resp.Maintenance || resp.McpRevokePending {
			t.Fatalf("%s: appliance = %+v", name, resp)
		}
	}
}
