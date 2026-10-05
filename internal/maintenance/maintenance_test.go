// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package maintenance

import (
	"errors"
	"os"
	"testing"

	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestANilModeIsOff(t *testing.T) {
	var m *Mode
	if on, _ := m.State(); on {
		t.Fatal("a nil mode reported maintenance on")
	}
}

func TestTheSettingForcesItOn(t *testing.T) {
	if on, _ := New(true, nil).State(); !on {
		t.Fatal("MAINTENANCE_READONLY did not turn maintenance on")
	}
	if on, _ := New(false, nil).State(); on {
		t.Fatal("maintenance on with nothing turning it on")
	}
}

func TestTheSourceTurnsItOnAndOff(t *testing.T) {
	on, reason := true, "upgrade to 0.2.0"
	m := New(false, func() (bool, string) { return on, reason })
	if got, r := m.State(); !got || r != reason {
		t.Fatalf("State() = %v, %q; want true, %q", got, r, reason)
	}
	on = false
	if got, _ := m.State(); got {
		t.Fatal("maintenance stayed on after the source turned it off")
	}
}

func TestTheRefusalCarriesTheReason(t *testing.T) {
	var gs interface{ GRPCStatus() *status.Status }
	if !errors.As(Refusal(), &gs) {
		t.Fatal("the refusal is not a gRPC status")
	}
	st := gs.GRPCStatus()
	if st.Code() != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", st.Code())
	}
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok && info.GetReason() == Reason && info.GetDomain() == Domain {
			return
		}
	}
	t.Fatalf("no ErrorInfo %s/%s in %v", Domain, Reason, st.Details())
}

// Every allowed name must be a real mutation, so a rename can't silently
// leave a mutation refused or a stale name in the list.
func TestTheAllowListsNameRealMutations(t *testing.T) {
	for file, allowed := range map[string][]string{
		"../../graphql/schema.graphqls":  HumanAllowed,
		"../../graphql/machine.graphqls": MachineAllowed,
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		schema, gerr := gqlparser.LoadSchema(&ast.Source{Name: file, Input: string(raw)})
		if gerr != nil {
			t.Fatalf("%s: %v", file, gerr)
		}
		for _, name := range allowed {
			if schema.Mutation.Fields.ForName(name) == nil {
				t.Errorf("%s has no mutation %q", file, name)
			}
		}
	}
}
