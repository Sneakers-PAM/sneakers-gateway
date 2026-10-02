// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	grpc "google.golang.org/grpc"

	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/setup"
)

type recordingSeedVault struct {
	vaultv1.VaultServiceClient
	req *vaultv1.SeedBuiltinsRequest
}

func (f *recordingSeedVault) SeedBuiltins(_ context.Context, in *vaultv1.SeedBuiltinsRequest, _ ...grpc.CallOption) (*vaultv1.SeedBuiltinsResponse, error) {
	f.req = in
	return &vaultv1.SeedBuiltinsResponse{}, nil
}

// Seeding acts as the bootstrap admin, so it needs that admin's real user id.
func TestSeedHandler_RefusesAMissingUserID(t *testing.T) {
	for _, body := range []string{`{"setupToken":"setup-tok"}`, `{"setupToken":"setup-tok","userId":"  "}`} {
		fv := &recordingSeedVault{}
		h := setup.New(fakeSeedIdentity{}, fv, "setup-tok", nil)
		rec := httptest.NewRecorder()
		h.SeedHandler()(rec, httptest.NewRequest(http.MethodPost, "/setup/seed", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", body, rec.Code)
		}
		if fv.req != nil {
			t.Fatalf("%s: SeedBuiltins was called", body)
		}
	}
}

func TestSeedHandler_ActsAsTheBootstrapAdmin(t *testing.T) {
	fv := &recordingSeedVault{}
	h := setup.New(fakeSeedIdentity{}, fv, "setup-tok", nil)
	rec := httptest.NewRecorder()
	h.SeedHandler()(rec, httptest.NewRequest(http.MethodPost, "/setup/seed", strings.NewReader(`{"setupToken":"setup-tok","userId":"user-1"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	a := fv.req.GetActor()
	if a.GetUserId() != "user-1" || a.GetPrincipalKind() != vaultv1.PrincipalKind_PRINCIPAL_KIND_HUMAN || !a.GetIsSiteAdmin() || !a.GetIsRoot() {
		t.Fatalf("actor = %+v", a)
	}
}
