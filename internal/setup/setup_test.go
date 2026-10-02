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

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/bff"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/setup"
)

// fakeSeedVault satisfies vaultv1.VaultServiceClient via embedding and
// overrides only SeedBuiltins, which is all SeedHandler calls.
type fakeSeedVault struct{ vaultv1.VaultServiceClient }

func (fakeSeedVault) SeedBuiltins(context.Context, *vaultv1.SeedBuiltinsRequest, ...grpc.CallOption) (*vaultv1.SeedBuiltinsResponse, error) {
	return &vaultv1.SeedBuiltinsResponse{}, nil
}

// fakeSeedIdentity satisfies identityv1.IdentityServiceClient via embedding.
// SeedHandler never calls identity methods, so no overrides are needed.
type fakeSeedIdentity struct {
	identityv1.IdentityServiceClient
}

func TestSeedHandler_ProvisionsSSOConnection(t *testing.T) {
	var jacksonHit bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/sso", func(w http.ResponseWriter, _ *http.Request) {
		jacksonHit = true
		_, _ = w.Write([]byte(`{"clientID":"c","clientSecret":"s"}`))
	})
	jackson := httptest.NewServer(mux)
	t.Cleanup(jackson.Close)

	prov := bff.NewJacksonProvisioner(jackson.URL, "k", "sneakers", "example.org", "https://gw", "https://idp/md")
	h := setup.New(fakeSeedIdentity{}, fakeSeedVault{}, "setup-tok", prov)

	body := `{"setupToken":"setup-tok"}`
	req := httptest.NewRequest(http.MethodPost, "/setup/seed", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.SeedHandler()(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("seed status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !jacksonHit {
		t.Fatal("SeedHandler did not provision the SSO connection")
	}
}
