// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package setup_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
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

// fakeBootstrapIdentity answers BootstrapRoot so the token check is the only
// thing under test.
type fakeBootstrapIdentity struct {
	identityv1.IdentityServiceClient
}

func (fakeBootstrapIdentity) BootstrapRoot(context.Context, *identityv1.BootstrapRootRequest, ...grpc.CallOption) (*identityv1.BootstrapRootResponse, error) {
	return &identityv1.BootstrapRootResponse{User: &identityv1.User{Id: "u-1"}}, nil
}

// A Secret made from a file often ends in a newline; the configured token is
// trimmed so the operator's token still matches.
func TestBootstrapHandler_TrimsConfiguredToken(t *testing.T) {
	h := setup.New(fakeBootstrapIdentity{}, fakeSeedVault{}, " setup-tok\n", nil)
	body := `{"setupToken":"setup-tok","username":"admin","email":"admin@example.org","password":"pw"}`
	rec := httptest.NewRecorder()
	h.BootstrapHandler()(rec, httptest.NewRequest(http.MethodPost, "/setup/bootstrap", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// A token pasted with a trailing newline is trimmed the same way.
func TestBootstrapHandler_TrimsSubmittedToken(t *testing.T) {
	h := setup.New(fakeBootstrapIdentity{}, fakeSeedVault{}, "setup-tok", nil)
	body := `{"setupToken":"setup-tok\n","username":"admin","email":"admin@example.org","password":"pw"}`
	rec := httptest.NewRecorder()
	h.BootstrapHandler()(rec, httptest.NewRequest(http.MethodPost, "/setup/bootstrap", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestSeedHandler_TrimsConfiguredToken(t *testing.T) {
	h := setup.New(fakeSeedIdentity{}, fakeSeedVault{}, "setup-tok\r\n", nil)
	rec := httptest.NewRecorder()
	h.SeedHandler()(rec, httptest.NewRequest(http.MethodPost, "/setup/seed", strings.NewReader(`{"setupToken":"setup-tok"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("seed status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestBootstrapHandler_WrongTokenStillRefused(t *testing.T) {
	h := setup.New(fakeBootstrapIdentity{}, fakeSeedVault{}, "setup-tok\n", nil)
	for _, tok := range []string{"setup-to", "", "other", "setup-tok-extra"} {
		body := `{"setupToken":` + strconv.Quote(tok) + `,"username":"admin","email":"admin@example.org","password":"pw"}`
		rec := httptest.NewRecorder()
		h.BootstrapHandler()(rec, httptest.NewRequest(http.MethodPost, "/setup/bootstrap", strings.NewReader(body)))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("token %q: status = %d, want 403", tok, rec.Code)
		}
	}
}

// A whitespace-only value is no token at all: setup stays disabled.
func TestBootstrapHandler_BlankTokenDisablesSetup(t *testing.T) {
	h := setup.New(fakeBootstrapIdentity{}, fakeSeedVault{}, " \n", nil)
	rec := httptest.NewRecorder()
	h.BootstrapHandler()(rec, httptest.NewRequest(http.MethodPost, "/setup/bootstrap", strings.NewReader(`{"setupToken":""}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
