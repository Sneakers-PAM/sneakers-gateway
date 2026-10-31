// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package machineresolvers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/resolvers"
)

func newTopLevelClient(fv *organizeVault) *client.Client {
	h := handler.New(NewExecutableSchema(Config{Resolvers: &Resolver{Vault: fv}}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return client.New(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := resolvers.WithUserTokenActor(r.Context(), "u-ada", "utok-1", nil)
		h.ServeHTTP(w, r.WithContext(resolvers.WithTokenOwnerSiteAdmin(ctx)))
	}))
}

func TestCreateFolderForPrincipal_NoParentPassesAnEmptyParentToTheVault(t *testing.T) {
	fv := &organizeVault{}
	var resp struct{ CreateFolderForPrincipal principalFolderResp }
	newTopLevelClient(fv).MustPost(`mutation { createFolderForPrincipal(name: "Infrastructure") { id name parentId path } }`, &resp)

	if fv.lastCreateFolder == nil {
		t.Fatal("vault.CreateFolderForPrincipal was not called")
	}
	if fv.lastCreateFolder.GetParentId() != "" || fv.lastCreateFolder.GetName() != "Infrastructure" {
		t.Fatalf("request = %+v", fv.lastCreateFolder)
	}
	if !fv.lastCreateFolder.GetActor().GetTokenOwnerIsSiteAdmin() {
		t.Fatalf("actor = %+v, want the token owner marked as a site admin", fv.lastCreateFolder.GetActor())
	}
	got := resp.CreateFolderForPrincipal
	if got.ID != "f9" || got.Name != "Infrastructure" || got.ParentID != nil || got.Path != "Infrastructure" {
		t.Fatalf("folder = %+v", got)
	}
}

func TestCreateFolderForPrincipal_RefusalReasonsPassThroughUnchanged(t *testing.T) {
	for _, reason := range []string{"TOP_LEVEL_FOLDERS_DISABLED", "NOT_SITE_ADMIN"} {
		t.Run(reason, func(t *testing.T) {
			const msg = `top-level folders need the "Agents may create top-level folders" setting`
			st, err := status.New(codes.PermissionDenied, msg).WithDetails(&errdetails.ErrorInfo{Reason: reason, Domain: "sneakers.vault"})
			if err != nil {
				t.Fatal(err)
			}
			resp, err := newTopLevelClient(&organizeVault{err: st.Err()}).RawPost(`mutation { createFolderForPrincipal(name: "Infrastructure") { id } }`)
			if err != nil {
				t.Fatal(err)
			}
			var errs []struct {
				Message    string
				Extensions struct{ Code, Reason, Domain string }
			}
			if err := json.Unmarshal(resp.Errors, &errs); err != nil || len(errs) != 1 {
				t.Fatalf("errors = %s (%v)", resp.Errors, err)
			}
			e := errs[0]
			if e.Extensions.Code != "PERMISSION_DENIED" || e.Extensions.Reason != reason || e.Extensions.Domain != "sneakers.vault" {
				t.Fatalf("extensions = %+v", e.Extensions)
			}
			if want := "rpc error: code = PermissionDenied desc = " + msg; e.Message != want {
				t.Fatalf("message = %q, want %q", e.Message, want)
			}
		})
	}
}
