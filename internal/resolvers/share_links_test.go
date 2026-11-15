// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package resolvers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	gqlclient "github.com/99designs/gqlgen/client"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/gqlerr"
	"github.com/Sneakers-PAM/sneakers-gateway/internal/share"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The signed-in person's side of one-time share links (#148): create, list and
// revoke. The link, the page and the vault rules are tested in internal/share.

type shareVault struct {
	vaultv1.VaultServiceClient
	mu       sync.Mutex
	prepared []*vaultv1.PrepareSecretUseRequest
	revoked  []string
	state    vaultv1.SecretUseState
	err      error
}

func (v *shareVault) PrepareSecretUse(_ context.Context, in *vaultv1.PrepareSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.PrepareSecretUseResponse, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.err != nil {
		return nil, v.err
	}
	v.prepared = append(v.prepared, in)
	return &vaultv1.PrepareSecretUseResponse{Use: &vaultv1.SecretUse{
		Id: "use-1", SecretId: in.GetSecretId(), FieldKey: in.GetFieldKey(), State: v.state,
		ExpiresAtUnix: time.Now().Add(time.Duration(in.GetShareTtlSeconds()) * time.Second).Unix(),
	}}, nil
}

func (v *shareVault) GetSecretUse(_ context.Context, in *vaultv1.GetSecretUseRequest, _ ...grpc.CallOption) (*vaultv1.GetSecretUseResponse, error) {
	return &vaultv1.GetSecretUseResponse{Use: &vaultv1.SecretUse{Id: in.GetUseId(), State: v.state}}, nil
}

func (v *shareVault) RevokeSecretShare(_ context.Context, in *vaultv1.RevokeSecretShareRequest, _ ...grpc.CallOption) (*vaultv1.RevokeSecretShareResponse, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if in.GetActor().GetUserId() != "user-ada" {
		return nil, status.Error(codes.PermissionDenied, "not the creator")
	}
	v.revoked = append(v.revoked, in.GetUseId())
	return &vaultv1.RevokeSecretShareResponse{}, nil
}

type shareMem struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newShareStore() *shareMem { return &shareMem{data: map[string][]byte{}} }

func (m *shareMem) Put(_ context.Context, k string, v any, _ time.Duration) error {
	b, err := json.Marshal(v)
	m.mu.Lock()
	m.data[k] = b
	m.mu.Unlock()
	return err
}

func (m *shareMem) Get(_ context.Context, k string, out any) (bool, error) {
	m.mu.Lock()
	b, ok := m.data[k]
	m.mu.Unlock()
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(b, out)
}

func (m *shareMem) Take(ctx context.Context, k string, out any) (bool, error) {
	ok, err := m.Get(ctx, k, out)
	m.mu.Lock()
	delete(m.data, k)
	m.mu.Unlock()
	return ok, err
}
func newShareClient(sv *shareVault, publicURL, userID string) *gqlclient.Client {
	svc := &share.Service{Store: newShareStore(), Vault: sv, PublicURL: publicURL, Log: log.Nop()}
	r := &Resolver{Vault: sv, Share: svc}
	if publicURL == "-nil-" {
		r.Share = nil
	}
	h := handler.New(NewExecutableSchema(Config{Resolvers: r}))
	h.AddTransport(transport.POST{})
	h.SetErrorPresenter(gqlerr.Present)
	return gqlclient.New(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		if userID != "" {
			ctx = WithActorInfo(WithActor(ctx, userID), false, false, nil)
		}
		h.ServeHTTP(w, req.WithContext(ctx))
	}))
}

const createLink = `mutation { createShareLink(secretId:"secret-1", fieldKey:"password", ttlSeconds:3600) { id url secretId fieldKey state expiresAtUnix } }`

type createResp struct {
	CreateShareLink struct {
		ID, URL, SecretID, FieldKey, State string
		ExpiresAtUnix                      int
	}
}

func TestCreateShareLinkReturnsTheUrlOnceAndAsksTheVaultAsThePerson(t *testing.T) {
	sv := &shareVault{state: vaultv1.SecretUseState_SECRET_USE_STATE_PENDING}
	var resp createResp
	if err := newShareClient(sv, "https://sneakers.example.org", "user-ada").Post(createLink, &resp); err != nil {
		t.Fatal(err)
	}
	l := resp.CreateShareLink
	if l.ID != "use-1" || !strings.HasPrefix(l.URL, "https://sneakers.example.org/share/use-1.") || l.State != "awaiting_approval" || l.SecretID != "secret-1" || l.ExpiresAtUnix == 0 {
		t.Fatalf("link = %+v", l)
	}
	p := sv.prepared[0]
	if p.GetActor().GetUserId() != "user-ada" || !p.GetReveal() || p.GetShareTtlSeconds() != 3600 || len(p.GetShareHash()) != 64 {
		t.Fatalf("prepare = %+v", p)
	}
}

func TestShareLinkMutationsRefuseWithoutAPerson(t *testing.T) {
	sv := &shareVault{state: vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED}
	var resp createResp
	err := newShareClient(sv, "https://sneakers.example.org", "").Post(createLink, &resp)
	if err == nil || !strings.Contains(err.Error(), "SHARE_NOT_PERSON") || len(sv.prepared) != 0 {
		t.Fatalf("err %v prepared %d", err, len(sv.prepared))
	}
	var rv struct{ RevokeShareLink bool }
	err = newShareClient(sv, "https://sneakers.example.org", "").Post(`mutation { revokeShareLink(id:"use-1") }`, &rv)
	if err == nil || !strings.Contains(err.Error(), "SHARE_NOT_PERSON") || len(sv.revoked) != 0 {
		t.Fatalf("revoke: err %v", err)
	}
}

func TestShareLinksAreOffWithoutAPublicURL(t *testing.T) {
	sv := &shareVault{state: vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED}
	var resp createResp
	for _, url := range []string{"", "-nil-"} {
		err := newShareClient(sv, url, "user-ada").Post(createLink, &resp)
		if err == nil || !strings.Contains(err.Error(), "SHARE_LINKS_OFF") || len(sv.prepared) != 0 {
			t.Fatalf("url %q: err %v", url, err)
		}
	}
}

func TestShareLinkLifetimeIsChecked(t *testing.T) {
	sv := &shareVault{state: vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED}
	for _, ttl := range []string{"0", "30", "700000", "-5"} {
		var resp createResp
		err := newShareClient(sv, "https://sneakers.example.org", "user-ada").Post(
			`mutation { createShareLink(secretId:"s", fieldKey:"f", ttlSeconds:`+ttl+`) { id } }`, &resp)
		if err == nil || !strings.Contains(err.Error(), "SHARE_TTL_INVALID") {
			t.Errorf("ttl %s: %v", ttl, err)
		}
	}
	var resp createResp
	if err := newShareClient(sv, "https://sneakers.example.org", "user-ada").Post(`mutation { createShareLink(secretId:"s", fieldKey:"f") { id } }`, &resp); err != nil {
		t.Fatalf("no ttl: %v", err)
	}
	if len(sv.prepared) != 1 || sv.prepared[0].GetShareTtlSeconds() != 86400 {
		t.Fatalf("a missing ttl is a day: %+v", sv.prepared)
	}
}

func TestShareLinkPassesTheVaultsRefusalThrough(t *testing.T) {
	sv := &shareVault{err: status.Error(codes.PermissionDenied, "not permitted to use this secret")}
	var resp createResp
	err := newShareClient(sv, "https://sneakers.example.org", "user-ada").Post(createLink, &resp)
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("err %v", err)
	}
}

func TestListAndRevokeShareLinks(t *testing.T) {
	sv := &shareVault{state: vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED}
	c := newShareClient(sv, "https://sneakers.example.org", "user-ada")
	var resp createResp
	if err := c.Post(createLink, &resp); err != nil {
		t.Fatal(err)
	}
	var list struct {
		ShareLinks []struct {
			ID, State string
			URL       *string
		}
	}
	if err := c.Post(`{ shareLinks { id url state } }`, &list); err != nil || len(list.ShareLinks) != 1 || list.ShareLinks[0].ID != "use-1" || list.ShareLinks[0].State != "ready" || list.ShareLinks[0].URL != nil {
		t.Fatalf("list %+v err %v", list, err)
	}
	var rv struct{ RevokeShareLink bool }
	if err := c.Post(`mutation { revokeShareLink(id:"use-1") }`, &rv); err != nil || !rv.RevokeShareLink || len(sv.revoked) != 1 {
		t.Fatalf("revoke %v err %v", rv, err)
	}
	if err := c.Post(`{ shareLinks { id } }`, &list); err != nil || len(list.ShareLinks) != 0 {
		t.Fatalf("after revoke: %+v err %v", list, err)
	}
	bob := newShareClient(sv, "https://sneakers.example.org", "user-bob")
	if err := bob.Post(`mutation { revokeShareLink(id:"use-1") }`, &rv); err == nil || !strings.Contains(err.Error(), "not the creator") {
		t.Fatalf("another person's revoke: %v", err)
	}
}
