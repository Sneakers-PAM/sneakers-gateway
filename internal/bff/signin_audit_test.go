// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auditv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/audit/v1"
	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
	"google.golang.org/grpc"
)

type fakeAudit struct {
	events []*auditv1.RecordEventRequest
	err    error
}

func (f *fakeAudit) RecordEvent(_ context.Context, in *auditv1.RecordEventRequest, _ ...grpc.CallOption) (*auditv1.RecordEventResponse, error) {
	f.events = append(f.events, in)
	if f.err != nil {
		return nil, f.err
	}
	return &auditv1.RecordEventResponse{}, nil
}

func loginWith(t *testing.T, h *Handler, user, password string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": user, "password": password})
	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body)))
	return rec
}

// A password Kratos rejects never reaches identity, so the gateway records it.
func TestLogin_RejectedPasswordIsAudited(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fa := &fakeAudit{}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: &fakeIdentity{}, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL), Audit: fa}

	if rec := loginWith(t, h, cfg.email, "wrong-password-value"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
	if len(fa.events) != 1 {
		t.Fatalf("events = %v", fa.events)
	}
	e := fa.events[0]
	if e.GetAction() != "auth.signin" || e.GetTier() != auditv1.Tier_TIER_AUDIT || e.GetAttributes()["outcome"] != "rejected" || e.GetAttributes()["step"] != "password" || e.GetAttributes()["identifier"] != cfg.email {
		t.Fatalf("event = %+v", e)
	}
	for k, v := range e.GetAttributes() {
		if strings.Contains(v, "wrong-password-value") {
			t.Fatalf("attribute %s carries the password", k)
		}
	}
}

func TestLogin_AcceptedPasswordIsNotAuditedByTheGateway(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fa := &fakeAudit{}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: &fakeIdentity{adoptUser: &identityv1.User{Id: "usr-42"}}, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL), Audit: fa}
	if rec := loginWith(t, h, cfg.email, cfg.goodPassword); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	if len(fa.events) != 0 {
		t.Fatalf("identity records accepted sign-ins; the gateway recorded %v", fa.events)
	}
}

// The audit write is best effort: the caller still gets its 401.
func TestLogin_AuditDownStillAnswers401(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	h := &Handler{Store: NewMemStore(time.Hour), Identity: &fakeIdentity{}, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL), Audit: &fakeAudit{err: errors.New("down")}}
	if rec := loginWith(t, h, cfg.email, "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", rec.Code)
	}
}

// A very long identifier is cut so a caller can't fill the audit chain.
func TestLogin_RejectedIdentifierIsCapped(t *testing.T) {
	cfg := defaultKratosLoginConfig()
	kratos := newKratosLoginServer(t, cfg)
	fa := &fakeAudit{}
	h := &Handler{Store: NewMemStore(time.Hour), Identity: &fakeIdentity{}, TTL: time.Hour, Auth: NewKratosClient(kratos.URL, kratos.URL), Audit: fa}
	loginWith(t, h, strings.Repeat("a", 500)+"@example.org", "wrong")
	if len(fa.events) != 1 || len(fa.events[0].GetAttributes()["identifier"]) > maxAuditIdentifier {
		t.Fatalf("events = %v", fa.events)
	}
}
