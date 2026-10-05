// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package bff

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/identity/v1"
)

// OAuth is the authorization server behind MCP /login: RFC 8252 native-app
// sign-in with PKCE, issuing a personal token. The browser part runs on the
// signed-in Sneakers session; consent needs a fresh second factor.
type OAuth struct {
	Handler   *Handler
	Store     OAuthStore
	PublicURL string
	Now       func() time.Time
}

const (
	oauthRequestTTL = 10 * time.Minute
	oauthCodeTTL    = time.Minute
	oauthClientTTL  = 365 * 24 * time.Hour
)

type oauthClient struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
}

type oauthRequest struct {
	ClientID    string    `json:"client_id"`
	RedirectURI string    `json:"redirect_uri"`
	Challenge   string    `json:"challenge"`
	State       string    `json:"state"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type oauthCode struct {
	UserID      string    `json:"user_id"`
	ClientID    string    `json:"client_id"`
	ClientName  string    `json:"client_name"`
	RedirectURI string    `json:"redirect_uri"`
	Challenge   string    `json:"challenge"`
	Label       string    `json:"label"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (o *OAuth) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OAuth) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", o.metadata)
	mux.HandleFunc("POST /oauth2/register", o.register)
	mux.HandleFunc("GET /oauth2/authorize", o.authorize)
	mux.HandleFunc("GET /oauth2/consent/{id}", o.consentDetails)
	mux.HandleFunc("POST /oauth2/consent/{id}", o.consent)
	mux.HandleFunc("POST /oauth2/consent/{id}/email-code", o.consentEmailCode)
	mux.HandleFunc("POST /oauth2/consent/{id}/passkey/begin", o.consentPasskeyBegin)
	mux.HandleFunc("POST /oauth2/token", o.token)
	return mux
}

func (o *OAuth) metadata(w http.ResponseWriter, _ *http.Request) {
	base := strings.TrimRight(o.PublicURL, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth2/authorize",
		"token_endpoint":                        base + "/oauth2/token",
		"registration_endpoint":                 base + "/oauth2/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	})
}

// isLoopback accepts only http redirect URIs on the local machine, the one
// place a native client can receive the code (RFC 8252 section 7.3).
func isLoopback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Fragment != "" || u.User != nil {
		return false
	}
	switch h := u.Hostname(); h {
	case "localhost":
		return true
	default:
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
}

// sameLoopback compares scheme, host and path but not the port, which a
// native client picks fresh for each sign-in.
func sameLoopback(registered, got string) bool {
	a, errA := url.Parse(registered)
	b, errB := url.Parse(got)
	return errA == nil && errB == nil && a.Scheme == b.Scheme && a.Hostname() == b.Hostname() && a.Path == b.Path
}

func randomID() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (o *OAuth) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&in); err != nil || len(in.RedirectURIs) == 0 || len(in.RedirectURIs) > 10 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	for _, u := range in.RedirectURIs {
		if !isLoopback(u) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "only loopback redirect URIs are allowed"})
			return
		}
	}
	id, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	c := oauthClient{ID: "snkc_" + id, Name: strings.TrimSpace(in.ClientName), RedirectURIs: in.RedirectURIs}
	if c.Name == "" {
		c.Name = "MCP client"
	}
	if err := o.Store.Put(r.Context(), "client:"+c.ID, c, oauthClientTTL); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id": c.ID, "client_name": c.Name, "redirect_uris": c.RedirectURIs,
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code"}, "response_types": []string{"code"},
	})
}

func (o *OAuth) client(ctx context.Context, id string) (oauthClient, bool) {
	var c oauthClient
	ok, err := o.Store.Get(ctx, "client:"+id, &c)
	return c, ok && err == nil
}

func redirectWith(w http.ResponseWriter, r *http.Request, target string, params url.Values) {
	if !isLoopback(target) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, withQuery(target, params), http.StatusFound) // #nosec G710 -- target is a registered loopback redirect_uri, re-checked just above
}

func (o *OAuth) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := o.client(r.Context(), q.Get("client_id"))
	redirect := q.Get("redirect_uri")
	registered := false
	for _, u := range c.RedirectURIs {
		registered = registered || (ok && sameLoopback(u, redirect))
	}
	if !registered {
		http.Error(w, "unknown client or redirect_uri", http.StatusBadRequest)
		return
	}
	state := q.Get("state")
	if q.Get("response_type") != "code" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		redirectWith(w, r, redirect, url.Values{"error": {"invalid_request"}, "state": {state}})
		return
	}
	id, err := randomID()
	if err != nil {
		redirectWith(w, r, redirect, url.Values{"error": {"server_error"}, "state": {state}})
		return
	}
	req := oauthRequest{ClientID: c.ID, RedirectURI: redirect, Challenge: q.Get("code_challenge"), State: state, ExpiresAt: o.now().Add(oauthRequestTTL)}
	if err := o.Store.Put(r.Context(), "request:"+id, req, oauthRequestTTL); err != nil {
		redirectWith(w, r, redirect, url.Values{"error": {"temporarily_unavailable"}, "state": {state}})
		return
	}
	http.Redirect(w, r, strings.TrimRight(o.PublicURL, "/")+"/oauth/consent?req="+url.QueryEscape(id), http.StatusFound)
}

func (o *OAuth) pendingRequest(ctx context.Context, id string) (oauthRequest, bool) {
	var req oauthRequest
	ok, err := o.Store.Get(ctx, "request:"+id, &req)
	return req, ok && err == nil && o.now().Before(req.ExpiresAt)
}

func (o *OAuth) consentDetails(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := o.Handler.authedSession(w, r); !ok {
		return
	}
	req, ok := o.pendingRequest(r.Context(), r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_expired"})
		return
	}
	c, _ := o.client(r.Context(), req.ClientID)
	writeJSON(w, http.StatusOK, map[string]string{"clientName": c.Name, "redirectHost": hostOf(req.RedirectURI)})
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

func (o *OAuth) consent(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := o.Handler.authedSession(w, r)
	if !ok {
		return
	}
	var in struct {
		Approve bool   `json:"approve"`
		Label   string `json:"label"`
		Factor  struct {
			Kind              string `json:"kind"`
			Code              string `json:"code"`
			CredentialJSON    string `json:"credentialJson"`
			WebauthnSessionID string `json:"webauthnSessionId"`
		} `json:"factor"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id := r.PathValue("id")
	req, ok := o.pendingRequest(r.Context(), id)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_expired"})
		return
	}
	if !in.Approve {
		_, _ = o.Store.Take(r.Context(), "request:"+id, &req)
		writeJSON(w, http.StatusOK, map[string]string{"redirect": withQuery(req.RedirectURI, url.Values{"error": {"access_denied"}, "state": {req.State}})})
		return
	}
	verified, err := o.Handler.verifyFactor(r.Context(), sess.UserID, in.Factor.Kind, in.Factor.Code, in.Factor.WebauthnSessionID, in.Factor.CredentialJSON)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	if !verified {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_code"})
		return
	}
	if ok, err := o.Store.Take(r.Context(), "request:"+id, &req); !ok || err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_expired"})
		return
	}
	c, _ := o.client(r.Context(), req.ClientID)
	code, err := randomID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	grant := oauthCode{
		UserID: sess.UserID, ClientID: req.ClientID, ClientName: c.Name, RedirectURI: req.RedirectURI,
		Challenge: req.Challenge, Label: strings.TrimSpace(in.Label), ExpiresAt: o.now().Add(oauthCodeTTL),
	}
	if err := o.Store.Put(r.Context(), "code:"+code, grant, oauthCodeTTL); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": withQuery(req.RedirectURI, url.Values{"code": {code}, "state": {req.State}})})
}

func withQuery(target string, params url.Values) string {
	u, _ := url.Parse(target)
	q := u.Query()
	for k, v := range params {
		q[k] = v
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

var errInvalidGrant = errors.New("invalid_grant")

func (o *OAuth) redeem(ctx context.Context, form url.Values) (oauthCode, error) {
	var grant oauthCode
	ok, err := o.Store.Take(ctx, "code:"+form.Get("code"), &grant)
	if err != nil {
		return oauthCode{}, err
	}
	switch {
	case !ok, !o.now().Before(grant.ExpiresAt),
		grant.ClientID != form.Get("client_id"),
		grant.RedirectURI != form.Get("redirect_uri"),
		subtle.ConstantTimeCompare([]byte(s256(form.Get("code_verifier"))), []byte(grant.Challenge)) != 1:
		return oauthCode{}, errInvalidGrant
	}
	return grant, nil
}

func (o *OAuth) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	grant, err := o.redeem(r.Context(), r.PostForm)
	if errors.Is(err, errInvalidGrant) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return
	}
	resp, err := o.Handler.Identity.MintUserToken(r.Context(), &identityv1.MintUserTokenRequest{
		UserId: grant.UserID, Label: grant.Label, ClientName: grant.ClientName, ClientKind: ClientKindMCP,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": resp.GetToken(), "token_type": "Bearer"})
}

// consentEmailCode lets a user whose second factor is email get a code for
// the consent step.
func (o *OAuth) consentEmailCode(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := o.Handler.authedSession(w, r)
	if !ok {
		return
	}
	if _, ok := o.pendingRequest(r.Context(), r.PathValue("id")); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_expired"})
		return
	}
	if _, err := o.Handler.Identity.SendEmailOtp(r.Context(), &identityv1.SendEmailOtpRequest{UserId: sess.UserID, Purpose: mfaLoginPurpose}); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (o *OAuth) consentPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	sess, _, ok := o.Handler.authedSession(w, r)
	if !ok {
		return
	}
	if _, ok := o.pendingRequest(r.Context(), r.PathValue("id")); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_expired"})
		return
	}
	resp, err := o.Handler.Identity.WebauthnAssertBegin(r.Context(), &identityv1.WebauthnAssertBeginRequest{UserId: sess.UserID})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "identity_unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"options": resp.GetOptionsJson(), "webauthnSessionId": resp.GetSessionId()})
}
