// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package share is the one-time share link for a secret field. A person asks
// for a link; the vault holds the approval, the value and the audit, as a
// share use the creator passes the ordinary reveal rules for. The link carries
// a token, and the gateway keeps only a record that names the use and the hash
// of the token. A GET on the link never reaches the vault, so a chat app's
// preview can't burn the view; a POST from the page does.
package share

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	vaultv1 "github.com/Sneakers-PAM/sneakers-gateway/gen/go/thirdparty/vault/v1"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Store keeps the link records. bff.OAuthStore satisfies it, so the records
// live in Valkey with the sessions.
type Store interface {
	Put(ctx context.Context, key string, v any, ttl time.Duration) error
	Get(ctx context.Context, key string, out any) (bool, error)
	Take(ctx context.Context, key string, out any) (bool, error)
}

// Vault is the part of the vault's API a share uses.
type Vault interface {
	PrepareSecretUse(ctx context.Context, in *vaultv1.PrepareSecretUseRequest, opts ...grpc.CallOption) (*vaultv1.PrepareSecretUseResponse, error)
	GetSecretUse(ctx context.Context, in *vaultv1.GetSecretUseRequest, opts ...grpc.CallOption) (*vaultv1.GetSecretUseResponse, error)
	RedeemSecretShare(ctx context.Context, in *vaultv1.RedeemSecretShareRequest, opts ...grpc.CallOption) (*vaultv1.RedeemSecretShareResponse, error)
	RevokeSecretShare(ctx context.Context, in *vaultv1.RevokeSecretShareRequest, opts ...grpc.CallOption) (*vaultv1.RevokeSecretShareResponse, error)
}

// What a link is doing, for the creator.
const (
	StateAwaitingApproval = "awaiting_approval"
	StateReady            = "ready"
	StateOpened           = "opened"
	StateExpired          = "expired"
	StateUnknown          = "unknown"
)

const (
	minTTL     = time.Minute
	defaultTTL = 24 * time.Hour
	maxTTL     = 7 * 24 * time.Hour
	closedTTL  = 24 * time.Hour
)

var (
	// ErrOff: no public URL is configured, so no link can be built.
	ErrOff = errors.New("share links are off: the public URL is not set")
	// ErrTTL: the lifetime is outside 60 seconds to 7 days.
	ErrTTL = errors.New("a share link lives from 60 seconds to 7 days")

	tokenPattern = regexp.MustCompile(`^([A-Za-z0-9_-]{1,64})\.([A-Za-z0-9_-]{43})$`)
)

// Service creates, lists and revokes links and serves them.
type Service struct {
	Store     Store
	Vault     Vault
	PublicURL string
	Now       func() time.Time
	Log       log.Logger
}

// CreateParams is what a person asks a link for.
type CreateParams struct {
	Actor    *vaultv1.ActorContext
	Active   *vaultv1.ActiveUsers
	SecretID string
	FieldKey string
	// TTL is how long the link lives; 0 means a day.
	TTL time.Duration
}

// Link is one share link. URL is set only when it is created: the token is not
// kept, so it can't be shown again.
type Link struct {
	ID            string
	URL           string
	SecretID      string
	FieldKey      string
	ExpiresAtUnix int64
	State         string
}

type record struct {
	UseID     string `json:"use_id"`
	Hash      string `json:"hash"`
	CreatorID string `json:"creator_id"`
	SecretID  string `json:"secret_id"`
	FieldKey  string `json:"field_key"`
	ExpiresAt int64  `json:"expires_at"`
	// Closed marks a link that was opened, revoked or has run out, so a later
	// visit reads "gone" rather than "not found".
	Closed bool `json:"closed,omitempty"`
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) logger(ctx context.Context) log.Logger { return s.Log.Ctx(ctx) }

func recordKey(useID string) string      { return "share:" + useID }
func indexKey(creator string) string     { return "shares:" + creator }
func hashOf(token string) string         { h := sha256.Sum256([]byte(token)); return hex.EncodeToString(h[:]) }
func (r record) live(now time.Time) bool { return !r.Closed && now.Unix() < r.ExpiresAt }

// Create asks the vault for a share use and keeps the record. The vault's
// refusals (no access, step-up, no approver) pass through unchanged. When the
// owner's approval is needed the link is created and waits.
func (s *Service) Create(ctx context.Context, p CreateParams) (Link, error) {
	lg := s.logger(ctx)
	base := strings.TrimRight(s.PublicURL, "/")
	if base == "" {
		return Link{}, ErrOff
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = defaultTTL
	}
	if ttl < minTTL || ttl > maxTTL {
		return Link{}, ErrTTL
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return Link{}, err
	}
	secret := base64.RawURLEncoding.EncodeToString(buf)
	hash := hashOf(secret)
	resp, err := s.Vault.PrepareSecretUse(ctx, &vaultv1.PrepareSecretUseRequest{
		Actor: p.Actor, SecretId: p.SecretID, FieldKey: p.FieldKey, Reveal: true, ClientLabel: "share link",
		ActiveUsers: p.Active, ShareHash: hash, ShareTtlSeconds: int64(ttl / time.Second),
	})
	if err != nil {
		lg.Info("share link refused by the vault", log.F("user_id", p.Actor.GetUserId()), log.F("code", status.Code(err).String()))
		return Link{}, err
	}
	use := resp.GetUse()
	rec := record{UseID: use.GetId(), Hash: hash, CreatorID: p.Actor.GetUserId(), SecretID: use.GetSecretId(), FieldKey: use.GetFieldKey(), ExpiresAt: use.GetExpiresAtUnix()}
	if err := s.Store.Put(ctx, recordKey(rec.UseID), rec, ttl+time.Minute); err != nil {
		lg.Error(err, "share link: the record store is unavailable", log.F("use_id", rec.UseID))
		_, _ = s.Vault.RevokeSecretShare(ctx, &vaultv1.RevokeSecretShareRequest{Actor: p.Actor, UseId: rec.UseID})
		return Link{}, status.Error(codes.Unavailable, "share links are unavailable right now")
	}
	s.index(ctx, rec.CreatorID, rec.UseID, true)
	lg.Info("share link created", log.F("use_id", rec.UseID), log.F("user_id", rec.CreatorID), log.F("state", use.GetState().String()), log.F("expires_at", rec.ExpiresAt))
	return Link{
		ID: rec.UseID, URL: base + "/share/" + rec.UseID + "." + secret, SecretID: rec.SecretID, FieldKey: rec.FieldKey,
		ExpiresAtUnix: rec.ExpiresAt, State: stateOf(use.GetState(), rec, s.now()),
	}, nil
}

func stateOf(st vaultv1.SecretUseState, rec record, now time.Time) string {
	switch {
	case st == vaultv1.SecretUseState_SECRET_USE_STATE_REDEEMED:
		return StateOpened
	case !rec.live(now), st == vaultv1.SecretUseState_SECRET_USE_STATE_EXPIRED, st == vaultv1.SecretUseState_SECRET_USE_STATE_DENIED:
		return StateExpired
	case st == vaultv1.SecretUseState_SECRET_USE_STATE_PENDING:
		return StateAwaitingApproval
	case st == vaultv1.SecretUseState_SECRET_USE_STATE_APPROVED:
		return StateReady
	}
	return StateUnknown
}

// index adds or drops a use id on its creator's list.
func (s *Service) index(ctx context.Context, creator, useID string, add bool) {
	var ids []string
	if _, err := s.Store.Get(ctx, indexKey(creator), &ids); err != nil {
		s.logger(ctx).Warn("share link index unreadable", log.F("user_id", creator))
		return
	}
	out := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		if id != useID {
			out = append(out, id)
		}
	}
	if add {
		out = append(out, useID)
	}
	if err := s.Store.Put(ctx, indexKey(creator), out, maxTTL+time.Hour); err != nil {
		s.logger(ctx).Warn("share link index not saved", log.F("user_id", creator))
	}
}

// List is the signed-in person's own links, with where each one stands. The
// token isn't kept, so no URL comes back.
func (s *Service) List(ctx context.Context, actor *vaultv1.ActorContext) ([]Link, error) {
	var ids []string
	if _, err := s.Store.Get(ctx, indexKey(actor.GetUserId()), &ids); err != nil {
		return nil, status.Error(codes.Unavailable, "share links are unavailable right now")
	}
	out := make([]Link, 0, len(ids))
	for _, id := range ids {
		var rec record
		ok, err := s.Store.Get(ctx, recordKey(id), &rec)
		if err != nil || !ok || rec.Closed || rec.CreatorID != actor.GetUserId() {
			continue
		}
		l := Link{ID: id, SecretID: rec.SecretID, FieldKey: rec.FieldKey, ExpiresAtUnix: rec.ExpiresAt, State: StateUnknown}
		if u, err := s.Vault.GetSecretUse(ctx, &vaultv1.GetSecretUseRequest{Actor: actor, UseId: id}); err == nil {
			l.State = stateOf(u.GetUse().GetState(), rec, s.now())
		}
		out = append(out, l)
	}
	return out, nil
}

// close keeps a short tombstone for a link that is over, and drops it from its
// creator's list.
func (s *Service) close(ctx context.Context, rec record) {
	rec.Closed = true
	if err := s.Store.Put(ctx, recordKey(rec.UseID), rec, closedTTL); err != nil {
		s.logger(ctx).Warn("share link not closed in the store", log.F("use_id", rec.UseID))
	}
	s.index(ctx, rec.CreatorID, rec.UseID, false)
}

// Revoke ends a link. The vault decides who may (the creator or a site admin)
// and its refusal passes through.
func (s *Service) Revoke(ctx context.Context, actor *vaultv1.ActorContext, id string) error {
	if _, err := s.Vault.RevokeSecretShare(ctx, &vaultv1.RevokeSecretShareRequest{Actor: actor, UseId: id}); err != nil {
		return err
	}
	var rec record
	if ok, _ := s.Store.Get(ctx, recordKey(id), &rec); ok {
		s.close(ctx, rec)
	}
	s.logger(ctx).Info("share link revoked", log.F("use_id", id), log.F("user_id", actor.GetUserId()))
	return nil
}

// reasonOf is the reason on a vault refusal, "" when it has none.
func reasonOf(err error) string {
	for _, d := range status.Convert(err).Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	return ""
}

// outcome is what a view came to.
type outcome int

const (
	outcomeOK outcome = iota
	outcomeNotFound
	outcomeGone
	outcomePending
	outcomeUnavailable
)

// lookup finds the record a token names, checking the secret half against its
// hash without asking the vault.
func (s *Service) lookup(ctx context.Context, token string) (record, string, outcome) {
	m := tokenPattern.FindStringSubmatch(token)
	if m == nil {
		return record{}, "", outcomeNotFound
	}
	var rec record
	ok, err := s.Store.Get(ctx, recordKey(m[1]), &rec)
	switch {
	case err != nil:
		return record{}, "", outcomeUnavailable
	case !ok || subtle.ConstantTimeCompare([]byte(rec.Hash), []byte(hashOf(m[2]))) != 1:
		return record{}, "", outcomeNotFound
	case !rec.live(s.now()):
		if !rec.Closed {
			s.close(ctx, rec)
		}
		return rec, m[2], outcomeGone
	}
	return rec, m[2], outcomeOK
}

// open asks the vault for the value, once.
func (s *Service) open(ctx context.Context, rec record, secret string) (string, outcome) {
	lg := s.logger(ctx)
	resp, err := s.Vault.RedeemSecretShare(ctx, &vaultv1.RedeemSecretShareRequest{UseId: rec.UseID, ShareHash: hashOf(secret)})
	if err == nil {
		s.close(ctx, rec)
		lg.Info("share link opened", log.F("use_id", rec.UseID))
		return resp.GetValue(), outcomeOK
	}
	reason := reasonOf(err)
	lg.Info("share link not opened", log.F("use_id", rec.UseID), log.F("code", status.Code(err).String()), log.F("reason", reason))
	switch {
	case reason == "SHARE_NOT_APPROVED":
		return "", outcomePending
	case reason == "SHARE_USED", reason == "SHARE_EXPIRED", reason == "SHARE_DENIED", status.Code(err) == codes.NotFound:
		s.close(ctx, rec)
		return "", outcomeGone
	}
	return "", outcomeUnavailable
}

// Handler serves GET, HEAD and POST of /share/{token}.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/share/{token}", s.serve)
	return mux
}

func (s *Service) serve(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		h.Set("Allow", "GET, HEAD, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rec, secret, out := s.lookup(r.Context(), r.PathValue("token"))
	if out != outcomeOK {
		s.page(w, r, out, "")
		return
	}
	if r.Method != http.MethodPost {
		s.page(w, r, outcomeOK, "")
		return
	}
	value, out := s.open(r.Context(), rec, secret)
	s.page(w, r, out, value)
}
