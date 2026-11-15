// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package netpolicy is the gateway's internal-only enforcement: when an admin
// marks the system internal-only, a request from outside the allowed source
// networks is refused with a stable code the phone apps map to a "connect to
// the VPN" message. The setting lives in the vault; the gateway reads it on a
// timer and enforces it by the request's source address.
package netpolicy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	log "github.com/Bugs5382/go-log"
)

// Settings are the stored settings the gateway enforces: internal-only with
// its allowed networks, and require-managed.
type Settings struct {
	InternalOnly   bool
	Networks       []string
	RequireManaged bool
}

// Source reads the stored settings.
type Source interface {
	Settings(ctx context.Context) (Settings, error)
}

// Published is what the release document says about the settings, and whether
// they have been read at all.
type Published struct {
	InternalOnly   bool
	RequireManaged bool
	Known          bool
}

// state is one reading of the settings.
type state struct {
	known          bool
	internalOnly   bool
	requireManaged bool
	allowed        []netip.Prefix
}

// Provider keeps the last setting read from the vault. Until the first read
// succeeds it is unknown, and the guard refuses (fails closed): it can't tell a
// request is allowed. After that a failed refresh keeps the last known setting.
type Provider struct {
	src Source
	log log.Logger

	mu  sync.RWMutex
	cur state
}

// NewProvider builds a provider that has read nothing yet.
func NewProvider(src Source, lg log.Logger) *Provider { return &Provider{src: src, log: lg} }

// Refresh reads the setting. An entry that isn't a network is skipped and
// logged, never read as "allow everything".
func (p *Provider) Refresh(ctx context.Context) error {
	got, err := p.src.Settings(ctx)
	on, nets := got.InternalOnly, got.Networks
	if err != nil {
		p.log.Ctx(ctx).Warn("network policy: the setting could not be read; keeping the last known one", log.F("error", err.Error()))
		return err
	}
	st := state{known: true, internalOnly: on, requireManaged: got.RequireManaged}
	for _, n := range nets {
		pf, perr := parsePrefix(n)
		if perr != nil {
			p.log.Ctx(ctx).Warn("network policy: skipping an allowed network that doesn't parse")
			continue
		}
		st.allowed = append(st.allowed, pf)
	}
	p.mu.Lock()
	changed := p.cur.known && (p.cur.internalOnly != st.internalOnly || p.cur.requireManaged != st.requireManaged || len(p.cur.allowed) != len(st.allowed))
	p.cur = st
	p.mu.Unlock()
	if changed || !p.cur.known {
		p.log.Ctx(ctx).Info("network policy: setting changed", log.F("internal_only", on), log.F("networks", len(st.allowed)), log.F("require_managed", st.requireManaged))
	}
	return nil
}

// Run refreshes every interval until ctx ends.
func (p *Provider) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_ = p.Refresh(ctx)
		}
	}
}

// Published reports the settings the release document publishes, and whether
// they have been read at all.
func (p *Provider) Published() Published {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return Published{InternalOnly: p.cur.internalOnly, RequireManaged: p.cur.requireManaged, Known: p.cur.known}
}

func (p *Provider) get() state {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cur
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if pf, err := netip.ParsePrefix(s); err == nil {
		return pf.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a CIDR prefix or an address", s)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// ParseTrustedProxies reads TRUSTED_PROXY_CIDRS: the networks of the proxies
// whose X-Forwarded-For the gateway believes. Empty means none.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range strings.Split(s, ",") {
		if strings.TrimSpace(e) == "" {
			continue
		}
		pf, err := parsePrefix(e)
		if err != nil {
			return nil, err
		}
		out = append(out, pf)
	}
	return out, nil
}

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func addrOf(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// ClientIP is the request's source address. It is the connection's peer, unless
// the peer is one of trusted (the web front end or the ingress), and then the
// nearest X-Forwarded-For hop that isn't itself trusted. A header from anyone
// else is ignored, so it can't be forged to look internal.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, ok := addrOf(host)
	if !ok {
		return netip.Addr{}
	}
	if !contains(trusted, peer) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := addrOf(hops[i])
		if !ok {
			return peer
		}
		if !contains(trusted, a) {
			return a
		}
	}
	return peer
}

// exempt are the paths that stay open off the network: the health and smoke
// probes (the kubelet isn't on the VPN) and the release document, so an app can
// tell the system is internal-only before it signs in.
var exempt = map[string]bool{
	"/livez": true, "/readyz": true, "/smoke": true, "/telemetry-status": true, "/.well-known/sneakers": true,
}

// Guard refuses every request from outside the allowed networks while the
// system is internal-only.
func Guard(next http.Handler, p *Provider, trusted []netip.Prefix, lg log.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if exempt[r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		st := p.get()
		switch {
		case !st.known:
			lg.Ctx(r.Context()).Warn("network policy: refusing a request, the setting has not been read yet", log.F("path", r.URL.Path))
			refuse(w, http.StatusServiceUnavailable, "NETWORK_POLICY_UNAVAILABLE", "Sneakers can't check where this request comes from yet. Try again in a moment.")
			return
		case !st.internalOnly:
			next.ServeHTTP(w, r)
			return
		}
		ip := ClientIP(r, trusted)
		if ip.IsValid() && contains(st.allowed, ip) {
			next.ServeHTTP(w, r)
			return
		}
		lg.Ctx(r.Context()).Info("network policy: refused a request from outside the allowed networks", log.F("path", r.URL.Path))
		refuse(w, http.StatusForbidden, "INTERNAL_ONLY", "This Sneakers install is internal-only. Connect to the VPN or the office network and try again.")
	})
}

func refuse(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "message": msg})
}
