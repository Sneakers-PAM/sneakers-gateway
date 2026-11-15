// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package netpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
)

// Internal-only (#147): an admin marks the system internal-only with the
// source networks it allows, and the gateway refuses every other request with a
// stable code the apps map to "connect to the VPN". Enforcement is here, by the
// request's source address, never in the app.

type fakeSource struct {
	internalOnly bool
	networks     []string
	err          error
	calls        int
}

func (f *fakeSource) Settings(context.Context) (bool, []string, error) {
	f.calls++
	return f.internalOnly, f.networks, f.err
}

func newProvider(t *testing.T, src *fakeSource) *Provider {
	t.Helper()
	p := NewProvider(src, log.Nop())
	if err := p.Refresh(context.Background()); err != nil && src.err == nil {
		t.Fatal(err)
	}
	return p
}

func request(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/graphql", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func TestClientIPUsesThePeerUnlessItIsATrustedProxy(t *testing.T) {
	proxy := prefixes(t, "203.0.113.128/25")
	for name, c := range map[string]struct {
		remote, xff string
		trusted     []netip.Prefix
		want        string
	}{
		"direct":                         {"192.0.2.9:4444", "", nil, "192.0.2.9"},
		"a header from a stranger":       {"192.0.2.9:4444", "198.51.100.1", proxy, "192.0.2.9"},
		"a header and no proxy set":      {"203.0.113.130:80", "198.51.100.1", nil, "203.0.113.130"},
		"through a trusted proxy":        {"203.0.113.130:80", "198.51.100.1", proxy, "198.51.100.1"},
		"a chain, nearest hop wins":      {"203.0.113.130:80", "203.0.113.50, 198.51.100.1", proxy, "198.51.100.1"},
		"a trusted hop in the chain":     {"203.0.113.130:80", "198.51.100.1, 203.0.113.177", proxy, "198.51.100.1"},
		"a forged left entry is ignored": {"203.0.113.130:80", "203.0.113.199, 203.0.113.50", proxy, "203.0.113.50"},
		"garbage in the header":          {"203.0.113.130:80", "not-an-ip", proxy, "203.0.113.130"},
		"ipv6":                           {"[2001:db8::7]:443", "", nil, "2001:db8::7"},
		"ipv6 client behind a proxy":     {"203.0.113.130:80", "2001:db8::99", proxy, "2001:db8::99"},
		"a mapped ipv4":                  {"[::ffff:192.0.2.9]:443", "", nil, "192.0.2.9"},
		"a port on the forwarded entry":  {"203.0.113.130:80", "198.51.100.1:5555", proxy, "198.51.100.1"},
	} {
		got := ClientIP(request(c.remote, c.xff), c.trusted)
		if got.String() != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
	}
}

func guarded(p *Provider, trusted []netip.Prefix) http.Handler {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return Guard(next, p, trusted, log.Nop())
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestGuardLetsInsideThroughAndRefusesOutsideWithAStableCode(t *testing.T) {
	p := newProvider(t, &fakeSource{internalOnly: true, networks: []string{"192.0.2.0/24", "2001:db8::/32"}})
	h := guarded(p, nil)
	for _, in := range []string{"192.0.2.77:1", "[2001:db8:1::5]:1"} {
		if rec := serve(h, request(in, "")); rec.Code != http.StatusOK {
			t.Errorf("inside %s: %d", in, rec.Code)
		}
	}
	for _, out := range []string{"198.51.100.7:1", "[2001:db9::1]:1", "203.0.113.1:1"} {
		rec := serve(h, request(out, ""))
		var body struct{ Error, Message string }
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != http.StatusForbidden || body.Error != "INTERNAL_ONLY" || body.Message == "" ||
			rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("outside %s: %d %s", out, rec.Code, rec.Body.String())
		}
	}
}

func TestGuardIsOffWhenTheSettingIsOff(t *testing.T) {
	p := newProvider(t, &fakeSource{internalOnly: false, networks: []string{"192.0.2.0/24"}})
	if rec := serve(guarded(p, nil), request("198.51.100.7:1", "")); rec.Code != http.StatusOK {
		t.Fatalf("setting off: %d", rec.Code)
	}
}

func TestGuardKeepsTheHealthChecksAndTheReleaseDocumentOpen(t *testing.T) {
	p := newProvider(t, &fakeSource{internalOnly: true, networks: []string{"192.0.2.0/24"}})
	h := guarded(p, nil)
	for _, path := range []string{"/livez", "/readyz", "/smoke", "/telemetry-status", "/.well-known/sneakers"} {
		r := request("198.51.100.7:1", "")
		r.URL.Path = path
		if rec := serve(h, r); rec.Code != http.StatusOK {
			t.Errorf("%s from outside: %d, want open", path, rec.Code)
		}
	}
	for _, path := range []string{"/graphql", "/machine/graphql", "/auth/login", "/oauth2/token", "/share/x.y", "/setup/state", "/livez/../graphql", "/.well-known/sneakers/x"} {
		r := request("198.51.100.7:1", "")
		r.URL.Path = path
		if rec := serve(h, r); rec.Code != http.StatusForbidden {
			t.Errorf("%s from outside: %d, want refused", path, rec.Code)
		}
	}
}

func TestGuardUsesTheForwardedAddressOnlyBehindATrustedProxy(t *testing.T) {
	p := newProvider(t, &fakeSource{internalOnly: true, networks: []string{"192.0.2.0/24"}})
	proxy := prefixes(t, "203.0.113.128/25")
	h := guarded(p, proxy)
	if rec := serve(h, request("203.0.113.130:80", "192.0.2.40")); rec.Code != http.StatusOK {
		t.Fatalf("inside through the proxy: %d", rec.Code)
	}
	if rec := serve(h, request("203.0.113.130:80", "198.51.100.1")); rec.Code != http.StatusForbidden {
		t.Fatalf("outside through the proxy: %d", rec.Code)
	}
	if rec := serve(h, request("198.51.100.1:80", "192.0.2.40")); rec.Code != http.StatusForbidden {
		t.Fatalf("a forged header from a stranger: %d", rec.Code)
	}
	if rec := serve(guarded(p, nil), request("203.0.113.130:80", "192.0.2.40")); rec.Code != http.StatusForbidden {
		t.Fatalf("no trusted proxy set must ignore the header: %d", rec.Code)
	}
}

func TestGuardFailsClosedUntilTheSettingIsKnownAndKeepsTheLastKnownOne(t *testing.T) {
	src := &fakeSource{err: errors.New("vault down")}
	p := newProvider(t, src)
	rec := serve(guarded(p, nil), request("192.0.2.9:1", ""))
	var body struct{ Error string }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusServiceUnavailable || body.Error != "NETWORK_POLICY_UNAVAILABLE" {
		t.Fatalf("unknown at start: %d %s", rec.Code, rec.Body.String())
	}
	src.err, src.internalOnly, src.networks = nil, true, []string{"192.0.2.0/24"}
	if err := p.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec := serve(guarded(p, nil), request("192.0.2.9:1", "")); rec.Code != http.StatusOK {
		t.Fatalf("known and inside: %d", rec.Code)
	}
	src.err = errors.New("vault down again")
	if err := p.Refresh(context.Background()); err == nil {
		t.Fatal("a failed refresh must say so")
	}
	if rec := serve(guarded(p, nil), request("198.51.100.1:1", "")); rec.Code != http.StatusForbidden {
		t.Fatalf("the last known setting must still hold: %d", rec.Code)
	}
}

func TestProviderIgnoresAnInvalidNetworkButNeverOpensUp(t *testing.T) {
	p := newProvider(t, &fakeSource{internalOnly: true, networks: []string{"not-a-network", "192.0.2.0/24"}})
	h := guarded(p, nil)
	if serve(h, request("192.0.2.9:1", "")).Code != http.StatusOK || serve(h, request("198.51.100.1:1", "")).Code != http.StatusForbidden {
		t.Fatal("an invalid entry must be skipped, and the rest enforced")
	}
	none := newProvider(t, &fakeSource{internalOnly: true, networks: []string{"not-a-network"}})
	if rec := serve(guarded(none, nil), request("192.0.2.9:1", "")); rec.Code != http.StatusForbidden {
		t.Fatalf("internal-only with no usable network must refuse everyone: %d", rec.Code)
	}
}

func TestProviderReportsTheSettingForThePublishedDocument(t *testing.T) {
	src := &fakeSource{internalOnly: true, networks: []string{"192.0.2.0/24"}}
	p := newProvider(t, src)
	if on, known := p.InternalOnly(); !on || !known {
		t.Fatalf("on=%v known=%v", on, known)
	}
	unknown := NewProvider(&fakeSource{err: errors.New("x")}, log.Nop())
	if on, known := unknown.InternalOnly(); on || known {
		t.Fatalf("before the first read: on=%v known=%v", on, known)
	}
}

func TestRunRefreshesUntilTheContextEnds(t *testing.T) {
	src := &fakeSource{internalOnly: false}
	p := NewProvider(src, log.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, 5*time.Millisecond); close(done) }()
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run must stop with its context")
	}
	if src.calls < 3 {
		t.Fatalf("refreshes: %d", src.calls)
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies(" 203.0.113.128/25, 192.0.2.5 ,2001:db8::/32 ")
	if err != nil || len(got) != 3 || got[1].String() != "192.0.2.5/32" {
		t.Fatalf("got %v err %v", got, err)
	}
	if got, err := ParseTrustedProxies(""); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	if _, err := ParseTrustedProxies("203.0.113.0/24, nonsense"); err == nil {
		t.Fatal("an invalid entry must be an error")
	}
}
