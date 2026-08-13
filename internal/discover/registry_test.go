package discover

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
)

func TestProbeHosts(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want []string
	}{
		// A wildcard answers anywhere, so it is probed over loopback and the
		// request never touches the network.
		{"v4 wildcard", "0.0.0.0", []string{"127.0.0.1", "::1"}},
		{"v6 wildcard", "::", []string{"::1", "127.0.0.1"}},
		// The matching family leads: a socket on ::1 never answers on 127.0.0.1.
		{"v4 loopback", "127.0.0.1", []string{"127.0.0.1", "::1"}},
		{"v6 loopback", "::1", []string{"::1", "127.0.0.1"}},
		// The regression this file exists for: a service bound to one LAN
		// address refuses a connection to 127.0.0.1, so probing loopback alone
		// dropped it from the page entirely.
		{"specific v4", "192.168.1.79", []string{"192.168.1.79", "127.0.0.1", "::1"}},
		{"specific v6", "2001:db8::1", []string{"2001:db8::1", "::1", "127.0.0.1"}},
		// Loopback is a whole /8, and only one of its addresses is 127.0.0.1.
		{"other loopback address", "127.0.0.2", []string{"127.0.0.2", "127.0.0.1", "::1"}},
		// /proc/net/tcp6 reports v4 sockets in mapped form; they dial as v4.
		{"v4-mapped", "::ffff:10.1.2.3", []string{"10.1.2.3", "127.0.0.1", "::1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := probeHosts(netip.MustParseAddr(tt.addr))
			if !slices.Equal(got, tt.want) {
				t.Errorf("probeHosts(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}

	// An address we failed to parse must still produce something dialable
	// rather than an empty list that skips the probe.
	if got := probeHosts(netip.Addr{}); !slices.Equal(got, []string{"127.0.0.1", "::1"}) {
		t.Errorf("zero address = %v, want the loopback pair", got)
	}
}

// A listener bound to one specific address must be probed at that address.
// 127.0.0.2 stands in for the LAN address a test cannot know: it is a
// different address from 127.0.0.1 in exactly the way that matters, and
// binding it needs no privileges and no network.
func TestProbeReachesSpecificallyBoundListener(t *testing.T) {
	addr := netip.MustParseAddr("127.0.0.2")
	ln, err := net.Listen("tcp", net.JoinHostPort(addr.String(), "0"))
	if err != nil {
		t.Skipf("cannot bind %s: %v", addr, err)
	}
	srv := &httptest.Server{
		Listener: ln,
		Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html><head><title>Bound Service</title></head></html>"))
		})},
	}
	srv.Start()
	defer srv.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	got := newProber().probe(port, probeHosts(addr))
	if !got.HTTP {
		t.Fatal("a service bound to a specific address must still be found")
	}
	if got.Title != "Bound Service" {
		t.Errorf("title = %q, want Bound Service", got.Title)
	}

	// The bug: nothing at all is listening on 127.0.0.1:port, so a probe that
	// only ever tries loopback finds no service and the card never renders.
	if newProber().probe(port, []string{"127.0.0.1"}).HTTP {
		t.Error("127.0.0.1 should not answer for a listener bound elsewhere")
	}
}

// The liveness dot follows the same rule: it must dial where the service
// actually answered, not 127.0.0.1 unconditionally.
func TestAliveDialsThePortsOwnHosts(t *testing.T) {
	addr := netip.MustParseAddr("127.0.0.2")
	ln, err := net.Listen("tcp", net.JoinHostPort(addr.String(), "0"))
	if err != nil {
		t.Skipf("cannot bind %s: %v", addr, err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	ctx := context.Background()
	if live := alive(ctx, map[int][]string{port: probeHosts(addr)}); !live[port] {
		t.Error("a listener bound to a specific address should read as alive")
	}
	if live := alive(ctx, map[int][]string{port: {"127.0.0.1"}}); live[port] {
		t.Error("loopback-only dial should not find a listener bound elsewhere")
	}

	// A port with nobody on it stays false however many hosts we try.
	ln.Close()
	if live := alive(ctx, map[int][]string{port: probeHosts(addr)}); live[port] {
		t.Error("a closed listener should not read as alive")
	}
}

// Tiering is decided by the bind address alone, and a specific routable
// address is public — the probe change must not quietly reclassify anything.
func TestTierForSpecificAddress(t *testing.T) {
	for addr, want := range map[string]Tier{
		"127.0.0.1":    TierPrivate,
		"127.0.0.2":    TierPrivate,
		"::1":          TierPrivate,
		"0.0.0.0":      TierPublic,
		"::":           TierPublic,
		"192.168.1.79": TierPublic,
	} {
		if got := tierFor(netip.MustParseAddr(addr)); got != want {
			t.Errorf("tierFor(%s) = %s, want %s", addr, got, want)
		}
	}
}
