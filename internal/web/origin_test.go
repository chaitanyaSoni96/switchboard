package web

import (
	"net/http"
	"net/http/httptest"

	"switchboard/internal/discover"
	"testing"
)

func req(remote, xff, host string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	r.Host = host
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestIsLocalUsesPeerAddressByDefault(t *testing.T) {
	s := &Server{}
	tests := []struct {
		name   string
		remote string
		want   bool
	}{
		{"v4 loopback", "127.0.0.1:51234", true},
		{"v4 loopback elsewhere in 127/8", "127.0.0.53:51234", true},
		{"v6 loopback", "[::1]:51234", true},
		{"v6 loopback with zone", "[::1%lo]:51234", true},
		{"v4-mapped loopback", "[::ffff:127.0.0.1]:51234", true},
		{"lan peer", "192.168.1.50:51234", false},
		{"public peer", "203.0.113.9:51234", false},
		{"v6 lan peer", "[fd00::5]:51234", false},
		{"unparseable", "garbage", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.isLocal(req(tt.remote, "", "host:8090")); got != tt.want {
				t.Errorf("isLocal(%s) = %v, want %v", tt.remote, got, tt.want)
			}
		})
	}
}

func TestForwardedHeaderIgnoredUnlessTrusted(t *testing.T) {
	// A LAN client can set X-Forwarded-For freely. Without the flag it must not
	// be able to talk its way into the private tier.
	s := &Server{trustForwarded: false}
	if s.isLocal(req("192.168.1.50:4444", "127.0.0.1", "host:8090")) {
		t.Fatal("spoofed X-Forwarded-For was believed with the flag off")
	}
	// Nor should it be able to hide a loopback caller, which would only ever
	// remove information the caller is entitled to.
	if !s.isLocal(req("127.0.0.1:4444", "8.8.8.8", "host:8090")) {
		t.Fatal("loopback peer was misclassified because of a header")
	}
}

func TestForwardedHeaderHonouredWhenTrusted(t *testing.T) {
	s := &Server{trustForwarded: true}
	// Left-most entry is the original client; anything after it is a proxy hop.
	if !s.isLocal(req("10.0.0.2:4444", "127.0.0.1, 10.0.0.2", "host:8090")) {
		t.Error("tunnelled loopback client should be local")
	}
	if s.isLocal(req("10.0.0.2:4444", "192.168.1.50, 10.0.0.2", "host:8090")) {
		t.Error("tunnelled LAN client should not be local")
	}
	// With the flag on but no header at all, fall back to the peer address.
	if !s.isLocal(req("127.0.0.1:4444", "", "host:8090")) {
		t.Error("no header should fall back to the peer address")
	}
	if s.isLocal(req("192.168.1.50:4444", "", "host:8090")) {
		t.Error("no header should fall back to the peer address")
	}
}

func TestLinkHost(t *testing.T) {
	// Cards link to the host the visitor actually used, so a LAN visitor is not
	// sent to their own loopback.
	tests := []struct{ host, want string }{
		{"box.local:8090", "box.local"},
		{"192.168.1.10:8090", "192.168.1.10"},
		{"[fd00::5]:8090", "fd00::5"},
		{"box.local", "box.local"},
		{"", "localhost"},
	}
	for _, tt := range tests {
		if got := linkHost(req("127.0.0.1:1", "", tt.host)); got != tt.want {
			t.Errorf("linkHost(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

// The icon route must not become an enumeration oracle. If a private port
// answered differently from an unused one, a LAN peer could map the private
// tier by probing /icon/<port> — exactly what the tier split withholds.
func TestIconVisibilityMatchesTier(t *testing.T) {
	snap := discover.Snapshot{Services: []discover.Service{
		{Port: 3000, Tier: discover.TierPublic},
		{Port: 12345, Tier: discover.TierPrivate},
	}}

	tests := []struct {
		name  string
		port  int
		local bool
		want  bool
	}{
		{"public port, local caller", 3000, true, true},
		{"public port, remote caller", 3000, false, true},
		{"private port, local caller", 12345, true, true},
		{"private port, remote caller", 12345, false, false},
		{"unused port, local caller", 55555, true, false},
		{"unused port, remote caller", 55555, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := iconVisible(snap, tt.port, tt.local); got != tt.want {
				t.Errorf("= %v, want %v", got, tt.want)
			}
		})
	}

	// The point stated directly: to a remote caller, a private port and a port
	// that does not exist must be the same answer.
	if iconVisible(snap, 12345, false) != iconVisible(snap, 55555, false) {
		t.Fatal("private port is distinguishable from an unused one")
	}
}
