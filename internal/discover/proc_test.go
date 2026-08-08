package discover

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseHexAddr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		size int
		want string
		port int
		ok   bool
	}{
		// IPv4: each 32-bit word is byte-swapped, so 0100007F reads 127.0.0.1.
		{"v4 loopback", "0100007F:1F90", 4, "127.0.0.1", 8080, true},
		{"v4 wildcard", "00000000:0050", 4, "0.0.0.0", 80, true},
		{"v4 lan", "0A01A8C0:23F0", 4, "192.168.1.10", 9200, true},
		{"v4 low port", "0100007F:0016", 4, "127.0.0.1", 22, true},

		// IPv6: four words, each byte-swapped the same way.
		{"v6 wildcard", "00000000000000000000000000000000:1F90", 16, "::", 8080, true},
		{"v6 loopback", "00000000000000000000000001000000:1F90", 16, "::1", 8080, true},
		// 2001:db8::1 — word 0 is 20 01 0d b8 stored byte-swapped as B80D0120,
		// word 3 is 00 00 00 01 stored as 01000000.
		{"v6 global", "B80D0120000000000000000001000000:0050", 16,
			"2001:db8::1", 80, true},

		// A v4-mapped socket in tcp6 must collapse to plain v4 so that tiering
		// and probing agree with the tcp4 view of the same listener.
		{"v4-mapped", "0000000000000000FFFF00000100007F:1F90", 16, "127.0.0.1", 8080, true},

		{"no port separator", "0100007F", 4, "", 0, false},
		{"wrong width", "0100:1F90", 4, "", 0, false},
		{"port zero", "0100007F:0000", 4, "", 0, false},
		{"bad hex", "ZZZZZZZZ:1F90", 4, "", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, port, ok := parseHexAddr(tt.in, tt.size)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if !ok {
				return
			}
			if addr.String() != tt.want || port != tt.port {
				t.Errorf("got %s:%d, want %s:%d", addr, port, tt.want, tt.port)
			}
		})
	}
}

func TestParseHexAddrRoundTripsTier(t *testing.T) {
	// The v4-mapped and plain-v4 spellings of the same loopback listener must
	// land in the same tier, or one socket would show up twice under two
	// different visibilities.
	v4, _, _ := parseHexAddr("0100007F:1F90", 4)
	mapped, _, _ := parseHexAddr("0000000000000000FFFF00000100007F:1F90", 16)
	if tierFor(v4) != tierFor(mapped) {
		t.Fatalf("tier mismatch: v4=%v mapped=%v", tierFor(v4), tierFor(mapped))
	}
	if tierFor(v4) != TierPrivate {
		t.Fatalf("127.0.0.1 should be private, got %v", tierFor(v4))
	}
}

const sampleNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41111 1 0000000000000000 100 0 0 10 0
   1: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41222 1 0000000000000000 100 0 0 10 0
   2: 0100007F:8AE2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 41333 1 0000000000000000 20 0 0 10 0
   3: 0A01A8C0:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 41444 1 0000000000000000 100 0 0 10 0
`

func TestParseNetTCPKeepsOnlyListeners(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tcp")
	if err := os.WriteFile(path, []byte(sampleNetTCP), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := parseNetTCP(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	// Row 2 is st=01 (ESTABLISHED) and must be dropped.
	if len(got) != 3 {
		t.Fatalf("got %d listeners, want 3: %+v", len(got), got)
	}

	want := []listener{
		{Port: 8080, Inode: 41111},
		{Port: 3000, Inode: 41222},
		{Port: 8081, Inode: 41444},
	}
	for i, w := range want {
		if got[i].Port != w.Port || got[i].Inode != w.Inode {
			t.Errorf("row %d = port %d inode %d, want port %d inode %d",
				i, got[i].Port, got[i].Inode, w.Port, w.Inode)
		}
	}
	if got[0].Addr.String() != "127.0.0.1" || got[1].Addr.String() != "0.0.0.0" {
		t.Errorf("addresses = %s, %s", got[0].Addr, got[1].Addr)
	}
}

func TestParseNetTCPMissingFile(t *testing.T) {
	if _, err := parseNetTCP(filepath.Join(t.TempDir(), "nope"), 4); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestTierFor(t *testing.T) {
	tests := []struct {
		addr string
		want Tier
	}{
		{"127.0.0.1", TierPrivate},
		{"127.0.0.53", TierPrivate}, // all of 127/8, not just .0.1
		{"::1", TierPrivate},
		{"0.0.0.0", TierPublic},
		{"::", TierPublic},
		{"192.168.1.10", TierPublic},
		{"10.0.0.5", TierPublic},
		{"2001:db8::1", TierPublic},
	}
	for _, tt := range tests {
		if got := tierFor(netip.MustParseAddr(tt.addr)); got != tt.want {
			t.Errorf("tierFor(%s) = %v, want %v", tt.addr, got, tt.want)
		}
	}
}

func TestSocketInode(t *testing.T) {
	tests := []struct {
		in    string
		want  uint64
		match bool
	}{
		{"socket:[41111]", 41111, true},
		{"socket:[1]", 1, true},
		{"pipe:[41111]", 0, false},
		{"/dev/null", 0, false},
		{"socket:[abc]", 0, false},
		{"socket:[41111", 0, false},
	}
	for _, tt := range tests {
		got, ok := socketInode(tt.in)
		if ok != tt.match || (ok && got != tt.want) {
			t.Errorf("socketInode(%q) = %d,%v; want %d,%v", tt.in, got, ok, tt.want, tt.match)
		}
	}
}

func TestParseStatStart(t *testing.T) {
	// Field 2 is the comm in parens and may contain spaces and parens of its
	// own, so the fields after it can only be found from the *last* ')'.
	tests := []struct {
		name string
		stat string
		want uint64
		ok   bool
	}{
		{
			name: "plain comm",
			stat: "1234 (nginx) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 1000 0",
			want: 987654,
			ok:   true,
		},
		{
			name: "comm with spaces and parens",
			stat: "1234 (my (odd) app) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 424242 1000 0",
			want: 424242,
			ok:   true,
		},
		{"truncated", "1234 (x) S 1 2 3", 0, false},
		{"no parens", "garbage", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseStatStart(tt.stat)
			if ok != tt.ok || got != tt.want {
				t.Errorf("= %d,%v; want %d,%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestParseTitle(t *testing.T) {
	tests := []struct{ in, want string }{
		{`<html><head><title>Grafana</title>`, "Grafana"},
		{`<TITLE>Shouty</TITLE>`, "Shouty"},
		{"<title>\n  wrapped\n  across lines\n</title>", "wrapped across lines"},
		{`<title lang="en">With attrs</title>`, "With attrs"},
		{`<title>A &amp; B &lt;3</title>`, "A & B <3"},
		{`<html><body>no title here</body></html>`, ""},
		{`<title></title>`, ""},
	}
	for _, tt := range tests {
		if got := parseTitle([]byte(tt.in)); got != tt.want {
			t.Errorf("parseTitle(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseTitleTruncates(t *testing.T) {
	got := parseTitle([]byte("<title>" + strings.Repeat("x", 200) + "</title>"))
	if len([]rune(got)) > 81 {
		t.Fatalf("title not truncated: %d runes", len([]rune(got)))
	}
}

func TestDisplayNameFallsBack(t *testing.T) {
	tests := []struct {
		name                string
		title, server, comm string
		want                string
	}{
		{"title wins", "Grafana", "nginx", "alloy", "Grafana"},
		// The Server header describes the service; comm often describes only
		// the container port-forwarder holding the socket.
		{"server beats comm", "", "MinIO", "rootlesskit", "MinIO"},
		{"comm when no header", "", "", "alloy", "alloy"},
		{"port is the last resort", "", "", "", "port 3000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := displayName(tt.title, tt.server, tt.comm, 3000); got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseServer(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Caddy", "Caddy"},
		{"nginx/1.24.0", "nginx"},
		{"Werkzeug/2.0.1 Python/3.9", "Werkzeug"},
		{"uvicorn", "uvicorn"},
		{"  gunicorn/20.1.0  ", "gunicorn"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := parseServer(tt.in); got != tt.want {
			t.Errorf("parseServer(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsTLSMismatch(t *testing.T) {
	// The exact wording differs per server, so the check keys on both protocol
	// names appearing together in a 400.
	caddy := []byte("Client sent an HTTP request to an HTTPS server.")
	nginx := []byte("<html><body>400 The plain HTTP request was sent to HTTPS port</body></html>")

	if !isTLSMismatch(400, caddy) {
		t.Error("should detect the Go/Caddy wording")
	}
	if !isTLSMismatch(400, nginx) {
		t.Error("should detect the nginx wording")
	}
	// A genuine 400 from a plain HTTP service must not send us down the TLS
	// path and mislabel a working http:// port.
	if isTLSMismatch(400, []byte("bad request: missing parameter")) {
		t.Error("false positive on an ordinary 400")
	}
	if isTLSMismatch(200, caddy) {
		t.Error("only a 400 should count")
	}
}

// A TLS port whose handshake we cannot complete must still be labelled https.
// Go omits SNI for IP literals, so a vhost server with no default certificate
// aborts the handshake even though the port is plainly TLS — and an http://
// card link would then be guaranteed to fail.
func TestTLSMismatchWinsOverFailedHandshake(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Client sent an HTTP request to an HTTPS server.\n"))
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	// The plaintext attempt reports a mismatch; the TLS attempt against this
	// plain HTTP server cannot succeed. The result must still say https.
	got := newProber().probe(port, []string{host})
	if !got.HTTP {
		t.Fatal("port should still count as an HTTP service")
	}
	if got.Scheme != "https" {
		t.Errorf("scheme = %q, want https", got.Scheme)
	}
	if got.Title != "" || got.Server != "" {
		t.Errorf("mismatch page must not supply a name: title=%q server=%q", got.Title, got.Server)
	}
}

// The ordinary case must not regress into the TLS path.
func TestPlainHTTPStaysHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "testsrv/1.2")
		_, _ = w.Write([]byte("<html><head><title>Plain Service</title></head></html>"))
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	port, _ := strconv.Atoi(portStr)

	got := newProber().probe(port, []string{host})
	if got.Scheme != "http" {
		t.Errorf("scheme = %q, want http", got.Scheme)
	}
	if got.Title != "Plain Service" {
		t.Errorf("title = %q", got.Title)
	}
	if got.Server != "testsrv" {
		t.Errorf("server = %q, want testsrv", got.Server)
	}
}

// A port that listens but does not speak HTTP at all is not a service.
func TestNonHTTPPortIsDropped(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("+OK not http\r\n"))
			c.Close()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	if got := newProber().probe(port, []string{"127.0.0.1"}); got.HTTP {
		t.Errorf("non-HTTP listener was accepted: %+v", got)
	}
}

func TestLoopbackHostsPrefersMatchingFamily(t *testing.T) {
	v4, _, _ := parseHexAddr("0100007F:1F90", 4)
	v6, _, _ := parseHexAddr("00000000000000000000000001000000:1F90", 16)
	if got := loopbackHosts(v4); got[0] != "127.0.0.1" {
		t.Errorf("v4 should probe 127.0.0.1 first, got %v", got)
	}
	if got := loopbackHosts(v6); got[0] != "::1" {
		t.Errorf("v6 should probe ::1 first, got %v", got)
	}
}

// A failed probe must expire even when the owning process is known. Metro and
// friends bind their port well before they can serve it, so a failure cached
// for the life of the process hides the service until it restarts.
func TestFailedProbeExpiresWithKnownPID(t *testing.T) {
	k := probeKey{Port: 8081, PID: 1234, Start: 99}

	fresh := probeResult{HTTP: false, At: time.Now()}
	if expired(k, fresh) {
		t.Error("a failure younger than failedProbeTTL should still be cached")
	}

	stale := probeResult{HTTP: false, At: time.Now().Add(-2 * failedProbeTTL)}
	if !expired(k, stale) {
		t.Error("a failure older than failedProbeTTL should expire and be re-probed")
	}
}

// A success is a statement about the process, and the key pins it to one PID
// and start time, so it stays valid for as long as that process runs.
func TestSuccessfulProbeNeverExpiresWithKnownPID(t *testing.T) {
	k := probeKey{Port: 3000, PID: 1234, Start: 99}
	old := probeResult{HTTP: true, At: time.Now().Add(-24 * time.Hour)}
	if expired(k, old) {
		t.Error("a successful probe for a live PID should never expire")
	}
}

// Without a PID the key cannot detect a restart, so even a success expires.
func TestSuccessfulProbeExpiresWhenPIDUnknown(t *testing.T) {
	k := probeKey{Port: 3000, PID: 0}
	if expired(k, probeResult{HTTP: true, At: time.Now()}) {
		t.Error("a fresh unattributed success should still be cached")
	}
	stale := probeResult{HTTP: true, At: time.Now().Add(-2 * unknownProbeTTL)}
	if !expired(k, stale) {
		t.Error("an unattributed success older than unknownProbeTTL should expire")
	}
}
