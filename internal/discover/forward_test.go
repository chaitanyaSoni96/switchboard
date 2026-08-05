package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProxyArgs(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantHost  int
		wantIP    string
		wantPort  int
		wantValid bool
	}{
		{
			name: "rootless docker",
			args: []string{"/usr/bin/docker-proxy", "-proto", "tcp",
				"-host-ip", "127.0.0.1", "-host-port", "9000",
				"-container-ip", "172.18.0.3", "-container-port", "9000",
				"-use-listen-fd"},
			wantHost: 9000, wantIP: "172.18.0.3", wantPort: 9000, wantValid: true,
		},
		{
			name: "host and container ports differ",
			args: []string{"docker-proxy", "-proto", "tcp", "-host-ip", "0.0.0.0",
				"-host-port", "8088", "-container-ip", "172.17.0.9", "-container-port", "80"},
			wantHost: 8088, wantIP: "172.17.0.9", wantPort: 80, wantValid: true,
		},
		{
			name: "ipv6 container",
			args: []string{"docker-proxy", "-proto", "tcp", "-host-ip", "::",
				"-host-port", "9000", "-container-ip", "fd00::3", "-container-port", "9000"},
			wantHost: 9000, wantIP: "fd00::3", wantPort: 9000, wantValid: true,
		},
		// Switchboard lists TCP services only, so a UDP rule must not become a
		// mapping that shadows the real TCP one for the same port.
		{
			name: "udp is ignored",
			args: []string{"docker-proxy", "-proto", "udp", "-host-port", "53",
				"-container-ip", "172.17.0.2", "-container-port", "53"},
			wantValid: false,
		},
		{
			name:      "incomplete",
			args:      []string{"docker-proxy", "-proto", "tcp", "-host-port", "9000"},
			wantValid: false,
		},
		{name: "empty", args: nil, wantValid: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, m, ok := parseProxyArgs(tt.args)
			if ok != tt.wantValid {
				t.Fatalf("ok = %v, want %v", ok, tt.wantValid)
			}
			if !ok {
				return
			}
			if host != tt.wantHost || m.containerIP != tt.wantIP || m.containerPort != tt.wantPort {
				t.Errorf("= %d -> %s:%d, want %d -> %s:%d",
					host, m.containerIP, m.containerPort, tt.wantHost, tt.wantIP, tt.wantPort)
			}
		})
	}
}

// Trimmed from a real container's /proc/<pid>/net/fib_trie. The container's own
// address is the link between a docker-proxy rule and the namespace serving it.
const sampleFibTrie = `Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 172.18.0.0/16 2 0 2
        |-- 172.18.0.0
           /16 link UNICAST
Local:
  +-- 0.0.0.0/2 1 0 2
     +-- 127.0.0.0/8 2 0 2
        |-- 127.0.0.0
           /8 host LOCAL
        |-- 127.0.0.1
           /32 host LOCAL
     +-- 172.18.0.0/16 2 0 2
        |-- 172.18.0.3
           /32 host LOCAL
`

func TestReadFibTrieFindsLocalAddrs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fib_trie")
	if err := os.WriteFile(path, []byte(sampleFibTrie), 0o600); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	readFibTrie(path, got)

	if !got["172.18.0.3"] {
		t.Errorf("container address not found: %v", got)
	}
	if !got["127.0.0.1"] {
		t.Errorf("loopback not found: %v", got)
	}
	// A route that is merely reachable from this namespace is not an address
	// *of* it — matching on one would attribute a port to the wrong container.
	if got["172.18.0.0/16"] || got["0.0.0.0"] {
		t.Errorf("non-local route treated as local: %v", got)
	}
}

func TestReadFibTrieMissingFile(t *testing.T) {
	got := map[string]bool{}
	readFibTrie(filepath.Join(t.TempDir(), "nope"), got) // must not panic
	if len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestReadIfInet6(t *testing.T) {
	// Unlike /proc/net/tcp6, if_inet6 stores plain big-endian hex with no
	// per-word byte swapping.
	const sample = "00000000000000000000000000000001 01 80 10 80       lo\n" +
		"fd000000000000000000000000000003 26 40 00 80     eth0\n"
	path := filepath.Join(t.TempDir(), "if_inet6")
	if err := os.WriteFile(path, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}

	got := map[string]bool{}
	readIfInet6(path, got)

	if !got["::1"] {
		t.Errorf("loopback missing: %v", got)
	}
	if !got["fd00::3"] {
		t.Errorf("container v6 address missing: %v", got)
	}
}

func TestIsForwarder(t *testing.T) {
	for _, comm := range []string{"rootlesskit", "docker-proxy", "rootlessport", "pasta.avx2", "slirp4netns"} {
		if !isForwarder(comm) {
			t.Errorf("%q should be recognised as a forwarder", comm)
		}
	}
	for _, comm := range []string{"minio", "caddy", "python3", "", "nginx"} {
		if isForwarder(comm) {
			t.Errorf("%q must not be treated as a forwarder", comm)
		}
	}
}

func TestJoinHostPort(t *testing.T) {
	if got := joinHostPort("172.18.0.3", 9000); got != "172.18.0.3:9000" {
		t.Errorf("got %q", got)
	}
	if got := joinHostPort("fd00::3", 9000); got != "[fd00::3]:9000" {
		t.Errorf("IPv6 must be bracketed, got %q", got)
	}
}

func TestBackendLabelPrefersCmdline(t *testing.T) {
	// Two ports of one container share a comm; only the command line tells them
	// apart, which is the whole reason the label prefers it.
	b := &Backend{Process: "minio", Cmdline: "minio server /data --console-address :9001"}
	if got := b.Label(); got != b.Cmdline {
		t.Errorf("got %q", got)
	}
	if got := (&Backend{Process: "minio"}).Label(); got != "minio" {
		t.Errorf("should fall back to comm, got %q", got)
	}
	if got := (*Backend)(nil).Label(); got != "" {
		t.Errorf("nil backend should render empty, got %q", got)
	}
}

func TestServiceOwnerPrefersBackend(t *testing.T) {
	s := Service{
		Process: "rootlesskit",
		Backend: &Backend{Via: "rootlesskit", Process: "minio", Cmdline: "minio server /data"},
	}
	if got := s.Owner(); got != "minio server /data" {
		t.Errorf("forwarded port should name the container process, got %q", got)
	}

	plain := Service{Process: "caddy"}
	if got := plain.Owner(); got != "caddy" {
		t.Errorf("unforwarded port should name its own process, got %q", got)
	}

	// The mapping is worth reporting even when the container process itself is
	// not readable; the card still gains "via X -> ip:port".
	partial := Service{Process: "rootlesskit", Backend: &Backend{Via: "rootlesskit", Addr: "172.18.0.3:9000"}}
	if got := partial.Owner(); got != "rootlesskit" {
		t.Errorf("got %q", got)
	}
}

func TestBackendCommFallback(t *testing.T) {
	if got := backendComm(&Backend{Process: "minio"}, "rootlesskit"); got != "minio" {
		t.Errorf("got %q", got)
	}
	if got := backendComm(nil, "caddy"); got != "caddy" {
		t.Errorf("got %q", got)
	}
	if got := backendComm(&Backend{}, "caddy"); got != "caddy" {
		t.Errorf("unresolved backend should not blank the name, got %q", got)
	}
}

// A port with no docker-proxy rule must degrade to the host-side view rather
// than inventing a backend — podman's pasta, for one, has no proxy process.
func TestResolveForwardsWithoutProxiesFindsNothing(t *testing.T) {
	got := resolveForwards(map[int]string{8737: "pasta.avx2"})
	if b, ok := got[8737]; ok && b != nil {
		t.Errorf("invented a backend: %+v", b)
	}
}
