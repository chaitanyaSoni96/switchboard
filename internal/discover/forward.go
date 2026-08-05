package discover

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// backendTTL bounds how long a resolved container backend is reused. Container
// restarts move the listener to a new PID and a new address, so this cannot be
// cached as aggressively as the HTTP probe.
const backendTTL = 30 * time.Second

// forwarderComms are processes that hold a listening socket on behalf of
// something else. When one of these owns a port, /proc has told us the truth
// and the truth is useless: the interesting process is on the far side.
var forwarderComms = map[string]bool{
	"rootlesskit":  true,
	"rootlessport": true,
	"docker-proxy": true,
	"slirp4netns":  true,
	"pasta":        true,
	"pasta.avx2":   true,
}

func isForwarder(comm string) bool { return forwarderComms[comm] }

// Backend is the process actually serving a forwarded port, found by following
// the forward into the container's network namespace.
type Backend struct {
	Via     string // the forwarder that held the host socket, e.g. "rootlesskit"
	Addr    string // container-side address, e.g. "172.18.0.3:9000"
	Process string // container-side /proc/<pid>/comm
	Cmdline string
	PID     int
}

// Label is the compact form shown on a card: the command line if we have one,
// since "minio server /data --console-address :9001" distinguishes two ports of
// the same image where the bare comm "minio" would not.
func (b *Backend) Label() string {
	if b == nil {
		return ""
	}
	if b.Cmdline != "" {
		return b.Cmdline
	}
	return b.Process
}

// resolver follows forwarded host ports to the processes behind them.
//
// This is the most expensive thing Switchboard does — it reads a namespace link
// for every process, a routing table per namespace, and then walks /proc/*/fd
// again — so results are cached and only ports that are actually forwarded and
// not already known trigger a pass.
type resolver struct {
	mu    sync.Mutex
	cache map[int]*Backend // host port -> backend (nil means "looked, found nothing")
	at    time.Time
}

func newResolver() *resolver {
	return &resolver{cache: map[int]*Backend{}}
}

// lookup resolves the given host ports, whose values are the comm of the
// forwarder holding each one.
func (r *resolver) lookup(want map[int]string) map[int]*Backend {
	r.mu.Lock()
	defer r.mu.Unlock()

	stale := time.Since(r.at) > backendTTL
	if !stale {
		for port := range want {
			if _, ok := r.cache[port]; !ok {
				stale = true // a forwarded port we have never chased
				break
			}
		}
	}
	if stale {
		r.cache = resolveForwards(want)
		r.at = time.Now()
	}

	out := make(map[int]*Backend, len(want))
	for port := range want {
		if b := r.cache[port]; b != nil {
			out[port] = b
		}
	}
	return out
}

// resolveForwards does the actual chase for every wanted host port.
func resolveForwards(want map[int]string) map[int]*Backend {
	out := make(map[int]*Backend, len(want))
	for port := range want {
		out[port] = nil // remember that we looked, even when we find nothing
	}

	maps := dockerProxyMaps()
	if len(maps) == 0 {
		return out
	}

	namespaces := readableNetns()
	inodeWant := map[uint64]bool{}
	pending := map[int]*Backend{}
	inodeOf := map[int]uint64{} // host port -> container-side socket inode

	for port, via := range want {
		m, ok := maps[port]
		if !ok {
			continue // not a docker-style forward, or the proxy is not visible
		}
		ns := namespaceOwning(namespaces, m.containerIP)
		if ns == nil {
			continue
		}
		inode, ok := listenInodeInNetns(ns.rep, m.containerPort)
		if !ok {
			continue
		}
		pending[port] = &Backend{Via: via, Addr: joinHostPort(m.containerIP, m.containerPort)}
		inodeOf[port] = inode
		inodeWant[inode] = true
	}

	if len(inodeWant) == 0 {
		return out
	}
	// The container-side listener still has to be attributed to a process, and
	// that is the same inode -> PID walk the host side uses; socket inodes are
	// global, so a namespaced socket resolves through /proc/*/fd like any other.
	owners := walkProcFDs(inodeWant)
	for port, b := range pending {
		// Even without a PID the mapping itself is worth reporting: knowing a
		// port forwards to 172.18.0.3:9000 beats knowing only "rootlesskit".
		if info, ok := owners[inodeOf[port]]; ok {
			b.PID, b.Process, b.Cmdline = info.PID, info.Comm, info.Cmdline
		}
		out[port] = b
	}
	return out
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// proxyMap is one host-port -> container-address rule.
type proxyMap struct {
	containerIP   string
	containerPort int
}

// dockerProxyMaps reads the port mappings straight out of the command lines of
// the running docker-proxy processes. Their arguments are the mapping table,
// which means no Docker socket and no API client are needed to read it.
func dockerProxyMaps() map[int]proxyMap {
	out := map[int]proxyMap{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		comm, err := os.ReadFile(filepath.Join("/proc", e.Name(), "comm"))
		if err != nil || strings.TrimSpace(string(comm)) != "docker-proxy" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		hostPort, m, ok := parseProxyArgs(args)
		if !ok {
			continue
		}
		// Docker runs one proxy per host address (v4 and v6); they agree on the
		// mapping, so the first one wins and the rest are duplicates.
		if _, seen := out[hostPort]; !seen {
			out[hostPort] = m
		}
	}
	return out
}

// parseProxyArgs reads a docker-proxy command line, e.g.
//
//	docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 9000
//	             -container-ip 172.18.0.3 -container-port 9000 -use-listen-fd
//
// UDP rules are ignored: Switchboard only ever lists TCP services.
func parseProxyArgs(args []string) (int, proxyMap, bool) {
	var hostPort, containerPort int
	var containerIP, proto string
	for i := 0; i+1 < len(args); i++ {
		switch strings.TrimLeft(args[i], "-") {
		case "proto":
			proto = args[i+1]
		case "host-port":
			hostPort, _ = strconv.Atoi(args[i+1])
		case "container-ip":
			containerIP = args[i+1]
		case "container-port":
			containerPort, _ = strconv.Atoi(args[i+1])
		}
	}
	if proto != "tcp" || hostPort == 0 || containerPort == 0 || containerIP == "" {
		return 0, proxyMap{}, false
	}
	return hostPort, proxyMap{containerIP: containerIP, containerPort: containerPort}, true
}

// netns is one network namespace we can read, with a representative process.
type netns struct {
	rep    int
	locals map[string]bool // filled lazily, nil until first asked
}

// readableNetns groups every process we can inspect by network namespace,
// excluding our own — a forwarded port by definition leads somewhere else.
func readableNetns() map[string]*netns {
	out := map[string]*netns{}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return out
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		id, err := os.Readlink(filepath.Join("/proc", e.Name(), "ns", "net"))
		if err != nil || id == self {
			continue // another user's process, or our own namespace
		}
		if _, seen := out[id]; !seen {
			out[id] = &netns{rep: pid}
		}
	}
	return out
}

// namespaceOwning finds the namespace in which addr is a local address.
//
// This is the link between a docker-proxy rule and the container it points at.
// It cannot be shortcut by using the proxy's own namespace: docker-proxy runs
// in the *network's* namespace, one hop short of the container's.
func namespaceOwning(namespaces map[string]*netns, addr string) *netns {
	for _, ns := range namespaces {
		if ns.locals == nil {
			ns.locals = localAddrs(ns.rep)
		}
		if ns.locals[addr] {
			return ns
		}
	}
	return nil
}

// localAddrs lists the addresses assigned inside a process's network namespace.
func localAddrs(pid int) map[string]bool {
	out := map[string]bool{}
	readFibTrie(filepath.Join("/proc", strconv.Itoa(pid), "net", "fib_trie"), out)
	readIfInet6(filepath.Join("/proc", strconv.Itoa(pid), "net", "if_inet6"), out)
	return out
}

// readFibTrie pulls IPv4 local addresses out of the kernel's routing trie. The
// format is a rendered tree, where an address line is followed by a line
// describing it; the ones marked LOCAL are addresses of this namespace.
func readFibTrie(path string, out map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	var prev string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "LOCAL") {
			if prev != "" {
				out[prev] = true
			}
			continue
		}
		if i := strings.LastIndex(line, "-- "); i >= 0 {
			prev = strings.TrimSpace(line[i+3:])
		}
	}
}

// readIfInet6 lists IPv6 addresses. Unlike /proc/net/tcp6, this file stores the
// address in plain big-endian hex with no per-word byte swapping.
func readIfInet6(path string, out map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || len(fields[0]) != 32 {
			continue
		}
		raw, err := hex.DecodeString(fields[0])
		if err != nil {
			continue
		}
		if addr, ok := netip.AddrFromSlice(raw); ok {
			out[addr.String()] = true
		}
	}
}

// listenInodeInNetns finds a socket listening on port inside a namespace, by
// reading that namespace's own view of /proc/net/tcp. Any bind address counts:
// a container process may listen on the wildcard, on loopback, or on the
// container IP, and all three are the service we are looking for.
func listenInodeInNetns(pid int, port int) (uint64, bool) {
	base := filepath.Join("/proc", strconv.Itoa(pid), "net")
	for _, f := range []struct {
		path string
		size int
	}{
		{filepath.Join(base, "tcp"), 4},
		{filepath.Join(base, "tcp6"), 16},
	} {
		rows, err := parseNetTCP(f.path, f.size)
		if err != nil {
			continue
		}
		for _, l := range rows {
			if l.Port == port {
				return l.Inode, true
			}
		}
	}
	return 0, false
}
