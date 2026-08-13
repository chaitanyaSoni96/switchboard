package discover

import (
	"context"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Tier is how exposed a listener is, judged purely by what address it bound to.
// The zero value is TierPrivate so an unclassifiable listener errs toward hidden.
type Tier int

const (
	TierPrivate Tier = iota // loopback only: 127.0.0.0/8, ::1
	TierPublic              // 0.0.0.0, ::, or a specific routable address
)

func (t Tier) String() string {
	if t == TierPublic {
		return "public"
	}
	return "private"
}

// Service is one discovered HTTP listener, as shown on a card.
type Service struct {
	Name    string // see displayName for the fallback chain
	Port    int
	Scheme  string // "http" or "https" — whichever the port actually answered
	Process string // /proc/<pid>/comm
	Server  string // Server: response header, product name only
	Cmdline string
	Bind    string // the most public address this port is bound to
	Tier    Tier
	PID     int // 0 when the socket could not be attributed
	Alive   bool
	// Icon is the href the page declared for its favicon, relative to the
	// service root. Empty means it declared none; /favicon.ico is tried anyway.
	Icon string
	// Backend is set when the listening socket belongs to a port forwarder and
	// the real process behind it could be found. See forward.go.
	Backend *Backend
}

// LinkAddr is the address a link to this service must use, or "" when the
// viewer's own host will do.
//
// A wildcard listener answers on every address, including whichever one the
// visitor typed, so their host is the better link — box.local beats a raw IP.
// A listener bound to one address answers only there, so that address is the
// only link that can work: a card for 192.168.1.79:8443 must say so even to a
// viewer who reached Switchboard over loopback.
func (s Service) LinkAddr() string {
	a, err := netip.ParseAddr(s.Bind)
	if err != nil || a.IsUnspecified() {
		return ""
	}
	return a.String()
}

// Owner is the process worth showing: the container-side one when this port is
// a forward, since "rootlesskit" names the plumbing rather than the service.
func (s Service) Owner() string {
	if label := s.Backend.Label(); label != "" {
		return label
	}
	return s.Process
}

// Snapshot is one complete view of the machine.
type Snapshot struct {
	Services  []Service
	ScannedAt time.Time
}

// Public and Private split a snapshot into the two rendered sections.
func (s Snapshot) Public() []Service  { return s.filter(TierPublic) }
func (s Snapshot) Private() []Service { return s.filter(TierPrivate) }

func (s Snapshot) filter(t Tier) []Service {
	var out []Service
	for _, svc := range s.Services {
		if svc.Tier == t {
			out = append(out, svc)
		}
	}
	return out
}

// Registry discovers services on demand and caches the expensive parts.
//
// There is no background goroutine: an idle Switchboard does no work at all.
// Each layer is cached according to what it costs and how fast it changes —
// see Scan.
type Registry struct {
	selfPID  int
	selfPort int
	attr     *attributor
	prob     *prober
	fwd      *resolver
	icons    *iconCache

	mu       sync.Mutex
	snap     *Snapshot
	scanning bool
	done     chan struct{} // closed when the in-flight scan publishes
}

// New returns a Registry that will exclude Switchboard's own PID and the port
// it listens on from every scan.
func New(selfPort int) *Registry {
	prob := newProber()
	return &Registry{
		icons:    newIconCache(prob.client),
		selfPID:  os.Getpid(),
		selfPort: selfPort,
		attr:     newAttributor(),
		prob:     prob,
		fwd:      newResolver(),
	}
}

// Scan returns the current view of the machine.
//
// If another Scan is already running, this one returns the previous snapshot
// immediately and lets the in-flight scan serve as the refresh — concurrent
// requests never queue behind each other. Only the very first callers, with no
// snapshot to fall back on, wait.
func (r *Registry) Scan(ctx context.Context) Snapshot {
	r.mu.Lock()
	if r.scanning {
		done, stale := r.done, r.snap
		r.mu.Unlock()
		if stale != nil {
			return *stale
		}
		select {
		case <-done:
		case <-ctx.Done():
			return Snapshot{ScannedAt: time.Now()}
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.snap != nil {
			return *r.snap
		}
		return Snapshot{ScannedAt: time.Now()}
	}
	r.scanning = true
	r.done = make(chan struct{})
	done := r.done
	r.mu.Unlock()

	snap := r.scan(ctx)

	r.mu.Lock()
	r.snap = &snap
	r.scanning = false
	r.mu.Unlock()
	close(done)
	return snap
}

// portAgg collects every listening socket sharing one port. A port can be bound
// more than once (SO_REUSEPORT, or separate v4 and v6 sockets); the most public
// bind decides the tier.
type portAgg struct {
	addr   netip.Addr
	tier   Tier
	inodes []uint64
}

func (r *Registry) scan(ctx context.Context) Snapshot {
	now := time.Now()

	rows, err := listeners()
	if err != nil {
		// /proc/net/tcp is unreadable — there is nothing to report, but the
		// page should still render rather than 500.
		return Snapshot{ScannedAt: now}
	}

	byPort := map[int]*portAgg{}
	want := map[uint64]bool{}
	for _, l := range rows {
		if l.Port == r.selfPort {
			continue
		}
		t := tierFor(l.Addr)
		a, ok := byPort[l.Port]
		if !ok {
			a = &portAgg{addr: l.Addr, tier: t}
			byPort[l.Port] = a
		} else if t > a.tier {
			a.addr, a.tier = l.Addr, t
		}
		a.inodes = append(a.inodes, l.Inode)
		want[l.Inode] = true
	}

	owners := r.attr.lookup(want)

	keys := make(map[probeKey][]string, len(byPort))
	meta := make(map[probeKey]*portAgg, len(byPort))
	info := make(map[probeKey]procInfo, len(byPort))
	for port, a := range byPort {
		var owner procInfo
		for _, inode := range a.inodes {
			if p, ok := owners[inode]; ok {
				owner = p
				break
			}
		}
		if owner.PID == r.selfPID && owner.PID != 0 {
			continue // our own listener, on some port other than selfPort
		}
		k := probeKey{Port: port, PID: owner.PID, Start: owner.Start}
		keys[k] = probeHosts(a.addr)
		meta[k] = a
		info[k] = owner
	}

	probes := r.prob.probeAll(keys)

	// The liveness dial reuses each port's probe hosts: a port that only
	// answered on one address is only alive at that same address.
	targets := make(map[int][]string, len(keys))
	forwarded := map[int]string{}
	for k, hosts := range keys {
		if !probes[k].HTTP {
			continue
		}
		targets[k.Port] = hosts
		// Only chase ports whose owner is plumbing. Everything else already
		// names itself, and the chase is the most expensive thing we do.
		if comm := info[k].Comm; isForwarder(comm) {
			forwarded[k.Port] = comm
		}
	}
	live := alive(ctx, targets)
	backends := r.fwd.lookup(forwarded)

	services := make([]Service, 0, len(targets))
	for k, res := range probes {
		if !res.HTTP {
			continue // listening, but not an HTTP service
		}
		a, owner := meta[k], info[k]
		backend := backends[k.Port]
		services = append(services, Service{
			Name:    displayName(res.Title, res.Server, backendComm(backend, owner.Comm), k.Port),
			Port:    k.Port,
			Scheme:  res.Scheme,
			Process: orUnknown(owner.Comm),
			Server:  res.Server,
			Cmdline: owner.Cmdline,
			Bind:    a.addr.String(),
			Tier:    a.tier,
			PID:     owner.PID,
			Alive:   live[k.Port],
			Icon:    res.Icon,
			Backend: backend,
		})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Port < services[j].Port })

	return Snapshot{Services: services, ScannedAt: now}
}

// tierFor classifies a bind address. Anything reachable from off the box —
// the wildcard addresses included — is public.
func tierFor(a netip.Addr) Tier {
	if a.IsLoopback() {
		return TierPrivate
	}
	return TierPublic
}

// probeHosts orders the addresses worth trying for a listener bound to a.
//
// A wildcard socket answers anywhere, so it is probed over loopback and never
// over the network. But a socket bound to one specific address answers only
// there: 192.168.1.79:8443 refuses a connection to 127.0.0.1:8443, and so does
// 127.0.0.2:8080 — the second is loopback and still not 127.0.0.1. Probing
// only 127.0.0.1 makes every such service invisible, so the bound address
// leads. That connection stays on the box: the kernel routes a local address
// through lo regardless of which interface owns it.
//
// Loopback follows as a fallback, matching family first, since a port can hold
// several sockets and the aggregate keeps only the most public of them — a
// service also bound to loopback is still reachable when its public address is
// not. A socket bound to ::1 never answers on 127.0.0.1, and vice versa.
func probeHosts(a netip.Addr) []string {
	a = a.Unmap() // ::ffff:127.0.0.1 is a v4 listener; dial it as one
	loopback := []string{"127.0.0.1", "::1"}
	if a.Is6() {
		loopback = []string{"::1", "127.0.0.1"}
	}
	if !a.IsValid() || a.IsUnspecified() {
		return loopback
	}
	hosts := []string{a.String()}
	for _, h := range loopback {
		if h != hosts[0] {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// displayName picks the most service-like label available.
//
// The Server header beats the process name deliberately. A header describes the
// thing answering the request; /proc/<pid>/comm describes whichever process
// happens to hold the socket, and on a box running containers that is usually a
// port-forwarder — "MinIO" is worth more than "rootlesskit", and "Caddy" is
// worth more than nothing at all when the process belongs to another user.
func displayName(title, server, comm string, port int) string {
	switch {
	case title != "":
		return title
	case server != "":
		return server
	case comm != "":
		return comm
	default:
		return "port " + strconv.Itoa(port)
	}
}

// backendComm prefers the container-side process name over the forwarder's,
// which is the whole point of chasing the forward in the first place.
func backendComm(b *Backend, comm string) string {
	if b != nil && b.Process != "" {
		return b.Process
	}
	return comm
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
