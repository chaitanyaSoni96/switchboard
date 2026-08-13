package discover

import (
	"context"
	"crypto/tls"
	"html"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	probeTimeout = 2 * time.Second
	dialTimeout  = 250 * time.Millisecond
	// titleScanLimit caps how much of a response body we read looking for a
	// <title>. A service that has not emitted one by here does not have one.
	titleScanLimit = 64 << 10
	// unknownProbeTTL applies to listeners we could not attribute to a PID.
	// Without a PID and start time the cache key cannot detect a restart, so
	// those entries expire on time instead.
	unknownProbeTTL = 60 * time.Second
	// failedProbeTTL applies to ports that did not answer as HTTP.
	//
	// A success describes the process and stays true for as long as it runs, but
	// a failure describes one probeTimeout-long window and nothing more. A dev
	// server still building its first bundle — Metro, Vite on a cold cache, a
	// JVM service behind a healthcheck — binds its port long before it can serve
	// it, and is indistinguishable at that moment from a port that will never
	// speak HTTP. Caching that verdict for the life of the process makes such a
	// service invisible until it restarts.
	//
	// Retrying costs one probeTimeout per still-silent port per TTL. They run
	// concurrently, so the cost is one ~2s scan a minute at worst, and only
	// while somebody is actually looking at the page.
	failedProbeTTL = 60 * time.Second
)

// probeKey identifies one process's listening port. Including the start time
// means a restarted service — same port, possibly even the same PID — misses
// the cache and gets re-probed, while a long-running one is probed exactly once.
type probeKey struct {
	Port  int
	PID   int
	Start uint64
}

// probeResult is the durable half of what we know about a port: whether it
// speaks HTTP at all, over which scheme, and what it calls itself. A successful
// result lasts as long as the process does; a failed one expires, see expired.
type probeResult struct {
	HTTP   bool
	Scheme string // "http" or "https" — the one that actually answered
	Title  string
	Server string // the Server: response header, product name only
	Icon   string // href from <link rel="icon">, "" when the page declares none
	At     time.Time
}

// prober performs and caches the HTTP identity probe.
type prober struct {
	mu     sync.Mutex
	cache  map[probeKey]probeResult
	client *http.Client
}

func newProber() *prober {
	return &prober{
		cache: map[probeKey]probeResult{},
		client: &http.Client{
			Timeout: probeTimeout,
			// A redirect is a perfectly good sign of life, and following it
			// could walk us off the box entirely.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: probeTimeout}).DialContext,
				DisableKeepAlives:   true,
				TLSHandshakeTimeout: probeTimeout,
				// Certificate validation is meaningless here and actively
				// harmful: we are identifying a socket on this same machine,
				// send it nothing, and read only its title. Local services use
				// self-signed or internal-CA certs as a matter of course, and
				// verifying would simply make every one of them invisible.
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // identification probe, this box's own addresses only
			},
		},
	}
}

// probeAll resolves every key, probing only those not already cached and
// running those probes concurrently. keys maps each key to the hosts worth
// trying for it, in order — see probeHosts.
func (p *prober) probeAll(keys map[probeKey][]string) map[probeKey]probeResult {
	p.mu.Lock()
	todo := make(map[probeKey][]string)
	out := make(map[probeKey]probeResult, len(keys))
	for k, hosts := range keys {
		if r, ok := p.cache[k]; ok && !expired(k, r) {
			out[k] = r
			continue
		}
		todo[k] = hosts
	}
	p.mu.Unlock()

	if len(todo) > 0 {
		var wg sync.WaitGroup
		var mu sync.Mutex
		for k, hosts := range todo {
			wg.Add(1)
			go func(k probeKey, hosts []string) {
				defer wg.Done()
				r := p.probe(k.Port, hosts)
				mu.Lock()
				out[k] = r
				mu.Unlock()
			}(k, hosts)
		}
		wg.Wait()

		p.mu.Lock()
		for k := range todo {
			p.cache[k] = out[k]
		}
		// Drop entries for listeners that are gone, so a box that churns
		// through short-lived servers does not grow the map without bound.
		for k := range p.cache {
			if _, live := keys[k]; !live {
				delete(p.cache, k)
			}
		}
		p.mu.Unlock()
	}
	return out
}

func expired(k probeKey, r probeResult) bool {
	// A failure is a claim about one probe window rather than about the process,
	// so it always perishes — including when the PID is known.
	if !r.HTTP {
		return time.Since(r.At) > failedProbeTTL
	}
	return k.PID == 0 && time.Since(r.At) > unknownProbeTTL
}

// probe issues GET / against each candidate host until one answers. Any valid
// HTTP response counts, including 4xx and 5xx — an authenticating service that
// says 401 is still a service worth linking to.
//
// Plain HTTP is tried first because that is what almost everything on a box
// speaks, but a TLS listener has to be recognised: probing one over http:// and
// believing the answer would produce a card whose http:// link can never work.
func (p *prober) probe(port int, hosts []string) probeResult {
	for _, host := range hosts {
		r, ok := p.try("http", host, port)
		if ok && !r.tlsMismatch {
			return r.result
		}
		// Either the plaintext request failed outright (Go rejects the TLS
		// alert record as a malformed response) or the server politely told us
		// we were speaking the wrong protocol. Both mean: try TLS.
		if s, ok := p.try("https", host, port); ok {
			return s.result
		}
		if ok {
			res := r.result
			if r.tlsMismatch {
				// The handshake failed but the server already told us what it
				// is, and that testimony beats our failed attempt. Reaching a
				// TLS vhost over loopback-by-IP often cannot work at all — Go
				// omits SNI for IP literals, so a server with no default
				// certificate has nothing to present — while a browser going
				// to the real hostname sends SNI and connects fine. Labelling
				// this http:// would produce a link certain to fail.
				res.Scheme = "https"
				// The 400 is the protocol-mismatch page, not the service.
				res.Title, res.Server = "", ""
			}
			return res
		}
	}
	return probeResult{At: time.Now()}
}

type attempt struct {
	result      probeResult
	tlsMismatch bool
}

func (p *prober) try(scheme, host string, port int) (attempt, bool) {
	url := scheme + "://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/"
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return attempt{}, false
	}
	req.Header.Set("User-Agent", "switchboard/1.0 (+local service discovery)")
	resp, err := p.client.Do(req)
	if err != nil {
		return attempt{}, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, titleScanLimit))
	resp.Body.Close()

	return attempt{
		result: probeResult{
			HTTP:   true,
			Scheme: scheme,
			Title:  parseTitle(body),
			Server: parseServer(resp.Header.Get("Server")),
			// The body is already in hand for the title, so the declared icon
			// costs nothing extra to find.
			Icon: parseIconHref(body),
			At:   time.Now(),
		},
		tlsMismatch: scheme == "http" && isTLSMismatch(resp.StatusCode, body),
	}, true
}

// isTLSMismatch spots the 400 a TLS server returns when handed a plaintext
// request. Go's own http.Server, Caddy and nginx all say so in slightly
// different words, but every one of them names both protocols in the body.
func isTLSMismatch(status int, body []byte) bool {
	if status != http.StatusBadRequest {
		return false
	}
	b := strings.ToLower(string(body))
	return strings.Contains(b, "http request") && strings.Contains(b, "https") ||
		strings.Contains(b, "plain http request") && strings.Contains(b, "https port")
}

// parseServer reduces a Server: header to its product name — "nginx/1.24.0"
// and "Werkzeug/2.0.1 Python/3.9" both become one word worth putting on a card.
func parseServer(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s, _, _ = strings.Cut(s, " ")
	s, _, _ = strings.Cut(s, "/")
	if len(s) > 40 {
		s = s[:40]
	}
	return strings.TrimSpace(s)
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// parseTitle pulls a display name out of an HTML head. Whitespace inside a
// title is collapsed because plenty of templates wrap it across lines.
//
// A page may carry more than one <title>, so this takes the first with content
// rather than simply the first. react-helmet and react-head emit an empty
// placeholder ahead of the real one — Expo's dev server is a stock example —
// and honouring that blank costs the card its name for no reason: the real
// title is a few bytes further into the same body we already read.
func parseTitle(body []byte) string {
	for _, m := range titleRe.FindAllSubmatch(body, -1) {
		title := html.UnescapeString(string(m[1]))
		title = strings.Join(strings.Fields(title), " ")
		if title == "" {
			continue
		}
		if len(title) > 80 {
			title = strings.TrimSpace(title[:80]) + "…"
		}
		return title
	}
	return ""
}

// alive reports whether each port still accepts a TCP connection, trying that
// port's hosts in order — the same ones the identity probe used, since a port
// that only ever answered on one address is only alive at that address. This
// runs on every request, so it is a bare dial with a short timeout — never a
// full HTTP round trip.
func alive(ctx context.Context, targets map[int][]string) map[int]bool {
	out := make(map[int]bool, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	d := net.Dialer{Timeout: dialTimeout}
	for port, hosts := range targets {
		wg.Add(1)
		go func(port int, hosts []string) {
			defer wg.Done()
			var ok bool
			for _, host := range hosts {
				if dialOnce(ctx, d, host, port) {
					ok = true
					break
				}
			}
			mu.Lock()
			out[port] = ok
			mu.Unlock()
		}(port, hosts)
	}
	wg.Wait()
	return out
}

func dialOnce(parent context.Context, d net.Dialer, host string, port int) bool {
	ctx, cancel := context.WithTimeout(parent, dialTimeout)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
