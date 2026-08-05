package web

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// isLocal decides which tiers a request is allowed to see.
//
// The default source of truth is the kernel-supplied peer address, which a
// client cannot forge. X-Forwarded-For is consulted only when the operator has
// opted in with --trust-forwarded, because any client can set that header — an
// unguarded reverse-proxy header would let a LAN peer ask to be treated as
// local and be believed.
func (s *Server) isLocal(r *http.Request) bool {
	if s.trustForwarded {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Left-most entry is the original client; the rest are proxies.
			first, _, _ := strings.Cut(xff, ",")
			return isLoopbackHost(strings.TrimSpace(first))
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return isLoopbackHost(host)
}

func isLoopbackHost(h string) bool {
	h = strings.Trim(h, "[]")
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i] // drop the IPv6 zone
	}
	addr, err := netip.ParseAddr(h)
	if err != nil {
		return false // a hostname, not an address: assume remote
	}
	return addr.Unmap().IsLoopback()
}

// linkHost returns the bare host the request came in on, which is what card
// links are built from. Using the request host rather than a fixed loopback
// address is what keeps LAN links working: a visitor on box.local:8090 gets
// links to box.local:3000, not to their own 127.0.0.1:3000.
func linkHost(r *http.Request) string {
	if r.Host == "" {
		return "localhost"
	}
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host
	}
	return strings.Trim(r.Host, "[]")
}
