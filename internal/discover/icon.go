package discover

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// iconLimit caps a favicon download. Real favicons are a few kilobytes; a
	// service answering with something much larger is not offering an icon.
	iconLimit = 128 << 10
	iconTTL   = 30 * time.Minute
)

// icon is a fetched favicon, ready to serve.
type icon struct {
	Data []byte
	Type string
	At   time.Time
}

// iconCache holds fetched favicons keyed by port. Icons are looked up lazily —
// only when a browser actually asks for one — so a page nobody opens costs
// nothing, and a service without an icon is asked once and then remembered as
// having none.
type iconCache struct {
	mu      sync.Mutex
	entries map[int]*icon // nil value means "asked, there is no icon"
	client  *http.Client
}

func newIconCache(client *http.Client) *iconCache {
	return &iconCache{entries: map[int]*icon{}, client: client}
}

// Icon returns the favicon for a discovered port.
//
// The href comes from the page's own <link rel="icon">, captured during the
// identity probe, so the usual case costs no extra request to find. Services
// that declare nothing get the conventional /favicon.ico.
func (r *Registry) Icon(ctx context.Context, port int) (data []byte, contentType string, ok bool) {
	r.mu.Lock()
	snap := r.snap
	r.mu.Unlock()
	if snap == nil {
		return nil, "", false
	}

	var svc *Service
	for i := range snap.Services {
		if snap.Services[i].Port == port {
			svc = &snap.Services[i]
			break
		}
	}
	if svc == nil {
		return nil, "", false
	}

	r.icons.mu.Lock()
	if got, seen := r.icons.entries[port]; seen && got != nil && time.Since(got.At) < iconTTL {
		r.icons.mu.Unlock()
		return got.Data, got.Type, true
	} else if seen && got == nil {
		r.icons.mu.Unlock()
		return nil, "", false // known to have no usable icon
	}
	r.icons.mu.Unlock()

	got := r.icons.fetch(ctx, *svc)

	r.icons.mu.Lock()
	r.icons.entries[port] = got
	r.icons.mu.Unlock()

	if got == nil {
		return nil, "", false
	}
	return got.Data, got.Type, true
}

// fetch retrieves and validates one service's icon, trying the declared href
// first and the conventional path second.
func (c *iconCache) fetch(ctx context.Context, svc Service) *icon {
	scheme := svc.Scheme
	if scheme == "" {
		scheme = "http"
	}
	base := &url.URL{Scheme: scheme, Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(svc.Port)), Path: "/"}

	candidates := make([]string, 0, 2)
	if svc.Icon != "" {
		// An inline data: URI is the icon — there is nothing to fetch. Both
		// Scratchpad and Switchboard declare their marks this way.
		if strings.HasPrefix(strings.ToLower(svc.Icon), "data:") {
			if data, ctype, ok := decodeDataURI(svc.Icon); ok {
				return &icon{Data: data, Type: ctype, At: time.Now()}
			}
		} else if ref, err := url.Parse(svc.Icon); err == nil {
			// Resolve relative hrefs, but pin the host: a page may point its
			// icon at a CDN, and Switchboard has no business fetching from the
			// internet to decorate a card.
			abs := base.ResolveReference(ref)
			abs.Scheme, abs.Host = base.Scheme, base.Host
			candidates = append(candidates, abs.String())
		}
	}
	candidates = append(candidates, base.ResolveReference(&url.URL{Path: "/favicon.ico"}).String())

	for _, u := range candidates {
		if got := c.get(ctx, u); got != nil {
			return got
		}
	}
	return nil
}

func (c *iconCache) get(ctx context.Context, rawURL string) *icon {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "switchboard/1.0 (+local service discovery)")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, iconLimit))
	if err != nil || len(data) == 0 {
		return nil
	}

	ct := imageType(resp.Header.Get("Content-Type"), data)
	if ct == "" {
		// Plenty of servers answer /favicon.ico with a 200 and an HTML error
		// page. Serving that as an image would put a broken icon on the card.
		return nil
	}
	return &icon{Data: data, Type: ct, At: time.Now()}
}

// imageType decides whether a response really is an image, preferring the
// declared type but falling back to content sniffing when it is missing or
// generic. It returns "" for anything that is not an image.
func imageType(declared string, data []byte) string {
	base, _, _ := strings.Cut(declared, ";")
	base = strings.TrimSpace(strings.ToLower(base))

	switch {
	case strings.HasPrefix(base, "image/"):
		return base
	// .ico is served under a pile of legacy and vendor-specific types.
	case base == "application/ico", base == "application/x-ico",
		base == "application/octet-stream", base == "":
		// fall through to sniffing
	default:
		return ""
	}

	if bytes.HasPrefix(data, []byte{0x00, 0x00, 0x01, 0x00}) {
		return "image/x-icon" // ICO has no magic number http.DetectContentType knows
	}
	if sniffed := http.DetectContentType(data); strings.HasPrefix(sniffed, "image/") {
		return sniffed
	}
	return ""
}

// decodeDataURI unpacks a "data:image/...;base64,..." or percent-encoded
// "data:image/svg+xml,..." href into bytes we can serve directly.
func decodeDataURI(s string) ([]byte, string, bool) {
	rest, ok := strings.CutPrefix(s, "data:")
	if !ok {
		rest, ok = strings.CutPrefix(s, "DATA:")
		if !ok {
			return nil, "", false
		}
	}
	meta, payload, ok := strings.Cut(rest, ",")
	if !ok {
		return nil, "", false
	}

	isBase64 := false
	ctype := meta
	if head, tail, found := strings.Cut(meta, ";"); found {
		ctype = head
		isBase64 = strings.Contains(strings.ToLower(tail), "base64")
	}
	ctype = strings.TrimSpace(strings.ToLower(ctype))
	if !strings.HasPrefix(ctype, "image/") {
		return nil, "", false
	}

	var data []byte
	if isBase64 {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
		if err != nil {
			return nil, "", false
		}
		data = decoded
	} else {
		// PathUnescape, not QueryUnescape: '+' is a literal plus in an SVG
		// path, not a space.
		decoded, err := url.PathUnescape(payload)
		if err != nil {
			return nil, "", false
		}
		data = []byte(decoded)
	}
	if len(data) == 0 || len(data) > iconLimit {
		return nil, "", false
	}
	return data, ctype, true
}

var linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
var attrRe = regexp.MustCompile(`(?is)([a-z-]+)\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)

// parseIconHref finds a page's declared favicon.
//
// Ordinary rel="icon" wins over apple-touch-icon, which is usually a large
// launcher image rather than the small mark a card wants.
func parseIconHref(body []byte) string {
	var fallback string
	for _, tag := range linkTagRe.FindAll(body, 40) {
		var rel, href string
		for _, m := range attrRe.FindAllSubmatch(tag, -1) {
			name := strings.ToLower(string(m[1]))
			value := strings.Trim(string(m[2]), `"'`)
			switch name {
			case "rel":
				rel = strings.ToLower(value)
			case "href":
				href = strings.TrimSpace(value)
			}
		}
		if href == "" || !strings.Contains(rel, "icon") {
			continue
		}
		if strings.Contains(rel, "apple-touch") || strings.Contains(rel, "mask-icon") {
			if fallback == "" {
				fallback = href
			}
			continue
		}
		return href
	}
	return fallback
}
