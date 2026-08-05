// Package web serves the single Switchboard page and the htmx fragment that
// refreshes it.
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"strconv"

	"switchboard/internal/discover"
	"switchboard/internal/web/templates"
)

// Listed file by file rather than as a directory so that input.css — the
// Tailwind source that style.css is built from — stays out of the binary.
//
//go:embed assets/style.css assets/htmx.min.js assets/search.js assets/refresh.js
var assetFS embed.FS

// Server holds the discovery registry and the one policy decision the web layer
// makes: whether to believe X-Forwarded-For.
type Server struct {
	reg            *discover.Registry
	trustForwarded bool
	hostname       string
}

func NewServer(reg *discover.Registry, trustForwarded bool) http.Handler {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "this machine"
	}
	s := &Server{reg: reg, trustForwarded: trustForwarded, hostname: host}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handlePage)
	mux.HandleFunc("GET /partials/services", s.handleServices)
	mux.HandleFunc("GET /icon/{port}", s.handleIcon)

	assets, err := fs.Sub(assetFS, "assets")
	if err != nil {
		panic(err)
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(assets)))
	return mux
}

func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	noStore(w)
	view := templates.PageView{Hostname: s.hostname, Services: s.servicesView(r)}
	_ = templates.Page(view).Render(r.Context(), w)
}

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	noStore(w)
	_ = templates.Services(s.servicesView(r)).Render(r.Context(), w)
}

// handleIcon serves a discovered service's favicon, which cards use as a
// watermark. Switchboard fetches it rather than pointing the browser straight
// at the service so that the icons keep working when Switchboard itself is
// behind an HTTPS tunnel, where http:// subresources would be blocked as mixed
// content even though the card links themselves still work.
//
// The tier gate applies here too, and it has to: an ungated icon route would
// answer 200 for a private port and 404 for an unused one, which is an
// enumeration oracle for exactly the services the tier split exists to withhold.
// Every rejection below returns the same bare 404.
func (s *Server) handleIcon(w http.ResponseWriter, r *http.Request) {
	port, err := strconv.Atoi(r.PathValue("port"))
	if err != nil || port < 1 || port > 65535 {
		http.NotFound(w, r)
		return
	}

	snap := s.reg.Scan(r.Context())
	if !iconVisible(snap, port, s.isLocal(r)) {
		http.NotFound(w, r)
		return
	}

	data, contentType, ok := s.reg.Icon(r.Context(), port)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", contentType)
	// These bytes came from another process on this box, and an SVG favicon is
	// a document, not just a picture: navigating straight to /icon/<port> would
	// render it same-origin with Switchboard. The sandbox directive stops any
	// script inside from running, and nosniff keeps the browser from deciding
	// it is really something else.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Icons are decorative and change about as often as the service does. Let
	// the browser keep them so the 15s poll does not re-fetch every one.
	w.Header().Set("Cache-Control", "private, max-age=1800")
	_, _ = w.Write(data)
}

// iconVisible reports whether a caller is entitled to a port's icon. A private
// service must be indistinguishable from a port that does not exist, so callers
// turn both answers into the same bare 404.
func iconVisible(snap discover.Snapshot, port int, local bool) bool {
	for _, svc := range snap.Services {
		if svc.Port == port {
			return local || svc.Tier == discover.TierPublic
		}
	}
	return false
}

// servicesView is the single place the tier gate is applied. A non-local
// request leaves Private nil, so private services are never serialised into the
// response at all — they are not hidden with CSS, they are simply not there.
func (s *Server) servicesView(r *http.Request) templates.ServicesView {
	snap := s.reg.Scan(r.Context())
	local := s.isLocal(r)

	v := templates.ServicesView{
		Public:      snap.Public(),
		ShowPrivate: local,
		LinkHost:    linkHost(r),
		ScannedAt:   snap.ScannedAt,
	}
	if local {
		v.Private = snap.Private()
	}
	return v
}

func noStore(w http.ResponseWriter) {
	// The page is a live view of the machine and its contents depend on who is
	// asking; a cache between here and the browser must not reuse it.
	w.Header().Set("Cache-Control", "no-store, private")
}
