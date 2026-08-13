package templates

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"switchboard/internal/discover"
)

func render(t *testing.T, v ServicesView) string {
	t.Helper()
	var sb strings.Builder
	if err := Services(v).Render(context.Background(), &sb); err != nil {
		t.Fatal(err)
	}
	return sb.String()
}

func fixture() ServicesView {
	return ServicesView{
		Public: []discover.Service{{
			Name: "Grafana", Port: 3000, Process: "grafana",
			Bind: "0.0.0.0", Tier: discover.TierPublic, PID: 100, Alive: true,
		}},
		Private: []discover.Service{{
			Name: "Secret Admin", Port: 9999, Process: "adminsrv",
			Bind: "127.0.0.1", Tier: discover.TierPrivate, PID: 200, Alive: true,
		}},
		LinkHost:  "box.local",
		ScannedAt: time.Date(2026, 8, 6, 3, 4, 5, 0, time.UTC),
	}
}

// The tier split has to be enforced by omission. If a private service can be
// found anywhere in the bytes we send a remote caller — in markup, in an
// attribute, in a comment — then it leaked, whatever CSS says about it.
func TestRemoteViewOmitsPrivateEntirely(t *testing.T) {
	v := fixture()
	v.ShowPrivate = false
	v.Private = nil // what Server.servicesView does for a non-local request

	out := render(t, v)
	for _, leak := range []string{"Secret Admin", "9999", "adminsrv", "private"} {
		if strings.Contains(out, leak) {
			t.Errorf("remote payload contains %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "Grafana") {
		t.Error("public service missing from remote payload")
	}
}

func TestLocalViewIncludesBothTiers(t *testing.T) {
	v := fixture()
	v.ShowPrivate = true

	out := render(t, v)
	for _, want := range []string{"Grafana", "Secret Admin", `data-section="public"`, `data-section="private"`} {
		if !strings.Contains(out, want) {
			t.Errorf("local payload missing %q", want)
		}
	}
}

// Links must use the host the visitor typed. A loopback href would resolve to
// the visitor's own machine and break every LAN card.
func TestCardLinksUseRequestHost(t *testing.T) {
	v := fixture()
	v.ShowPrivate = true

	out := render(t, v)
	if !strings.Contains(out, `href="http://box.local:3000/"`) {
		t.Error("public card should link to the request host")
	}
	if strings.Contains(out, "http://127.0.0.1:3000/") {
		t.Error("card linked to loopback instead of the request host")
	}

	v6 := fixture()
	v6.LinkHost = "fd00::5"
	if got := v6.Href(v6.Public[0]); got != "http://[fd00::5]:3000/" {
		t.Errorf("IPv6 host must be bracketed, got %q", got)
	}
}

// A service bound to one address is the exception: it answers only there, so
// the request host would produce a link that refuses the connection.
func TestCardLinksUseTheBoundAddressWhenNotWildcard(t *testing.T) {
	v := fixture()
	v.Public = []discover.Service{{
		Name: "Catalogue", Port: 8443, Scheme: "https",
		Bind: "192.168.1.79", Tier: discover.TierPublic, Alive: true,
	}}

	if got := v.Href(v.Public[0]); got != "https://192.168.1.79:8443/" {
		t.Errorf("Href = %q, want the bound address", got)
	}
	if out := render(t, v); !strings.Contains(out, `href="https://192.168.1.79:8443/"`) {
		t.Errorf("card should link to the bound address:\n%s", out)
	}

	v6 := fixture()
	v6.Public = []discover.Service{{Name: "v6", Port: 8443, Bind: "fd00::1", Tier: discover.TierPublic}}
	if got := v6.Href(v6.Public[0]); got != "http://[fd00::1]:8443/" {
		t.Errorf("bound IPv6 address must be bracketed, got %q", got)
	}

	// A wildcard bind keeps the visitor's own host — a raw IP would be a
	// downgrade from the name they typed.
	wild := fixture()
	if got := wild.Href(wild.Public[0]); got != "http://box.local:3000/" {
		t.Errorf("wildcard bind should keep the request host, got %q", got)
	}
}

func TestEmptyState(t *testing.T) {
	out := render(t, ServicesView{ShowPrivate: true, LinkHost: "localhost", ScannedAt: time.Now()})
	if !strings.Contains(out, "No HTTP services found") {
		t.Errorf("empty state not rendered:\n%s", out)
	}
	if strings.Contains(out, "grid-cards") {
		t.Error("empty state should not render a grid")
	}
	if !strings.Contains(out, "0 services found") {
		t.Error("count line should read zero")
	}
}

func TestHaystackIsLowercasedAndSearchable(t *testing.T) {
	s := discover.Service{Name: "Grafana Alloy", Port: 12345, Process: "alloy", Bind: "127.0.0.1"}
	got := haystack(s)
	for _, term := range []string{"grafana", "alloy", "12345", "127.0.0.1"} {
		if !strings.Contains(got, term) {
			t.Errorf("haystack %q missing %q", got, term)
		}
	}
	if strings.ToLower(got) != got {
		t.Errorf("haystack must be lowercase, got %q", got)
	}
}

func TestTooltipTruncatesLongCmdline(t *testing.T) {
	s := discover.Service{
		Process: "rootlesskit", PID: 42, Alive: true,
		Cmdline: strings.Repeat("--flag=value ", 60),
	}
	if got := tooltip(s); len(got) > 220 {
		t.Errorf("tooltip not truncated: %d chars", len(got))
	}
}

func TestForwardedPortShowsBackend(t *testing.T) {
	v := fixture()
	v.ShowPrivate = true
	v.Public[0] = discover.Service{
		Name: "MinIO", Port: 9000, Scheme: "http", Process: "rootlesskit",
		Server: "MinIO", Bind: "0.0.0.0", Tier: discover.TierPublic, Alive: true,
		Backend: &discover.Backend{
			Via: "rootlesskit", Addr: "172.18.0.3:9000",
			Process: "minio", Cmdline: "minio server /data --console-address :9001", PID: 3733930,
		},
	}

	out := render(t, v)
	// The card must name the container process, not the forwarder that merely
	// holds the socket.
	if !strings.Contains(out, "minio server /data --console-address :9001") {
		t.Error("backend command line missing from card")
	}
	// ...and must say that is what it did, rather than silently swapping names.
	if !strings.Contains(out, "via rootlesskit") || !strings.Contains(out, "172.18.0.3:9000") {
		t.Error("forward attribution line missing")
	}
	// Searching "minio" has to find a port whose host-side process is only ever
	// called rootlesskit.
	if !strings.Contains(haystack(v.Public[0]), "minio") {
		t.Error("backend not searchable")
	}
}

func TestUnforwardedPortHasNoBackendLine(t *testing.T) {
	v := fixture()
	v.ShowPrivate = true
	out := render(t, v)
	if strings.Contains(out, "via ") {
		t.Error("plain service should not claim to be forwarded")
	}
}

// titleAttr strips the hover tooltip, which lists everything we know and so is
// not evidence about what the card actually displays.
var titleAttr = regexp.MustCompile(`(?s) title="[^"]*"`)

func TestServerHeaderShownOnlyWhenItAddsSomething(t *testing.T) {
	base := fixture()
	base.ShowPrivate = false
	base.Private = nil

	// Server repeats the name: showing it again would be noise.
	same := base
	same.Public = []discover.Service{{
		Name: "MinIO", Port: 9000, Process: "rootlesskit", Server: "MinIO",
		Bind: "0.0.0.0", Tier: discover.TierPublic, Alive: true,
	}}
	if body := titleAttr.ReplaceAllString(render(t, same), ""); strings.Count(body, "MinIO") != 1 {
		t.Errorf("redundant Server header rendered %d times, want 1", strings.Count(body, "MinIO"))
	}

	// Server differs from the name: it is extra information and belongs on the
	// card, since "uvicorn" tells you what LiteLLM is actually served by.
	diff := base
	diff.Public = []discover.Service{{
		Name: "LiteLLM API", Port: 13378, Process: "unknown", Server: "uvicorn",
		Bind: "::", Tier: discover.TierPublic, Alive: true,
	}}
	if body := titleAttr.ReplaceAllString(render(t, diff), ""); !strings.Contains(body, "uvicorn") {
		t.Error("distinct Server header should be shown on the card")
	}
}

func TestDeadServiceIsMarked(t *testing.T) {
	if dotClass(true) == dotClass(false) {
		t.Fatal("alive and dead services must render differently")
	}
}
