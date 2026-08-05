package discover

import (
	"strings"
	"testing"
)

func TestParseIconHref(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"plain", `<link rel="icon" href="/favicon.png">`, "/favicon.png"},
		{"shortcut icon", `<link rel="shortcut icon" href="/fav.ico">`, "/fav.ico"},
		{"single quotes", `<link rel='icon' href='/a.svg'>`, "/a.svg"},
		{"unquoted", `<link rel=icon href=/b.png>`, "/b.png"},
		{"attribute order", `<link href="/c.png" type="image/png" rel="icon">`, "/c.png"},
		{"uppercase", `<LINK REL="ICON" HREF="/D.PNG">`, "/D.PNG"},
		{"self closing", `<link rel="icon" href="/e.png" />`, "/e.png"},
		{"relative", `<link rel="icon" href="static/f.png">`, "static/f.png"},
		{
			// Scratchpad and Switchboard both inline their mark this way.
			name: "data uri",
			body: `<link rel="icon" href="data:image/svg+xml,%3Csvg%3E%3C/svg%3E">`,
			want: "data:image/svg+xml,%3Csvg%3E%3C/svg%3E",
		},
		{
			// A real icon beats a launcher image even when declared second.
			name: "prefers icon over apple-touch",
			body: `<link rel="apple-touch-icon" href="/big.png"><link rel="icon" href="/small.ico">`,
			want: "/small.ico",
		},
		{
			name: "apple-touch only, as a fallback",
			body: `<link rel="apple-touch-icon" href="/big.png">`,
			want: "/big.png",
		},
		{"stylesheet is not an icon", `<link rel="stylesheet" href="/style.css">`, ""},
		{"no link at all", `<html><body>hi</body></html>`, ""},
		{"icon rel with no href", `<link rel="icon">`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseIconHref([]byte(tt.body)); got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeDataURI(t *testing.T) {
	t.Run("percent encoded svg", func(t *testing.T) {
		// Scratchpad's actual favicon.
		const in = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'%3E%3C/svg%3E"
		data, ctype, ok := decodeDataURI(in)
		if !ok {
			t.Fatal("should decode")
		}
		if ctype != "image/svg+xml" {
			t.Errorf("ctype = %q", ctype)
		}
		if !strings.HasPrefix(string(data), "<svg") {
			t.Errorf("data = %q", data)
		}
	})

	t.Run("base64 png", func(t *testing.T) {
		const in = "data:image/png;base64,iVBORw0KGgo="
		data, ctype, ok := decodeDataURI(in)
		if !ok || ctype != "image/png" {
			t.Fatalf("ok=%v ctype=%q", ok, ctype)
		}
		if len(data) == 0 || data[0] != 0x89 {
			t.Errorf("expected PNG magic, got %v", data)
		}
	})

	t.Run("rejects non-image", func(t *testing.T) {
		// A data: URI is attacker-controlled content from another process; only
		// image types may be served back.
		for _, in := range []string{
			"data:text/html,<script>alert(1)</script>",
			"data:application/javascript,alert(1)",
			"data:,plain",
		} {
			if _, _, ok := decodeDataURI(in); ok {
				t.Errorf("%q should be rejected", in)
			}
		}
	})

	t.Run("malformed", func(t *testing.T) {
		for _, in := range []string{"", "notdata:image/png,x", "data:image/png", "data:image/png;base64,!!!"} {
			if _, _, ok := decodeDataURI(in); ok {
				t.Errorf("%q should be rejected", in)
			}
		}
	})
}

func TestImageType(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0}
	ico := []byte{0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x10, 0x10, 0, 0, 0, 0}
	html := []byte("<!doctype html><html><body>404 not found</body></html>")

	tests := []struct {
		name     string
		declared string
		data     []byte
		want     string
	}{
		{"declared image wins", "image/png", png, "image/png"},
		{"strips parameters", "image/svg+xml; charset=utf-8", png, "image/svg+xml"},
		{"sniffs when generic", "application/octet-stream", png, "image/png"},
		{"sniffs when absent", "", png, "image/png"},
		// ICO has no signature http.DetectContentType recognises, so it is
		// matched explicitly or every .ico would be rejected.
		{"legacy ico type", "application/octet-stream", ico, "image/x-icon"},
		{"ico with no declared type", "", ico, "image/x-icon"},
		// Servers routinely answer /favicon.ico with an HTML error page; that
		// must not end up on a card as a broken image.
		{"rejects html", "text/html", html, ""},
		{"rejects html sniffed under a generic type", "application/octet-stream", html, ""},
		{"rejects json", "application/json", []byte(`{"error":"nope"}`), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := imageType(tt.declared, tt.data); got != tt.want {
				t.Errorf("= %q, want %q", got, tt.want)
			}
		})
	}
}
