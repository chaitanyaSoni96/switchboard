# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Switchboard serves one page linking to every HTTP service listening on this Linux box, discovered by reading `/proc` on demand. One static Go binary; no database, no config file, no background scanner. Linux-only by design — see Non-goals in README.md.

## Commands

```sh
make build                          # regenerate CSS + templ, then build -> bin/switchboard
make test                           # go vet ./... && go test ./...
go test ./internal/discover -run TestName   # single test
make run                            # build and serve on :8090
make generate                       # tailwind CSS + templ generate only
```

`make css` downloads the Tailwind standalone binary to `bin/tailwindcss` on first use. A plain `go build ./cmd/switchboard` works without templ or Tailwind installed because their outputs are checked in (see below).

## Generated files are checked in

- `internal/web/templates/*_templ.go` is generated from the `.templ` files. Edit the `.templ` file, run `templ generate` (or `make generate`), and commit **both**. Never hand-edit `*_templ.go`.
- `internal/web/assets/style.css` is built from `assets/input.css` by Tailwind. Edit `input.css` (or add/remove utility classes in templates), run `make css`, commit the result.

## Architecture

The whole scan happens per-request inside `Registry.Scan` (`internal/discover/registry.go`) — there is no background goroutine, and an idle process burns zero CPU. Concurrent requests never queue: if a scan is in flight, callers get the previous snapshot (stale-while-in-flight).

Pipeline, one stage per file in `internal/discover/`:

1. `proc.go` — parse `/proc/net/tcp{,6}` for `LISTEN` sockets (little-endian hex addresses, v4-mapped v6).
2. `process.go` — socket inode → PID/comm/cmdline by walking `/proc/*/fd` (cached 30s).
3. `probe.go` — `GET /` at the address the socket bound to; only ports that answer HTTP are listed. Extracts `<title>`, `Server:` header, favicon href; detects TLS listeners and retries over https.
4. `forward.go` — when the socket owner is a container port-forwarder (`rootlesskit`, `docker-proxy`, …), chase through `/proc` network namespaces to the real container process.
5. `icon.go` — fetch/validate favicons, served same-origin from `/icon/<port>`.
6. `registry.go` — aggregates sockets by port (most public bind wins), tiers, excludes Switchboard itself, assembles `Service` values.

Caching is deliberately uneven per layer and documented in `docs/discovery.md` — read it before touching cache keys or TTLs. The load-bearing detail: successful probes are keyed on port + PID + process **start time** (`/proc/<pid>/stat` field 22), so they live forever per process but a restarted service re-probes even under a recycled PID; failed probes expire after 60s.

`internal/web/` renders it: `server.go` has three routes (page, htmx fragment `/partials/services`, `/icon/<port>`), `origin.go` classifies the caller as loopback vs remote, templates are [templ](https://templ.guide).

## The tier gate is a security invariant

Services are tiered `public`/`private` by bind address. Two rules the code is built around:

- `servicesView` in `internal/web/server.go` is the **single place** the gate applies: a non-local request never has private services serialised into the response at all. Don't add a route that renders services without going through it.
- `/icon/<port>` must return an identical bare 404 for both "private port" and "no such port" — anything else is an enumeration oracle for the withheld tier. Preserve this if touching `handleIcon`/`iconVisible`.

`--trust-forwarded` is off by default because `X-Forwarded-For` is client-controlled; `docs/security.md` explains this and the two capabilities in the systemd unit.

## Design tokens come from Scratchpad

The palette, fonts, card geometry and dark/light mechanism are lifted verbatim from the sibling `../scratchpad` project: seven CSS custom properties that Tailwind utilities are mapped onto (`bg-surface`, `text-accent`). Don't introduce new colour values or CSS variables — extend through the existing tokens so the two projects stay visually identical.
