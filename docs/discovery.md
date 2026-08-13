# How discovery works

There is no background scanner and no scan interval. Everything happens on
demand, when a request arrives, so an idle Switchboard does no work at all —
literally none: the process burns zero CPU between requests.

Because nothing runs on a schedule server-side, the refresh cadence is a
property of the page rather than the process, and it lives in the header:

- **Auto-refresh defaults to off.** An open tab costs nothing until you ask it
  to. The selector offers 5s / 15s / 30s / 1m / 5m, and the choice is remembered
  in `localStorage`.
- **↻ refreshes once**, swapping just the grid rather than reloading the page.
- **A hidden tab gets no timer at all.** Switching away stops the interval;
  switching back refreshes once — regardless of whether auto-refresh is on,
  since whatever is on screen after a spell away is stale — and then resumes.

So the rule is exact rather than approximate: if nobody is looking at the page,
Switchboard is doing nothing.

## Caching

The work is cached in layers, because the costs are wildly uneven:

| Layer | Cost | Caching |
|---|---|---|
| Parse `/proc/net/tcp` + `tcp6` | sub-millisecond | none — re-read every request |
| Socket inode → PID | walks every `/proc/*/fd` | 30s, and only re-walked when an inode is actually unknown |
| Container forward → backend | reads a namespace link per process | 30s, and only for ports held by a forwarder |
| HTTP probe for `<title>` | up to 2s per new port | success is keyed on port + PID + process start time, so effectively permanent per process; a failure expires after 60s |
| Liveness | one TCP dial | every request, all ports in parallel, 250ms timeout |

Keying the probe cache on `/proc/<pid>/stat` field 22 (start time) alongside the
PID is what makes a *successful* probe safe to keep forever: a restarted service
misses the cache and gets re-probed even if the kernel handed it the same PID,
while a long-running one is probed exactly once.

A *failed* probe gets no such treatment, because it is a much weaker claim — it
says only that one port did not complete an HTTP exchange inside one two-second
window. A dev server binds its port well before it can serve it, so a cold Metro
or Vite bundle looks exactly like a port that will never speak HTTP. Those
verdicts expire after 60s and are retried, which is why a service that was slow
to start appears on its own rather than staying invisible until you restart it.

If a scan is already in flight when a request arrives, that request is served
the previous snapshot immediately rather than queueing behind it — the in-flight
scan is the refresh. In practice a cold first request takes about two seconds
(dominated by probe timeouts against ports that turn out not to speak HTTP) and
every subsequent one takes about ten milliseconds.

Liveness deliberately uses a bare TCP dial, never a full HTTP `GET`. It runs on
every single request, so with auto-refresh turned up it is the one cost that
recurs — a `GET` there would mean hammering every service on the box on every
tick for no new information.

## Details worth knowing

- **Only HTTP ports are listed.** A port that listens but does not answer
  `GET /` with a valid HTTP response is dropped. Any status counts, including
  `401` and `500` — a service that demands auth is still a service.
- **Names** come from the page's `<title>`, then the `Server:` response header,
  then the process name, then `port N`. The header sits above the process name
  on purpose: it describes the thing answering the request, while
  `/proc/<pid>/comm` describes whichever process holds the socket — on a box
  running containers that is usually a port-forwarder, so `MinIO` beats
  `rootlesskit` and `Caddy` beats nothing at all.
- **HTTPS ports are detected and linked as `https://`.** Plain HTTP is tried
  first since that is what most local services speak, but a TLS listener that
  answers a plaintext request with `400 Client sent an HTTP request to an HTTPS
  server` (Go, Caddy and nginx all say something to that effect) is re-probed
  over TLS and marked `tls` on its card.

  Certificates are not verified during the probe. Nothing is sent to the service
  and only its title is read, and local services use self-signed or internal-CA
  certs as a matter of course — verifying would simply make every one of them
  invisible.

  A TLS vhost may refuse the probe outright: Go omits SNI for IP literals, so a
  server with no default certificate has no certificate to present when probed
  by IP and aborts the handshake. When that happens the mismatch reply
  is still believed and the card is still labelled `https` — a browser going to
  the real hostname sends SNI and connects fine, whereas an `http://` link would
  be certain to fail.
- **The probe dials the address the socket bound to.** A wildcard listener
  (`0.0.0.0`, `::`) answers anywhere, so it is probed over loopback and the
  request never leaves the box. A listener bound to one address answers only
  there: `192.168.1.79:8443` refuses a connection to `127.0.0.1:8443`, and so
  does `127.0.0.2:8080` — loopback is a whole `/8` and only one of its addresses
  is `127.0.0.1`. Probing loopback alone made every such service invisible.
  Dialling the bound address still stays on the machine; the kernel routes a
  local address through `lo` whichever interface owns it. Loopback follows as a
  fallback, since a port can hold several sockets and only the most public of
  them decides the card. Liveness dials the same list.
- **Card links use the host you came in on.** Visit `http://box.local:8090` and
  the cards point at `http://box.local:3000`, not at a loopback address that
  would resolve to your own machine. The exception is that same specifically
  bound listener: it answers at one address and nowhere else, so its card links
  there — `https://192.168.1.79:8443/` even for a viewer on loopback, because
  every other host would refuse.
- **Switchboard excludes itself** — both its own PID and its listening port.
- **Each card is watermarked with the service's own favicon**, faded down its
  left edge. The href comes from the `<link rel="icon">` already present in the
  body the probe read, so finding it costs no extra request; `/favicon.ico` is
  tried for pages that declare nothing, and inline `data:` URIs are decoded
  rather than fetched. A service with no usable icon simply renders without one.

  Switchboard fetches the icon and serves it from `/icon/<port>` rather than
  pointing the browser at the service directly. Same-origin means the
  watermarks keep working when Switchboard is behind an HTTPS tunnel, where an
  `http://` image would be blocked as mixed content even though the card links
  still work. Each is watermarked as a fixed 120px square against the card's
  right edge, faded out towards the label so the text keeps its contrast.

  That route is tier-gated like everything else, and it has to be: answering
  `200` for a private port and `404` for an unused one would be an enumeration
  oracle for exactly the services the tier split withholds. Both cases return
  the same bare `404`. Responses also carry a `sandbox` CSP and `nosniff`, since
  an SVG favicon is a document and these bytes came from another process.
- **Permission errors are normal**, not failures. Sockets owned by other users
  degrade to a process name of `unknown` and everything else still works. If a
  card reads `port 2019` with process `unknown`, that service offered no
  `<title>` and no `Server:` header and belongs to another user — the process
  name would have been the last thing left to name it with, and that is the one
  case `CAP_SYS_PTRACE` in the systemd unit exists to fix.
- **The scan timestamp sits at the top of the grid rather than in the header
  bar**, because only the grid is re-fetched by the poll — a timestamp in the
  static header would freeze at page load and quietly lie.

## Following a container port-forward

A published container port is held by a forwarder process (`rootlesskit`,
`docker-proxy`, `rootlessport`, `slirp4netns`, `pasta`), so `/proc` correctly but
unhelpfully reports `rootlesskit` for every one of them. Switchboard chases the
forward the rest of the way, using nothing but `/proc` — no Docker socket, no API
client, no new dependency:

1. **Read the mapping off the proxies.** Every running `docker-proxy` carries
   its rule in its own arguments (`-host-port 9000 -container-ip 172.18.0.3
   -container-port 9000`), so the port table can simply be read from `/proc`.
   UDP rules are skipped.
2. **Find the container's network namespace.** Group every readable process by
   `/proc/<pid>/ns/net`, then read `/proc/<pid>/net/fib_trie` in each and look
   for the one where the container IP is a `LOCAL` address.
3. **Find the listener inside it.** That namespace's own `/proc/<pid>/net/tcp`
   and `tcp6` list its sockets; take the one on the container-side port.
4. **Attribute it.** Socket inodes are global, so the namespaced socket resolves
   through the same `/proc/*/fd` walk the host side already uses.

Step 2 is the subtle one, and the obvious shortcut is wrong: `docker-proxy` runs
in the *network's* namespace, one hop short of the container's, so following the
proxy's own `ns/net` lands somewhere that has no listener. Matching on the
container IP as a local address is what identifies the right namespace — and it
also disambiguates the very common case of several containers each listening on
the same internal port number.

The result is that ports 9000 and 9001 both read `minio server /data
--console-address :9001` with a `via rootlesskit → 172.18.0.3:900x` line, which
makes it obvious they are one container serving its API and its console rather
than two similar services. The forwarder is still named, because silently
swapping one process for another would be worse than the problem it fixes.

Everything here degrades: no `docker-proxy` (podman's `pasta`, for instance), no
matching namespace, or an unreadable container process each just falls back to
the host-side view. Nothing is invented.
