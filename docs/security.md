# The tier split is presentation, not access control

**Read this before you rely on it.**

Switchboard sorts services into `public` and `private` by looking at the address
each one bound to, and it will not send `private` entries to a request that did
not come from this machine — they are absent from the HTML, not hidden with CSS,
so View Source and DevTools show nothing either.

That is where the guarantee stops. Switchboard is an index, not a gate:

- It does not proxy anything. Every card is a plain link straight to the
  service's own port. Nothing about the service's own reachability changes
  because Switchboard did or did not list it.
- A peer on your LAN who never loads Switchboard at all can still run
  `nmap` against the box and find every port in seconds. Not being on the page
  is not the same as not being reachable.
- Switchboard has no authentication. Anyone who can reach its port gets the
  public list.
- A public card carries what Switchboard knows about that service: its process
  name, its bind address, and — for a container port — the backend it forwards
  to, such as `172.18.0.3:9000`. That is internal topology, disclosed to anyone
  who can load the page. It describes a service that is already publicly bound,
  but if you would rather it were not visible, bind the service to loopback.

**If something must be private, bind it to loopback.** That is what actually
makes it unreachable; Switchboard merely reports what you already decided. The
`private` tier is a label for "you bound this to 127.0.0.1", not a mechanism that
makes it so.

## `--trust-forwarded`

This flag classifies origin from `X-Forwarded-For` instead of the peer address.
It exists for running behind a tunnel or reverse proxy, where every request
arrives from the proxy and the peer address tells you nothing. It is **off by
default and should stay off unless a proxy you control is the only way in**: any
client can set `X-Forwarded-For` themselves, so with the flag on and Switchboard
directly exposed, a LAN peer can simply claim to be `127.0.0.1` and be shown the
private tier.

## The two capabilities in the systemd unit

`systemd/switchboard.service` runs Switchboard as a dynamically allocated,
unprivileged user, and grants two capabilities. The reason is narrow. Reading
`/proc/net/tcp` needs no privileges — ports, bind addresses and tiers all work
as any user. Naming the *process* behind a socket means walking
`/proc/<pid>/fd`, and that crosses two different kernel checks:

| Step | Check | Capability |
|---|---|---|
| List `/proc/<pid>/fd` | DAC — the directory is `dr-x------`, owned by the target's uid | `CAP_DAC_READ_SEARCH` |
| Resolve each `socket:[N]` symlink | `ptrace_may_access()` | `CAP_SYS_PTRACE` |

Both are required. `CAP_SYS_PTRACE` alone is not enough — it is not a DAC
capability, so the listing fails with `EACCES` before any symlink is read, and
the result is identical to granting nothing at all.

They are genuinely powerful: `CAP_SYS_PTRACE` also permits reading any
process's memory, and `CAP_DAC_READ_SEARCH` permits reading any file on the
box. **Deleting the two capability lines from the unit is a perfectly good
choice.** Switchboard degrades cleanly without them — other users' services
still appear, still get probed, still get their `<title>`, and simply show
`unknown` as the process name.
