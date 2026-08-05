// Package discover finds HTTP services listening on the local machine by
// reading /proc, attributing sockets to processes, and probing them.
//
// Everything here is Linux-specific by design: /proc/net/tcp is the only way to
// enumerate listeners without root, and /proc/<pid>/fd is the only way to map a
// socket back to the process that owns it.
package discover

import (
	"bufio"
	"encoding/hex"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// tcpListen is the st value for a socket in the LISTEN state.
const tcpListen = "0A"

// listener is one row of /proc/net/tcp{,6} in the LISTEN state.
type listener struct {
	Addr  netip.Addr
	Port  int
	Inode uint64
}

// listeners parses both /proc/net/tcp and /proc/net/tcp6. A missing tcp6 (kernel
// built without IPv6) is not an error — we just return what v4 gave us.
func listeners() ([]listener, error) {
	var out []listener
	v4, err := parseNetTCP("/proc/net/tcp", 4)
	if err != nil {
		return nil, err
	}
	out = append(out, v4...)
	if v6, err := parseNetTCP("/proc/net/tcp6", 16); err == nil {
		out = append(out, v6...)
	}
	return out, nil
}

// parseNetTCP reads one /proc/net/tcp-family file, keeping only LISTEN rows.
// size is the expected address width in bytes (4 for v4, 16 for v6).
func parseNetTCP(path string, size int) ([]listener, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []listener
	sc := bufio.NewScanner(f)
	sc.Scan() // header row: "  sl  local_address rem_address st ..."
	for sc.Scan() {
		// Fields: 0=sl 1=local 2=rem 3=st 4=tx:rx 5=tr:tm 6=retrnsmt 7=uid
		//         8=timeout 9=inode
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 || fields[3] != tcpListen {
			continue
		}
		addr, port, ok := parseHexAddr(fields[1], size)
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		out = append(out, listener{Addr: addr, Port: port, Inode: inode})
	}
	return out, sc.Err()
}

// parseHexAddr decodes the "ADDRESS:PORT" hex pair /proc uses.
//
// The port is plain big-endian hex. The address is the kernel's in-memory
// representation dumped word by word, so each 32-bit word is byte-swapped on a
// little-endian host: "0100007F" is 127.0.0.1, and an IPv6 address is four such
// words in a row. Reversing every 4-byte group undoes it for both families.
func parseHexAddr(s string, size int) (netip.Addr, int, bool) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok || len(host) != size*2 {
		return netip.Addr{}, 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 32)
	if err != nil || port == 0 || port > 65535 {
		return netip.Addr{}, 0, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	for i := 0; i < len(raw); i += 4 {
		w := raw[i : i+4]
		w[0], w[1], w[2], w[3] = w[3], w[2], w[1], w[0]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, false
	}
	// A v4-mapped v6 listener (::ffff:127.0.0.1) is a v4 listener as far as
	// tiering and probing are concerned; collapse it so both agree.
	return addr.Unmap(), int(port), true
}
