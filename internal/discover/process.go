package discover

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pidTTL bounds how stale the inode -> PID map may get. Inodes are reused, so
// even a map that answers every question still gets rebuilt this often.
const pidTTL = 30 * time.Second

// minWalkInterval floors how often an unrecognised inode may force an early
// rebuild. Without it a host churning through listeners walks all of /proc on
// every request; with it a genuinely new service can show "unknown" for up to
// this long before it is named, which is the cheaper mistake.
const minWalkInterval = time.Second

// procInfo is what we can learn about the process behind a socket.
type procInfo struct {
	PID     int
	Comm    string
	Cmdline string
	// Start is field 22 of /proc/<pid>/stat, in clock ticks since boot. Paired
	// with the PID it identifies one process run, which is what makes the probe
	// cache safe across PID reuse.
	Start uint64
}

// attributor maps socket inodes to processes.
//
// Walking every /proc/<pid>/fd is the expensive half of discovery, so it runs
// only when the cached map cannot answer — either an inode is missing from it,
// or it has aged past pidTTL.
type attributor struct {
	mu      sync.Mutex
	byInode map[uint64]procInfo
	// unresolved records the inodes the last walk looked for and did not find.
	// Without it those inodes are indistinguishable from newly appeared ones, so
	// each would force a rebuild on every lookup and pidTTL would never apply —
	// and a host with any listener Switchboard cannot attribute (sshd and
	// systemd-resolved qualify on most machines) always has at least one.
	unresolved map[uint64]bool
	lastWalk   time.Time
	// walk is always walkProcFDs outside tests, which cannot stage a /proc.
	walk func(map[uint64]bool) map[uint64]procInfo
}

func newAttributor() *attributor {
	return &attributor{
		byInode:    map[uint64]procInfo{},
		unresolved: map[uint64]bool{},
		walk:       walkProcFDs,
	}
}

// lookup resolves every inode in want. Inodes that cannot be attributed are
// simply absent from the result: without CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE
// only the current user's processes can be walked, and that is a normal
// deployment, not a failure.
func (a *attributor) lookup(want map[uint64]bool) map[uint64]procInfo {
	a.mu.Lock()
	defer a.mu.Unlock()

	stale := time.Since(a.lastWalk) > pidTTL
	if !stale {
		for inode := range want {
			if _, ok := a.byInode[inode]; ok {
				continue
			}
			if a.unresolved[inode] {
				continue // already looked for and not found; walking again will not help
			}
			stale = true // a listener we have never attributed appeared
			break
		}
		// Rebuilding for a new inode is right, but not at unbounded frequency.
		if stale && time.Since(a.lastWalk) < minWalkInterval {
			stale = false
		}
	}
	if stale {
		a.byInode = a.walk(want)
		a.unresolved = make(map[uint64]bool, len(want)-len(a.byInode))
		for inode := range want {
			if _, ok := a.byInode[inode]; !ok {
				a.unresolved[inode] = true
			}
		}
		a.lastWalk = time.Now()
	}

	out := make(map[uint64]procInfo, len(want))
	for inode := range want {
		if info, ok := a.byInode[inode]; ok {
			out[inode] = info
		}
	}
	return out
}

// walkProcFDs scans /proc/*/fd for symlinks of the form "socket:[<inode>]" and
// returns the ones matching want. Every error is skipped rather than returned:
// processes exit mid-walk and most of /proc belongs to somebody else.
//
// Two distinct permission checks stand between us and a process name, and a
// deployment can pass one without the other. Listing the fd directory is a DAC
// check (needs CAP_DAC_READ_SEARCH); resolving the symlinks inside it is a
// ptrace check (needs CAP_SYS_PTRACE). See systemd/switchboard.service.
func walkProcFDs(want map[uint64]bool) map[uint64]procInfo {
	found := make(map[uint64]procInfo, len(want))

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return found
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // not a PID directory
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			// EACCES here means no CAP_DAC_READ_SEARCH, so every process but our
			// own is skipped before the ptrace-gated Readlink below is ever
			// reached. Expected when the unit grants no capabilities.
			continue
		}
		var info *procInfo
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(target)
			if !ok || !want[inode] {
				continue
			}
			if info == nil {
				info = readProcInfo(pid)
			}
			found[inode] = *info
		}
		if len(found) == len(want) {
			break // every listener accounted for
		}
	}
	return found
}

// socketInode pulls N out of a "socket:[N]" fd symlink target.
func socketInode(target string) (uint64, bool) {
	const prefix = "socket:["
	if !strings.HasPrefix(target, prefix) || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(target[len(prefix):len(target)-1], 10, 64)
	return n, err == nil
}

// readProcInfo gathers the label fields for a PID, degrading to blanks rather
// than failing when a field is unreadable.
func readProcInfo(pid int) *procInfo {
	info := &procInfo{PID: pid}
	dir := filepath.Join("/proc", strconv.Itoa(pid))

	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		info.Comm = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		// cmdline is NUL-separated and NUL-terminated.
		args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		info.Cmdline = strings.TrimSpace(strings.Join(args, " "))
	}
	info.Start, _ = processStart(pid)
	return info
}

// processStart reads field 22 of /proc/<pid>/stat (starttime, in clock ticks).
//
// Fields cannot be split naively: field 2 is the executable name in parentheses
// and may itself contain spaces and parentheses. Everything after the *last*
// ')' is space-separated, and starts at field 3.
func processStart(pid int) (uint64, bool) {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	return parseStatStart(string(b))
}

func parseStatStart(stat string) (uint64, bool) {
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	rest := strings.Fields(stat[i+1:])
	const startTimeField = 22
	idx := startTimeField - 3 // rest[0] is field 3 (state)
	if idx >= len(rest) {
		return 0, false
	}
	n, err := strconv.ParseUint(rest[idx], 10, 64)
	return n, err == nil
}
