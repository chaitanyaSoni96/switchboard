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
	mu       sync.Mutex
	byInode  map[uint64]procInfo
	lastWalk time.Time
}

func newAttributor() *attributor {
	return &attributor{byInode: map[uint64]procInfo{}}
}

// lookup resolves every inode in want. Inodes belonging to other users'
// processes are simply absent from the result: /proc/<pid>/fd is readable only
// by the owner, and that is the normal case, not a failure.
func (a *attributor) lookup(want map[uint64]bool) map[uint64]procInfo {
	a.mu.Lock()
	defer a.mu.Unlock()

	stale := time.Since(a.lastWalk) > pidTTL
	if !stale {
		for inode := range want {
			if _, ok := a.byInode[inode]; !ok {
				stale = true // a listener we have never attributed appeared
				break
			}
		}
	}
	if stale {
		a.byInode = walkProcFDs(want)
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
			continue // another user's process; expected
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
