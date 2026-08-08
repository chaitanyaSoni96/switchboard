package discover

import (
	"testing"
	"time"
)

// stubAttributor builds an attributor whose walk resolves only the inodes in
// resolvable, and counts how many times it ran.
func stubAttributor(resolvable ...uint64) (*attributor, *int) {
	ok := map[uint64]bool{}
	for _, inode := range resolvable {
		ok[inode] = true
	}
	walks := 0
	a := newAttributor()
	a.walk = func(want map[uint64]bool) map[uint64]procInfo {
		walks++
		found := map[uint64]procInfo{}
		for inode := range want {
			if ok[inode] {
				found[inode] = procInfo{PID: int(inode), Comm: "svc"}
			}
		}
		return found
	}
	return a, &walks
}

// An inode that cannot be attributed must not force a rebuild on every call.
// Before the unresolved set existed it was indistinguishable from a newly
// appeared listener, so pidTTL never applied and every request walked /proc.
func TestLookupDoesNotRewalkForUnattributableInode(t *testing.T) {
	a, walks := stubAttributor(1) // inode 2 is never resolvable
	want := map[uint64]bool{1: true, 2: true}

	for i := 0; i < 5; i++ {
		// Backdate past the floor but well within pidTTL, so this exercises the
		// unresolved set rather than minWalkInterval.
		if i > 0 {
			a.lastWalk = time.Now().Add(-2 * minWalkInterval)
		}
		got := a.lookup(want)
		if _, ok := got[1]; !ok {
			t.Fatalf("call %d: inode 1 should resolve", i)
		}
		if _, ok := got[2]; ok {
			t.Fatalf("call %d: inode 2 should be absent", i)
		}
	}
	if *walks != 1 {
		t.Errorf("walked %d times, want 1: an unattributable inode is re-walked every lookup", *walks)
	}
}

// A genuinely new listener must still trigger a rebuild rather than waiting for
// pidTTL — the negative cache must not swallow real changes.
func TestLookupRewalksForNewInode(t *testing.T) {
	a, walks := stubAttributor(1, 2)

	a.lookup(map[uint64]bool{1: true})
	if *walks != 1 {
		t.Fatalf("walked %d times after first lookup, want 1", *walks)
	}

	// Backdate past the floor so only the new-inode rule is under test.
	a.lastWalk = time.Now().Add(-2 * minWalkInterval)

	got := a.lookup(map[uint64]bool{1: true, 2: true})
	if *walks != 2 {
		t.Errorf("walked %d times, want 2: a new inode should force a rebuild", *walks)
	}
	if _, ok := got[2]; !ok {
		t.Error("inode 2 appeared but was not attributed")
	}
}

// The floor bounds how often new inodes can force a rebuild.
func TestLookupFloorsRewalkFrequency(t *testing.T) {
	a, walks := stubAttributor(1, 2, 3)

	a.lookup(map[uint64]bool{1: true})
	a.lookup(map[uint64]bool{1: true, 2: true})
	a.lookup(map[uint64]bool{1: true, 2: true, 3: true})

	if *walks != 1 {
		t.Errorf("walked %d times within minWalkInterval, want 1", *walks)
	}
}

// Past pidTTL everything is rebuilt, including inodes previously unresolved —
// otherwise a process that starts later is never picked up.
func TestLookupRetriesUnresolvedAfterTTL(t *testing.T) {
	a, walks := stubAttributor(1)
	want := map[uint64]bool{1: true, 2: true}

	a.lookup(want)
	a.lastWalk = time.Now().Add(-2 * pidTTL)
	a.lookup(want)

	if *walks != 2 {
		t.Errorf("walked %d times, want 2: pidTTL should force a rebuild", *walks)
	}
	if !a.unresolved[2] {
		t.Error("inode 2 should still be recorded as unresolved after the rebuild")
	}
}
