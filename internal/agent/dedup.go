package agent

import "github.com/anomalyco/pilot/internal/store"

// DedupTracker ensures we only diagnose the first failure per host per run.
// It uses SQLite as durable storage so that re-runs within the same run-id
// (e.g. after a crash) preserve the dedup state, and an in-memory cache
// for fast path.
type DedupTracker struct {
	store *store.Store
	cache map[string]bool // key: runID + "|" + host
}

func NewDedupTracker(s *store.Store) *DedupTracker {
	return &DedupTracker{store: s, cache: map[string]bool{}}
}

// ShouldDiagnose returns true the first time it's called for a given
// (runID, host) pair, false thereafter. It also records the fact in the store
// so a process restart won't reset the state mid-run.
func (d *DedupTracker) ShouldDiagnose(runID, host string) bool {
	if runID == "" || host == "" {
		return true // no host context → always allow
	}
	key := runID + "|" + host
	if d.cache[key] {
		return false
	}
	if d.store == nil {
		d.cache[key] = true
		return true
	}
	seen, _ := d.store.HasFailureBeenSeen(runID, host)
	if seen {
		d.cache[key] = true
		return false
	}
	_ = d.store.MarkFailureSeen(runID, host)
	d.cache[key] = true
	return true
}

// Reset clears the in-memory cache (does not touch SQLite).
func (d *DedupTracker) Reset() {
	d.cache = map[string]bool{}
}
