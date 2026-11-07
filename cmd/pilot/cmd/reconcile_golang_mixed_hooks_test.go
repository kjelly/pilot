//go:build identity_live_hooks

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/livehooks"
)

// Where the live driver's stop points sit in the MIXED run (spec 2026-11-06 phase 2 §10.2, D31; the arms A17(iii),
// A18 and the H arms rely on them): in the Go phase, which is between the lock the apply step takes and the identity
// playbook's apply. A tagged test, since the points exist only in the tagged build: CI runs it with the tag
// (TestCITaggedStepRunsThePlacementTests), and without the tag there is no point to stop at
// (internal/livehooks TestTheReleasedBinaryHasNoInjectionPoints).
//
// At each point the run is held while the test looks at the world: the lock is held, the playbook's apply has not
// started, and FreeIPA has not been written; at after_entry the obligation has been recorded (the entry ran). Then it
// is let go and the run ends as a mixed run does, the playbook after the Go write.
func TestMixedGoPhasePausesBeforeThePlaybookAtTheDriversPoints(t *testing.T) {
	for _, tc := range []struct {
		point string
		entry bool // the entry has run when the run is held here
	}{
		{"after_entry", true},
		{"before_stage:S3", true},
		{"before_batch:S3:1", true},
	} {
		t.Run(tc.point, func(t *testing.T) {
			e := newMixedCLIEnv(t, rosterWithNewUser())
			hooks := t.TempDir()
			t.Setenv(livehooks.EnvDir, hooks)
			t.Setenv(livehooks.EnvPoints, tc.point)
			done := make(chan error, 1)
			go func() {
				_, err := runReconcileCLI(t, mixedArgs()...)
				done <- err
			}()
			n := waitForStop(t, hooks, tc.point, done)
			if e.identityArgs("apply") != nil {
				t.Errorf("the identity playbook's apply had started at %s: %v", tc.point, e.runs())
			}
			if got := slices.Contains(e.runs(), "freeipa-identity-auth-cache.yml apply"); got != tc.entry {
				t.Errorf("the entry ran = %v at %s, want %v: %v", got, tc.point, tc.entry, e.runs())
			}
			if w := e.a.writeMethods(); len(w) != 0 {
				t.Errorf("FreeIPA had been written at %s: %v", tc.point, w)
			}
			if evs := readEvents(t, e.events); !slices.Contains(evs, "lock ipa-1") || slices.Contains(evs, "release ipa-1") {
				t.Errorf("the lock is not held at %s: %v", tc.point, evs)
			}
			if err := os.WriteFile(filepath.Join(hooks, fmt.Sprintf("go.%d", n)), []byte("resume\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("the run after %s: %v", tc.point, err)
				}
			case <-time.After(2 * time.Minute):
				t.Fatal("the run did not end after the stop was released")
			}
			runs := e.runs()
			write, apply := slices.Index(runs, "ipa-write"), slices.Index(runs, "freeipa-identity-apply.yml apply")
			if write < 0 || apply < 0 || write > apply {
				t.Fatalf("the Go write must come before the playbook's apply: %v", runs)
			}
		})
	}
}

// waitForStop waits for the run to stop at point and returns the number of the stop.
func waitForStop(t *testing.T, dir, point string, done <-chan error) int {
	t.Helper()
	deadline := time.After(2 * time.Minute)
	for {
		if data, err := os.ReadFile(filepath.Join(dir, "notify")); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				var n int
				var got string
				if _, err := fmt.Sscanf(line, "%d %s", &n, &got); err == nil && got == point {
					return n
				}
			}
		}
		select {
		case err := <-done:
			t.Fatalf("the run ended (%v) before it stopped at %s", err, point)
		case <-deadline:
			t.Fatalf("the run did not stop at %s", point)
		case <-time.After(20 * time.Millisecond):
		}
	}
}
