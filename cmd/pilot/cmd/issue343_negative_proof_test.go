package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/store"
)

// Issue #343, F10 call site: the Alertmanager receiver screen must read the
// mode the playbook will apply, including a live alertmanager_config in
// group_vars (the five-node PoC finding F10). The existing status test calls
// the helpers directly, so putting the call site back to the vault-only
// alertmanagerReceiverStatus(doc) passed every test. This one drives the real
// edit router from the top menu and reads the screen's title.
func TestAlertmanagerReceiverScreenShowsTheGroupVarsConfig(t *testing.T) {
	for _, tc := range []struct {
		name, groupVars, want string
	}{
		{"live config in group_vars", "alertmanager_config: |\n  route:\n    receiver: 'null'\n", "目前：custom（legacy，來自 group_vars/alertmanager.yml）"},
		{"nothing configured", "---\n", "目前：null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "group_vars"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "group_vars", "alertmanager.yml"), []byte(tc.groupVars), 0o644); err != nil {
				t.Fatal(err)
			}
			r := newEditRouterModel(dir)
			d := automationDriver{}
			if err := d.choose(&r, "Alertmanager 通知"); err != nil {
				t.Fatalf("open the Alertmanager receiver screen: %v", err)
			}
			st := automationState(&r)
			if st.ScreenID != "alertmanager.receiver" {
				t.Fatalf("screen = %s, want alertmanager.receiver", st.ScreenID)
			}
			if !strings.Contains(st.Title, tc.want) {
				t.Fatalf("title = %q, want it to contain %q", st.Title, tc.want)
			}
		})
	}
}

// Issue #343, verify.go: both final Finish calls of `pilot verify` (the PASS
// and the FAIL verdict) are wrapped in delivery.RetryTransientEvidence, and
// nothing tested it. These run the real `pilot verify <spec>` entry with a
// store that reports "database is locked" on the first Finish.
func TestVerifyFinishRetriesATransientStoreFailure(t *testing.T) {
	for _, tc := range []struct {
		name, row, outcome, wantErr string
	}{
		{"pass verdict", "| C1 | functional | ok | 0 | sh -c 'echo 0' |", "success", ""},
		{"fail verdict", "| C1 | functional | ok | 0 | sh -c 'echo 1' |", "failure", "verification failed: 1 rows"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := runVerifyWithFinish(t, tc.row, func(ctx context.Context, w *store.RunWriter, f store.RunFinished) error {
				calls++
				if calls == 1 {
					return errors.New("database is locked")
				}
				return w.Finish(ctx, f)
			})
			if tc.wantErr == "" && err != nil {
				t.Fatalf("pilot verify = %v, want success after the store recovered", err)
			}
			if tc.wantErr != "" && (err == nil || err.Error() != tc.wantErr) {
				t.Fatalf("pilot verify = %v, want %q (the verdict, not an evidence error)", err, tc.wantErr)
			}
			if calls != 2 {
				t.Errorf("Finish called %d times, want 2 (one transient failure, one retry)", calls)
			}
			if got := lastVerifyOutcome(t); got != tc.outcome {
				t.Errorf("recorded outcome = %q, want %q", got, tc.outcome)
			}
		})
	}
}

// A failure that is not transient is reported, not retried, for both verdicts.
// The FAIL row matters: its Finish site returns the verdict error
// ("verification failed: N rows") next, so a site that swallows the Finish error
// still returns an error and would pass any test that only checks for one. Here
// the error must be the evidence failure, and the run must not be recorded as a
// success (the deferred fallback Finish records the failure).
func TestVerifyFinishReportsAPermanentStoreFailure(t *testing.T) {
	for _, tc := range []struct {
		name, row string
	}{
		{"pass verdict", "| C1 | functional | ok | 0 | sh -c 'echo 0' |"},
		{"fail verdict", "| C1 | functional | ok | 0 | sh -c 'echo 1' |"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			err := runVerifyWithFinish(t, tc.row, func(context.Context, *store.RunWriter, store.RunFinished) error {
				calls++
				return errors.New("disk I/O error")
			})
			if err == nil || !strings.HasPrefix(err.Error(), "finalize verification evidence: ") || !strings.Contains(err.Error(), "disk I/O error") {
				t.Fatalf("pilot verify = %v, want the evidence failure reported (not the verdict, not nil)", err)
			}
			if calls != 1 {
				t.Errorf("Finish called %d times, want 1 (no retry for a permanent failure)", calls)
			}
			if got := lastVerifyOutcome(t); got != "failure" {
				t.Errorf("recorded outcome = %q, want failure: a run whose evidence could not be finalized is not a success", got)
			}
		})
	}
}

func runVerifyWithFinish(t *testing.T, row string, finish func(context.Context, *store.RunWriter, store.RunFinished) error) error {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("PILOT_DATA_DIR", filepath.Join(tmp, "pilot-data"))
	spec := "# Verification Spec — issue-343\n\n## 2. Checklist\n\n" +
		"| ID | Category | Check | Expected | Command |\n" +
		"|----|----------|-------|----------|---------|\n" + row + "\n"
	if err := os.WriteFile(filepath.Join(tmp, "spec.md"), []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	// Package state the verify entry reads: saved and restored, and set to what
	// this test needs. dataDir (the --data-dir flag) outranks PILOT_DATA_DIR, so a
	// value another test left there would send the evidence run to its directory;
	// verifyDir, verifyProbe and verifyStage would send runVerify to another mode
	// or reject the stage.
	savedRoot, savedReport, savedInv, savedLocal, savedFinish := verifyRoot, verifyReportDir, verifyInventory, verifyLocal, finishVerifyRun
	savedDataDir, savedDir, savedStage, savedProbe := dataDir, verifyDir, verifyStage, verifyProbe
	t.Cleanup(func() {
		verifyRoot, verifyReportDir, verifyInventory, verifyLocal, finishVerifyRun = savedRoot, savedReport, savedInv, savedLocal, savedFinish
		dataDir, verifyDir, verifyStage, verifyProbe = savedDataDir, savedDir, savedStage, savedProbe
	})
	verifyRoot, verifyInventory, verifyLocal = tmp, "", true
	dataDir, verifyDir, verifyStage, verifyProbe = "", "", "", ""
	finishVerifyRun = finish
	return runVerify(nil, []string{"spec.md"})
}

func lastVerifyOutcome(t *testing.T) string {
	t.Helper()
	st, err := openSpecStore()
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runs, err := st.ListRuns(store.RunFilter{Limit: 1})
	if err != nil || len(runs) != 1 {
		t.Fatalf("ListRuns = %v, %v", runs, err)
	}
	return runs[0].Outcome
}
