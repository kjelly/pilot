// edit_workspace_apply.go is pilot_edit_apply's engine — Phase 2's
// planEditScenario against a temp copy, mirrored for real: dir is
// mutated directly, under a mutation lock, with an in-memory
// before-snapshot that a mid-scenario failure rolls back to.
package cmd

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/inventory"
)

// editApplyResult is what an apply attempt produces — success or a
// clean rollback are both represented here (rollback is a well-defined
// recovery outcome, not a Go error, per spec AC8); only a genuinely
// broken state (lock busy, rollback itself failing to restore) returns
// a non-nil error instead.
type editApplyResult struct {
	RevisionBefore string
	RevisionAfter  string
	AffectedFiles  []string
	Diff           string
	RedactedDiff   bool
	Blocking       []string
	Warnings       []string
	RolledBack     bool
	// ScenarioErr is the automation driver's error when the scenario
	// failed partway (nil on success). Only meaningful when RolledBack
	// is true.
	ScenarioErr error
	// Before/After are the managed-file snapshots audit artifacts need
	// (managed-files-before.json/managed-files-after.json). For a
	// rolled-back apply After is dir as the rollback left it: Before,
	// except for the rosters another pilot process changed meanwhile,
	// whose change the rollback kept (listed in Warnings) — the state
	// RevisionAfter is the revision of.
	Before []managedFileEntry
	After  []managedFileEntry
}

// revisionWith is the revision of snapshot with the files named in kept as
// they are in now — what a rollback that kept those must produce.
func revisionWith(snapshot, now []managedFileEntry, kept []string) string {
	if len(kept) == 0 {
		return revisionOfEntries(snapshot)
	}
	keep := map[string]bool{}
	for _, rel := range kept {
		keep[rel] = true
	}
	var want []managedFileEntry
	for _, e := range snapshot {
		if !keep[e.RelPath] {
			want = append(want, e)
		}
	}
	for _, e := range now {
		if keep[e.RelPath] {
			want = append(want, e)
		}
	}
	sort.Slice(want, func(i, j int) bool { return want[i].RelPath < want[j].RelPath })
	return revisionOfEntries(want)
}

// applyEditScenario validates scenario, then runs it against dir for
// real — under an exclusive workspace lock (acquireWorkspaceLock) so
// only one apply session touches dir at a time. If the scenario fails
// partway, dir is restored to its exact pre-apply state
// (restoreManagedFiles) and the failure is reported as a rolled-back
// result rather than a bare error — but for rosters another pilot process
// changed meanwhile: the rollback undoes only the session's own writes to
// them, recorded by a RosterJournal opened on .vault/ before the scenario
// runs, keeps the other process's change (Warnings), and returns an error
// naming any roster it cannot safely restore, for a hand check.
func applyEditScenario(dir, sessionID string, scenario editScenario, opts editAgentSessionOptions) (*editApplyResult, error) {
	if err := validateInventorySecretStorage(dir); err != nil {
		return nil, err
	}
	if err := validateEditScenario(scenario); err != nil {
		return nil, err
	}

	lock, err := acquireWorkspaceLock(dir, sessionID)
	if err != nil {
		return nil, err
	}
	defer lock.release() //nolint:errcheck

	revisionBefore, err := computeWorkspaceRevision(dir)
	if err != nil {
		return nil, err
	}
	snapshot, err := managedFileEntries(dir)
	if err != nil {
		return nil, err
	}

	// Every roster write the session makes to its .vault/ files, recorded
	// where it is written (writeLockedRoster), so a rollback undoes exactly
	// that: rosters have writers outside this lock (restoreManagedFiles).
	journal, err := openSessionRosterJournal(dir, snapshot)
	if err != nil {
		return nil, err
	}
	defer journal.Close()
	// Which .vault/ files changed while a step ran, by anyone: a roster
	// that did without a recorded write cannot be attributed.
	touched, last := map[string]bool{}, map[string][]byte{}
	before := opts.BeforeStep
	opts.BeforeStep = func() {
		last = secretFileContents(dir)
		if before != nil {
			before()
		}
	}
	trace := opts.Trace
	opts.Trace = func(event automationTraceEvent) {
		noteSessionWrites(dir, last, touched)
		if trace != nil {
			trace(event)
		}
	}

	opts.Transaction = true
	session := newEditAgentSession(dir, opts)
	run, runErr := session.Run(scenario)
	if runErr == nil {
		runErr = validateInventorySecretStorage(dir)
	}

	if runErr != nil {
		// The rollback's own writes are not the session's.
		journal.Close()
		report, restoreErr := restoreManagedFiles(dir, snapshot, &sessionRosterWrites{writes: journal.Writes(), touched: touched})
		if restoreErr != nil {
			return nil, fmt.Errorf("apply failed (%v) and rollback also failed: %w", runErr, restoreErr)
		}
		if len(report.left) > 0 {
			kept := ""
			if len(report.notes) > 0 {
				kept = "; kept: " + strings.Join(report.notes, "; ")
			}
			return nil, fmt.Errorf("apply failed (%v); rolled back everything except %s; check each by hand — it may hold this apply's changes, another pilot process's, or both — and make sure its freeipa.admin.password equals .vault/main.yaml's ipa_admin_password%s", runErr, strings.Join(report.left, ", "), kept)
		}
		afterRollback, err := managedFileEntries(dir)
		if err != nil {
			return nil, fmt.Errorf("apply failed (%v); rollback revision verification failed: %w", runErr, err)
		}
		revisionAfterRollback := revisionOfEntries(afterRollback)
		// The rosters another writer changed meanwhile are theirs: the
		// rollback must have restored everything else exactly.
		if revisionAfterRollback != revisionWith(snapshot, afterRollback, report.kept) {
			return nil, fmt.Errorf("apply failed (%v); rollback did not restore the original revision (before=%s, after=%s)", runErr, revisionBefore, revisionAfterRollback)
		}
		return &editApplyResult{
			RevisionBefore: revisionBefore,
			RevisionAfter:  revisionAfterRollback,
			Warnings:       report.notes,
			RolledBack:     true,
			ScenarioErr:    runErr,
			Before:         snapshot,
			After:          afterRollback,
		}, nil
	}

	after, err := managedFileEntries(dir)
	if err != nil {
		return nil, err
	}
	diff, affected, redacted := diffEntries(snapshot, after)
	blocking, warnings := collectWorkspaceValidation(dir)
	warnings = append(warnings, run.Warnings...)
	revisionAfter, err := computeWorkspaceRevision(dir)
	if err != nil {
		return nil, err
	}

	return &editApplyResult{
		RevisionBefore: revisionBefore,
		RevisionAfter:  revisionAfter,
		AffectedFiles:  affected,
		Diff:           diff,
		RedactedDiff:   redacted,
		Blocking:       blocking,
		Warnings:       warnings,
		RolledBack:     false,
		Before:         snapshot,
		After:          after,
	}, nil
}

// openSessionRosterJournal starts recording the roster writes an apply on
// dir makes to its managed .vault/ files: every file directly in .vault/,
// and the file each of the snapshot's .vault/ entries names (a .vault/
// symlink to a roster kept elsewhere). Another apply in this process
// already recording one of them refuses this one before it writes
// anything (inventory.ErrRosterJournalBusy).
func openSessionRosterJournal(dir string, snapshot []managedFileEntry) (*inventory.RosterJournal, error) {
	var targets []string
	for _, e := range snapshot {
		if e.IsSecret {
			targets = append(targets, filepath.Join(dir, filepath.FromSlash(e.RelPath)))
		}
	}
	journal, err := inventory.JournalRosterWrites(targets, []string{filepath.Join(dir, ".vault")})
	if err != nil {
		return nil, fmt.Errorf("apply refused, nothing written: %w", err)
	}
	return journal, nil
}
