// edit_workspace_apply.go is pilot_edit_apply's engine — Phase 2's
// planEditScenario against a temp copy, mirrored for real: dir is
// mutated directly, under a mutation lock, with an in-memory
// before-snapshot that a mid-scenario failure rolls back to.
package cmd

import "fmt"

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
	Blocking       []string
	Warnings       []string
	RolledBack     bool
	// ScenarioErr is the automation driver's error when the scenario
	// failed partway (nil on success). Only meaningful when RolledBack
	// is true.
	ScenarioErr error
	// Before/After are the managed-file snapshots audit artifacts need
	// (managed-files-before.json/managed-files-after.json) — for a
	// rolled-back apply, After equals Before, since that's what dir was
	// restored to.
	Before []managedFileEntry
	After  []managedFileEntry
}

// applyEditScenario validates scenario, then runs it against dir for
// real — under an exclusive workspace lock (acquireWorkspaceLock) so
// only one apply session touches dir at a time. If the scenario fails
// partway, dir is restored to its exact pre-apply state
// (restoreManagedFiles) and the failure is reported as a rolled-back
// result rather than a bare error.
func applyEditScenario(dir, sessionID string, scenario editScenario, opts editAgentSessionOptions) (*editApplyResult, error) {
	if err := validateEditScenario(scenario); err != nil {
		return nil, err
	}

	lock, err := acquireWorkspaceLock(dir, sessionID)
	if err != nil {
		return nil, err
	}
	defer lock.release()

	revisionBefore, err := computeWorkspaceRevision(dir)
	if err != nil {
		return nil, err
	}
	snapshot, err := managedFileEntries(dir)
	if err != nil {
		return nil, err
	}

	session := newEditAgentSession(dir, opts)
	runErr := session.Run(scenario)

	if runErr != nil {
		if restoreErr := restoreManagedFiles(dir, snapshot); restoreErr != nil {
			return nil, fmt.Errorf("apply failed (%v) and rollback also failed: %w", runErr, restoreErr)
		}
		revisionAfterRollback, err := computeWorkspaceRevision(dir)
		if err != nil {
			return nil, fmt.Errorf("apply failed (%v); rollback revision verification failed: %w", runErr, err)
		}
		if revisionAfterRollback != revisionBefore {
			return nil, fmt.Errorf("apply failed (%v); rollback did not restore the original revision (before=%s, after=%s)", runErr, revisionBefore, revisionAfterRollback)
		}
		return &editApplyResult{
			RevisionBefore: revisionBefore,
			RevisionAfter:  revisionAfterRollback,
			RolledBack:     true,
			ScenarioErr:    runErr,
			Before:         snapshot,
			After:          snapshot,
		}, nil
	}

	after, err := managedFileEntries(dir)
	if err != nil {
		return nil, err
	}
	diff, affected := diffEntries(snapshot, after)
	blocking, warnings := collectWorkspaceValidation(dir)
	revisionAfter, err := computeWorkspaceRevision(dir)
	if err != nil {
		return nil, err
	}

	return &editApplyResult{
		RevisionBefore: revisionBefore,
		RevisionAfter:  revisionAfter,
		AffectedFiles:  affected,
		Diff:           diff,
		Blocking:       blocking,
		Warnings:       warnings,
		RolledBack:     false,
		Before:         snapshot,
		After:          after,
	}, nil
}
