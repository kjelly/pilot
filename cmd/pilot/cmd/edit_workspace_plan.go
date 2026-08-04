// edit_workspace_plan.go ties workspace revision, temp copy,
// editAgentSession, validation, and diff together into the engine
// behind the spec's future `pilot_edit_plan` MCP tool. This file has no
// CLI or MCP surface yet — Phase 3+ wires planEditScenario up to an
// actual tool; this is purely the capability.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/kjelly/pilot/internal/inventory"
)

// editPlanResult is what a plan run produces — the in-memory
// counterpart of the spec's `pilot_edit_plan` JSON output, minus the
// audit-artifact fields Phase 2 doesn't write yet.
type editPlanResult struct {
	BaseRevision  string
	AffectedFiles []string
	Diff          string
	Blocking      []string
	Warnings      []string
}

// planEditScenario validates scenario, runs it against a disposable
// copy of dir's managed files (never dir itself), and reports what
// would change plus any completeness/lint findings on the result.
//
// Every write scenario.Steps causes happens inside a temp copy built by
// copyManagedFilesToTemp — dir is only ever read (by
// computeWorkspaceRevision and diffManagedFiles), never written to
// here, matching the spec's "Plan 不得修改真實 workspace" invariant
// (AC4). opts is passed straight through to newEditAgentSession — a
// caller that wants trace.jsonl/session.cast output (e.g. the MCP plan
// tool) sets opts.Trace/opts.Recorder; the zero value behaves exactly
// like a bare recorder-less session (every field defaults to a no-op).
func planEditScenario(dir string, scenario editScenario, opts editAgentSessionOptions) (*editPlanResult, error) {
	if err := validateEditScenario(scenario); err != nil {
		return nil, err
	}

	baseRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		return nil, err
	}

	tempDir, cleanup, err := copyManagedFilesToTemp(dir)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	session := newEditAgentSession(tempDir, opts)
	if err := session.Run(scenario); err != nil {
		return nil, fmt.Errorf("plan scenario: %w", err)
	}

	blocking, warnings := collectWorkspaceValidation(tempDir)

	patch, affected, err := diffManagedFiles(dir, tempDir)
	if err != nil {
		return nil, err
	}

	// AC4 defense-in-depth: a bug that accidentally pointed the session
	// at dir instead of tempDir would otherwise only be caught by a
	// test noticing dir changed — assert it here too, every time.
	afterRevision, err := computeWorkspaceRevision(dir)
	if err != nil {
		return nil, err
	}
	if afterRevision != baseRevision {
		return nil, fmt.Errorf("internal error: plan mutated the real workspace (revision %s -> %s); this must never happen", baseRevision, afterRevision)
	}

	return &editPlanResult{
		BaseRevision:  baseRevision,
		AffectedFiles: affected,
		Diff:          patch,
		Blocking:      blocking,
		Warnings:      warnings,
	}, nil
}

// collectWorkspaceValidation runs the same completeness sweep and lint pass
// a real save already goes through (checkWorkspaceCompleteness,
// inventory.Lint — see saveHosts) against dir, splitting results into
// blocking vs. warning by severity.
func collectWorkspaceValidation(dir string) (blocking, warnings []string) {
	for _, c := range checkWorkspaceCompleteness(dir) {
		if c.OK {
			continue
		}
		for _, d := range c.Details {
			blocking = append(blocking, fmt.Sprintf("%s: %s", c.Label, d))
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		return blocking, warnings
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return blocking, warnings
	}
	for _, issue := range inventory.Lint(hf) {
		if issue.Severity == "warning" {
			warnings = append(warnings, issue.String())
		} else {
			blocking = append(blocking, issue.String())
		}
	}
	return blocking, warnings
}
