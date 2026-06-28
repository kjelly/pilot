package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/anomalyco/pilot/internal/store"
)

// SummarizeRunTool produces a structured end-of-run report from the
// audit trail stored in SQLite. The LLM is expected to call this
// after it has decided its work is done; the returned JSON is what
// the agent loop surfaces to the user as the task's official summary.
//
// This addresses the "I have no idea what just happened" problem
// users hit when the run is over and they're staring at 200 lines of
// chat history. Instead they get:
//
//   - goal + outcomes (plain text)
//   - files changed (audit trail)
//   - CIS controls addressed
//   - counts of proposals approved / rejected / failed
//   - concrete next-step suggestions
type SummarizeRunTool struct {
	Store *store.Store
}

var summarizeRunArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "run_id": {
      "type": "string",
      "description": "The run id to summarise. If omitted, the most recent run for this session is used."
    },
    "outcome": {
      "type": "string",
      "description": "One-line summary the LLM composed for this run, e.g. 'Hardened sshd_config and restarted sshd'."
    }
  }
}`)

func (t *SummarizeRunTool) Spec() *Spec {
	return &Spec{
		Name: "summarize_run",
		Description: "Produce a structured end-of-run summary from the audit log (SQLite). Call this as the LAST tool call when you believe the user's goal has been achieved. The output is rendered to the user as the task summary. Do NOT call this for intermediate steps — only when the task is genuinely done.",
		RiskLevel:    "none",
		Reversible:   true,
		DryRunSafe:   true,
		Parameters:   summarizeRunArgs,
	}
}

type RunSummary struct {
	RunID             string   `json:"run_id"`
	StartedAt         string   `json:"started_at,omitempty"`
	FinishedAt        string   `json:"finished_at,omitempty"`
	Status            string   `json:"status"`
	Goal              string   `json:"goal,omitempty"`
	Outcome           string   `json:"outcome,omitempty"`
	FilesChanged      []string `json:"files_changed,omitempty"`
	CISAddressed      []string `json:"cis_addressed,omitempty"`
	ProposalsTotal    int      `json:"proposals_total"`
	ProposalsApproved int      `json:"proposals_approved"`
	ProposalsRejected int      `json:"proposals_rejected"`
	ProposalsFailed   int      `json:"proposals_failed"`
	ProposalsApplied  int      `json:"proposals_applied"`
	NextSteps         []string `json:"next_steps,omitempty"`
}

func (t *SummarizeRunTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		RunID   string `json:"run_id"`
		Outcome string `json:"outcome"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("summarize_run: invalid args: %w", err)
	}
	if t.Store == nil {
		return &Result{Content: "ERROR: store not configured", IsError: true}, nil
	}

	runID := a.RunID
	if runID == "" {
		runs, err := t.Store.ListRuns("", 1)
		if err != nil || len(runs) == 0 {
			return &Result{Content: "ERROR: no runs available; specify run_id", IsError: true}, nil
		}
		runID = runs[0].ID
	}

	run, err := t.Store.GetRun(runID)
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: run %s not found: %v", runID, err), IsError: true}, nil
	}
	proposals, err := t.Store.ListProposals(runID)
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: list proposals: %v", err), IsError: true}, nil
	}

	summary := buildRunSummary(run, proposals, a.Outcome)

	out, _ := json.MarshalIndent(summary, "", "  ")
	return &Result{Content: string(out)}, nil
}

// buildRunSummary aggregates the run + proposals into the structured
// RunSummary. Pure function — used by tests too.
func buildRunSummary(run *store.Run, proposals []*store.Proposal, outcome string) RunSummary {
	s := RunSummary{
		RunID:   run.ID,
		Status:  run.Status,
		Goal:    run.Playbook, // closest thing the store has to a "goal" string
		Outcome: outcome,
	}
	if !run.StartedAt.IsZero() {
		s.StartedAt = run.StartedAt.UTC().Format("2006-01-02T15:04:05Z")
	}
	if run.FinishedAt != nil {
		s.FinishedAt = run.FinishedAt.UTC().Format("2006-01-02T15:04:05Z")
	}

	fileset := map[string]struct{}{}
	cisset := map[string]struct{}{}
	for _, p := range proposals {
		s.ProposalsTotal++
		switch p.Status {
		case "approved", "applied":
			s.ProposalsApproved++
		case "rejected":
			s.ProposalsRejected++
		case "failed":
			s.ProposalsFailed++
		}
		if p.Status == "applied" {
			s.ProposalsApplied++
		}
		// Extract file paths from proposals whose args reference them.
		// Cheap heuristic: scan the args JSON for any string that looks
		// like a path under /etc, /var, /opt, /tmp.
		collectFilesFromArgs(p.Args, fileset)
		if p.CISControl != "" {
			cisset[p.CISControl] = struct{}{}
		}
	}
	for f := range fileset {
		s.FilesChanged = append(s.FilesChanged, f)
	}
	for c := range cisset {
		s.CISAddressed = append(s.CISAddressed, c)
	}
	sort.Strings(s.FilesChanged)
	sort.Strings(s.CISAddressed)

	// Build next-step suggestions based on what happened.
	switch {
	case s.ProposalsFailed > 0:
		s.NextSteps = append(s.NextSteps, fmt.Sprintf("Re-run the %d failed proposals after addressing the error.", s.ProposalsFailed))
	}
	if s.ProposalsApproved > s.ProposalsApplied {
		s.NextSteps = append(s.NextSteps, fmt.Sprintf("Run `pilot show-plan %s` to confirm %d approved proposals are applied.", run.ID, s.ProposalsApproved-s.ProposalsApplied))
	}
	if s.FilesChanged != nil {
		s.NextSteps = append(s.NextSteps, "Run `pilot run inspec` against the target host to verify compliance.")
	}
	if s.CISAddressed != nil {
		s.NextSteps = append(s.NextSteps, "Append this run's audit trail to your compliance report.")
	}
	if len(s.NextSteps) == 0 {
		s.NextSteps = []string{"No further action required."}
	}
	return s
}

// collectFilesFromArgs scans an args JSON blob for path-shaped strings.
// Cheap heuristic — we don't try to interpret the schema per tool.
func collectFilesFromArgs(raw json.RawMessage, out map[string]struct{}) {
	if len(raw) == 0 {
		return
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return
	}
	walkStrings(v, out)
}

func walkStrings(v any, out map[string]struct{}) {
	switch x := v.(type) {
	case string:
		if looksLikePath(x) {
			out[x] = struct{}{}
		}
	case []any:
		for _, e := range x {
			walkStrings(e, out)
		}
	case map[string]any:
		for _, e := range x {
			walkStrings(e, out)
		}
	}
}

func looksLikePath(s string) bool {
	// Heuristic: starts with /, has at least one more segment, and is
	// under a "system" directory we care about. We avoid sweeping in
	// /usr/bin or other huge trees.
	switch {
	case strings.HasPrefix(s, "/etc/"):
		return true
	case strings.HasPrefix(s, "/var/log/"):
		return true
	case strings.HasPrefix(s, "/opt/"):
		return true
	case strings.HasPrefix(s, "/tmp/pilot/"):
		return true
	}
	return false
}

// Compile-time check that store is used (avoid an unused-import lint
// if we later refactor).
var _ = store.Proposal{}
