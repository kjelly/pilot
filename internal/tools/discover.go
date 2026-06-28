package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anomalyco/pilot/internal/docs"
)

// DiscoverTool is the first-turn "guide me" tool. Instead of letting
// the LLM fumble when a user says something vague like "help me
// harden this box", it returns a structured set of clarifying
// questions the LLM can then pass to ask_user.
//
// The questions are pre-baked — the LLM doesn't generate them, because
// that opens the door to prompt injection. We give the LLM a small,
// curated decision tree of the four most common first-turn forks:
//   1. What scope (read-only audit vs. active hardening)
//   2. Which CIS profile level (Level 1 vs. Level 2)
//   3. Which focus area (network / accounts / packages / logging)
//   4. Whether the user wants InSpec scan first or wants the LLM to
//      jump straight to playbook generation.
//
// The tool reads nothing from disk and asks nothing of the human —
// it is purely a planning aid the LLM uses to drive ask_user.
type DiscoverTool struct {
	// ModuleIndex is consulted so the LLM can also see which modules
	// are available (so the discovery prompt can mention them).
	// Optional.
	ModuleIndex *docs.ModuleIndex
}

var discoverArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "stage": {
      "type": "string",
      "enum": ["initial", "followup"],
      "description": "Stage of the conversation. 'initial' is the first turn after the user's vague goal. 'followup' is mid-conversation when more decisions are needed."
    }
  }
}`)

func (t *DiscoverTool) Spec() *Spec {
	return &Spec{
		Name:        "discover",
		Description: "Returns a structured list of clarifying questions to ask the user when their goal is vague (e.g. 'help me harden this box'). Use this tool on the first turn whenever the user has not specified: (a) whether they want read-only audit or active hardening, (b) which CIS profile / level, (c) which focus area, (d) whether to start with an InSpec scan. Pass each question to ask_user next.",
		RiskLevel:   "none",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  discoverArgs,
	}
}

type DiscoverQuestion struct {
	ID       string   `json:"id"`
	Question string   `json:"question"`
	Options  []string `json:"options,omitempty"`
	// Why is a brief hint the LLM can echo to the user.
	Why string `json:"why,omitempty"`
}

type DiscoverOutput struct {
	Questions []DiscoverQuestion `json:"questions"`
	// SuggestedNextTools is the action plan after the user answers.
	SuggestedNextTools []ToolSuggestion `json:"suggested_next_tools"`
}

type ToolSuggestion struct {
	Tool      string `json:"tool"`
	Rationale string `json:"rationale"`
}

func (t *DiscoverTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Stage string `json:"stage"`
	}
	_ = json.Unmarshal(args, &a)
	if a.Stage == "followup" {
		return &Result{Content: followupDiscoveryJSON()}, nil
	}
	return &Result{Content: initialDiscoveryJSON()}, nil
}

func initialDiscoveryJSON() string {
	out := DiscoverOutput{
		Questions: []DiscoverQuestion{
			{
				ID:       "scope",
				Question: "What kind of help do you want for this host?",
				Options:  []string{"Read-only audit", "Active hardening", "Rollback a previous change"},
				Why:      "Read-only audit runs InSpec and reports findings. Active hardening proposes and (after y/N) applies Ansible playbooks. Rollback inverts a previous change.",
			},
			{
				ID:       "cis_level",
				Question: "Which CIS hardening target?",
				Options:  []string{"CIS Ubuntu 22.04 Level 1", "CIS Ubuntu 22.04 Level 2", "CIS Ubuntu 20.04 Level 1", "Skip CIS, custom goal"},
				Why:      "Level 1 = practical baseline (most teams). Level 2 = defence-in-depth (often breaks usability). 22.04 vs 20.04 picks the matching InSpec profile.",
			},
			{
				ID:       "focus",
				Question: "Which area should we focus on first?",
				Options:  []string{"Network (firewall, SSH)", "Accounts & sudo", "Packages & updates", "Logging & auditing", "All of the above"},
				Why:      "Doing them all at once is slower and the diff is harder to review. Pick the highest-priority area first; you can re-run for the others.",
			},
			{
				ID:       "first_action",
				Question: "How should we start?",
				Options:  []string{"Run InSpec scan first", "Skip scan, generate playbook now"},
				Why:      "InSpec gives a concrete list of failing controls, so the LLM can target real gaps instead of guessing. Skipping the scan is fine for routine tasks.",
			},
		},
		SuggestedNextTools: []ToolSuggestion{
			{Tool: "ask_user", Rationale: "Pose the four questions above (one call per question, or batch by passing the same question text)."},
			{Tool: "run_inspec", Rationale: "After 'first_action' = scan, run the InSpec profile matching the chosen CIS level."},
			{Tool: "search_docs", Rationale: "Use this to look up module parameters before generating playbooks."},
			{Tool: "generate_playbook", Rationale: "Once you have a concrete failing control, generate a single-task playbook for it."},
		},
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

func followupDiscoveryJSON() string {
	out := DiscoverOutput{
		Questions: []DiscoverQuestion{
			{
				ID:       "apply_mode",
				Question: "Apply mode for the proposed playbooks?",
				Options:  []string{"Check-only (no changes, just diff)", "Apply (writes after y/N)", "Save playbook to disk for manual review"},
				Why:      "Check-only is the safest first run; apply is the normal mode once you've reviewed the diff.",
			},
			{
				ID:       "blast_radius",
				Question: "Target host scope?",
				Options:  []string{"localhost only", "Inventory group / host pattern"},
				Why:      "Limiting scope reduces accidental blast radius.",
			},
		},
		SuggestedNextTools: []ToolSuggestion{
			{Tool: "run_ansible", Rationale: "Use the chosen apply mode (check=true for first run)."},
		},
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}

// Compile-time guard so unused imports surface if we shrink the file.
var _ = fmt.Sprintf
var _ = strings.TrimSpace
