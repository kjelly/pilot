package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/anomalyco/pilot/internal/store"
)

// PlanOperationsTool submits a batch of operations for human approval
// as a single plan. The tool creates a Plan record in the audit log,
// then surfaces it to the human via the Approver. If approved, the
// agent loop executes each operation in sequence (with auto-approval
// for that phase).
type PlanOperationsTool struct {
	Store *store.Store
}

type planOperation struct {
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	Host       string          `json:"host,omitempty"`
	Rationale  string          `json:"rationale"`
	RiskLevel  string          `json:"risk_level,omitempty"`
	CISControl string          `json:"cis_control,omitempty"`
}

type planArgsStruct struct {
	Title      string          `json:"title"`
	Summary    string          `json:"summary"`
	Operations []planOperation `json:"operations"`
}

func (t *PlanOperationsTool) Spec() *Spec {
	return &Spec{
		Name: "plan_operations",
		Description: "Submit a batch of operations for human review as a single plan. The human sees the entire list at once and either approves or rejects the whole plan. Approved plans are then executed sequentially. Use this when a complex task would generate many individual tool calls.",
		RiskLevel: "low", // doesn't actually mutate; just creates a Plan record
		Reversible: true,
		DryRunSafe: true,
		Parameters: planOperationsArgs,
	}
}

func (t *PlanOperationsTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a planArgsStruct
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("plan_operations: invalid args: %w", err)
	}
	if a.Title == "" {
		return nil, fmt.Errorf("plan_operations: title is required")
	}
	if len(a.Operations) == 0 {
		return nil, fmt.Errorf("plan_operations: at least one operation is required")
	}
	if t.Store == nil {
		return &Result{Content: "ERROR: store not configured", IsError: true}, nil
	}

	// Convert to store.PlanOperation.
	ops := make([]store.PlanOperation, 0, len(a.Operations))
	for i, op := range a.Operations {
		if op.Tool == "" {
			return &Result{Content: fmt.Sprintf("ERROR: operation #%d is missing 'tool'", i), IsError: true}, nil
		}
		risk := strings.ToLower(op.RiskLevel)
		if risk != "low" && risk != "medium" && risk != "high" {
			risk = "medium"
		}
		ops = append(ops, store.PlanOperation{
			Tool:       op.Tool,
			Args:       op.Args,
			Host:       op.Host,
			Rationale:  op.Rationale,
			RiskLevel:  risk,
			CISControl: op.CISControl,
		})
	}

	plan := &store.Plan{
		ID:         uuid.NewString(),
		RunID:      "", // set by the caller via UpdatePlan or by the loop
		Title:      a.Title,
		Summary:    a.Summary,
		Operations: ops,
		Status:     "pending",
	}
	if err := t.Store.CreatePlan(plan); err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: create plan: %v", err), IsError: true}, nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "Plan submitted for approval.\n\n")
	fmt.Fprintf(&sb, "ID:       %s\n", plan.ID)
	fmt.Fprintf(&sb, "Title:    %s\n", plan.Title)
	if plan.Summary != "" {
		fmt.Fprintf(&sb, "Summary:  %s\n", plan.Summary)
	}
	fmt.Fprintf(&sb, "Operations (%d):\n", len(ops))
	for i, op := range ops {
		fmt.Fprintf(&sb, "  [%d] %s — %s\n", i+1, op.Tool, op.Rationale)
	}
	fmt.Fprintf(&sb, "\nUse `pilot show-plan %s` to inspect.\n", plan.ID)
	return &Result{Content: sb.String()}, nil
}

var planOperationsArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "title": {
      "type": "string",
      "description": "Short title for the plan (e.g. 'Disable root SSH and restart sshd')."
    },
    "summary": {
      "type": "string",
      "description": "1-3 sentence rationale for the plan as a whole."
    },
    "operations": {
      "type": "array",
      "description": "Ordered list of operations to execute.",
      "items": {
        "type": "object",
        "properties": {
          "tool": {"type": "string", "description": "Tool name (e.g. 'run_ansible', 'read_file')."},
          "args": {"type": "object", "description": "Tool args as JSON."},
          "host": {"type": "string", "description": "Optional target host for Ansible proposals."},
          "rationale": {"type": "string", "description": "Why this operation is part of the plan."},
          "risk_level": {"type": "string", "description": "low | medium | high (defaults to medium)."},
          "cis_control": {"type": "string"}
        },
        "required": ["tool", "args", "rationale"]
      }
    }
  },
  "required": ["title", "operations"]
}`)
