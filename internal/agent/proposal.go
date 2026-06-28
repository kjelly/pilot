package agent

import (
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// ProposalStatus values
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"
	StatusApplied  = "applied"
	StatusFailed   = "failed"
)

// RiskLevel values
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// Proposal represents a single AI-suggested action that requires human review.
type Proposal struct {
	ID         string          `json:"id"`
	RunID      string          `json:"run_id"`
	Host       string          `json:"host"`
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	Rationale  string          `json:"rationale"`
	RiskLevel  string          `json:"risk_level"`
	CISControl string          `json:"cis_control,omitempty"`
	Status     string          `json:"status"`
	Reversible bool            `json:"reversible"`
	DryRun     bool            `json:"dry_run,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	ReviewedAt *time.Time      `json:"reviewed_at,omitempty"`
	AppliedAt  *time.Time      `json:"applied_at,omitempty"`
	FilePath   string          `json:"file_path,omitempty"`

	// Pre-flight dry-run output captured before approval
	DryRunOutput string `json:"dry_run_output,omitempty"`
	// Tool result after execution
	ResultContent string `json:"result_content,omitempty"`
	ResultIsError bool   `json:"result_is_error,omitempty"`
}

func NewProposal(runID, host, tool string, args json.RawMessage, rationale, risk, cis string, reversible bool) *Proposal {
	return &Proposal{
		ID:         uuid.NewString(),
		RunID:      runID,
		Host:       host,
		Tool:       tool,
		Args:       args,
		Rationale:  rationale,
		RiskLevel:  risk,
		CISControl: cis,
		Status:     StatusPending,
		Reversible: reversible,
		CreatedAt:  time.Now(),
	}
}

// ToYAML serializes the proposal to a YAML-friendly map for the file artifact.
func (p *Proposal) ToFileMap() map[string]any {
	m := map[string]any{
		"id":         p.ID,
		"run_id":     p.RunID,
		"host":       p.Host,
		"tool":       p.Tool,
		"args":       json.RawMessage(p.Args),
		"rationale":  p.Rationale,
		"risk_level": p.RiskLevel,
		"status":     p.Status,
		"reversible": p.Reversible,
		"created_at": p.CreatedAt.Format(time.RFC3339),
	}
	if p.CISControl != "" {
		m["cis_control"] = p.CISControl
	}
	if p.DryRunOutput != "" {
		m["dry_run_output"] = p.DryRunOutput
	}
	return m
}

// FilePathFor builds the on-disk path for a proposal artifact.
func FilePathFor(dataDir, proposalID string) string {
	return filepath.Join(dataDir, "proposals", proposalID+".yaml")
}
