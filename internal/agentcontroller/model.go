// Package agentcontroller implements the Phase 1 observe-only Incident
// Controller (docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md).
// It normalizes Prometheus-rule and Detection Engine alerts delivered by
// Alertmanager into one incident model, dispatches read-only diagnosis
// requests to an external Agent Runtime, and persists the result. It is
// an incident orchestrator and state store — never a second anomaly
// detector, and it never holds mutation/raw-command MCP capability.
package agentcontroller

import (
	"fmt"
	"time"
)

// IncidentEvent is the canonical internal event produced by normalizing
// one Alertmanager webhook alert (spec §6). Source is either
// "prometheus-rule" or "detection-engine".
type IncidentEvent struct {
	Source      string
	GroupKey    string
	Fingerprint string
	Episode     string
	Status      string // firing | resolved
	AlertName   string
	Severity    string
	Host        string
	Site        string
	Component   string
	Category    string
	StartsAt    time.Time
	EndsAt      *time.Time
	Labels      map[string]string
	Annotations map[string]string
	ReceivedAt  time.Time
	// AlertBodySHA256 hashes this one alert's normalized identity fields
	// (not the whole webhook body) — it is the controller's own replay/
	// dedup key (store.go), independent of Alertmanager's per-request
	// RawBodySHA256 the ingress layer logs (spec §5.7).
	AlertBodySHA256 string
}

// IncidentEnvelopeV1 is the versioned input contract handed to the
// external Agent Runtime (spec §9). DiagnosticPolicy is always
// zero-mutation in Phase 1 — the Agent Runtime must not need to be told
// this out of band, it is part of the wire contract itself.
type IncidentEnvelopeV1 struct {
	SchemaVersion    int                      `json:"schema_version"`
	IncidentID       string                   `json:"incident_id"`
	Source           string                   `json:"source"`
	Status           string                   `json:"status"`
	Alert            IncidentEnvelopeAlert    `json:"alert"`
	DiagnosticPolicy IncidentDiagnosticPolicy `json:"diagnostic_policy"`
}

type IncidentEnvelopeAlert struct {
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	Host      string `json:"host,omitempty"`
	Site      string `json:"site,omitempty"`
	Component string `json:"component,omitempty"`
}

type IncidentDiagnosticPolicy struct {
	MutationAllowed       bool `json:"mutation_allowed"`
	RawCommandAllowed     bool `json:"raw_command_allowed"`
	WorkspaceWriteAllowed bool `json:"workspace_write_allowed"`
}

// NewIncidentEnvelopeV1 builds the fixed, always-zero-mutation envelope
// for one incident (spec §9 — deliberately does not dump the full
// Alertmanager body into the prompt; keeps normalized context small and
// deterministic).
func NewIncidentEnvelopeV1(incidentID string, ev IncidentEvent) IncidentEnvelopeV1 {
	return IncidentEnvelopeV1{
		SchemaVersion: 1,
		IncidentID:    incidentID,
		Source:        ev.Source,
		Status:        ev.Status,
		Alert: IncidentEnvelopeAlert{
			Name:      ev.AlertName,
			Severity:  ev.Severity,
			Host:      ev.Host,
			Site:      ev.Site,
			Component: ev.Component,
		},
		DiagnosticPolicy: IncidentDiagnosticPolicy{
			MutationAllowed:       false,
			RawCommandAllowed:     false,
			WorkspaceWriteAllowed: false,
		},
	}
}

// DiagnosisEvidence names one piece of evidence backing a verdict (spec
// §10) — it must name a Pilot diagnose tool or another immutable
// evidence source, never free prose alone.
type DiagnosisEvidence struct {
	Tool    string `json:"tool"`
	Summary string `json:"summary"`
	Ref     string `json:"ref,omitempty"`
}

// RecommendedAction is advisory-only in Phase 1 — the controller never
// executes it; Phase 3 is what turns a recommendation into a plan.
type RecommendedAction struct {
	Kind      string `json:"kind"`
	Host      string `json:"host,omitempty"`
	Component string `json:"component,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Verdict enum values (spec §10). No prose parser controls incident
// state — only these five values are accepted.
const (
	VerdictExplained            = "explained"
	VerdictProbable             = "probable"
	VerdictInsufficientEvidence = "insufficient_evidence"
	VerdictFalsePositive        = "false_positive"
	VerdictAgentError           = "agent_error"
)

// DiagnosisResult is the ONLY structured output the controller accepts
// from the Agent Runtime (spec §10). A malformed result must become
// AGENT_FAILED, never a partial diagnosis.
type DiagnosisResult struct {
	SchemaVersion          int                 `json:"schema_version"`
	Verdict                string              `json:"verdict"`
	Confidence             float64             `json:"confidence"`
	Summary                string              `json:"summary"`
	SuspectedCause         string              `json:"suspected_cause"`
	Evidence               []DiagnosisEvidence `json:"evidence"`
	RecommendedNextActions []RecommendedAction `json:"recommended_next_actions"`
}

// Validate enforces spec §10's structural rules.
func (r DiagnosisResult) Validate() error {
	switch r.Verdict {
	case VerdictExplained, VerdictProbable, VerdictInsufficientEvidence, VerdictFalsePositive, VerdictAgentError:
	default:
		return fmt.Errorf("diagnosis: invalid verdict %q", r.Verdict)
	}
	if r.Confidence < 0 || r.Confidence > 1 {
		return fmt.Errorf("diagnosis: confidence %v out of [0,1]", r.Confidence)
	}
	if r.Verdict != VerdictAgentError && len(r.Evidence) == 0 {
		return fmt.Errorf("diagnosis: verdict %q requires at least one evidence entry", r.Verdict)
	}
	for i, e := range r.Evidence {
		if e.Tool == "" {
			return fmt.Errorf("diagnosis: evidence[%d] missing tool name", i)
		}
	}
	return nil
}
