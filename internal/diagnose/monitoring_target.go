package diagnose

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// DiagnosticQuery is one named, fixed PromQL template in a diagnostic
// profile (spec §10.5) — never arbitrary caller-supplied PromQL. Target
// name and window/topN are substituted via fixed placeholder tokens,
// never string-concatenated without escaping (spec §10.5: "不得以字串
// 串接未 escape 的 target").
type DiagnosticQuery struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	PromQL      string `yaml:"promql"`
}

// DiagnosticProfile is the parsed form of a
// monitoring/snmp/diagnostic-profiles/*.yaml query pack.
type DiagnosticProfile struct {
	ID      string            `yaml:"id"`
	Queries []DiagnosticQuery `yaml:"queries"`
}

// LoadDiagnosticProfile reads and parses one diagnostic profile file.
func LoadDiagnosticProfile(path string) (DiagnosticProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return DiagnosticProfile{}, fmt.Errorf("read diagnostic profile %s: %w", path, err)
	}
	var p DiagnosticProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return DiagnosticProfile{}, fmt.Errorf("parse diagnostic profile %s: %w", path, err)
	}
	if p.ID == "" || len(p.Queries) == 0 {
		return DiagnosticProfile{}, fmt.Errorf("diagnostic profile %s: id and at least one query are required", path)
	}
	return p, nil
}

// escapePromQLLabelValue defensively escapes a label value for
// embedding inside a PromQL `"..."` matcher. Exact target names are
// already constrained to internal/monitoring's targetNamePattern
// (no quotes/backslashes possible), so this never actually changes a
// real target name — it exists so a future looser name grammar can
// never silently reopen a PromQL injection.
func escapePromQLLabelValue(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// MonitoringTargetDiagnosisSteps renders profile's query pack into
// bounded ad-hoc steps against Thanos Query's own Prometheus-compatible
// API (the same endpoint/mechanism MetricsSteps uses) — target/window/
// topN are substituted via fixed placeholder tokens the profile YAML
// declares, never raw string concatenation of caller input into a
// hand-built query. window/topN are the CALLER's bounded input (already
// clamped by the MCP tool layer to spec §10.4's window<=6h/topN<=20
// before this function ever sees them).
func MonitoringTargetDiagnosisSteps(profile DiagnosticProfile, target, window string, topN int) []Step {
	escaped := escapePromQLLabelValue(target)
	steps := make([]Step, 0, len(profile.Queries))
	for _, q := range profile.Queries {
		query := strings.NewReplacer(
			"__TARGET__", escaped,
			"__WINDOW__", window,
			"__TOPN__", fmt.Sprintf("%d", topN),
		).Replace(q.PromQL)
		url := fmt.Sprintf("http://127.0.0.1:%d/api/v1/query", thanosQueryPort)
		steps = append(steps, Step{
			ID:          q.Name,
			Description: q.Description,
			Module:      "command",
			Command:     curlQueryCommand(url, [][2]string{{"query", query}}),
		})
	}
	return steps
}

// DiagnosisSubject mirrors internal/agentcontroller.IncidentSubject's
// shape (spec §10.1) without importing that package — agentcontroller
// already depends on internal/repair, which depends on
// internal/diagnose, so the reverse import here would be a cycle. Both
// types exist to satisfy the exact same spec §4 invariant (generic,
// non-inventable subject identity); keep them in lockstep by hand if
// either one's fields change.
type DiagnosisSubject struct {
	ID      string `json:"id,omitempty"`
	Kind    string `json:"kind,omitempty"`
	Site    string `json:"site,omitempty"`
	Managed bool   `json:"managed"`
}

// ScrapeHealth summarizes target_up/scrape_duration_seconds (spec §10.4).
type ScrapeHealth struct {
	Up                bool    `json:"up"`
	ScrapeDurationSec float64 `json:"scrape_duration_seconds,omitempty"`
}

// MetricFact is one scalar/vector fact pulled from a query-pack result
// (spec §10.4) — never the full raw Thanos JSON response, only a
// sanitized summary plus a reference to the stored raw evidence.
type MetricFact struct {
	Value float64 `json:"value"`
	Unit  string  `json:"unit,omitempty"`
}

// InterfaceSummary bounds interface-level facts to at most TopN entries
// each (spec §10.4) — never the full per-interface time series.
type InterfaceSummary struct {
	AdminUpOperDown   []string `json:"admin_up_oper_down,omitempty"`
	TopInputErrors    []string `json:"top_input_errors,omitempty"`
	TopOutputErrors   []string `json:"top_output_errors,omitempty"`
	TopInputDiscards  []string `json:"top_input_discards,omitempty"`
	TopOutputDiscards []string `json:"top_output_discards,omitempty"`
}

// SignalSummary is a bounded reference to an active Detection Engine
// SignalEvent for this subject (spec §10.4) — never the full signal
// history.
type SignalSummary struct {
	SignalID string  `json:"signal_id"`
	Category string  `json:"category,omitempty"`
	Score    float64 `json:"score,omitempty"`
}

// DiagnosisEvidence records one query-pack call's provenance (spec
// §10.4: "每項 evidence MUST 記錄 tool/query-pack name、query time range、
// subject ID、sanitized summary、reference to raw bounded response").
type DiagnosisEvidence struct {
	Tool      string `json:"tool"`
	QueryName string `json:"query_name"`
	Window    string `json:"window,omitempty"`
	SubjectID string `json:"subject_id"`
	Summary   string `json:"summary"`
	Ref       string `json:"ref,omitempty"`
}

// MonitoringTargetDiagnosis is pilot_diagnose_monitoring_target's
// structured output (spec §10.4).
type MonitoringTargetDiagnosis struct {
	Subject       DiagnosisSubject      `json:"subject"`
	Profile       string                `json:"profile"`
	Scrape        ScrapeHealth          `json:"scrape"`
	Device        map[string]MetricFact `json:"device,omitempty"`
	Interfaces    InterfaceSummary      `json:"interfaces,omitempty"`
	ActiveSignals []SignalSummary       `json:"active_signals,omitempty"`
	Evidence      []DiagnosisEvidence   `json:"evidence"`
	Warnings      []string              `json:"warnings,omitempty"`
}

// promInstantVector is the subset of Prometheus/Thanos's
// /api/v1/query response shape this package actually reads.
type promInstantVector struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	} `json:"data"`
	Error string `json:"error,omitempty"`
}

// PromSample is one (label-set, value) pair parsed from a Thanos/
// Prometheus instant-query response.
type PromSample struct {
	Labels map[string]string
	Value  float64
}

// parsePromInstantVector parses one Thanos/Prometheus instant-query
// response body (as returned by curl inside MonitoringTargetDiagnosisSteps'
// generated command) into (label-set, float value) pairs, sorted by
// value descending — a bounded, sanitized summary, never the raw JSON
// passed straight through.
func parsePromInstantVector(body string) (samples []PromSample, err error) {
	var parsed promInstantVector
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return nil, fmt.Errorf("parse prometheus response: %w", err)
	}
	if parsed.Status != "success" {
		return nil, fmt.Errorf("prometheus query failed: %s", parsed.Error)
	}
	for _, r := range parsed.Data.Result {
		valStr, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			continue
		}
		samples = append(samples, PromSample{Labels: r.Metric, Value: v})
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].Value > samples[j].Value })
	return samples, nil
}

// ParsePromInstantVectorForDiagnose is parsePromInstantVector, exported
// for cmd/pilot/cmd's monitoring-target diagnose handler.
func ParsePromInstantVectorForDiagnose(body string) ([]PromSample, error) {
	return parsePromInstantVector(body)
}

// FormatInterfaceSample renders one topk() sample as a compact,
// human-readable string ("ifIndex=47 (value=12.3)") — bounded to the
// labels a diagnosis actually needs, never the full label set.
func FormatInterfaceSample(labels map[string]string, value float64) string {
	idx := labels["ifIndex"]
	if idx == "" {
		idx = "?"
	}
	return fmt.Sprintf("ifIndex=%s (value=%.4g)", idx, value)
}
