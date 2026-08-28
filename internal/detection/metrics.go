package detection

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// MetricsSnapshot is the point-in-time counter/gauge state rendered into
// the node_exporter textfile collector (spec §38). Every map key here MUST
// be a finite enum value, never a raw error string (spec: "reason 必須
// finite enum，不放raw error").
type MetricsSnapshot struct {
	Up                           bool
	CycleDurationSeconds         float64
	CycleOverrunTotal            int64
	LastSuccessTimestampSeconds  int64
	SubjectsTotal                int
	SubjectSkippedTotal          map[string]int64      // reason -> count
	FeatureInvalidTotal          map[[2]string]int64   // [feature, reason] -> count
	AnomalyScore                 map[[2]string]float64 // [pilot_host, detector] -> score
	ActiveSignals                map[string]int64      // severity -> count
	SignalTotal                  map[string]int64      // transition -> count
	ModelProviderUp              bool
	ModelRequestTotal            map[[2]string]int64 // [provider, result] -> count
	ModelRequestDurationSeconds  map[string]float64  // provider -> seconds
	ModelCandidatesTotal         int64
	ModelCandidatesDroppedTotal  map[string]int64 // reason -> count
	ModelCircuitOpen             bool
	OutboxPending                int
	AlertmanagerSendFailureTotal map[string]int64 // reason -> count
}

func boolToMetric(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

func sortedStringKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedPairKeys[V any](m map[[2]string]V) [][2]string {
	keys := make([][2]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	return keys
}

// Render produces the Prometheus text exposition format for this snapshot
// (spec §38's required metric set).
func (m MetricsSnapshot) Render() string {
	var b strings.Builder

	line := func(name string, value string) {
		fmt.Fprintf(&b, "%s %s\n", name, value)
	}
	labeled := func(name, labels, value string) {
		fmt.Fprintf(&b, "%s{%s} %s\n", name, labels, value)
	}

	line("pilot_detection_engine_up", boolToMetric(m.Up))
	line("pilot_detection_cycle_duration_seconds", formatFloat(m.CycleDurationSeconds))
	line("pilot_detection_cycle_overrun_total", strconv.FormatInt(m.CycleOverrunTotal, 10))
	line("pilot_detection_last_success_timestamp_seconds", strconv.FormatInt(m.LastSuccessTimestampSeconds, 10))
	line("pilot_detection_subjects_total", strconv.Itoa(m.SubjectsTotal))

	for _, reason := range sortedStringKeys(m.SubjectSkippedTotal) {
		labeled("pilot_detection_subject_skipped_total", fmt.Sprintf("reason=%q", reason), strconv.FormatInt(m.SubjectSkippedTotal[reason], 10))
	}
	for _, k := range sortedPairKeys(m.FeatureInvalidTotal) {
		labeled("pilot_detection_feature_invalid_total", fmt.Sprintf("feature=%q,reason=%q", k[0], k[1]), strconv.FormatInt(m.FeatureInvalidTotal[k], 10))
	}
	for _, k := range sortedPairKeys(m.AnomalyScore) {
		labeled("pilot_detection_anomaly_score", fmt.Sprintf("pilot_host=%q,detector=%q", k[0], k[1]), formatFloat(m.AnomalyScore[k]))
	}
	for _, sev := range sortedStringKeys(m.ActiveSignals) {
		labeled("pilot_detection_active_signals", fmt.Sprintf("severity=%q", sev), strconv.FormatInt(m.ActiveSignals[sev], 10))
	}
	for _, transition := range sortedStringKeys(m.SignalTotal) {
		labeled("pilot_detection_signal_total", fmt.Sprintf("transition=%q", transition), strconv.FormatInt(m.SignalTotal[transition], 10))
	}

	line("pilot_detection_model_provider_up", boolToMetric(m.ModelProviderUp))
	for _, k := range sortedPairKeys(m.ModelRequestTotal) {
		labeled("pilot_detection_model_request_total", fmt.Sprintf("provider=%q,result=%q", k[0], k[1]), strconv.FormatInt(m.ModelRequestTotal[k], 10))
	}
	for _, provider := range sortedStringKeys(m.ModelRequestDurationSeconds) {
		labeled("pilot_detection_model_request_duration_seconds", fmt.Sprintf("provider=%q", provider), formatFloat(m.ModelRequestDurationSeconds[provider]))
	}
	line("pilot_detection_model_candidates_total", strconv.FormatInt(m.ModelCandidatesTotal, 10))
	for _, reason := range sortedStringKeys(m.ModelCandidatesDroppedTotal) {
		labeled("pilot_detection_model_candidates_dropped_total", fmt.Sprintf("reason=%q", reason), strconv.FormatInt(m.ModelCandidatesDroppedTotal[reason], 10))
	}
	line("pilot_detection_model_circuit_open", boolToMetric(m.ModelCircuitOpen))

	line("pilot_detection_outbox_pending", strconv.Itoa(m.OutboxPending))
	for _, reason := range sortedStringKeys(m.AlertmanagerSendFailureTotal) {
		labeled("pilot_detection_alertmanager_send_failure_total", fmt.Sprintf("reason=%q", reason), strconv.FormatInt(m.AlertmanagerSendFailureTotal[reason], 10))
	}

	return b.String()
}

// WriteTextfile atomically publishes the textfile collector output (temp +
// rename, spec §38).
func (m MetricsSnapshot) WriteTextfile(path string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".metrics-*.prom.tmp")
	if err != nil {
		return fmt.Errorf("create metrics temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.WriteString(m.Render()); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write metrics temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close metrics temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename metrics file: %w", err)
	}
	return nil
}
