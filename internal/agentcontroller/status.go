package agentcontroller

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Status is the /run/pilot/agent-controller/status.json contract (spec
// §16 Task 6). It never carries a diagnosis Summary/SuspectedCause text —
// only counts — so it can never leak evidence content as a metric/status
// label (spec §16 Task 6: "never expose diagnosis text as metric labels").
type Status struct {
	SchemaVersion int              `json:"schema_version"`
	State         string           `json:"state"` // "healthy" | "degraded"
	Incidents     StatusIncidents  `json:"incidents"`
	Runs          StatusRuns       `json:"runs"`
	Dispatcher    StatusDispatcher `json:"dispatcher"`
	Ingress       StatusIngress    `json:"ingress"`
}

type StatusIncidents struct {
	Open          int `json:"open"`
	Investigating int `json:"investigating"`
}

type StatusRuns struct {
	Active int `json:"active"`
}

type StatusDispatcher struct {
	Kind string `json:"kind"`
}

type StatusIngress struct {
	AuthFailures       int64 `json:"auth_failures"`
	OversizeRejections int64 `json:"oversize_rejections"`
	IngestErrors       int64 `json:"ingest_errors"`
	IngestedEvents     int64 `json:"ingested_events"`
}

// WriteStatus atomically publishes status.json (temp file + rename).
func WriteStatus(path string, s Status) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal status: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".status-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create status temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write status temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close status temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename status file: %w", err)
	}
	return nil
}

// ReadStatus reads and parses status.json.
func ReadStatus(path string) (Status, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Status{}, fmt.Errorf("read status %s: %w", path, err)
	}
	var s Status
	if err := json.Unmarshal(data, &s); err != nil {
		return Status{}, fmt.Errorf("decode status %s: %w", path, err)
	}
	return s, nil
}

func boolToMetric(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// MetricsSnapshot is the point-in-time counter/gauge state rendered into
// the node_exporter textfile collector.
type MetricsSnapshot struct {
	Up                  bool
	IncidentsOpen       int
	IncidentsInvesting  int
	RunsActive          int
	AuthFailuresTotal   int64
	OversizeTotal       int64
	IngestErrorsTotal   int64
	IngestedEventsTotal int64
}

// Render produces the Prometheus text exposition format for this
// snapshot.
func (m MetricsSnapshot) Render() string {
	var b strings.Builder
	line := func(name string, value string) {
		fmt.Fprintf(&b, "%s %s\n", name, value)
	}
	line("pilot_agent_controller_up", boolToMetric(m.Up))
	line("pilot_agent_controller_incidents_open", strconv.Itoa(m.IncidentsOpen))
	line("pilot_agent_controller_incidents_investigating", strconv.Itoa(m.IncidentsInvesting))
	line("pilot_agent_controller_runs_active", strconv.Itoa(m.RunsActive))
	line("pilot_agent_controller_webhook_auth_failures_total", strconv.FormatInt(m.AuthFailuresTotal, 10))
	line("pilot_agent_controller_webhook_oversize_rejections_total", strconv.FormatInt(m.OversizeTotal, 10))
	line("pilot_agent_controller_ingest_errors_total", strconv.FormatInt(m.IngestErrorsTotal, 10))
	line("pilot_agent_controller_ingested_events_total", strconv.FormatInt(m.IngestedEventsTotal, 10))
	return b.String()
}

// WriteTextfile atomically publishes the textfile collector output (temp
// + rename).
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
