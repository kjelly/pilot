package detection

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Status is the /run/pilot/detection-engine/status.json contract (spec §37).
type Status struct {
	SchemaVersion int                 `json:"schema_version"`
	State         string              `json:"state"` // "healthy" | "degraded"
	Source        StatusSource        `json:"source"`
	Subjects      StatusSubjects      `json:"subjects"`
	ModelProvider StatusModelProvider `json:"model_provider"`
	Signals       StatusSignals       `json:"signals"`
	LastCycle     StatusLastCycle     `json:"last_cycle"`
}

type StatusSource struct {
	Healthy bool `json:"healthy"`
}

type StatusSubjects struct {
	Active int `json:"active"`
}

// StatusModelProvider.Healthy never affects engine health while Enabled is
// false (spec §37: "provider disabled: model_provider.healthy does not
// affect engine health").
type StatusModelProvider struct {
	Enabled  bool   `json:"enabled"`
	Healthy  bool   `json:"healthy"`
	Protocol string `json:"protocol"`
	Circuit  string `json:"circuit"`
}

type StatusSignals struct {
	Active int `json:"active"`
}

type StatusLastCycle struct {
	Success bool `json:"success"`
}

// NewDisabledProviderStatus returns the Stage A shape of the
// model_provider block (spec §37's example): disabled, not healthy,
// closed circuit, no protocol name.
func NewDisabledProviderStatus() StatusModelProvider {
	return StatusModelProvider{Enabled: false, Healthy: false, Protocol: "", Circuit: "closed"}
}

// WriteStatus atomically publishes status.json (temp file + rename, per
// spec §37).
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
