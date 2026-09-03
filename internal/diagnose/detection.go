package diagnose

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// DetectionEngineGroup is the inventory group the central Detection Engine
// lives on — contractually hostCardinality: exactly-one
// (contracts/detection-engine.yaml). Exported so
// cmd/pilot/cmd/mcp_diagnose_tools.go can resolve it via
// ResolveSingletonGroupHost without a caller-supplied host parameter.
const DetectionEngineGroup = "detection-engine"

// detectionEngineBin is the fixed install path from
// docs/superpowers/specs/2026-08-28-detection-engine-spec.md §8 — never a
// caller-suppliable path.
const detectionEngineBin = "/usr/local/bin/pilot-detection-engine"

// These are the deployment-owned paths and account from the Detection Engine
// apply playbook.  They are deliberately not MCP inputs.
const (
	detectionEngineUser       = "pilot-detect"
	detectionEngineConfigPath = "/etc/pilot/detection-engine/config.yaml"
)

// SignalIDPattern matches a well-formed ULID (spec §21: signal_id is a
// ULID — 26-character Crockford base32). Callers MUST reject anything
// that doesn't match this before it can reach DetectionSteps; Crockford
// base32 excludes I/L/O/U, hence the character classes below.
var SignalIDPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

var detectionDBPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

// DetectionConfigDBPathStep reads only the dbPath line from the deployed,
// secret-free Detection Engine config. It runs as the service account so the
// subsequent status/database reads have precisely the same file permissions
// as the daemon. The command is fixed; neither its path nor its arguments are
// caller-supplied.
func DetectionConfigDBPathStep() Step {
	return Step{
		ID:          "db_path",
		Description: "Detection Engine configured state database path",
		Module:      "command",
		Command: fmt.Sprintf(
			"sudo -n -u %s /usr/bin/grep -m 1 ^dbPath: %s",
			detectionEngineUser, detectionEngineConfigPath,
		),
	}
}

// DetectionDBPath parses the one dbPath YAML line returned by
// DetectionConfigDBPathStep. The apply playbook renders this as a quoted
// top-level scalar. Keep the accepted shape deliberately narrow before it is
// put into a later command-module argv string.
func DetectionDBPath(stdout string) (string, error) {
	line := strings.TrimSpace(stdout)
	if !strings.HasPrefix(line, "dbPath:") {
		return "", fmt.Errorf("Detection Engine config did not return a dbPath line")
	}
	path := strings.TrimSpace(strings.TrimPrefix(line, "dbPath:"))
	if len(path) >= 2 && ((path[0] == '"' && path[len(path)-1] == '"') || (path[0] == '\'' && path[len(path)-1] == '\'')) {
		path = path[1 : len(path)-1]
	}
	if !detectionDBPathPattern.MatchString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("Detection Engine dbPath %q is not a safe absolute path", path)
	}
	return path, nil
}

// DetectionSteps returns the fixed, read-only ad-hoc commands for
// pilot_diagnose_detection (spec §46). dbPath must come from
// DetectionConfigDBPathStep and be validated by DetectionDBPath; it is never
// caller supplied. status, signals, and signal-show run as the daemon account
// because their state files are intentionally mode 0600. signalID MUST
// already have been validated against SignalIDPattern by the caller.
func DetectionSteps(dbPath, signalID string) []Step {
	steps := []Step{
		{ID: "status", Description: "detection engine status", Module: "command",
			Command: fmt.Sprintf("sudo -n -u %s %s status --json", detectionEngineUser, detectionEngineBin)},
	}
	if dbPath != "" {
		steps = append(steps, Step{ID: "signals_list", Description: "active SignalEvent episodes", Module: "command",
			Command: fmt.Sprintf("sudo -n -u %s %s signals list --db %s", detectionEngineUser, detectionEngineBin, dbPath)})
	}
	steps = append(steps, Step{ID: "journal", Description: "bounded pilot-detection-engine journal tail", Module: "command",
		Command: "journalctl -u pilot-detection-engine --no-pager -n 200"})
	if dbPath != "" && signalID != "" {
		steps = append(steps, Step{
			ID: "signal_show", Description: "one SignalEvent episode by signal_id", Module: "command",
			Command: fmt.Sprintf("sudo -n -u %s %s signals show %s --db %s", detectionEngineUser, detectionEngineBin, signalID, dbPath),
		})
	}
	return steps
}
