package diagnose

import (
	"fmt"
	"regexp"
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

// SignalIDPattern matches a well-formed ULID (spec §21: signal_id is a
// ULID — 26-character Crockford base32). Callers MUST reject anything
// that doesn't match this before it can reach DetectionSteps; Crockford
// base32 excludes I/L/O/U, hence the character classes below.
var SignalIDPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// DetectionSteps returns the fixed, read-only ad-hoc commands for
// pilot_diagnose_detection (spec §46): engine status, the active signals
// list, and a bounded journal tail always run; signalID's own detail row
// is added only when non-empty. signalID MUST already have been validated
// against SignalIDPattern by the caller — this function does not
// re-validate it (the MCP input boundary is where untrusted input gets
// rejected, not scattered across every command builder).
func DetectionSteps(signalID string) []Step {
	steps := []Step{
		{ID: "status", Description: "detection engine status", Module: "command",
			Command: fmt.Sprintf("%s status --json", detectionEngineBin)},
		{ID: "signals_list", Description: "active SignalEvent episodes", Module: "command",
			Command: fmt.Sprintf("%s signals list --json", detectionEngineBin)},
		{ID: "journal", Description: "bounded pilot-detection-engine journal tail", Module: "command",
			Command: "journalctl -u pilot-detection-engine --no-pager -n 200"},
	}
	if signalID != "" {
		steps = append(steps, Step{
			ID: "signal_show", Description: "one SignalEvent episode by signal_id", Module: "command",
			Command: fmt.Sprintf("%s signals show %s --json", detectionEngineBin, signalID),
		})
	}
	return steps
}
