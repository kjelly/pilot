package ansible

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
)

// TransportUnreachableReason is ansible_callback/pilot_result.py's
// classification of why a host was reported unreachable. Go never
// re-derives a reason from raw message text — the Python callback is the
// single classifier — but both sides must agree on the same vocabulary
// (spec.md §17.4), so the identifiers here are copied verbatim from
// pilot_result.py's TOLERATED_REASONS/FATAL_REASONS.
type TransportUnreachableReason string

const (
	ReasonConnectionRefused         TransportUnreachableReason = "connection_refused"
	ReasonConnectionTimeout         TransportUnreachableReason = "connection_timeout"
	ReasonNetworkUnreachable        TransportUnreachableReason = "network_unreachable"
	ReasonHostUnreachable           TransportUnreachableReason = "host_unreachable"
	ReasonNoRoute                   TransportUnreachableReason = "no_route"
	ReasonConnectionReset           TransportUnreachableReason = "connection_reset"
	ReasonConnectionClosed          TransportUnreachableReason = "connection_closed"
	ReasonAuthenticationFailed      TransportUnreachableReason = "authentication_failed"
	ReasonHostKeyVerificationFailed TransportUnreachableReason = "host_key_verification_failed"
	ReasonIdentityFileError         TransportUnreachableReason = "identity_file_error"
	ReasonPermissionDenied          TransportUnreachableReason = "permission_denied"
	ReasonUnsupportedConnection     TransportUnreachableReason = "unsupported_connection"
	ReasonUnknown                   TransportUnreachableReason = "unknown"
)

// toleratedTransportReasons are the only reasons spec §17.4 allows Pilot to
// treat as an expected offline-transport condition rather than a real
// defect. Every other TransportUnreachableReason value is fatal.
var toleratedTransportReasons = map[TransportUnreachableReason]bool{
	ReasonConnectionRefused:  true,
	ReasonConnectionTimeout:  true,
	ReasonNetworkUnreachable: true,
	ReasonHostUnreachable:    true,
	ReasonNoRoute:            true,
	ReasonConnectionReset:    true,
	ReasonConnectionClosed:   true,
}

// HostStats mirrors cmd/pilot/cmd's AnsibleHostStats field-for-field (same
// JSON tags) so pilot_result.py's "stats" event unmarshals directly with
// no translation layer (spec §17.6).
type HostStats struct {
	Ok          int `json:"ok"`
	Changed     int `json:"changed"`
	Failures    int `json:"failures"`
	Unreachable int `json:"unreachable"`
	Skipped     int `json:"skipped"`
	Rescued     int `json:"rescued"`
	Ignored     int `json:"ignored"`
}

// resultEvent is one JSON-lines record written by
// ansible_callback/pilot_result.py. Only "unreachable", "failed", and
// "stats" events are currently emitted; unrecognized event names are
// ignored rather than treated as a parse error, so this classifier can
// tolerate an additive schema change.
type resultEvent struct {
	Event  string                     `json:"event"`
	Host   string                     `json:"host,omitempty"`
	Task   string                     `json:"task,omitempty"`
	Reason TransportUnreachableReason `json:"reason,omitempty"`
	Hosts  map[string]HostStats       `json:"hosts,omitempty"`
}

// DeploymentOutcome is the semantic result of one ansible-playbook apply
// invocation, distinct from its raw process exit code (spec.md §18).
type DeploymentOutcome struct {
	RawExitCode int
	// Success is true when the run genuinely converged, or when the raw
	// exit was non-zero solely because of tolerated optional-host
	// transport disappearance (spec §17.5). It stays false whenever
	// semantic success cannot be provably established — this classifier
	// fails closed (spec §25.3).
	Success bool
	// DeferredHosts lists hosts whose non-zero contribution to RawExitCode
	// was excused as a tolerated mid-run transport disappearance. Empty
	// when Success is false or when RawExitCode was already 0.
	DeferredHosts []string
}

// ClassifyDeploymentOutcome reclassifies a raw non-zero ansible-playbook
// exit code as a semantic success-with-deferred outcome, but only when
// every condition in spec §17.5 provably holds:
//   - the result file at resultFilePath parses as valid JSON-lines,
//   - it contains exactly one final "stats" event,
//   - no host shows Failures > 0,
//   - every host with Unreachable > 0 is present in optionalHosts,
//   - every such host has a recorded "unreachable" event whose Reason is
//     one of the tolerated transport classes.
//
// If any condition does not provably hold — missing file, malformed
// JSON, missing stats event, a real task failure, an unreachable
// required host, or an unrecognized/fatal unreachable reason — it fails
// closed: Success is false and RawExitCode is preserved unexamined
// further. A raw exit code of 0 always short-circuits to Success without
// reading the file at all.
func ClassifyDeploymentOutcome(rawExitCode int, resultFilePath string, optionalHosts map[string]bool) DeploymentOutcome {
	outcome := DeploymentOutcome{RawExitCode: rawExitCode, Success: rawExitCode == 0}
	if rawExitCode == 0 {
		return outcome
	}

	events, ok := readResultEvents(resultFilePath)
	if !ok {
		return outcome
	}

	stats, unreachableReason, ok := summarizeResultEvents(events)
	if !ok {
		return outcome
	}

	var deferred []string
	for host, s := range stats {
		if s.Failures > 0 {
			return outcome
		}
		if s.Unreachable == 0 {
			continue
		}
		if !optionalHosts[host] {
			return outcome
		}
		reason, seen := unreachableReason[host]
		if !seen || !toleratedTransportReasons[reason] {
			return outcome
		}
		deferred = append(deferred, host)
	}

	sort.Strings(deferred)
	outcome.Success = true
	outcome.DeferredHosts = deferred
	return outcome
}

// readResultEvents reads and parses every line of resultFilePath as a
// resultEvent. It reports ok=false — never panics or returns a partial
// result — when the file is missing, empty, or contains any line that
// does not parse as JSON, since a partially-trustworthy event stream is
// exactly as dangerous as no event stream (spec §25.3/§25.4).
func readResultEvents(path string) ([]resultEvent, bool) {
	if path == "" {
		return nil, false
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var events []resultEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev resultEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, false
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, false
	}
	return events, true
}

// summarizeResultEvents extracts the final per-host stats and the most
// recent unreachable-reason recorded for each host from a parsed event
// stream. ok is false when there is not exactly one "stats" event — spec
// §17.5 requires a valid final-stats event to exist before any downgrade
// is considered.
func summarizeResultEvents(events []resultEvent) (map[string]HostStats, map[string]TransportUnreachableReason, bool) {
	var stats map[string]HostStats
	statsSeen := 0
	reasons := make(map[string]TransportUnreachableReason)
	for _, ev := range events {
		switch ev.Event {
		case "stats":
			statsSeen++
			stats = ev.Hosts
		case "unreachable":
			if ev.Host != "" {
				reasons[ev.Host] = ev.Reason
			}
		}
	}
	if statsSeen != 1 || stats == nil {
		return nil, nil, false
	}
	return stats, reasons, true
}
