package spec

import (
	"strconv"
	"strings"
	"testing"
)

// TestRegression_HostDecommissionSpec locks the structure of the Phase 0
// acceptance contract for
// docs/superpowers/specs/2026-09-02-host-decommission-spec.md. HD1-HD28
// are that spec's own §32 hard safety/behavior invariants (INV-1..INV-15
// made observable) — silently dropping or renumbering a row here would
// desync this file from the design doc it is supposed to trace, and a
// coding agent implementing a later phase could "satisfy" a weaker
// acceptance row than the one actually agreed on.
func TestRegression_HostDecommissionSpec(t *testing.T) {
	const specPath = "../../docs/verification/host-decommission.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := make([]string, 0, 28)
	for i := 1; i <= 28; i++ {
		wantIDs = append(wantIDs, "HD"+strconv.Itoa(i))
	}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// Every row must be verifyOnly: the acceptance contract itself never
	// mutates anything (spec.md INV-2/INV-4: no mutation may execute
	// without a persisted, approved plan, and a spec probe is neither).
	for _, r := range s.Rows {
		if !r.VerifyOnly {
			t.Errorf("row %s must be verifyOnly (this contract asserts behavior via go test, it never mutates)", r.ID)
		}
	}

	// No vague expected values (AGENTS.md §3 requires this globally; the
	// project-wide convention for a go-test probe is "PASS" as a
	// substring match against `go test -v` output, which is NOT vague —
	// it is the literal marker `go test` prints for a passing test).
	for _, r := range s.Rows {
		trimmed := strings.ToLower(strings.TrimSpace(r.Expected))
		if trimmed == "" || trimmed == "ok" || trimmed == "success" || trimmed == "true" {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// Every probe must invoke `go test -run <name>` against a real,
	// distinct Go test name in internal/decommission or cmd/pilot/cmd —
	// this is a Go-feature spec (like snmp-monitoring-integration.md),
	// not an infra-role spec with shell/ansible probes.
	seenTestNames := map[string]string{}
	for _, r := range s.Rows {
		if !strings.Contains(r.Command, "go test") || !strings.Contains(r.Command, "-run") {
			t.Errorf("row %s probe must run `go test ... -run <TestName>`, got %q", r.ID, r.Command)
			continue
		}
		name := extractRunArg(r.Command)
		if name == "" {
			t.Errorf("row %s: could not extract -run test name from probe %q", r.ID, r.Command)
			continue
		}
		if prior, ok := seenTestNames[name]; ok {
			t.Errorf("row %s reuses test name %q already used by row %s — every HD row must assert a distinct behavior", r.ID, name, prior)
		}
		seenTestNames[name] = r.ID
	}

	// HD20 is the top-level acceptance criterion (spec.md §45): it must
	// stay phrased as "remains" (host stays present), never "removed"
	// (host disappears) — the whole point of the saga is that inventory
	// removal is the LAST step, not an early one (INV-1).
	for _, r := range s.Rows {
		if r.ID == "HD20" && !strings.Contains(strings.ToLower(r.Check), "remain") {
			t.Errorf("HD20 must assert the host REMAINS until verification passes, not that it is removed early; got check=%q", r.Check)
		}
	}

	// HD23 is the hard FreeIPA-server/-replica exclusion (INV-13) — must
	// name both roles explicitly, not just "freeipa".
	for _, r := range s.Rows {
		if r.ID == "HD23" {
			if !strings.Contains(r.Check, "freeipa-server") || !strings.Contains(r.Check, "freeipa-server-replica") {
				t.Errorf("HD23 must name both freeipa-server and freeipa-server-replica; got check=%q", r.Check)
			}
		}
	}

	// Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}

// extractRunArg pulls the value following "-run" out of a shell command
// string, tolerating the trailing " -v" this repo's go-test probes use.
func extractRunArg(cmd string) string {
	fields := strings.Fields(cmd)
	for i, f := range fields {
		if f == "-run" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}
