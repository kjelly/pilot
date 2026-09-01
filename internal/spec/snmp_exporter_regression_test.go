package spec

import (
	"strings"
	"testing"
)

// TestRegression_SnmpExporterSpec locks the structure of
// docs/verification/snmp-exporter.md (v1.0 — site-local snmp_exporter,
// spec docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md
// §15 Phase 1):
//
//	C1  pilot-snmp-exporter container running
//	C2  image version pinned
//	C3  container hardening (no-new-privileges, cap-drop ALL)
//	C4  no Docker socket bind-mount
//	C5  no SSH key/vault file bind-mount
//	C6  HTTP port binds only to loopback/private, never 0.0.0.0
//	C7  config directory 0750 root-owned
//	C8  env file 0600 root-owned
//	C9  catalog/module files contain no secret-like key
//	C10 self metrics endpoint reachable
//	C11 idempotent reapply (verifyOnly)
//	C12 prod version-policy gate (verifyOnly)
//
// Cross-row invariants locked below:
//
//   - C3/C4/C5 must NOT use Docker's own Go-template `--format
//     '{{...}}'` syntax — ansible ad-hoc Jinja-finalizes the whole
//     Command string, and a leading-dot token like `{{.HostConfig...}}`
//     is a Jinja syntax error (same trap as dcgm-exporter.md's C1/C4/C5
//     and dashboard.md's C14; confirmed via a real `pilot verify` run
//     against a disposable VM during development).
//   - No row may use a vague Expected value ("ok", "正常", ...).
func TestRegression_SnmpExporterSpec(t *testing.T) {
	const specPath = "../../docs/verification/snmp-exporter.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		switch strings.ToLower(strings.TrimSpace(r.Expected)) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	for _, id := range []string{"C3", "C4", "C5"} {
		if strings.Contains(cmd[id], "{{") || strings.Contains(cmd[id], "}}") {
			t.Errorf("%s must not contain Docker Go-template braces {{...}} — ansible ad-hoc Jinja-finalizes the Command string, got %q", id, cmd[id])
		}
	}

	if !strings.Contains(cmd["C1"], "docker ps") || !strings.Contains(cmd["C1"], "status=running") {
		t.Errorf("C1 must check docker ps --filter status=running, got %q", cmd["C1"])
	}
	if !strings.Contains(cmd["C3"], "no-new-privileges") || !strings.Contains(cmd["C3"], "CapDrop") {
		t.Errorf("C3 must check both no-new-privileges and CapDrop, got %q", cmd["C3"])
	}
	if !strings.Contains(cmd["C6"], "9116") {
		t.Errorf("C6 must check the exporter's own port 9116, got %q", cmd["C6"])
	}
	if !strings.Contains(cmd["C9"], "community") || !strings.Contains(cmd["C9"], "password") {
		t.Errorf("C9 must scan for community/username/password/privPassword-shaped keys, got %q", cmd["C9"])
	}
}
