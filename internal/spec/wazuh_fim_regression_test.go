package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_WazuhFimSpec locks the structure of
// docs/verification/wazuh-fim.md (v1.1 — Wazuh agent FIM/syscheck with
// whodata on a per-host-overridable directory list, auditd-backed who-data
// attribution, optional enrollment against
// docs/verification/wazuh-manager.md):
//
//	C1/C2   wazuh-agent + auditd installed
//	C3/C4   wazuh-agent.service + auditd.service active
//	C5      at least one directory configured with check_all+whodata
//	        (host-agnostic — v1.1 dropped the literal /etc, /boot check
//	        since wazuh_fim_directories is now overridable per host)
//	C6      whodata provider explicitly set to "audit"
//	C7      /etc/hosts pins the wazuh-manager alias
//	C8      <address> in ossec.conf points at the wazuh-manager alias
//	C9      client.keys populated (agent-auth registration completed)
//
// Cross-row invariants locked below:
//
//   - C1-C9 must all use positive-logic rc per
//     verification-spec-template.md trap 1.
//   - C9 must use the `sh -c '... && echo 0 || echo 1'` form.
//   - C5 must NOT hardcode a literal path (/etc or /boot) — v1.1's whole
//     point is that wazuh_fim_directories is overridable per host, so a
//     literal-path assertion would false-fail on hosts with a custom list.
//   - C7/C8 must reference the `wazuh-manager` alias (not a raw
//     site-specific IP/host), same design as audit-log-forwarding.md's
//     siem-log-server alias.
//   - No row may use ~active (matches inactive as a substring).
//   - wazuh_manager_host must be OPTIONAL: the apply playbook must not
//     hard-fail when it's omitted (local FIM whodata rules are independent
//     of whether a manager exists yet).
//   - wazuh_fim_directories must be a templated list (Jinja loop), not a
//     hardcoded pair of directory lines, so it's genuinely overridable
//     per-host (host_vars) rather than requiring a playbook edit.
//   - agent-auth (registration) must be idempotency-gated on client.keys
//     being empty/missing, not run unconditionally on every apply — running
//     it every time would re-request a key each run and thrash the
//     manager's agent list.
func TestRegression_WazuhFimSpec(t *testing.T) {
	const specPath = "../../docs/verification/wazuh-fim.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
		switch strings.ToLower(exp[r.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// All rows are rc-based numeric `0`.
	for _, id := range wantIDs {
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}
	for _, id := range []string{"C1", "C2"} {
		if !strings.Contains(cmd[id], "command -v rpm") ||
			!strings.Contains(cmd[id], "dpkg-query") {
			t.Errorf("%s package probe must support both EL rpm and Ubuntu dpkg, got %q", id, cmd[id])
		}
	}

	// C9 must use the `sh -c '... && echo 0 || echo 1'` form.
	if !strings.Contains(cmd["C9"], "&& echo 0") || !strings.Contains(cmd["C9"], "|| echo 1") {
		t.Errorf("C9 must use the `... && echo 0 || echo 1` form, got %q", cmd["C9"])
	}

	// C5 must gate on check_all+whodata attributes together, but must NOT
	// hardcode a specific path — the whole point of v1.1 is that the
	// directory list is host-overridable, so a literal /etc or /boot
	// assertion would false-fail on a host with a custom list.
	if !strings.Contains(cmd["C5"], `check_all="yes"`) || !strings.Contains(cmd["C5"], `whodata="yes"`) {
		t.Errorf("C5 must assert both check_all=\"yes\" and whodata=\"yes\", got %q", cmd["C5"])
	}
	if strings.Contains(cmd["C5"], ">/etc<") || strings.Contains(cmd["C5"], ">/boot<") {
		t.Errorf("C5 must not hardcode a literal monitored path (breaks per-host overrides), got %q", cmd["C5"])
	}

	// C7/C8 must reference the site-independent wazuh-manager alias.
	for _, id := range []string{"C7", "C8"} {
		if !strings.Contains(cmd[id], "wazuh-manager") {
			t.Errorf("%s must reference the wazuh-manager alias, got %q", id, cmd[id])
		}
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	playbookRaw, err := os.ReadFile("../../playbooks/apply/wazuh-fim-apply.yml")
	if err != nil {
		t.Fatalf("read wazuh-fim-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)

	// wazuh_manager_host must be OPTIONAL.
	if strings.Contains(applyRaw, "Missing required var") || strings.Contains(applyRaw, "Assert required variables") {
		t.Errorf("wazuh-fim-apply.yml must not hard-require wazuh_manager_host; enrollment must be optional")
	}
	if !strings.Contains(applyRaw, "wazuh_manager_host | default(") {
		t.Errorf("wazuh-fim-apply.yml must use default() filter for wazuh_manager_host so group_vars can override")
	}
	if !strings.Contains(applyRaw, "wazuh_enrollment_enabled") {
		t.Errorf("wazuh-fim-apply.yml must derive a wazuh_enrollment_enabled gate from wazuh_manager_host")
	}

	// wazuh_fim_directories must be a real, templated (per-host overridable)
	// list, not a hardcoded pair of directory lines.
	if !strings.Contains(applyRaw, `wazuh_fim_directories: ["/etc", "/boot"]`) {
		t.Errorf("wazuh-fim-apply.yml must default wazuh_fim_directories to [\"/etc\", \"/boot\"]")
	}
	if !strings.Contains(applyRaw, "{% for dir in wazuh_fim_directories %}") {
		t.Errorf("wazuh-fim-apply.yml must render <directories> entries via a Jinja loop over wazuh_fim_directories (per-host overridable), not hardcoded lines")
	}

	// agent-auth must be idempotency-gated on client.keys being empty, not
	// run unconditionally on every apply.
	authIdx := strings.Index(applyRaw, "agent-auth -m")
	if authIdx < 0 {
		t.Fatalf("wazuh-fim-apply.yml must invoke agent-auth to register with the manager")
	}
	if !strings.Contains(applyRaw, "wazuh_client_keys_stat.stat.exists") && !strings.Contains(applyRaw, "wazuh_client_keys_stat.stat.size") {
		t.Errorf("wazuh-fim-apply.yml's agent-auth task must be gated on client.keys being empty/missing (idempotency), not run unconditionally")
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}
}
