package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_AuditLogForwardingSpec locks the structure of
// docs/verification/audit-log-forwarding.md (v1.0 — auditd custom rules +
// logrotate + rsyslog forwarding to docs/verification/log-server.md):
//
//	C1/C2   auditd + audispd-plugins installed
//	C3      custom audit rules file exists
//	C4/C5   setuid/setgid EXECUTION monitoring (execve + uid!=euid/gid!=egid)
//	C6      setuid/setgid CHANGE monitoring (chmod/fchmod/fchmodat)
//	C7      sudo binary execution watch
//	C8/C9   /etc/passwd + /etc/sudoers watches
//	C10     rules loaded into the running kernel audit list
//	C11     a real sudo invocation produces a matching audit.log record
//	C12/C13 logrotate policy files for auditd + syslog exist
//	C14     both logrotate policies pass a dry-run
//	C15     /etc/hosts pins the siem-log-server alias
//	C16/C17 rsyslog forward directives for local6.* and auth,authpriv.*
//	C18/C19 auditd + rsyslog active
//
// Cross-row invariants locked below:
//
//   - C1–C19 must all use positive-logic rc (never a reverse-logic grep
//     with a numeric expected) per verification-spec-template.md trap 1.
//   - C4/C5 must gate on the actual privilege-escalation condition
//     (uid!=euid / gid!=egid with euid=0/egid=0), not just `-S execve`
//     alone — a bare execve watch would fire on every process exec,
//     which is not "setuid/setgid execution monitoring".
//   - C11 must grep the raw audit.log directly (never `ausearch`) — a
//     live vm-target run found this Ubuntu 24.04 audit build emits
//     enriched fields without a separating space (`key="x"ARCH=...`),
//     which breaks ausearch's own parser even though the record is
//     genuinely present in the log.
//   - The generated audit.rules.j2 must list the sudo/passwd/sudoers
//     watches BEFORE the generic setuid/setgid execve rules — a live
//     vm-target run found that audit's "exit" filterlist stops at the
//     first matching rule (like iptables), and /usr/bin/sudo is itself
//     a setuid-root binary, so if the generic rules came first every
//     sudo invocation would be shadowed and "privileged-sudo" would
//     never fire.
//   - C16/C17 must reference the `siem-log-server` alias (not a raw
//     site-specific IP/host) — the spec's Command/Expected columns are
//     fixed at authoring time and cannot be templated per-site, so the
//     apply playbook pins the alias into /etc/hosts and the forward
//     config references the alias, keeping the spec site-independent.
//   - No row may use `~active` (matches `inactive` as a substring).
func TestRegression_AuditLogForwardingSpec(t *testing.T) {
	const specPath = "../../docs/verification/audit-log-forwarding.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{
		"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10",
		"C11", "C12", "C13", "C14", "C15", "C16", "C17", "C18", "C19",
	}
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

	// Positive-logic rc rows (numeric `0`; C3/C12/C13 are file-presence
	// checks and legitimately use `present` instead). C11 uses the
	// `sh -c '... && echo 0 || echo 1'` idiom so the outer command
	// always exits 0 regardless of match outcome.
	rcRows := []string{"C1", "C2", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C14", "C15", "C16", "C17", "C18", "C19"}
	for _, id := range rcRows {
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}
	for _, id := range []string{"C3", "C12", "C13"} {
		if exp[id] != "present" {
			t.Errorf("%s expected should be `present` (file-existence check), got %q", id, exp[id])
		}
	}
	for _, id := range []string{"C1", "C2"} {
		if !strings.Contains(cmd[id], "command -v rpm") ||
			!strings.Contains(cmd[id], "dpkg-query") {
			t.Errorf("%s package probe must support both EL rpm and Ubuntu dpkg, got %q", id, cmd[id])
		}
	}

	// C4/C5 must gate on the actual privilege-transition condition, not
	// just a bare -S execve watch.
	if !strings.Contains(cmd["C4"], "uid!=euid") || !strings.Contains(cmd["C4"], "euid=0") {
		t.Errorf("C4 must gate on uid!=euid + euid=0, got %q", cmd["C4"])
	}
	if !strings.Contains(cmd["C5"], "gid!=egid") || !strings.Contains(cmd["C5"], "egid=0") {
		t.Errorf("C5 must gate on gid!=egid + egid=0, got %q", cmd["C5"])
	}

	// C11 must grep the raw audit.log directly, never ausearch (see the
	// rule-order/parsing lesson in the package doc comment above), and
	// must neutralize the grep's own rc via `&& echo 0 || echo 1`.
	if strings.Contains(cmd["C11"], "ausearch") {
		t.Errorf("C11 must not use ausearch (parser trap on this audit build), got %q", cmd["C11"])
	}
	if !strings.Contains(cmd["C11"], "audit.log") {
		t.Errorf("C11 must grep /var/log/audit/audit.log directly, got %q", cmd["C11"])
	}
	if !strings.Contains(cmd["C11"], "&& echo 0") || !strings.Contains(cmd["C11"], "|| echo 1") {
		t.Errorf("C11 must use the `... && echo 0 || echo 1` form, got %q", cmd["C11"])
	}

	// The generated audit.rules.j2 must list the specific sudo/passwd/
	// sudoers watches BEFORE the generic setuid/setgid execve rules —
	// audit's "exit" filterlist stops at the first match, and sudo is
	// itself setuid-root, so the wrong order silently shadows the
	// "privileged-sudo" key on every real sudo invocation.
	rulesRaw, err := os.ReadFile("../../playbooks/templates/audit.rules.j2")
	if err != nil {
		t.Fatalf("read audit.rules.j2: %v", err)
	}
	sudoLine, execLine := -1, -1
	for i, line := range strings.Split(string(rulesRaw), "\n") {
		line = strings.TrimSpace(line)
		if sudoLine < 0 && strings.HasPrefix(line, "-w /usr/bin/sudo") {
			sudoLine = i
		}
		if execLine < 0 && strings.HasPrefix(line, "-a ") && strings.Contains(line, "setuid_setgid_exec") {
			execLine = i
		}
	}
	if sudoLine < 0 {
		t.Fatalf("audit.rules.j2 missing the /usr/bin/sudo watch rule")
	}
	if execLine < 0 {
		t.Fatalf("audit.rules.j2 missing the setuid_setgid_exec rule")
	}
	if sudoLine > execLine {
		t.Errorf("audit.rules.j2 must list the /usr/bin/sudo watch rule BEFORE the generic setuid_setgid_exec rules (filterlist stops at first match); sudo watch at line %d, exec rule at line %d", sudoLine+1, execLine+1)
	}

	// C16/C17 must reference the site-independent siem-log-server alias,
	// never a raw IP (which would make the spec non-portable).
	for _, id := range []string{"C15", "C16", "C17"} {
		if !strings.Contains(cmd[id], "siem-log-server") {
			t.Errorf("%s must reference the siem-log-server alias, got %q", id, cmd[id])
		}
	}
	if !strings.Contains(cmd["C16"], "local6") {
		t.Errorf("C16 must forward local6.*, got %q", cmd["C16"])
	}
	if !strings.Contains(cmd["C17"], "auth") || !strings.Contains(cmd["C17"], "authpriv") {
		t.Errorf("C17 must forward auth,authpriv.*, got %q", cmd["C17"])
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	// siem_forward_host must be OPTIONAL (v1.1): the apply playbook must not
	// hard-fail when it's omitted, since local auditd monitoring (C1-C14,
	// C18, C19) is independent of whether a log server exists yet. Forward
	// setup (C15-C17) must be gated behind a `when:` derived from whether
	// the var was actually provided.
	playbookRaw, err := os.ReadFile("../../playbooks/apply/audit-log-forwarding-apply.yml")
	if err != nil {
		t.Fatalf("read audit-log-forwarding-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)
	for _, required := range []string{"audit_syslog_path", "/var/log/messages", "audit_syslog_group"} {
		if !strings.Contains(applyRaw, required) {
			t.Errorf("audit-log-forwarding apply must render a portable EL/Ubuntu syslog logrotate policy; missing %q", required)
		}
	}
	if strings.Contains(applyRaw, "Missing required var") || strings.Contains(applyRaw, "Assert required variables") {
		t.Errorf("audit-log-forwarding-apply.yml must not hard-require siem_forward_host; forwarding must be optional")
	}
	if !strings.Contains(applyRaw, "siem_forward_host | default(") {
		t.Errorf("audit-log-forwarding-apply.yml must use default() filter for siem_forward_host so group_vars can override")
	}
	if !strings.Contains(applyRaw, "siem_forwarding_enabled") {
		t.Errorf("audit-log-forwarding-apply.yml must derive a siem_forwarding_enabled gate from siem_forward_host")
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
