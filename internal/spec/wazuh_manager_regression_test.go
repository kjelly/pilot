package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_WazuhManagerSpec locks the structure of
// docs/verification/wazuh-manager.md (v1.0 — Wazuh all-in-one
// manager+indexer+dashboard via the official wazuh-install.sh assistant,
// FIM/who-data rule engine, CVE vulnerability-detection, optional syslog
// forward to docs/verification/log-server.md):
//
//	C1/C2   wazuh-manager + wazuh-indexer installed
//	C3/C4   wazuh-manager.service + wazuh-indexer.service active
//	C5/C6   agent port 1514 + enrollment port 1515 listening
//	C7      vulnerability-detection (CVE scanning) enabled
//	C8      disk headroom >= 5GB (CVE feed occupies ~7-9GB; see §5 incident)
//	C9      wazuh-logtest matches a real named rule and flags it alert-worthy
//	C10/C11 /etc/hosts pins siem-log-server + <syslog_output> forwards to it
//
// Cross-row invariants locked below:
//
//   - C1-C11 must all use positive-logic rc (never a reverse-logic grep
//     with a numeric expected) per verification-spec-template.md trap 1.
//   - C5/C6/C9 must use the `sh -c '... && echo 0 || echo 1'` form so the
//     outer command always exits 0 regardless of match outcome.
//   - C9 must feed wazuh-logtest a REALISTIC full syslog line (timestamp +
//     hostname + `sshd[pid]:` prefix) — a live vm-target run found that a
//     bare message with no syslog header fails to match any named decoder
//     and falls through to the generic "Unknown problem" rule (id 1002,
//     level 2), which would make a naive check for the substring "level:"
//     pass even when the rule engine hasn't actually matched anything
//     meaningful. The check must instead assert the string
//     "Alert to be generated." which wazuh-logtest only prints once the
//     matched rule's level clears the configured alert threshold.
//   - C10/C11 must reference the `siem-log-server` alias (not a raw
//     site-specific IP/host), same design as audit-log-forwarding.md.
//   - No row may use ~active (matches inactive as a substring).
//   - siem_forward_host must be OPTIONAL: the apply playbook must not
//     hard-fail when it's omitted (local alerting + CVE scanning is
//     independent of whether a log server exists yet).
//   - The apply playbook must call the official wazuh-install.sh assistant
//     (not a hand-rolled `apt install wazuh-manager` + manual indexer/cert
//     setup) — CVE scanning in Wazuh 4.8+ requires the indexer to actually
//     store/correlate results, and hand-rolling indexer certs is high-risk.
func TestRegression_WazuhManagerSpec(t *testing.T) {
	const specPath = "../../docs/verification/wazuh-manager.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"}
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

	// C5/C6/C9 must use the `sh -c '... && echo 0 || echo 1'` form.
	for _, id := range []string{"C5", "C6", "C9"} {
		if !strings.Contains(cmd[id], "&& echo 0") || !strings.Contains(cmd[id], "|| echo 1") {
			t.Errorf("%s must use the `... && echo 0 || echo 1` form, got %q", id, cmd[id])
		}
	}

	// C9 must feed a realistic full syslog line (not a bare, header-less
	// message) and assert the alert-worthy marker, not just "level:" (which
	// the generic no-match rule 1002 also prints).
	if !strings.Contains(cmd["C9"], "sshd[") {
		t.Errorf("C9 must inject a full syslog-formatted line (hostname + sshd[pid]:), got %q", cmd["C9"])
	}
	if !strings.Contains(cmd["C9"], "Alert to be generated.") {
		t.Errorf("C9 must assert on \"Alert to be generated.\", not a generic level marker, got %q", cmd["C9"])
	}
	if strings.Contains(cmd["C9"], "\"Level:\"") {
		t.Errorf("C9 must not assert on the capitalized \"Level:\" string (not present in wazuh-logtest output; also matches the generic no-decoder-match rule 1002), got %q", cmd["C9"])
	}

	// C10/C11 must reference the site-independent siem-log-server alias.
	for _, id := range []string{"C10", "C11"} {
		if !strings.Contains(cmd[id], "siem-log-server") {
			t.Errorf("%s must reference the siem-log-server alias, got %q", id, cmd[id])
		}
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	// siem_forward_host must be OPTIONAL.
	playbookRaw, err := os.ReadFile("../../playbooks/apply/wazuh-manager-apply.yml")
	if err != nil {
		t.Fatalf("read wazuh-manager-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)
	if strings.Contains(applyRaw, "Missing required var") || strings.Contains(applyRaw, "Assert required variables") {
		t.Errorf("wazuh-manager-apply.yml must not hard-require siem_forward_host; forwarding must be optional")
	}
	if !strings.Contains(applyRaw, `siem_forward_host: ""`) {
		t.Errorf("wazuh-manager-apply.yml must default siem_forward_host to an empty string (optional var)")
	}
	if !strings.Contains(applyRaw, "siem_forwarding_enabled") {
		t.Errorf("wazuh-manager-apply.yml must derive a siem_forwarding_enabled gate from siem_forward_host")
	}

	// Must call the official all-in-one installer, not a hand-rolled
	// manager-only apt install (CVE scanning needs the indexer connection
	// the official script wires up; see spec §1).
	if !strings.Contains(applyRaw, "wazuh-install.sh") {
		t.Errorf("wazuh-manager-apply.yml must run the official wazuh-install.sh assistant")
	}
	if !strings.Contains(applyRaw, "-a -i") && !strings.Contains(applyRaw, `"-a -i"`) {
		t.Errorf("wazuh-manager-apply.yml must invoke wazuh-install.sh with -a (all-in-one), got install command not matching -a -i")
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
