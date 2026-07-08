package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_WazuhManagerSpec locks the structure of
// docs/verification/wazuh-manager.md (v2.0 — Dockerized Wazuh single-node
// manager+indexer+dashboard from the OFFICIAL wazuh-docker release bundle,
// FIM/who-data rule engine, CVE vulnerability-detection, optional syslog
// forward to docs/verification/log-server.md):
//
//	C1/C2/C3 manager + indexer + dashboard containers running
//	C4       indexer HTTPS API answers 401 without credentials (security
//	         plugin actually bootstrapped, not merely container-exists)
//	C5/C6    agent port 1514 + enrollment port 1515 listening
//	C7       vulnerability-detection (CVE scanning) enabled in the LIVE
//	         in-container ossec.conf (proves /wazuh-config-mount injection)
//	C8       disk headroom >= 5GB (CVE feed occupies ~7-9GB; see §5 incident)
//	C9       wazuh-logtest (docker exec -i) matches a real named rule and
//	         flags it alert-worthy
//	C10/C11  /etc/hosts pins siem-log-server + the live in-container
//	         ossec.conf contains the <syslog_output> forward block
//
// Cross-row invariants locked below:
//
//   - C1-C11 must all use positive-logic rc (never a reverse-logic grep
//     with a numeric expected) per verification-spec-template.md trap 1.
//   - Container/functional rows must use the `sh -c '... && echo 0 ||
//     echo 1'` form so the outer command always exits 0 regardless of
//     match outcome.
//   - No row may use docker Go-template syntax (`{{ ... }}`) — ansible
//     ad-hoc would eat it as Jinja. Container liveness goes through
//     `docker ps --filter` instead of `docker inspect -f '{{...}}'`.
//   - Rows probing the manager must address the deterministic compose
//     container name single-node-wazuh.manager-1 (project name is pinned
//     in the apply playbook; spec commands are static text).
//   - C9 must feed wazuh-logtest a REALISTIC full syslog line (timestamp +
//     hostname + `sshd[pid]:` prefix) via `docker exec -i` — a live
//     vm-target run (v1.0) found that a bare message with no syslog header
//     fails to match any named decoder and falls through to the generic
//     "Unknown problem" rule (id 1002, level 2), which would make a naive
//     check for the substring "level:" pass even when the rule engine
//     hasn't actually matched anything meaningful. The check must instead
//     assert the string "Alert to be generated." which wazuh-logtest only
//     prints once the matched rule's level clears the alert threshold.
//   - C10/C11 must reference the `siem-log-server` alias (not a raw
//     site-specific IP/host), same design as audit-log-forwarding.md.
//   - C7 and C11 must verify the LIVE config inside the container
//     (/var/ossec/etc/ossec.conf via docker exec), not just the host-side
//     file — the host file changing proves nothing until the official
//     entrypoint re-injects it on container (re)start.
//   - No row may use ~active (matches inactive as a substring).
//   - siem_forward_host must be OPTIONAL: the apply playbook must not
//     hard-fail when it's omitted (local alerting + CVE scanning is
//     independent of whether a log server exists yet).
//   - The apply playbook must deploy from the official wazuh-docker
//     release bundle (official cert-generator one-shot + official compose
//     project) — NOT the v1.0 wazuh-install.sh host install, and NOT a
//     hand-rolled trio of docker_container tasks with a hand-built TLS
//     chain (CVE scanning in Wazuh 4.8+ requires the indexer, and
//     hand-rolling indexer certs is high-risk; see spec §1).
//   - The apply playbook must set vm.max_map_count (official indexer
//     hard requirement — the one host-level knob containers can't carry).
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

	// Container/functional rows must use the `sh -c '... && echo 0 || echo 1'`
	// form (C10 keeps the native-rc `; echo $?` form like v1.0).
	for _, id := range []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C11"} {
		if !strings.Contains(cmd[id], "&& echo 0") || !strings.Contains(cmd[id], "|| echo 1") {
			t.Errorf("%s must use the `... && echo 0 || echo 1` form, got %q", id, cmd[id])
		}
	}

	// Container liveness must avoid docker Go-template `{{ }}` (Jinja trap):
	// `docker ps --filter`, never `docker inspect -f '{{...}}'`.
	for _, r := range s.Rows {
		if strings.Contains(r.Command, "{{") {
			t.Errorf("row %s uses `{{` (ansible ad-hoc eats it as Jinja), got %q", r.ID, r.Command)
		}
	}
	for id, svc := range map[string]string{"C1": "wazuh.manager", "C2": "wazuh.indexer", "C3": "wazuh.dashboard"} {
		if !strings.Contains(cmd[id], "docker ps --filter") || !strings.Contains(cmd[id], svc) {
			t.Errorf("%s must check the %s container via `docker ps --filter`, got %q", id, svc, cmd[id])
		}
	}

	// C7/C9/C11 must probe the LIVE config/engine inside the deterministic
	// manager container, not the host-side copy of the file.
	for _, id := range []string{"C7", "C9", "C11"} {
		if !strings.Contains(cmd[id], "docker exec") || !strings.Contains(cmd[id], "single-node-wazuh.manager-1") {
			t.Errorf("%s must `docker exec` into single-node-wazuh.manager-1, got %q", id, cmd[id])
		}
	}
	for _, id := range []string{"C7", "C11"} {
		if !strings.Contains(cmd[id], "/var/ossec/etc/ossec.conf") {
			t.Errorf("%s must grep the live in-container /var/ossec/etc/ossec.conf, got %q", id, cmd[id])
		}
	}

	// C9 must feed a realistic full syslog line (not a bare, header-less
	// message) through docker exec -i and assert the alert-worthy marker,
	// not just "level:" (which the generic no-match rule 1002 also prints).
	if !strings.Contains(cmd["C9"], "sshd[") {
		t.Errorf("C9 must inject a full syslog-formatted line (hostname + sshd[pid]:), got %q", cmd["C9"])
	}
	if !strings.Contains(cmd["C9"], "docker exec -i") {
		t.Errorf("C9 must pipe the test line via `docker exec -i` (wazuh-logtest reads stdin), got %q", cmd["C9"])
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
			t.Errorf("row %s uses ~active (matches inactive); use rc-based checks", r.ID)
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
	if !strings.Contains(applyRaw, "siem_forward_host | default(") {
		t.Errorf("wazuh-manager-apply.yml must use default() filter for siem_forward_host so group_vars can override")
	}
	if !strings.Contains(applyRaw, "siem_forwarding_enabled") {
		t.Errorf("wazuh-manager-apply.yml must derive a siem_forwarding_enabled gate from siem_forward_host")
	}

	// Must deploy from the official wazuh-docker bundle: official cert
	// generator + official compose project, pinned project name, and the
	// indexer's host-level sysctl. Must NOT regress to the v1.0 host
	// install (wazuh-install.sh) or a hand-rolled per-container setup.
	for _, want := range []string{
		"wazuh-docker",                  // official release bundle
		"generate-indexer-certs.yml",    // official cert-generator one-shot
		"docker_compose_v2",             // compose-driven, not ad-hoc docker run
		"project_name",                  // deterministic container names for the spec
		"vm.max_map_count",              // official indexer hard requirement
		"/wazuh-config-mount/etc/ossec", // official config-injection mechanism documented
		"recreate: always",              // config re-injection needs RECREATE (see below)
	} {
		if !strings.Contains(applyRaw, want) {
			t.Errorf("wazuh-manager-apply.yml must contain %q (official wazuh-docker deployment contract)", want)
		}
	}
	// Config re-injection must RECREATE the manager container, never merely
	// restart it: the official image's 0-wazuh-init deletes
	// /var/ossec/data_tmp after the first boot, so on a mere restart the
	// init script dies (empty multigroups dir, missing data_tmp) BEFORE
	// mount_files runs and /wazuh-config-mount is never re-injected — found
	// live on vm-target (runbook §5); a restart-based task always looks
	// green while silently leaving the old config loaded.
	if strings.Contains(applyRaw, "state: restarted") {
		t.Errorf("wazuh-manager-apply.yml must not use `state: restarted` (official image init dies on restart; use recreate: always)")
	}
	// Comment lines may reference wazuh-install.sh as v1.0 history; no
	// executable (non-comment) line may.
	for _, line := range strings.Split(applyRaw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if strings.Contains(line, "wazuh-install.sh") {
			t.Errorf("wazuh-manager-apply.yml must not run the v1.0 wazuh-install.sh host installer (v2.0 is Docker-based), got %q", line)
		}
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
