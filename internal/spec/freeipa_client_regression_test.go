package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaClientSpec locks the structural contract of
// docs/verification/freeipa-client.md: 11 rows C1..C11, lint-clean, and a
// generated verify playbook that covers every row.
//
// Note on inventory alignment: like freeipa-server.md, this spec's §1 Targets
// table declares group `freeipa-client`, but the vm-target reference
// environment puts the single host in group `all` (run/verify with
// `-e target_group=all`). We therefore do NOT assert SpecAndInventoryAgree
// here — the alignment responsibility lives in the `-e target_group=` override
// documented in the spec, not in a fixed group name.
func TestRegression_FreeipaClientSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// 1. Row count is locked at 11.
	if len(s.Rows) != 11 {
		t.Fatalf("rows=%d want=11 (spec must cover C1..C11 inclusive)", len(s.Rows))
	}

	// 2. IDs are C1..C11 with no gaps and no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"}
	gotIDs := make([]string, 0, len(s.Rows))
	seen := map[string]bool{}
	for _, r := range s.Rows {
		if seen[r.ID] {
			t.Errorf("duplicate row ID %q", r.ID)
		}
		seen[r.ID] = true
		gotIDs = append(gotIDs, r.ID)
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("row IDs = %v, want %v", gotIDs, wantIDs)
	}

	// 3. No vague expected values, no empty fields.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", fsToString(fs))
	}
	for _, r := range s.Rows {
		if strings.TrimSpace(r.Expected) == "" {
			t.Errorf("row %s has empty Expected", r.ID)
		}
		if strings.TrimSpace(r.Command) == "" {
			t.Errorf("row %s has empty Command", r.ID)
		}
	}

	// 4. Generated playbook must be runnable YAML AND cover every row.
	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := pb.RenderYAML()
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(out), &plays); err != nil {
		t.Fatalf("generated playbook does not parse as YAML: %v\n--- output ---\n%s", err, out)
	}
	if len(plays) != 1 {
		t.Fatalf("generated playbook plays=%d, want 1", len(plays))
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

// TestRegression_FreeipaClientSpec_AAACoverage — the spec's reason for
// existing is that FreeIPA supplies this Ubuntu client with Authentication,
// Authorization AND Audit. Lock one concrete, non-substitutable check per leg
// so a future edit can't quietly drop a whole AAA dimension.
func TestRegression_FreeipaClientSpec_AAACoverage(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	cmd := map[string]string{}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
	}

	// Authentication: C5 must resolve an IPA identity via SSSD (the id lookup).
	if !strings.HasPrefix(cmd["C5"], "id ") {
		t.Errorf("C5 (authentication) must be an `id <ipa-user>` lookup, got %q", cmd["C5"])
	}
	// Authentication: C4 must inspect the host Kerberos keytab.
	if !strings.Contains(cmd["C4"], "krb5.keytab") {
		t.Errorf("C4 (authentication) must check /etc/krb5.keytab, got %q", cmd["C4"])
	}
	// Authorization: C6 must assert SSSD delegates access control to IPA (HBAC).
	if !strings.Contains(cmd["C6"], "access_provider") || !strings.Contains(cmd["C6"], "ipa") {
		t.Errorf("C6 (authorization/HBAC) must assert access_provider=ipa, got %q", cmd["C6"])
	}
	// Authorization: C8 must query centrally-defined sudo as root without
	// invoking runuser/PAM, because canonical HBAC may intentionally deny the
	// fixture account's login while its sudo policy remains valid.
	if !strings.Contains(cmd["C8"], "sudo -l -U pilotuser") {
		t.Errorf("C8 (authorization/sudo) must use `sudo -l -U <user>`, got %q", cmd["C8"])
	}
	if strings.Contains(cmd["C8"], "runuser") {
		t.Errorf("C8 must not invoke runuser/PAM when isolating central sudo policy, got %q", cmd["C8"])
	}
	// Audit: C9 must check the audit daemon.
	if !strings.Contains(cmd["C9"], "auditd") {
		t.Errorf("C9 (audit) must check auditd, got %q", cmd["C9"])
	}
	// Audit: C10 must inspect kernel auditing state.
	if !strings.Contains(cmd["C10"], "auditctl") {
		t.Errorf("C10 (audit) must use auditctl, got %q", cmd["C10"])
	}
}

// TestRegression_FreeipaClientSpec_EnrollBeforeAAA — you cannot verify AAA
// before the host is enrolled and SSSD is up. C1 (enrolled) and C2 (sssd
// active) must precede every authn/authz/audit row.
func TestRegression_FreeipaClientSpec_EnrollBeforeAAA(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	lineOf := map[string]int{}
	for _, r := range s.Rows {
		lineOf[r.ID] = r.Line
	}
	for _, base := range []string{"C1", "C2"} {
		if _, ok := lineOf[base]; !ok {
			t.Fatalf("%s row missing", base)
		}
	}
	for _, aaa := range []string{"C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11"} {
		if lineOf["C1"] >= lineOf[aaa] {
			t.Errorf("ordering: C1 (enrolled) at line %d must precede %s at line %d",
				lineOf["C1"], aaa, lineOf[aaa])
		}
		if lineOf["C2"] >= lineOf[aaa] {
			t.Errorf("ordering: C2 (sssd active) at line %d must precede %s at line %d",
				lineOf["C2"], aaa, lineOf[aaa])
		}
	}
}

// TestRegression_FreeipaClientSpec_C11QueriesAuthoritativeDNS locks spec.md
// §17: C11 must directly query authoritative FreeIPA DNS, never fall back to
// getent/ping (which would false-positive off /etc/hosts pins C1/C3 already
// write).
func TestRegression_FreeipaClientSpec_C11QueriesAuthoritativeDNS(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-client.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	var c11 string
	for _, r := range s.Rows {
		if r.ID == "C11" {
			c11 = r.Command
		}
	}
	if c11 == "" {
		t.Fatal("C11 row missing")
	}
	if !strings.HasPrefix(strings.TrimSpace(c11), "dig ") {
		t.Errorf("C11 must query DNS directly via `dig`, got %q", c11)
	}
	if !strings.Contains(c11, "@") {
		t.Errorf("C11 must target an explicit DNS server (@server), got %q", c11)
	}
	for _, forbidden := range []string{"getent", "ping "} {
		if strings.Contains(c11, forbidden) {
			t.Errorf("C11 must not use %q — that reads /etc/hosts, not authoritative DNS (spec.md §17), got %q", forbidden, c11)
		}
	}
}

// TestRegression_FreeipaClientApplyPlaybook_HostDNSSafety locks the
// non-negotiable safety rules from spec.md §27/§28 for the host DNS
// registration feature: no --all-ip-addresses, no default dynamic DNS
// updates, and the shared DNS task file is wired in before AND after
// ipa-client-install (plan preflight before mutation, apply+verify after).
func TestRegression_FreeipaClientApplyPlaybook_HostDNSSafety(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	if strings.Contains(playbook, "--all-ip-addresses") {
		t.Error("playbook must never use --all-ip-addresses (spec.md §4.5)")
	}
	if strings.Contains(playbook, "--enable-dns-updates") {
		t.Error("playbook must not default to --enable-dns-updates (spec.md §2.2)")
	}

	planIdx := strings.Index(playbook, "freeipa_client_dns_phase: plan")
	installIdx := strings.Index(playbook, "run ipa-client-install")
	applyIdx := strings.Index(playbook, "freeipa_client_dns_phase: apply")
	if planIdx < 0 || installIdx < 0 || applyIdx < 0 {
		t.Fatalf("playbook must include tasks/freeipa-client-host-dns.yml in both plan and apply phases, around ipa-client-install")
	}
	if !(planIdx < installIdx && installIdx < applyIdx) {
		t.Errorf("DNS preflight (plan) must run before ipa-client-install, and backfill+verify (apply) must run after it: planIdx=%d installIdx=%d applyIdx=%d", planIdx, installIdx, applyIdx)
	}

	// The plan phase must be reachable from pre_tasks (before ANY mutation,
	// including the /etc/hosts pin) — spec.md §16's "DNS preflight" step.
	preTasksIdx := strings.Index(playbook, "pre_tasks:")
	hostsPinIdx := strings.Index(playbook, "pin this host")
	if preTasksIdx < 0 || hostsPinIdx < 0 || !(preTasksIdx < planIdx && planIdx < hostsPinIdx) {
		t.Errorf("DNS plan-phase include must sit inside pre_tasks, before the /etc/hosts self-pin task")
	}
}

// TestRegression_FreeipaClientHostDNSTask_NoLog locks spec.md §12: the
// dedicated-ccache kinit task in the DNS backfill path must be no_log, same
// convention as the main enrollment task and freeipa-dns-apply.yml.
func TestRegression_FreeipaClientHostDNSTask_NoLog(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	kinitIdx := strings.Index(task, "kinit admin into the dedicated ccache")
	if kinitIdx < 0 {
		t.Fatal("expected a kinit task for the DNS backfill ccache")
	}
	// Look for no_log: true within a reasonable window after the task name.
	window := task[kinitIdx:]
	if end := strings.Index(window, "\n\n"); end > 0 {
		window = window[:end]
	}
	if !strings.Contains(window, "no_log: true") {
		t.Error("DNS backfill kinit task must be no_log: true — it pipes ipa_enroll_password")
	}

	for _, forbidden := range []string{"--all-ip-addresses", "--enable-dns-updates"} {
		if strings.Contains(task, forbidden) {
			t.Errorf("shared DNS task file must not contain %q", forbidden)
		}
	}
}

// TestRegression_FreeipaClientHostDNSTask_FailClosedAuthoritativeQueries
// prevents DNS transport diagnostics from being mistaken for either a CNAME
// or an existing A/AAAA address.  `dig +short` can emit a UDP timeout message
// on stdout even with rc=0, so the preflight must require a parsed DNS header
// before it decides whether registration is safe.
func TestRegression_FreeipaClientHostDNSTask_FailClosedAuthoritativeQueries(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if strings.Contains(task, "+short") {
		t.Error("authoritative DNS preflight must not use dig +short: diagnostics can be misclassified as records")
	}
	for _, required := range []string{
		"Gate: authoritative DNS queries must return a usable response",
		"+noall", "+comments", "+answer",
		"(?m)^;; Got answer:$",
		"status:[ ]+(NOERROR|NXDOMAIN),",
		"ipa_client_dns_current_cname_records",
		"select('match', '^\\S+\\s+\\d+\\s+IN\\s+CNAME",
		"select('match', '^\\S+\\s+\\d+\\s+IN\\s+A",
		"select('match', '^\\S+\\s+\\d+\\s+IN\\s+AAAA",
	} {
		if !strings.Contains(task, required) {
			t.Errorf("DNS preflight must contain %q", required)
		}
	}
}

// TestRegression_FreeipaClientHostDNSTask_FailClosedGateSkipsCheckMode locks
// the 2026-08-31 fix: a genuinely fresh FreeIPA host has no DNS service to
// answer this preflight query at all during a `--check` preview, because
// ipa-server-install (a real mutation) is correctly skipped there. The
// fail-closed assert must therefore only apply to a real (non-check) run —
// otherwise every `--check --diff` preview of a fresh clean-room topology
// hard-fails before any host has actually been provisioned.
func TestRegression_FreeipaClientHostDNSTask_FailClosedGateSkipsCheckMode(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	gateIdx := strings.Index(task, "Gate: authoritative DNS queries must return a usable response")
	if gateIdx < 0 {
		t.Fatal("expected the plan-phase authoritative DNS response gate")
	}
	window := task[gateIdx:]
	if end := strings.Index(window, "\n\n"); end > 0 {
		window = window[:end]
	}
	if !strings.Contains(window, "not ansible_check_mode") {
		t.Error("plan-phase fail-closed gate must be skipped in check mode (a fresh host's DNS server isn't running yet during --check)")
	}
}

// TestRegression_FreeipaClientApplyPlaybook_HasCloudInitEtcHostsGuard locks
// the 2026-08-18 fix for cloud-init-freeipa-incident-report.md:
// yk-pro6k-dev-01/02/03 all lost their FreeIPA server /etc/hosts pin on
// reboot because cloud-init's manage_etc_hosts regenerated /etc/hosts from
// its own template. freeipa-client-apply.yml must include the shared
// cloud-init-etc-hosts-guard.yml task BEFORE its own /etc/hosts pin, so the
// pin survives every future reboot instead of only the next apply.
func TestRegression_FreeipaClientApplyPlaybook_HasCloudInitEtcHostsGuard(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	guardIdx := strings.Index(playbook, "tasks/cloud-init-etc-hosts-guard.yml")
	if guardIdx < 0 {
		t.Fatalf("playbook must include tasks/cloud-init-etc-hosts-guard.yml")
	}
	pinIdx := strings.Index(playbook, `regexp: '\s{{ ipa_server_fqdn | regex_escape }}(\s|$)'`)
	if pinIdx < 0 {
		t.Fatalf("playbook must still pin the FreeIPA server FQDN in /etc/hosts")
	}
	if guardIdx > pinIdx {
		t.Errorf("cloud-init-etc-hosts-guard.yml must be included BEFORE the /etc/hosts server-FQDN pin, else a reboot between guard-install and pin could still wipe an unpinned host")
	}
}

// TestRegression_CloudInitEtcHostsGuardTask locks the shared task file's
// core behavior: disable cloud-init's manage_etc_hosts via a new,
// pilot-owned cloud.cfg.d drop-in, gated on cloud-init actually being
// present (no-op elsewhere).
func TestRegression_CloudInitEtcHostsGuardTask(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/cloud-init-etc-hosts-guard.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	for _, required := range []string{
		"/etc/cloud/cloud.cfg.d/99-pilot-disable-manage-etc-hosts.cfg",
		"manage_etc_hosts: false",
		"path: /etc/cloud/cloud.cfg",
	} {
		if !strings.Contains(task, required) {
			t.Errorf("cloud-init-etc-hosts-guard.yml must contain %q", required)
		}
	}
}
