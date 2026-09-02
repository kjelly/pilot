package spec

import (
	"os"
	"regexp"
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

// TestRegression_FreeipaClientApplyPlaybook_FreshFactsNotCached locks a real
// bug found live during the Day-2 spec §19 L2 run: this repo's ansible.cfg
// enables fact_caching (1h TTL). With the implicit `gather_facts: true`
// default, a rerun against a host that had just been migrated to a new IP
// within that TTL window silently reused the STALE pre-migration
// ansible_default_ipv4.address from cache — making "desired" equal the OLD
// address again and reporting a false NOOP instead of detecting the real
// IP change. The playbook must instead disable the implicit gather and run
// an explicit `ansible.builtin.setup` task, which always executes for real
// (unlike gather_facts's cache-aware skip).
func TestRegression_FreeipaClientApplyPlaybook_FreshFactsNotCached(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	// Match only an actual YAML `gather_facts: true` key, not the
	// explanatory comment above it that mentions the string in backticks.
	if regexp.MustCompile(`(?m)^\s*gather_facts:\s*true\s*$`).MatchString(playbook) {
		t.Error("playbook must not use gather_facts: true — this repo's fact_caching can silently reuse a stale pre-migration ansible_default_ipv4.address and mask a real Day-2 IP change as a false NOOP")
	}
	if !strings.Contains(playbook, "gather_facts: false") {
		t.Fatal("expected gather_facts: false (paired with an explicit setup task below)")
	}
	setupIdx := strings.Index(playbook, "ansible.builtin.setup:")
	preTasksIdx := strings.Index(playbook, "pre_tasks:")
	if setupIdx < 0 || preTasksIdx < 0 || setupIdx < preTasksIdx {
		t.Error("expected an explicit `ansible.builtin.setup` task in pre_tasks to gather fresh facts unconditionally")
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

// ─────────────────────────────────────────────────────────────────────────
// Day-2 IP replacement (docs/superpowers/specs/2026-09-02-freeipa-client-
// host-dns-ip-replacement-spec.md). These lock the safety invariants
// (§14 S1-S10) and the §18.1 static-regression checklist. Like the tests
// above, they inspect the generated playbook/task-file TEXT rather than
// executing Ansible — the semantic behavior is proven by the live VM
// matrix (spec §19 L1-L11), not by these structural locks.
// ─────────────────────────────────────────────────────────────────────────

// TestRegression_FreeipaClientContract_DNSReplaceFromAddress locks Day-2
// spec §18.1.1: the new CAS token is registered, optional, string, and
// non-secret — never required, never a boolean allow-flag.
func TestRegression_FreeipaClientContract_DNSReplaceFromAddress(t *testing.T) {
	const contractPath = "../../contracts/freeipa-client.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	contractYAML := string(raw)

	if !strings.Contains(contractYAML, "freeipa_client_dns_replace_from_address") {
		t.Fatal("contract must register freeipa_client_dns_replace_from_address")
	}
	if !strings.Contains(contractYAML, "{name: freeipa_client_dns_replace_from_address, type: string, required: false, secret: false}") {
		t.Error("freeipa_client_dns_replace_from_address must be declared optional, type string, non-secret (Day-2 spec §4.1) — matching this file's existing inline groupVars style")
	}
}

// TestRegression_FreeipaClientHostDNSTask_NoOwnerWideDelete locks S6: every
// dnsrecord-del call in the shared task file must be scoped to a specific
// record type/value (--a-rec=/--aaaa-rec=), never a bare
// `ipa dnsrecord-del <zone> <owner>` that would remove the whole owner
// (including foreign RRs like TXT — S7).
func TestRegression_FreeipaClientHostDNSTask_NoOwnerWideDelete(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	delRe := regexp.MustCompile(`(?s)dnsrecord-del.{0,400}`)
	matches := delRe.FindAllString(task, -1)
	if len(matches) == 0 {
		t.Fatal("expected at least one dnsrecord-del invocation (cross-family stale removal, Day-2 spec §9.5)")
	}
	for i, m := range matches {
		// Both the flag name and the value are templated (the flag comes
		// from a Jinja ternary/loop var, not a literal "-rec=" substring),
		// so check for the "-rec" flag family rather than a literal
		// "-rec=" adjacency, and additionally require an "=" further in the
		// same window (the value assignment) — together they rule out a
		// bare `[ipa, dnsrecord-del, zone, name]` owner-wide call.
		if !strings.Contains(m, "-rec") || !strings.Contains(m, "=") {
			t.Errorf("dnsrecord-del invocation #%d has no record-type/value scoping within 400 chars — looks owner-wide (spec.md §12/Day-2 spec §9.1/S6): %q", i, m)
		}
	}
}

// TestRegression_FreeipaClientHostDNSTask_ReplaceStateMachine locks Day-2
// spec §5.1's action state machine shape: every action label from the
// table is present, the precedence order in the ternary chain matches the
// table (extra-empty decided before any R-dependent branch; multi-extra
// before CAS-mismatch; CAS-mismatch before identity), and no permanent
// allow-flag (freeipa_client_dns_allow_replace or similar) was introduced.
func TestRegression_FreeipaClientHostDNSTask_ReplaceStateMachine(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	actionIdx := strings.Index(task, "ipa_client_dns_plan_action: >-")
	if actionIdx < 0 {
		t.Fatal("expected an ipa_client_dns_plan_action set_fact block")
	}
	block := task[actionIdx:]
	if end := strings.Index(block, "\n  when:"); end > 0 {
		block = block[:end]
	}

	for _, label := range []string{
		"'NOOP_STALE_ACK'", "'NOOP'", "'ADD'", "'CONFLICT_UNAUTHORIZED'",
		"'CONFLICT_MULTI_EXTRA'", "'CONFLICT_CAS_MISMATCH'",
		"'CONFLICT_IDENTITY_UNPROVEN'", "'REPLACE'",
	} {
		if !strings.Contains(block, label) {
			t.Errorf("plan-action state machine must produce %s (Day-2 spec §5.1 table)", label)
		}
	}

	// Precedence: the extra-empty branch (NOOP/NOOP_STALE_ACK/ADD) must be
	// decided before any R-dependent CONFLICT_* branch, and each CONFLICT_*
	// must appear in the table's own precedence order.
	order := []string{
		"(ipa_client_dns_extra | default([]) | length) == 0 and (ipa_client_dns_missing | default([]) | length) == 0",
		"(ipa_client_dns_extra | default([]) | length) == 0",
		"'CONFLICT_UNAUTHORIZED'",
		"'CONFLICT_MULTI_EXTRA'",
		"'CONFLICT_CAS_MISMATCH'",
		"'REPLACE'",
	}
	pos := 0
	for _, needle := range order {
		// Search strictly AFTER the previous match's end (not merely at a
		// later start index) — several needles here are literal prefixes
		// of an earlier, longer condition (e.g. the ADD branch's bare
		// "extra == 0" is a textual prefix of the NOOP branch's combined
		// "extra == 0 and missing == 0"), so a plain re-search from offset
		// 0 would "find" the shorter needle inside the longer one's own
		// match and falsely appear out of order.
		i := strings.Index(block[pos:], needle)
		if i < 0 {
			t.Fatalf("expected %q within the plan-action block after offset %d", needle, pos)
		}
		pos += i + len(needle)
	}

	for _, forbidden := range []string{"freeipa_client_dns_allow_replace", "allow_replace", "--all-ip-addresses", "--enable-dns-updates"} {
		if strings.Contains(task, forbidden) {
			t.Errorf("shared DNS task file must not contain %q — Day-2 spec §3.2 forbids a permanent allow-flag", forbidden)
		}
	}
}

// TestRegression_FreeipaClientHostDNSTask_IdentityProof locks S4/Day-2 spec
// §6: a replacement candidate's identity proof must combine an existing
// enrollment config, an existing keytab, a config host/realm match, AND a
// successful `kinit -k -t` of the exact host principal — not any single one
// of those in isolation — and the kinit must be no_log.
func TestRegression_FreeipaClientHostDNSTask_IdentityProof(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	kinitIdx := strings.Index(task, "kinit the exact host keytab principal")
	if kinitIdx < 0 {
		t.Fatal("expected a dedicated identity-proof kinit task")
	}
	if !strings.Contains(task, "kinit, -k, -t, /etc/krb5.keytab") {
		t.Error(`identity proof must use "kinit -k -t /etc/krb5.keytab host/<fqdn>@<realm>" — not a password-based kinit (Day-2 spec §6.4)`)
	}
	window := task[kinitIdx:]
	if end := strings.Index(window, "\n\n"); end > 0 {
		window = window[:end]
	}
	if !strings.Contains(window, "no_log: true") {
		t.Error("identity-proof kinit task must be no_log: true (spec S9)")
	}

	provenIdx := strings.Index(task, "ipa_client_dns_identity_proven: >-")
	if provenIdx < 0 {
		t.Fatal("expected an ipa_client_dns_identity_proven set_fact")
	}
	provenBlock := task[provenIdx:]
	if end := strings.Index(provenBlock, "\n  when:"); end > 0 {
		provenBlock = provenBlock[:end]
	}
	for _, must := range []string{
		"ipa_cfg.stat.exists",
		"ipa_client_dns_keytab_stat.stat.exists",
		"ipa_client_dns_identity_config_check.rc",
		"ipa_client_dns_identity_kinit.rc",
	} {
		if !strings.Contains(provenBlock, must) {
			t.Errorf("identity_proven must require %q (all four independent checks, Day-2 spec §6)", must)
		}
	}
}

// TestRegression_FreeipaClientApplyPlaybook_EnrollmentProbeBeforeDNSPlan
// locks Day-2 spec §6.2: the enrollment (/etc/ipa/default.conf) and keytab
// (/etc/krb5.keytab) stats must be registered in pre_tasks BEFORE the DNS
// plan-phase include, and reused (not re-probed) by the installer gate
// later in tasks — a single canonical enrollment check, not two.
func TestRegression_FreeipaClientApplyPlaybook_EnrollmentProbeBeforeDNSPlan(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	preTasksIdx := strings.Index(playbook, "pre_tasks:")
	cfgStatIdx := strings.Index(playbook, `path: "{{ ipa_config_marker }}"`)
	keytabStatIdx := strings.Index(playbook, "path: /etc/krb5.keytab")
	planIdx := strings.Index(playbook, "freeipa_client_dns_phase: plan")
	tasksIdx := strings.Index(playbook, "\n  tasks:\n")

	if preTasksIdx < 0 || cfgStatIdx < 0 || keytabStatIdx < 0 || planIdx < 0 || tasksIdx < 0 {
		t.Fatal("expected pre_tasks, both stat probes, the DNS plan include, and a tasks: section")
	}
	if !(preTasksIdx < cfgStatIdx && cfgStatIdx < planIdx) {
		t.Errorf("enrollment-config stat must sit inside pre_tasks, before the DNS plan include: preTasksIdx=%d cfgStatIdx=%d planIdx=%d", preTasksIdx, cfgStatIdx, planIdx)
	}
	if !(preTasksIdx < keytabStatIdx && keytabStatIdx < planIdx) {
		t.Errorf("keytab stat must sit inside pre_tasks, before the DNS plan include: preTasksIdx=%d keytabStatIdx=%d planIdx=%d", preTasksIdx, keytabStatIdx, planIdx)
	}
	// Only ONE stat of ipa_config_marker in the whole playbook — the
	// installer gate must reuse the pre_tasks result, not re-probe.
	if n := strings.Count(playbook, `path: "{{ ipa_config_marker }}"`); n != 1 {
		t.Errorf("expected exactly one stat of ipa_config_marker (reused by both DNS plan and the installer gate), got %d", n)
	}
	if idx := strings.Index(playbook, "register: ipa_cfg"); idx < 0 || idx > tasksIdx {
		t.Error("ipa_cfg must still be registered in pre_tasks (reused, not moved into tasks:)")
	}
}

// TestRegression_FreeipaClientHostDNSTask_ApplyTimeCASRecheck locks S5/Day-2
// spec §8: a REPLACE action must re-query authoritative DNS live at apply
// time (never trust the plan snapshot) and re-verify CNAME-absent,
// single-extra, CAS-match, and identity_proven before the first write.
func TestRegression_FreeipaClientHostDNSTask_ApplyTimeCASRecheck(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	replaceBlockIdx := strings.Index(task, "Day-2 replacement: re-check + mutate")
	if replaceBlockIdx < 0 {
		t.Fatal("expected a dedicated apply-phase REPLACE block")
	}
	block := task[replaceBlockIdx:]

	for _, must := range []string{
		"apply-time CAS re-read",
		"FAIL CLOSED — authoritative state changed after planning",
		"ipa_client_dns_apply_extra[0] == ipa_client_dns_replace_from_effective",
		"(ipa_client_dns_apply_cname_records | default([]) | length) == 0",
		"(ipa_client_dns_identity_proven | default(false) | bool)",
	} {
		if !strings.Contains(block, must) {
			t.Errorf("REPLACE apply block must contain %q (apply-time CAS re-check, Day-2 spec §8.1/S5)", must)
		}
	}

	// The re-query tasks (A/AAAA/CNAME) must appear before the first
	// mutating dnsrecord-mod/dnsrecord-del in this block.
	reQueryIdx := strings.Index(block, "re-query authoritative DNS: A records")
	firstMutationIdx := strings.Index(block, "dnsrecord-mod")
	if reQueryIdx < 0 || firstMutationIdx < 0 || reQueryIdx >= firstMutationIdx {
		t.Errorf("apply-time DNS re-query must precede the first mutating command: reQueryIdx=%d firstMutationIdx=%d", reQueryIdx, firstMutationIdx)
	}
}

// TestRegression_FreeipaClientHostDNSTask_PostApplyExactVerification locks
// Day-2 spec §10.1/S8: the post-apply "exact" gate must check BOTH
// directions of the set difference, not just desired-minus-post
// (missing-only) — the pre-existing bug this feature is required to fix.
// Applies to every DNS-write path (ADD and REPLACE share this one gate).
func TestRegression_FreeipaClientHostDNSTask_PostApplyExactVerification(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	gateIdx := strings.Index(task, "matches desired addresses EXACTLY after apply")
	if gateIdx < 0 {
		t.Fatal("expected the post-apply exact-match gate")
	}
	window := task[gateIdx:]
	if end := strings.Index(window, "\n\n    - name:"); end > 0 {
		window = window[:end]
	}
	if !strings.Contains(window, "ipa_client_dns_addresses_effective | difference(ipa_client_dns_verify_current)") {
		t.Error("exact-match gate must check desired - post == ∅ (missing)")
	}
	if !strings.Contains(window, "ipa_client_dns_verify_current | difference(ipa_client_dns_addresses_effective)") {
		t.Error("exact-match gate must ALSO check post - desired == ∅ (extra) — this is the fix for the pre-existing missing-only gap (Day-2 spec §10.1)")
	}
}

// TestRegression_FreeipaClientHostDNSTask_DeleteUsesRawStoredValue locks a
// bug found via live testing (Day-2 spec §19 L11): FreeIPA/LDAP stores a
// record's value exactly as entered — it does not normalize an IPv6
// literal to compressed form the way `dig` display output does — so
// `dnsrecord-del --aaaa-rec=<value>` matches by exact string. Passing our
// own canonicalized (compressed) value fails with "AAAA record does not
// contain ..." whenever the stale record happens to be stored in expanded
// form. The cross-family delete must resolve the record's actual raw
// stored value (via --all --raw, same convention as
// freeipa-dns-apply.yml) before deleting, not delete by the canonicalized
// comparison value directly.
func TestRegression_FreeipaClientHostDNSTask_DeleteUsesRawStoredValue(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "dnsrecord-show") || !strings.Contains(task, "--all, --raw") {
		t.Error("REPLACE apply block must read the record's raw stored values (ipa dnsrecord-show ... --all --raw) before a value-scoped delete")
	}
	if !strings.Contains(task, "ipa_client_dns_apply_stale_raw_value") {
		t.Fatal("expected a resolved as-stored raw value fact for the stale delete")
	}

	delIdx := strings.Index(task, `name: "FreeIPA client DNS replace — value-scoped removal of the authorized stale address (cross-family only)"`)
	if delIdx < 0 {
		t.Fatal("expected the cross-family stale-removal delete task")
	}
	window := task[delIdx:]
	if end := strings.Index(window, "\n    - name:"); end > 0 {
		window = window[:end]
	}
	if !strings.Contains(window, "ipa_client_dns_apply_stale_raw_value") {
		t.Error("the dnsrecord-del argv must use the resolved as-stored raw value, not the canonicalized comparison value directly")
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
