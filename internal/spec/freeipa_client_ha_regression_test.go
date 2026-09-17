package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaServerPoolTask_TopologyModeGate locks that
// playbooks/apply/tasks/freeipa-server-pool.yml validates
// freeipa_client_topology_mode against the three legal values
// (docs/tmp/now/freeipa-client-ha-spec.md §2.2) before doing anything else,
// and defaults to "auto" when unset — existing single-server inventories
// must not need any new variable to keep working.
func TestRegression_FreeipaServerPoolTask_TopologyModeGate(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "freeipa_client_topology_mode | default('auto')") {
		t.Errorf("task must default freeipa_client_topology_mode to 'auto' when unset")
	}
	if !strings.Contains(task, "freeipa_client_topology_mode_input in ['auto', 'single', 'ha']") {
		t.Errorf("task must gate topology_mode against exactly auto|single|ha")
	}
}

// TestRegression_FreeipaServerPoolTask_PoolSourceFixed locks spec §3.1: pool
// membership comes ONLY from groups['freeipa-server'] then
// groups['freeipa-server-replica'] — never from DNS SRV discovery or an
// existing client's sssd.conf, both of which would make "desired state"
// drift with whatever happens to be reachable/configured right now instead
// of staying a pure inventory-driven declaration.
func TestRegression_FreeipaServerPoolTask_PoolSourceFixed(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	for _, want := range []string{
		"groups['freeipa-server']",
		"groups['freeipa-server-replica']",
	} {
		if !strings.Contains(task, want) {
			t.Errorf("task must read pool membership from %q", want)
		}
	}
	// Pool membership must be pure inventory/Jinja computation — no task in
	// this file may execute a remote command or read remote file state
	// (which is how a "derive from sssd.conf" or "derive from what's
	// currently reachable" anti-pattern would sneak in). Only
	// set_fact/assert/debug are allowed.
	for _, forbiddenModule := range []string{
		"ansible.builtin.command",
		"ansible.builtin.shell",
		"ansible.builtin.slurp",
		"ansible.builtin.uri",
		"ansible.builtin.raw",
	} {
		if strings.Contains(task, forbiddenModule) {
			t.Errorf("task must be pure inventory/Jinja computation — found remote-executing module %q (spec §3.1 forbids reachability/sssd.conf-derived pool membership)", forbiddenModule)
		}
	}
}

// TestRegression_FreeipaServerPoolTask_HAModeRequiresTwo locks spec §3.2:
// an operator-forced `ha` topology_mode with fewer than 2 pool members must
// fail closed, and this gate must only fire for ha mode — auto/single with
// a single provider must NOT be blocked by it (spec §2.1: single-node is a
// first-class, not degraded, mode).
func TestRegression_FreeipaServerPoolTask_HAModeRequiresTwo(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	gateIdx := strings.Index(task, "ha mode requires >= 2 providers")
	if gateIdx == -1 {
		t.Fatalf("could not find the ha->2-providers gate task")
	}
	// The gate task's `when:` must scope it to topology_mode_input == 'ha'
	// specifically, not fire unconditionally.
	gateBlock := task[gateIdx:]
	whenIdx := strings.Index(gateBlock, "when:")
	if whenIdx == -1 || !strings.Contains(gateBlock[whenIdx:whenIdx+120], "freeipa_client_topology_mode_input == 'ha'") {
		t.Errorf("the >=2-providers gate must be scoped to `when: freeipa_client_topology_mode_input == 'ha'`, not fire for auto/single")
	}
}

// TestRegression_FreeipaServerPoolTask_DuplicateInvariants locks spec §3.2's
// fail-closed duplicate checks: no two pool members may share an FQDN
// (which also covers "primary FQDN == replica FQDN" as a special case), and
// no two DIFFERENT FQDNs may share a non-empty IP.
func TestRegression_FreeipaServerPoolTask_DuplicateInvariants(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "no duplicate FQDNs in the pool") {
		t.Errorf("task must gate against duplicate FQDNs across the whole pool")
	}
	if !strings.Contains(task, "no IP reused across different FQDNs") {
		t.Errorf("task must gate against the same IP bound to two different FQDNs")
	}
}

// TestRegression_FreeipaServerPoolTask_MultiReplicaFQDNGate locks spec
// §3.2's "Replica FQDN backward compatibility" rule: a SINGLE replica may
// still rely on the legacy ipa2.<domain> default, but as soon as a second
// replica is present, every replica host must set its own
// freeipa_replica_fqdn — the task must fail closed rather than let two
// replicas silently collide on the same default FQDN.
func TestRegression_FreeipaServerPoolTask_MultiReplicaFQDNGate(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	gateIdx := strings.Index(task, "each need an explicit freeipa_replica_fqdn host var")
	if gateIdx == -1 {
		t.Fatalf("could not find the multi-replica FQDN gate task")
	}
	gateBlock := task[gateIdx:]
	whenIdx := strings.Index(gateBlock, "when:")
	if whenIdx == -1 || !strings.Contains(gateBlock[whenIdx:whenIdx+150], "groups['freeipa-server-replica'] | default([]) | length) > 1") {
		t.Errorf("the multi-replica FQDN gate must only fire when there is more than one replica host, so a single replica keeps the legacy ipa2.<domain> default")
	}
	if !strings.Contains(task, "'ipa2.' ~ freeipa_domain") {
		t.Errorf("task must still preserve the single-replica legacy default (ipa2.<domain>) for backward compatibility")
	}
}

// TestRegression_FreeipaServerPoolTask_SingleModeActiveUsesPrimaryOnly locks
// that a forced `single` topology_mode uses ONLY the primary for the active
// pool (freeipa_server_fqdns/ips/dns_server_ips), even when a replica is
// present in inventory — while freeipa_server_pool itself (the full
// discovered pool) still lists every member, so Phase 4 Day-2 reconciliation
// always has the true desired pool to converge toward without
// re-discovery when an operator later switches back to auto/ha.
func TestRegression_FreeipaServerPoolTask_SingleModeActiveUsesPrimaryOnly(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-server-pool.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	activeIdx := strings.Index(task, "freeipa_server_pool_active:")
	if activeIdx == -1 {
		t.Fatalf("could not find freeipa_server_pool_active computation")
	}
	activeBlock := task[activeIdx : activeIdx+400]
	if !strings.Contains(activeBlock, "freeipa_server_pool_primary") {
		t.Errorf("freeipa_server_pool_active must fall back to freeipa_server_pool_primary (not the full pool) outside ha mode")
	}
	if !strings.Contains(activeBlock, "== 'ha'") {
		t.Errorf("freeipa_server_pool_active must branch on freeipa_client_topology_mode_effective == 'ha'")
	}
}

// TestRegression_FreeipaClientContract_TopologyModeGroupVar locks that
// contracts/freeipa-client.yaml declares freeipa_client_topology_mode as an
// optional group var, so `pilot contract lint` and any future
// contract-driven UI (pilot edit) surface it.
func TestRegression_FreeipaClientContract_TopologyModeGroupVar(t *testing.T) {
	const contractPath = "../../contracts/freeipa-client.yaml"
	raw, err := os.ReadFile(contractPath)
	if err != nil {
		t.Fatalf("read %s: %v", contractPath, err)
	}
	var doc struct {
		GroupVars []struct {
			Name     string `yaml:"name"`
			Type     string `yaml:"type"`
			Required bool   `yaml:"required"`
		} `yaml:"groupVars"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", contractPath, err)
	}
	for _, gv := range doc.GroupVars {
		if gv.Name == "freeipa_client_topology_mode" {
			if gv.Required {
				t.Errorf("freeipa_client_topology_mode must be optional (default auto) — existing single-server inventories must not need to set it")
			}
			if gv.Type != "string" {
				t.Errorf("freeipa_client_topology_mode type = %q, want string", gv.Type)
			}
			return
		}
	}
	t.Fatalf("contracts/freeipa-client.yaml groupVars is missing freeipa_client_topology_mode")
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 4 — Existing client Day-2 HA reconciliation
// (playbooks/apply/tasks/freeipa-client-server-failover.yml, spec §7/§8/§9).
// ─────────────────────────────────────────────────────────────────────────

// TestRegression_FreeipaClientServerFailoverTask_NoEmbeddedNewlineEscape
// locks the real bug found live in Phase 4 (2026-09-17): building the
// krb5.conf server-list block via `regex_replace` with `\n` embedded in a
// SINGLE-QUOTED YAML replacement string lands a literal two-character
// backslash-n in the file, not a real newline — single-quoted YAML never
// interprets backslash escapes. The fix uses a Jinja {% for %} template
// (real newlines in the rendered block scalar) instead.
func TestRegression_FreeipaClientServerFailoverTask_NoEmbeddedNewlineEscape(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-server-failover.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if strings.Contains(task, `\1:88\n`) {
		t.Errorf("must not build the krb5 server-list block via regex_replace with \\n embedded in a single-quoted replacement string — single-quoted YAML never interprets backslash escapes, so \\n lands as a literal 2-character sequence, not a real newline (confirmed live)")
	}
	if !strings.Contains(task, "{% for fqdn in") {
		t.Errorf("krb5 server-list block must be built via a Jinja {%% for %%} template (real newlines), not a regex_replace replacement string")
	}
}

// TestRegression_FreeipaClientServerFailoverTask_ConcatenationNotRegexReplace
// locks that the krb5.conf server-list block is spliced in via plain
// string concatenation around two regex_search anchors, not a
// regex_replace with the computed block embedded in the replacement
// string — a computed block containing anything that looks like a
// backreference (a literal digit after a backslash) would corrupt a
// regex_replace substitution; concatenation has no such risk.
func TestRegression_FreeipaClientServerFailoverTask_ConcatenationNotRegexReplace(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-server-failover.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "regex_search") {
		t.Errorf("must locate the pre/post anchors via regex_search")
	}
	newIdx := strings.Index(task, "freeipa_client_krb5_new:")
	if newIdx == -1 {
		t.Fatalf("could not find freeipa_client_krb5_new computation")
	}
	newLine := task[newIdx : newIdx+200]
	if !strings.Contains(newLine, "freeipa_client_krb5_pre") || !strings.Contains(newLine, "freeipa_client_krb5_post") {
		t.Errorf("freeipa_client_krb5_new must concatenate freeipa_client_krb5_pre + desired_block + freeipa_client_krb5_post")
	}
}

// TestRegression_FreeipaClientServerFailoverTask_BackupAtomicValidateRollback
// locks spec §9.2's required mutation discipline: backup before mutating,
// atomic write (ansible.builtin.copy, not an in-place multi-line sed),
// validate with a REAL `kinit -k` using the host's own keytab (not just
// "SSSD still resolves identities" — spec §15 explicitly forbids that as
// proof), and restore the backup + fail the play if validation fails.
func TestRegression_FreeipaClientServerFailoverTask_BackupAtomicValidateRollback(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-client-server-failover.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "krb5.conf.pilot-backup") {
		t.Errorf("must back up /etc/krb5.conf before mutating it")
	}
	backupIdx := strings.Index(task, "backup current krb5.conf before mutation")
	writeIdx := strings.Index(task, "write reconciled krb5.conf (atomic)")
	validateIdx := strings.Index(task, "validate: kinit with host keytab")
	rollbackIdx := strings.Index(task, "restore krb5.conf backup after failed validation")
	failIdx := strings.Index(task, "fail loudly after restoring backup")
	for name, idx := range map[string]int{
		"backup": backupIdx, "write": writeIdx, "validate": validateIdx,
		"rollback": rollbackIdx, "fail": failIdx,
	} {
		if idx == -1 {
			t.Fatalf("could not find the %q task", name)
		}
	}
	if !(backupIdx < writeIdx && writeIdx < validateIdx && validateIdx < rollbackIdx && rollbackIdx < failIdx) {
		t.Errorf("mutation steps must run in order: backup -> write -> validate -> rollback -> fail (got backup=%d write=%d validate=%d rollback=%d fail=%d)", backupIdx, writeIdx, validateIdx, rollbackIdx, failIdx)
	}
	if !strings.Contains(task, "kinit, -k, -t, /etc/krb5.keytab") {
		t.Errorf("validation must use a real kinit -k -t /etc/krb5.keytab, not an SSSD-only check (spec §15)")
	}
}

// TestRegression_FreeipaClientApplyPlaybook_FailoverReconciliationWiredIn
// locks that freeipa-client-apply.yml includes the failover reconciliation
// task UNCONDITIONALLY (not gated on "was this a fresh enroll" or "is this
// host already enrolled") — Phase 0 found live that ipa-client-install's
// own reachability probe can leave a freshly-enrolled client with an
// incomplete pool, so reconciliation must run every time, not just for
// pre-existing clients.
func TestRegression_FreeipaClientApplyPlaybook_FailoverReconciliationWiredIn(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	includeIdx := strings.Index(playbook, "tasks/freeipa-client-server-failover.yml")
	if includeIdx == -1 {
		t.Fatalf("playbook must include tasks/freeipa-client-server-failover.yml")
	}
	includeBlock := playbook[max(0, includeIdx-400) : includeIdx+200]
	if strings.Contains(includeBlock, "ipa_cfg.stat.exists") {
		t.Errorf("failover reconciliation must NOT be gated on prior-enrollment detection (ipa_cfg.stat.exists) — it must run unconditionally, including right after a fresh enrollment (spec §7, Phase 0 finding)")
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Phase 5 — Control-plane admin endpoint selection
// (playbooks/apply/tasks/freeipa-admin-endpoint-select.yml, spec §13).
// ─────────────────────────────────────────────────────────────────────────

// TestRegression_FreeipaAdminEndpointSelectTask_FailClosedNonMutating locks
// spec §13: the selector picks the first REACHABLE pool member (not
// necessarily the first in desired-pool order), fails closed when none are
// reachable, and never rewrites /etc/ipa/default.conf — confirmed live in
// Phase 0 that `ipa -e xmlrpc_uri=<url>` is a real, non-mutating,
// per-invocation override, so there is no shared-mutable-state
// concurrency concern to serialize around.
func TestRegression_FreeipaAdminEndpointSelectTask_FailClosedNonMutating(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-admin-endpoint-select.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	if !strings.Contains(task, "freeipa_admin_server_fqdn") {
		t.Fatalf("task must output freeipa_admin_server_fqdn")
	}
	if !strings.Contains(task, "selectattr('1.failed', 'equalto', false)") {
		t.Errorf("selection must filter to only the REACHABLE probe results before picking the first one")
	}
	if !strings.Contains(task, "(freeipa_admin_server_fqdn | length) > 0") {
		t.Errorf("must fail closed when no pool member is reachable")
	}
	for _, mutator := range []string{"ansible.builtin.copy", "ansible.builtin.lineinfile", "ansible.builtin.blockinfile"} {
		if strings.Contains(task, mutator) {
			t.Errorf("selector must never mutate any file (found %q) — it is a non-mutating per-invocation override (spec §13.1)", mutator)
		}
	}
}

// TestRegression_FreeipaClientApplyPlaybook_AdminEndpointWiredIntoDNSBackfill
// locks that the DNS backfill ADD task (freeipa-client-host-dns.yml) uses
// the live-selected endpoint via `-e xmlrpc_uri=`, not a bare `ipa
// dnsrecord-add` that would fall through to /etc/ipa/default.conf's
// primary-only xmlrpc_uri. Confirmed live: with the primary stopped, the
// bare form's implicit default.conf routing made even a plain DNS
// backfill fail; the fix let it succeed via the surviving replica.
func TestRegression_FreeipaClientApplyPlaybook_AdminEndpointWiredIntoDNSBackfill(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)
	if !strings.Contains(playbook, "tasks/freeipa-admin-endpoint-select.yml") {
		t.Fatalf("playbook must include tasks/freeipa-admin-endpoint-select.yml")
	}

	const dnsTaskPath = "../../playbooks/apply/tasks/freeipa-client-host-dns.yml"
	dnsRaw, err := os.ReadFile(dnsTaskPath)
	if err != nil {
		t.Fatalf("read %s: %v", dnsTaskPath, err)
	}
	dnsTask := string(dnsRaw)
	addIdx := strings.Index(dnsTask, "add each missing address to authoritative DNS")
	if addIdx == -1 {
		t.Fatalf("could not find the DNS backfill ADD task")
	}
	addBlock := dnsTask[addIdx : addIdx+400]
	if !strings.Contains(addBlock, "xmlrpc_uri=https://{{ freeipa_admin_server_fqdn }}/ipa/xml") {
		t.Errorf("DNS backfill ADD must target the live-selected endpoint via -e xmlrpc_uri=, not fall through to /etc/ipa/default.conf's primary-only routing")
	}

	// The plan/apply/verify authoritative reads must also redirect off the
	// primary-only default (spec §12's narrower, non-consistency-checked
	// half — see the wiring comment in freeipa-client-apply.yml for what's
	// deliberately still deferred).
	if strings.Contains(dnsTask, `"@{{ ipa_server_ip }}"`) {
		t.Errorf("authoritative DNS reads must not hard-code @{{ ipa_server_ip }} (primary-only) — use freeipa_dns_read_authority_ip, confirmed live to matter when the primary is down")
	}
	if !strings.Contains(dnsTask, "@{{ freeipa_dns_read_authority_ip }}") {
		t.Errorf("authoritative DNS reads must use freeipa_dns_read_authority_ip")
	}
}

// TestRegression_FreeipaHostAnnotationsTask_UsesAdminEndpoint locks that
// freeipa-host-annotations.yml's `ipa host-show`/`ipa host-mod` calls also
// use the live-selected endpoint — found live in Phase 5: with the primary
// stopped, this task's bare `ipa host-show` (implicit default.conf
// routing) returned a connection-refused misreported as rc=1 "host object
// does not exist", failing the whole play even after the DNS backfill fix
// let enrollment/DNS succeed.
func TestRegression_FreeipaHostAnnotationsTask_UsesAdminEndpoint(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-host-annotations.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	for _, forbidden := range []string{
		"[ipa, host-show,", "[ipa, host-mod,",
	} {
		if strings.Contains(task, forbidden) {
			t.Errorf("found a bare %q argv — every ipa host-show/host-mod call in this file must include the -e xmlrpc_uri= admin-endpoint override", forbidden)
		}
	}
	if strings.Count(task, "xmlrpc_uri=https://{{ freeipa_admin_server_fqdn }}/ipa/xml") < 6 {
		t.Errorf("expected the admin-endpoint override on all 6 ipa host-show/host-mod calls in this file, found fewer")
	}
}
