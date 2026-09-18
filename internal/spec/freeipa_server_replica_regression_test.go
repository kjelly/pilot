package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaServerReplicaSpec locks the structural contract of
// docs/verification/freeipa-server-replica.md: 15 rows C1..C15 (C1-C13 mirror
// freeipa-server.md's own-host health checks; C14-C15 are the
// multi-master-topology checks unique to a replica), lint-clean, and a
// generated verify playbook that covers every row.
//
// Inventory alignment: like freeipa-server.md/freeipa-client.md, §1 declares
// group `freeipa-server-replica` while the vm-target reference environment
// puts the host in `all` (run/verify with `-e target_group=all`). Per
// AGENTS.md §3 we therefore do NOT assert SpecAndInventoryAgree — the
// alignment lives in the `-e target_group=` override, not a fixed group name.
func TestRegression_FreeipaServerReplicaSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-server-replica.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	if len(s.Rows) != 16 {
		t.Fatalf("rows=%d want=16 (spec must cover C1..C16 inclusive)", len(s.Rows))
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15", "C16"}
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

// TestRegression_FreeipaServerReplicaSpec_TopologyRows locks the two
// hard-won design decisions behind C14/C15 (the reason this spec exists,
// distinct from freeipa-server.md): both query the SAME cn=masters subtree
// and match by ~contains-fqdn, never by counting entries. A fixed count
// would break the moment a third node joins the topology; a substring match
// on a specific node's fqdn stays valid regardless of topology size.
func TestRegression_FreeipaServerReplicaSpec_TopologyRows(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-server-replica.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
	}

	for _, id := range []string{"C14", "C15"} {
		if !strings.Contains(cmd[id], "cn=masters,cn=ipa,cn=etc") {
			t.Errorf("%s must query the cn=masters,cn=ipa,cn=etc topology subtree, got %q", id, cmd[id])
		}
		if !strings.HasPrefix(exp[id], "~cn=") {
			t.Errorf("%s expected must be a ~contains match on a specific master's cn=<fqdn>, not a count, got %q", id, exp[id])
		}
	}

	// C14 asserts the PRIMARY is visible from this replica; C15 asserts this
	// replica registered ITSELF. They must reference different fqdns —
	// otherwise a bug that only ever checks the primary would silently pass
	// both rows.
	if exp["C14"] == exp["C15"] {
		t.Errorf("C14 and C15 must assert different fqdns (primary vs. this replica), both got %q", exp["C14"])
	}

	// Same matcher traps as freeipa-server.md: no ^-anchored expected
	// anywhere (ad-hoc wrapper defeats the anchor) and no bare ~active.
	for _, r := range s.Rows {
		e := strings.TrimSpace(r.Expected)
		if strings.HasPrefix(e, "^") {
			t.Errorf("row %s uses a ^-anchored expected %q — broken under ad-hoc", r.ID, e)
		}
		if strings.EqualFold(e, "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}
}

// TestRegression_FreeipaServerReplicaSpec_JoinBeforeTopology — you cannot
// verify replication topology before the host itself is configured and
// healthy. C1 (installed) and C2 (services healthy) must precede C14/C15.
func TestRegression_FreeipaServerReplicaSpec_JoinBeforeTopology(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-server-replica.md"
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
	for _, topo := range []string{"C14", "C15"} {
		if lineOf["C1"] >= lineOf[topo] {
			t.Errorf("ordering: C1 (installed) at line %d must precede %s at line %d", lineOf["C1"], topo, lineOf[topo])
		}
		if lineOf["C2"] >= lineOf[topo] {
			t.Errorf("ordering: C2 (services healthy) at line %d must precede %s at line %d", lineOf["C2"], topo, lineOf[topo])
		}
	}
}

// TestRegression_FreeipaServerReplicaApplyPlaybook_DNSDefaultMatchesPrimary
// locks docs/tmp/now/freeipa-client-ha-spec.md §10: ipa_setup_dns's DEFAULT
// on the replica must match the primary's own default (both default(true)),
// closing the SPOF where an operator who took every default ended up with
// DNS on only one node. Verified with real vm-target evidence (2026-09-17,
// docs/evidence/freeipa-client-ha/2026-09-17-phase2-replica-dns-parity/).
func TestRegression_FreeipaServerReplicaApplyPlaybook_DNSDefaultMatchesPrimary(t *testing.T) {
	replicaPath := "../../playbooks/apply/freeipa-server-replica-apply.yml"
	replicaRaw, err := os.ReadFile(replicaPath)
	if err != nil {
		t.Fatalf("read %s: %v", replicaPath, err)
	}
	primaryPath := "../../playbooks/apply/freeipa-server-apply.yml"
	primaryRaw, err := os.ReadFile(primaryPath)
	if err != nil {
		t.Fatalf("read %s: %v", primaryPath, err)
	}
	const wantDefault = `ipa_setup_dns: "{{ freeipa_setup_dns | default(true) }}"`
	if !strings.Contains(string(replicaRaw), wantDefault) {
		t.Errorf("replica must default ipa_setup_dns via %q (found a different default — reintroduces the primary/replica DNS SPOF asymmetry)", wantDefault)
	}
	if !strings.Contains(string(primaryRaw), wantDefault) {
		t.Fatalf("test assumption broken: primary no longer defaults ipa_setup_dns via %q — update this test's expectation together with whichever file changed", wantDefault)
	}
}

// TestRegression_FreeipaServerReplicaApplyPlaybook_Day2DNSReconciliation
// locks spec §10.1: an already-promoted replica whose DNS role is absent
// must get it installed retroactively when ipa_setup_dns is (now) true —
// this can't rely solely on the `creates:`-gated ipa-replica-install task,
// since that task is a full no-op on an already-promoted host and never
// gets a second chance to pass --setup-dns. Also locks that detection uses
// a ticket-free local probe (systemctl is-active), not an `ipa` CLI call —
// confirmed live that `ipa dnsserver-show` fails with "did not receive
// Kerberos credentials" when root has no ticket (the common case for an
// ordinary Day-2 apply run).
func TestRegression_FreeipaServerReplicaApplyPlaybook_Day2DNSReconciliation(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-server-replica-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	if !strings.Contains(playbook, "systemctl, is-active, named.service") {
		t.Errorf("Day-2 DNS reconciliation must probe named.service directly (ticket-free), not the ipa CLI")
	}
	// No task in this file may invoke `ipa dnsserver-show`/`ipa server-role-
	// find` as an ACTUAL COMMAND (both require a Kerberos ticket root won't
	// have on an ordinary apply run) — checked via the command module forms
	// those calls would actually take, not a bare substring, since this
	// file's own comments legitimately name both commands when explaining
	// why they're avoided.
	for _, forbiddenCall := range []string{
		"'dnsserver-show'", `"dnsserver-show"`, "dnsserver-show,",
		"'server-role-find'", `"server-role-find"`, "server-role-find,",
	} {
		if strings.Contains(playbook, forbiddenCall) {
			t.Errorf("Day-2 DNS detection must not invoke %q as a command — it requires a Kerberos ticket root won't have on an ordinary apply run", forbiddenCall)
		}
	}
	if !strings.Contains(playbook, "ipa-dns-install") {
		t.Errorf("Day-2 DNS reconciliation must run ipa-dns-install when the role is absent and desired")
	}
	if !strings.Contains(playbook, "warn on drift") {
		t.Errorf("Day-2 DNS reconciliation must warn (not silently ignore) when desired=false but DNS is currently active")
	}
}

// TestRegression_FreeipaServerReplicaApplyPlaybook_DNSDriftNeverDestructive
// locks spec §10.1's explicit prohibition: desired=false with an actually-
// active DNS role must NEVER trigger an automatic removal (no
// `ipa-dns-install --uninstall`-equivalent, no `dnf remove ipa-server-dns`)
// — only a warning. An automated removal could silently take down every
// client still resolving through this node.
func TestRegression_FreeipaServerReplicaApplyPlaybook_DNSDriftNeverDestructive(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-server-replica-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	// Look for --uninstall/state:absent as an actual argv/module ARGUMENT
	// (a YAML list item like `- --uninstall` / `- "--uninstall"`, or a
	// `state: absent` module parameter), not free text — this file's
	// existing rescue diagnostics and this task's own explanatory comments
	// both legitimately mention "--uninstall" in human-readable prose
	// (recovering a half-finished ipa-server-install; explaining what the
	// Day-2 DNS reconciliation deliberately does NOT do).
	for _, trimmed := range strings.Split(playbook, "\n") {
		line := strings.TrimSpace(trimmed)
		isArgvItem := (line == `- --uninstall` || line == `- "--uninstall"` || line == `- '--uninstall'`)
		isStateAbsent := strings.HasPrefix(line, "state: absent") || strings.HasPrefix(line, "state:absent")
		if isArgvItem || isStateAbsent {
			t.Errorf("playbook must never automatically remove an existing DNS role (found %q) — spec §10.1 requires a warning only, decommissioning must be a deliberate separate step", line)
		}
	}
	warnIdx := strings.Index(playbook, "warn on drift")
	if warnIdx == -1 {
		t.Fatalf("could not find the drift-warning task")
	}
	warnBlock := playbook[warnIdx:]
	whenIdx := strings.Index(warnBlock, "when:")
	whenEnd := whenIdx + 250
	if whenEnd > len(warnBlock) {
		whenEnd = len(warnBlock)
	}
	if whenIdx == -1 || !strings.Contains(warnBlock[whenIdx:whenEnd], "not (ipa_setup_dns | bool)") {
		t.Errorf("the drift-warning task must be scoped to `not (ipa_setup_dns | bool)` (desired=false)")
	}
}

// TestRegression_FreeipaServerReplicaApplyPlaybook_DNSSelfRegistration locks
// the 2026-09-18 fix: this playbook self-registers its own A record in the
// primary's authoritative DNS (delegated to the primary, since this host has
// no working Kerberos config of its own yet), so an operator no longer needs
// to manually run `ipa dnsrecord-add` before joining a replica. Also locks
// the two delegate_to gotchas found live while implementing this:
//   - `delegate_to:` must reference a plain variable, never a bracket-
//     subscript expression directly (e.g. `groups['freeipa-server'][0]`) —
//     that failed live with "object of type 'dict' has no attribute
//     'freeipa-server'" instead of resolving.
//   - the variable `delegate_to:` references must NEVER be left undefined by
//     a conditional set_fact — delegate_to is templated before that block's
//     own `when:` is evaluated, so an undefined delegate_to variable crashes
//     the whole play even when the intent was simply to skip. It must always
//     be assigned (with a safe self-referential fallback), and the actual
//     skip decision belongs in the block's own `when:` instead.
func TestRegression_FreeipaServerReplicaApplyPlaybook_DNSSelfRegistration(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-server-replica-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	if !strings.Contains(playbook, "self-register this host's A record in the primary's DNS") {
		t.Fatalf("could not find the DNS self-registration task")
	}
	if !strings.Contains(playbook, "dnsrecord-add") {
		t.Errorf("self-registration must use ipa dnsrecord-add")
	}
	if !strings.Contains(playbook, "'no modifications to be performed' not in") {
		t.Errorf("self-registration must be idempotent via the established 'no modifications to be performed' convention, matching tasks/freeipa-client-host-dns.yml's own DNS backfill task")
	}

	// delegate_to must never contain a raw bracket-subscript expression —
	// only a plain variable reference.
	for _, badDelegate := range []string{
		`delegate_to: "{{ groups['freeipa-server'][0] }}"`,
		"delegate_to: \"{{ groups[",
	} {
		if strings.Contains(playbook, badDelegate) {
			t.Errorf("delegate_to must reference a plain variable, not a bracket-subscript expression directly (found %q) — confirmed live this fails with a nonsense dict-attribute error instead of resolving", badDelegate)
		}
	}
	if !strings.Contains(playbook, `delegate_to: "{{ freeipa_replica_primary_inventory_host }}"`) {
		t.Errorf("delegate_to must reference the plain freeipa_replica_primary_inventory_host variable")
	}

	// The variable delegate_to depends on must be assigned unconditionally
	// (no `when:` on the set_fact task that defines it), with a safe
	// self-referential fallback — never left undefined.
	setFactIdx := strings.Index(playbook, "who to delegate DNS registration to")
	if setFactIdx == -1 {
		t.Fatalf("could not find the set_fact task computing freeipa_replica_primary_inventory_host")
	}
	setFactBlock := playbook[setFactIdx:min(setFactIdx+900, len(playbook))]
	if !strings.Contains(setFactBlock, "else inventory_hostname") {
		t.Errorf("freeipa_replica_primary_inventory_host must always resolve to a value (fallback: inventory_hostname) — leaving it undefined when there's no freeipa-server group crashes the play, since delegate_to is templated before when: is evaluated (confirmed live)")
	}
	// The set_fact task itself must NOT have its own top-level `when:` gate
	// before the next task's `- name:` marker (that would reintroduce the
	// undefined-variable crash).
	nextTaskIdx := strings.Index(setFactBlock[1:], "\n    - name:")
	if nextTaskIdx != -1 {
		taskBody := setFactBlock[:nextTaskIdx+1]
		if strings.Contains(taskBody, "\n      when:") {
			t.Errorf("the set_fact task computing freeipa_replica_primary_inventory_host must not have its own when: gate — it must always run and always assign a value")
		}
	}

	// The consuming block's own when: is where the real skip decision lives.
	blockIdx := strings.Index(playbook, "self-register this host's A record in the primary's DNS")
	blockWhen := playbook[blockIdx : blockIdx+400]
	if !strings.Contains(blockWhen, "freeipa_replica_primary_inventory_host != inventory_hostname") {
		t.Errorf("the self-registration block's own when: must check freeipa_replica_primary_inventory_host != inventory_hostname (this is what actually skips when there's no known primary)")
	}
}
