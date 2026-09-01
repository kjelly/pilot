package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaIdentitySpec locks the single-host + target_group
// contract. The spec names freeipa-server while vm-target evidence uses an
// explicit target_group override, so SpecAndInventoryAgree does not apply.
func TestRegression_FreeipaIdentitySpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-identity.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15", "C16", "C17", "C18", "C19", "C20", "C21", "C22", "C23", "C24"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	gotIDs := make([]string, 0, len(s.Rows))
	seen := map[string]bool{}
	for _, row := range s.Rows {
		if seen[row.ID] {
			t.Errorf("duplicate row ID %q", row.ID)
		}
		seen[row.ID] = true
		gotIDs = append(gotIDs, row.ID)
		if strings.TrimSpace(row.Command) == "" || strings.TrimSpace(row.Expected) == "" {
			t.Errorf("row %s has an empty command or expected value", row.ID)
		}
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("row IDs=%v want=%v", gotIDs, wantIDs)
	}
	if findings := Lint(s); HasErrors(findings) {
		t.Errorf("spec lint errors:\n%s", fsToString(findings))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(pb.RenderYAML()), &plays); err != nil {
		t.Fatalf("generated playbook YAML: %v", err)
	}
	covered := map[string]bool{}
	for _, task := range pb.Tasks {
		for _, id := range task.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("row %s is not covered by generated verification", id)
		}
	}

	commands := map[string]string{}
	for _, row := range s.Rows {
		commands[row.ID] = row.Command + " " + row.Expected
	}
	for _, id := range []string{"C9", "C10", "C11", "C12"} {
		if !strings.Contains(commands[id], "fixture-canonical") {
			t.Errorf("%s must verify canonical fixture state, got %q", id, commands[id])
		}
	}
	if !strings.Contains(commands["C10"], "nsAccountLock") {
		t.Errorf("C10 must verify effective disabled state, got %q", commands["C10"])
	}
	if !strings.Contains(commands["C12"], "data-fixture-canonical-rw") {
		t.Errorf("C12 must verify nested group membership, got %q", commands["C12"])
	}
	if !strings.Contains(commands["C14"], "fixture-canonical-breakglass") {
		t.Errorf("C14 must verify canonical break-glass state, got %q", commands["C14"])
	}
	if !strings.Contains(commands["C16"], "role-fixture-canonical-ops") {
		t.Errorf("C16 must verify role-category sudo attachment, got %q", commands["C16"])
	}
	if !strings.Contains(commands["C18"], "sec=krb5i") ||
		!strings.Contains(commands["C18"], "[[:alnum:].-]+:/projects/fixture-alpha") ||
		strings.Contains(commands["C18"], "freeipa-nfs-v2.ipa.pilot.internal") {
		t.Errorf("C18 must verify a portable FQDN Kerberos automount target, got %q", commands["C18"])
	}
}

// TestRegression_FreeipaIdentityAllowsSharedNFSRoster locks the canonical
// roster hand-off: identity reconciliation must tolerate nfs_clients entries
// that the dedicated NFS client playbook consumes, while migration stays
// fail-closed until it has its own supported workflow.
func TestRegression_FreeipaIdentityAllowsSharedNFSRoster(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-identity-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)
	if strings.Contains(playbook, "freeipa_roster.freeipa.domain") || strings.Contains(playbook, "freeipa_roster.freeipa.realm") {
		t.Fatal("FreeIPA domain/realm must come from inventory group_vars, not the identity roster")
	}
	if !strings.Contains(playbook, `ipa_domain: "{{ freeipa_domain | default('ipa.pilot.internal') }}"`) {
		t.Fatal("identity reconciliation must source its domain from freeipa_domain")
	}
	if strings.Contains(playbook, "freeipa_roster.nfs_clients | default([]) | length == 0") {
		t.Fatal("identity reconciliation must accept nfs_clients in the shared canonical roster")
	}
	if !strings.Contains(playbook, "freeipa_roster.migration | default({}) | length == 0") {
		t.Fatal("identity reconciliation must keep unsupported migration input fail-closed")
	}
	if strings.Contains(playbook, "--host={{ ansible_fqdn }}") {
		t.Fatal("HBAC self-tests must not depend on gathered facts when gather_facts is false")
	}
	if !strings.Contains(playbook, `identity_hbac_test_host: "{{ freeipa_roster.freeipa.server | default(ipa_server_fqdn | default(inventory_hostname)) }}"`) ||
		strings.Count(playbook, `--host={{ identity_hbac_test_host }}`) != 2 {
		t.Fatal("HBAC pre/post-lock tests must use the canonical roster server FQDN")
	}
}

// TestRegression_FreeipaIdentityAllowAllUsesCommandCategory prevents an empty
// command list from becoming deny-everything and locks the explicit canonical
// roster mechanism: allow.command_category: all.
func TestRegression_FreeipaIdentityAllowAllUsesCommandCategory(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-identity-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)
	if !strings.Contains(playbook, "Normalize canonical sudo rules for the compatibility reconciler") ||
		!strings.Contains(playbook, "'allow_commands': (item.allow | default({})).commands | default([])") ||
		!strings.Contains(playbook, "item.allow | default({})).command_groups | default([]) | length > 0") ||
		!strings.Contains(playbook, "'cmdcat': (item.allow | default({})).command_category | default('all')") {
		t.Fatal("allow.command_category: all must reconcile to FreeIPA cmdcat=all")
	}
}

// TestRegression_FreeipaIdentityHBACReconciliationCanonicalizesMemberNames
// locks the comparison boundary between a human-authored roster and FreeIPA's
// lowercase canonical member names.  A mixed-case roster name must not cause
// the reconciliation's remove phase to detach an otherwise desired member.
func TestRegression_FreeipaIdentityHBACReconciliationCanonicalizesMemberNames(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-identity-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	for _, want := range []string{
		"live_hosts_fqdn | map('regex_replace', '\\\\..*$', '') | map('lower') | list",
		"item.item.hostgroups | default([])) | map('lower') | list",
		"item.item.services | default([])) | map('lower') | list",
		"item.item.users | default([])) | map('lower') | list",
		"item.item.groups | default([])) | map('lower') | list",
		"'hostgroups': (live_hostgroups | difference(roster_hostgroups))",
		"'services': (live_services | difference(roster_services))",
		"'users': (live_users | difference(roster_users))",
		"'groups': (live_groups | difference(roster_groups))",
	} {
		if !strings.Contains(playbook, want) {
			t.Errorf("HBAC reconciliation must canonicalize and compare %q", want)
		}
	}
}

// TestRegression_FreeipaIdentityRefreshesClientSSSDCache locks the post-
// reconcile hand-off: FreeIPA authorization changes must not remain hidden
// behind stale client-side SSSD caches.
func TestRegression_FreeipaIdentityRefreshesClientSSSDCache(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-identity-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)
	for _, want := range []string{
		"ipa_identity_refresh_sssd_cache: true",
		`name: "Refresh SSSD caches on enrolled FreeIPA clients"`,
		"ansible.builtin.command: sss_cache -E",
		`delegate_to: "{{ item }}"`,
		"pilot_deferred_hosts",
		"reject('in', pilot_deferred_hosts | default([]))",
		"become: true",
		"become_method: sudo",
		"- not ansible_check_mode",
		"- ipa_identity_refresh_sssd_cache | bool",
		"changed_when: false",
	} {
		if !strings.Contains(playbook, want) {
			t.Errorf("identity playbook must contain %q", want)
		}
	}
}

// TestRegression_FreeipaIdentityAuthenticatesBeforeCheckModeProbes locks the
// reconcile preview contract: pilot reconcile runs a --check --diff preview,
// but the identity playbook still performs live IPA reads.  Kinit must run in
// check mode, and a groups-only tagged run must not bypass authentication.
func TestRegression_FreeipaIdentityAuthenticatesBeforeCheckModeProbes(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-identity-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)
	kinitStart := strings.Index(playbook, `- name: "Kinit admin"`)
	if kinitStart < 0 {
		t.Fatal("identity playbook must contain the Kinit admin task")
	}
	kinitEnd := strings.Index(playbook[kinitStart:], "\n    # ── Groups")
	if kinitEnd < 0 {
		t.Fatal("could not isolate Kinit admin task")
	}
	kinit := playbook[kinitStart : kinitStart+kinitEnd]
	if !strings.Contains(kinit, "check_mode: false") {
		t.Fatal("Kinit admin must run during --check previews so live IPA probes have a fresh ticket")
	}
	if !strings.Contains(kinit, "tags: [identity, groups]") {
		t.Fatal("Kinit admin must run for a groups-only tagged reconciliation")
	}
}
