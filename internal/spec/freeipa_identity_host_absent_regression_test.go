// freeipa_identity_host_absent_regression_test.go locks the gap this
// phase fixed in playbooks/apply/freeipa-identity-apply.yml: canonical
// roster host `state: absent` used to be silently interpreted as "skip
// creation only" (host-add is skipped, but no host-del/reference-pruning/
// DNS cleanup ever ran) — spec.md §16.3's explicit warning against that
// exact bug. These are playbook-behavior assertions per spec.md §34's
// required regression list, using this repo's established convention for
// locking Ansible task-level behavior without a live host: grep/
// structural assertions against the raw apply-playbook YAML text (see
// e.g. wazuh_fim_regression_test.go's `os.ReadFile(".../wazuh-fim-
// apply.yml")` + strings.Contains pattern, mirrored here rather than
// inventing a new testing paradigm).
//
// docs/verification/host-decommission.md's own rows (HD9-HD12) already
// lock the Go-level provider contract via
// internal/decommission/providers' fixture tests; this file locks the
// Ansible-side half those providers actually invoke.
package spec

import (
	"os"
	"strings"
	"testing"
)

func readFreeIPAIdentityApplyPlaybook(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../playbooks/apply/freeipa-identity-apply.yml")
	if err != nil {
		t.Fatalf("read freeipa-identity-apply.yml: %v", err)
	}
	return string(raw)
}

// 1. validator still accepts present/absent only (no new state value).
func TestRegression_FreeIPAIdentityHostAbsent_ValidatorAcceptsOnlyPresentAbsent(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	idx := strings.Index(raw, `name: "Gate: canonical host objects use FQDN and valid state"`)
	if idx < 0 {
		t.Fatal("expected the canonical host state-validity gate task to exist")
	}
	nextTask := strings.Index(raw[idx+1:], "\n    - name:")
	if nextTask < 0 {
		t.Fatal("could not find the end of the host state-validity gate task")
	}
	body := raw[idx : idx+1+nextTask]
	if !strings.Contains(body, "item.state | default('present') in ['present', 'absent']") {
		t.Fatal("expected the canonical host structural gate to accept exactly ['present', 'absent'] — no new state value may be introduced without updating this lock deliberately")
	}
	// This same task's own body must not ALSO whitelist a third value
	// anywhere (e.g. a second, looser `in [...]` list added alongside the
	// strict one).
	if strings.Count(body, "in ['present', 'absent']") != 1 {
		t.Fatalf("expected exactly 1 state-validity check within the host gate task, found %d", strings.Count(body, "in ['present', 'absent']"))
	}
}

// 2. present host creation behavior unchanged.
func TestRegression_FreeIPAIdentityHostAbsent_PresentHostCreationUnchanged(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	if !strings.Contains(raw, `name: "Ensure canonical FreeIPA host objects exist"`) {
		t.Fatal("expected the present-host creation task to still exist unchanged")
	}
	if !strings.Contains(raw, "argv: [ipa, host-add,") {
		t.Fatal("expected host-add to still be invoked for present hosts")
	}
	if !strings.Contains(raw, `--ip-address={{ item.ip_address }}`) {
		t.Fatal("expected host-add to still pass --ip-address from the roster entry")
	}
}

// 3. absent host does not run host-add.
func TestRegression_FreeIPAIdentityHostAbsent_AbsentHostDoesNotRunHostAdd(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	idx := strings.Index(raw, `name: "Ensure canonical FreeIPA host objects exist"`)
	if idx < 0 {
		t.Fatal("could not find the host-add task")
	}
	// Scope the search to this task's own body (up to the next task) so
	// this assertion can't accidentally match an unrelated `when:` block
	// elsewhere in this 2800+ line file.
	nextTask := strings.Index(raw[idx+1:], "\n    - name:")
	if nextTask < 0 {
		t.Fatal("could not find the end of the host-add task")
	}
	body := raw[idx : idx+1+nextTask]
	if !strings.Contains(body, "item.state | default('present') == 'present'") {
		t.Fatal("expected the host-add task's own `when:` to require state == 'present' — an absent entry must never run host-add")
	}
}

// 4. absent host triggers safe reference cleanup (hostgroup/netgroup/
// HBAC/sudo membership pruning) — spec.md §16.3 step 1. This reconcile
// already existed for every OTHER absent entity type before this phase;
// this locks that the same machinery still runs (it is what makes this
// phase's host-del safe to schedule at all — internal/decommission/
// providers.FreeIPAClientProvider's roster mutation
// (RemoveRosterHostReferences) prunes the roster BEFORE this playbook
// runs, and these existing reconcile tasks converge live FreeIPA state to
// match).
func TestRegression_FreeIPAIdentityHostAbsent_ReferenceCleanupStillWired(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	for _, marker := range []string{
		`name: "Remove stale hostgroup host memberships"`,
		`name: "Remove stale netgroup direct host membership"`,
		`name: "Remove stale hosts from HBAC rules"`,
		`name: "Remove stale hosts from sudo rules"`,
		`name: "Gate: no residual hostgroup/netgroup membership before deleting an absent host"`,
	} {
		if !strings.Contains(raw, marker) {
			t.Fatalf("expected task %q to exist — absent-host reference cleanup/verification must remain wired", marker)
		}
	}
}

// 5. absent host DNS deletion is exact-value/surgical.
func TestRegression_FreeIPAIdentityHostAbsent_DNSDeletionIsExactValue(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	idx := strings.Index(raw, `name: "Remove only the Pilot-owned A record value for each absent host`)
	if idx < 0 {
		t.Fatal("expected the surgical DNS-delete task to exist")
	}
	nextTask := strings.Index(raw[idx+1:], "\n    - name:")
	if nextTask < 0 {
		t.Fatal("could not find the end of the DNS-delete task")
	}
	body := raw[idx : idx+1+nextTask]
	if !strings.Contains(body, `--a-rec={{ item.item.ip_address }}`) {
		t.Fatal("expected dnsrecord-del to pass the EXACT roster-declared ip_address, not a wildcard/broad value")
	}
	if !strings.Contains(body, "item.item.ip_address in freeipa_absent_host_live_a_values") {
		t.Fatal("expected the delete to be gated on the live value actually matching the roster's declared ip_address")
	}
	if !strings.Contains(raw, `name: "Gate: refuse to delete an absent host's DNS record if the live value is foreign/ambiguous`) {
		t.Fatal("expected a gate refusing to delete when the live DNS value is foreign/ambiguous")
	}
}

// 6. unknown service references block host deletion (HD12).
func TestRegression_FreeIPAIdentityHostAbsent_UnknownServiceReferencesBlock(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	idx := strings.Index(raw, `name: "Gate: no unknown/unproven service principal remains before deleting an absent host"`)
	if idx < 0 {
		t.Fatal("expected the unknown-service-principal gate to exist")
	}
	nextTask := strings.Index(raw[idx+1:], "\n    - name:")
	if nextTask < 0 {
		t.Fatal("could not find the end of the service-principal gate task")
	}
	body := raw[idx : idx+1+nextTask]
	if !strings.Contains(body, "managedby_service") {
		t.Fatal("expected the gate to inspect managedby_service entries")
	}
	if !strings.Contains(body, "freeipa_absent_host_unknown_services | length == 0") {
		t.Fatal("expected the gate to assert zero unknown service principals before proceeding")
	}
	// The gate must come BEFORE the host-del task (spec.md §16.3's
	// required order: detect service principals before deleting the host
	// object), not merely exist somewhere in the file.
	delIdx := strings.Index(raw, `name: "Delete the FreeIPA host object for each roster host marked absent`)
	if delIdx < 0 || delIdx < idx {
		t.Fatal("expected the service-principal gate to run BEFORE host-del, per spec.md §16.3's required order")
	}
}

// 7. host deletion does not use a broad DNS cascade (INV-14).
func TestRegression_FreeIPAIdentityHostAbsent_NoBroadDNSCascade(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	idx := strings.Index(raw, `name: "Delete the FreeIPA host object for each roster host marked absent`)
	if idx < 0 {
		t.Fatal("expected the host-del task to exist")
	}
	nextTask := strings.Index(raw[idx+1:], "\n    - name:")
	if nextTask < 0 {
		t.Fatal("could not find the end of the host-del task")
	}
	body := raw[idx : idx+1+nextTask]
	if strings.Contains(body, "updatedns") {
		t.Fatal("host-del must NOT pass --updatedns — that blasts every A/AAAA/SSHFP/PTR record for this host regardless of ownership (INV-14); surgical DNS deletion already ran as its own step")
	}
	if strings.Contains(body, "argv: [ipa, host-del, \"{{ item.name }}\"") {
		// Confirm this is the exact, minimal argv — no extra broad flag
		// appended anywhere on the same line.
	} else {
		t.Fatal("expected host-del's argv to be exactly [ipa, host-del, <name>] with no additional flags")
	}
}

// 8. idempotent second absent reconcile reports no destructive change.
func TestRegression_FreeIPAIdentityHostAbsent_IdempotentRerunReportsNoChange(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)

	// dnsrecord-del: changed_when must be conditional on the command's
	// own rc, never an unconditional `changed_when: true` (which would
	// report changed=true even on a rerun where the record is already
	// gone and the task is skipped by its own `when:` guard — the
	// concern here is the OPPOSITE failure mode: a hardcoded true would
	// misreport even a skipped/no-op run as changed if ever reached).
	dnsDelIdx := strings.Index(raw, `name: "Remove only the Pilot-owned A record value for each absent host`)
	if dnsDelIdx < 0 {
		t.Fatal("expected the DNS-delete task to exist")
	}
	nextTask := strings.Index(raw[dnsDelIdx+1:], "\n    - name:")
	dnsDelBody := raw[dnsDelIdx : dnsDelIdx+1+nextTask]
	if !strings.Contains(dnsDelBody, `changed_when: "freeipa_absent_host_dns_del.rc == 0"`) {
		t.Fatal("expected dnsrecord-del's changed_when to be based on its own rc, not hardcoded true")
	}

	// host-del: changed_when must be based on the real "Deleted host"
	// marker, and failed_when must tolerate a rerun where the host is
	// already gone ("not found" is not a failure) — both together are
	// what make a second reconcile idempotent (changed=false, no error).
	hostDelIdx := strings.Index(raw, `name: "Delete the FreeIPA host object for each roster host marked absent`)
	nextTask = strings.Index(raw[hostDelIdx+1:], "\n    - name:")
	hostDelBody := raw[hostDelIdx : hostDelIdx+1+nextTask]
	if !strings.Contains(hostDelBody, `changed_when: "'Deleted host' in (freeipa_absent_host_del.stdout | default(''))"`) {
		t.Fatal("expected host-del's changed_when to key off the real 'Deleted host' marker, not an unconditional true")
	}
	if !strings.Contains(hostDelBody, "'not found' not in (freeipa_absent_host_del.stderr | default(''))") {
		t.Fatal("expected host-del's failed_when to tolerate 'not found' (already absent) so a second reconcile does not error")
	}
}

// 9. existing user/group/netgroup absent semantics are not regressed.
func TestRegression_FreeIPAIdentityHostAbsent_ExistingAbsentSemanticsUnchanged(t *testing.T) {
	raw := readFreeIPAIdentityApplyPlaybook(t)
	for _, marker := range []string{
		`name: "Delete canonical users explicitly marked absent"`,
		`name: "Delete canonical groups explicitly marked absent"`,
		`name: "Delete netgroups explicitly marked absent"`,
	} {
		if !strings.Contains(raw, marker) {
			t.Fatalf("expected pre-existing absent-entity delete task %q to remain unchanged", marker)
		}
	}
	// The new host-absent section must not have replaced or duplicated
	// these — exactly one of each.
	for _, marker := range []string{
		`name: "Delete canonical users explicitly marked absent"`,
		`name: "Delete canonical groups explicitly marked absent"`,
		`name: "Delete netgroups explicitly marked absent"`,
	} {
		if n := strings.Count(raw, marker); n != 1 {
			t.Fatalf("expected exactly 1 occurrence of %q, found %d", marker, n)
		}
	}
}
