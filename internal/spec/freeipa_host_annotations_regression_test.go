package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_FreeipaHostAnnotationsTask_StaticSafetyInvariants locks the
// 12 static, non-live-VM-dependent invariants from
// docs/superpowers/specs/2026-09-09-host-annotations-freeipa-sync-spec.md
// §25 against the annotations task file's actual text — the same
// string/ordering-based approach TestRegression_FreeipaClientApplyPlaybook_
// HostDNSSafety already uses for the sibling DNS task file.
func TestRegression_FreeipaHostAnnotationsTask_StaticSafetyInvariants(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-host-annotations.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	// 2. Read uses `ipa host-show --all --raw`.
	if !strings.Contains(task, "host-show") || !strings.Contains(task, "--all") || !strings.Contains(task, "--raw") {
		t.Error("expected the live read to use `ipa host-show --all --raw` (spec.md §25.2)")
	}

	// 3/4. Mutation is scoped add/delete on userclass, never a full replace.
	if !strings.Contains(task, "--addattr=userclass=") {
		t.Error("expected a scoped --addattr=userclass= mutation (spec.md §25.3)")
	}
	if !strings.Contains(task, "--delattr=userclass=") {
		t.Error("expected a scoped --delattr=userclass= mutation (spec.md §25.3)")
	}
	if strings.Contains(task, "--setattr=userclass=") {
		t.Error("must never fully replace userClass via --setattr=userclass= (spec.md §25.4/§19.6)")
	}

	// 5. Foreign-preservation logic exists and is actually asserted post-apply.
	if !strings.Contains(task, "preserve_foreign") {
		t.Error("expected foreign-userClass preservation logic (preserve_foreign, spec.md §25.5)")
	}
	if !strings.Contains(task, "Gate: pre-existing foreign userClass values are all still present after apply") {
		t.Error("expected a post-apply assert that foreign userClass values are still present (spec.md §25.5/§10 Phase F)")
	}

	// 6. Duplicate/malformed managed-state gates exist and run before Phase E
	// mutation (the first --addattr=userclass= task).
	dupIdx := strings.Index(task, "CONFLICT_DUPLICATE_MANAGED_KEY")
	malformedIdx := strings.Index(task, "CONFLICT_MALFORMED_MANAGED_VALUE")
	mutationIdx := strings.Index(task, "--addattr=userclass=")
	if dupIdx < 0 || malformedIdx < 0 || mutationIdx < 0 {
		t.Fatal("expected CONFLICT_DUPLICATE_MANAGED_KEY, CONFLICT_MALFORMED_MANAGED_VALUE, and a userclass mutation to all be present")
	}
	if !(dupIdx < mutationIdx && malformedIdx < mutationIdx) {
		t.Errorf("duplicate/malformed conflict detection must run before any userClass mutation: dupIdx=%d malformedIdx=%d mutationIdx=%d", dupIdx, malformedIdx, mutationIdx)
	}

	// 7. Every userclass/nshostlocation mutation task is gated on
	// `not ansible_check_mode` — check mode must never mutate.
	for _, marker := range []string{"--addattr=userclass=", "--delattr=userclass=", "--setattr=nshostlocation=", "--delattr=nshostlocation="} {
		idx := strings.Index(task, marker)
		if idx < 0 {
			t.Errorf("expected to find a task using %q", marker)
			continue
		}
		// The task block containing this command starts at the nearest
		// preceding "- name:" and ends at the next one (or EOF).
		start := strings.LastIndex(task[:idx], "- name:")
		end := strings.Index(task[idx:], "\n    - name:")
		var block string
		if end < 0 {
			block = task[start:]
		} else {
			block = task[start : idx+end]
		}
		if !strings.Contains(block, "not ansible_check_mode") {
			t.Errorf("task using %q must be gated on `not ansible_check_mode` (spec.md §25.7/§12); block:\n%s", marker, block)
		}
	}

	// 8. Post-mutation re-read + verify exists, after the mutation tasks.
	verifyIdx := strings.Index(task, "re-read live state for verification")
	if verifyIdx < 0 || verifyIdx < mutationIdx {
		t.Error("expected a post-mutation re-read + verify step, after Phase E mutation (spec.md §25.8/§10 Phase F)")
	}

	// 9. Native location has an ownership/drift gate — both conflict codes
	// from spec.md §8.2/§8.3 must appear.
	if !strings.Contains(task, "CONFLICT_FOREIGN_LOCATION") {
		t.Error("expected a CONFLICT_FOREIGN_LOCATION gate for nshostlocation ownership (spec.md §25.9/§8.2)")
	}
	if !strings.Contains(task, "CONFLICT_LOCATION_DRIFT") {
		t.Error("expected a CONFLICT_LOCATION_DRIFT gate for nshostlocation ownership (spec.md §25.9/§8.2/§8.3)")
	}

	// 10. Never falls back to creating the host object itself.
	if strings.Contains(task, "host-add") {
		t.Error("must never call `ipa host-add` — annotations only project onto an already-enrolled host (spec.md §25.10/§19.8)")
	}

	// 11. Every `ipa` invocation uses argv, never a shell string.
	if strings.Contains(task, "ansible.builtin.shell") {
		// The only shell task in this file is the admin kinit (piping the
		// password via stdin, which argv cannot express) — every other
		// `ipa` call must be ansible.builtin.command with argv.
		shellCount := strings.Count(task, "ansible.builtin.shell")
		if shellCount != 1 {
			t.Errorf("expected exactly 1 ansible.builtin.shell task (the kinit password pipe), got %d", shellCount)
		}
	}
	if strings.Contains(task, "command: \"ipa ") || strings.Contains(task, "command: ipa ") {
		t.Error("every `ipa` invocation must use argv, not a bare command string")
	}

	// 12. Annotations are never written into FreeIPA's native `description`
	// attribute (spec.md §19.4).
	if strings.Contains(task, "--desc=") || strings.Contains(task, "description=") {
		t.Error("annotations must never be written to FreeIPA host `description` (spec.md §25.12/§19.4)")
	}
}

// TestRegression_FreeipaHostAnnotationsTask_KinitIsNoLog mirrors
// TestRegression_FreeipaClientHostDNSTask_NoLog for the annotations task's
// own dedicated-ccache kinit — it also pipes ipa_enroll_password.
func TestRegression_FreeipaHostAnnotationsTask_KinitIsNoLog(t *testing.T) {
	const taskPath = "../../playbooks/apply/tasks/freeipa-host-annotations.yml"
	raw, err := os.ReadFile(taskPath)
	if err != nil {
		t.Fatalf("read %s: %v", taskPath, err)
	}
	task := string(raw)

	kinitIdx := strings.Index(task, "kinit admin into the dedicated ccache")
	if kinitIdx < 0 {
		t.Fatal("expected a kinit task for the annotations ccache")
	}
	window := task[kinitIdx:]
	if end := strings.Index(window, "\n\n"); end > 0 {
		window = window[:end]
	}
	if !strings.Contains(window, "no_log: true") {
		t.Error("annotations kinit task must be no_log: true — it pipes ipa_enroll_password")
	}
}

// TestRegression_FreeipaClientApplyPlaybook_AnnotationsRunAfterEnrollment
// locks spec.md §9.1/§9.3: the annotations reconcile must be included after
// enrollment + the post-enroll health/AAA checks succeed, never before —
// mutating host metadata before the host object is confirmed to exist would
// risk operating on a host that doesn't actually exist yet.
func TestRegression_FreeipaClientApplyPlaybook_AnnotationsRunAfterEnrollment(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-client-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	healthIdx := strings.Index(playbook, "post-enroll health + AAA checks")
	annotationsIdx := strings.Index(playbook, "tasks/freeipa-host-annotations.yml")
	if healthIdx < 0 || annotationsIdx < 0 {
		t.Fatalf("playbook must include the post-enroll health block and tasks/freeipa-host-annotations.yml")
	}
	if !(healthIdx < annotationsIdx) {
		t.Errorf("annotations reconcile must be included AFTER the post-enroll health/AAA checks: healthIdx=%d annotationsIdx=%d", healthIdx, annotationsIdx)
	}
}
