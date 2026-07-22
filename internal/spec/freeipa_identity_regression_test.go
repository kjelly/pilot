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

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15", "C16", "C17", "C18"}
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
	if !strings.Contains(commands["C18"], "freeipa-nfs-v2.ipa.pilot.internal") {
		t.Errorf("C18 must verify FQDN Kerberos automount target, got %q", commands["C18"])
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
	if strings.Contains(playbook, "freeipa_roster.nfs_clients | default([]) | length == 0") {
		t.Fatal("identity reconciliation must accept nfs_clients in the shared canonical roster")
	}
	if !strings.Contains(playbook, "freeipa_roster.migration | default({}) | length == 0") {
		t.Fatal("identity reconciliation must keep unsupported migration input fail-closed")
	}
}
