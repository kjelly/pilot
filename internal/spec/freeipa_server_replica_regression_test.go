package spec

import (
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

	if len(s.Rows) != 15 {
		t.Fatalf("rows=%d want=15 (spec must cover C1..C15 inclusive)", len(s.Rows))
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15"}
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
