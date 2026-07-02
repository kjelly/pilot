package spec

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaServerSpec locks the structural contract of
// docs/verification/freeipa-server.md: 13 rows C1..C13, lint-clean, and a
// generated verify playbook that covers every row.
//
// Inventory alignment: like freeipa-client.md, §1 declares group
// `freeipa-server` while the vm-target reference environment puts the host in
// `all` (run/verify with `-e target_group=all`). Per AGENTS.md §3 we therefore
// do NOT assert SpecAndInventoryAgree — the alignment lives in the
// `-e target_group=` override, not a fixed group name.
func TestRegression_FreeipaServerSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-server.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	if len(s.Rows) != 13 {
		t.Fatalf("rows=%d want=13 (spec must cover C1..C13 inclusive)", len(s.Rows))
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13"}
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

// TestRegression_FreeipaServerSpec_MatcherChoices locks the two hard-won
// matcher decisions the spec documents (both were verify false-negatives in
// practice): C2 must use POSITIVE logic (`sudo ipactl status`, not a
// reverse-logic `| grep STOPPED`), and C3 must use `~contains` (not a
// `^`-anchored regex that the ad-hoc wrapper would defeat).
func TestRegression_FreeipaServerSpec_MatcherChoices(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-server.md"
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

	// C2: positive-logic service health, rc-based.
	if !strings.Contains(cmd["C2"], "ipactl status") {
		t.Errorf("C2 must check `ipactl status`, got %q", cmd["C2"])
	}
	if strings.Contains(cmd["C2"], "grep") {
		t.Errorf("C2 must NOT use reverse-logic grep (ad-hoc reports rc=2 on the healthy path); got %q", cmd["C2"])
	}
	if exp["C2"] != "0" {
		t.Errorf("C2 expected must be rc-based `0`, got %q", exp["C2"])
	}

	// C3: contains-match for the FQDN, never a ^-anchored regex.
	if strings.HasPrefix(exp["C3"], "^") {
		t.Errorf("C3 must use ~contains not a ^-anchored regex (ad-hoc wrapper defeats the anchor); got %q", exp["C3"])
	}
	if !strings.HasPrefix(exp["C3"], "~") {
		t.Errorf("C3 expected should be a ~contains match on the FQDN, got %q", exp["C3"])
	}

	// The whole spec must be lint-warning-free for the matcher traps: no
	// ^-anchored expected and no ~active anywhere.
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
