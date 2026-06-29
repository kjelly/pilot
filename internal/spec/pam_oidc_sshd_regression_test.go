package spec

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_PamOidcSshdSpec is a regression test pinned to
// docs/verification/pam-oidc-sshd.md. It enforces the schema AND the
// cross-row invariants that made the previous version of this spec
// silently rot:
//
//   - 7 rows, IDs C1..C7, no gaps and no duplicates
//   - every Expected is non-empty AND not on the vague-word list
//   - every Command is non-empty AND runnable as a shell command
//   - C3 (backup) precedes C4 (modify sshd) — i.e. a fail of C4
//     must not happen before C3 was verified (lockout safety)
//   - the generated playbook, after IncludeRaw, parses as valid YAML
//     and contains 7 task entries (before dedup) covering all rows.
//
// The intent is that any future refactor of the parser, the lint
// rules, or the spec schema that breaks this concrete spec is caught
// here without spinning up a real ansible run. The "double regression
// pattern" (fix in place, revert fix, restore) is applied at the
// spec level — see TestRegression_PamOidcSshdSpec_BackupBeforeEdit
// below for the targeted lockout-safety invariant.
func TestRegression_PamOidcSshdSpec(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// 1. Row count is locked at 7.
	if len(s.Rows) != 7 {
		t.Fatalf("rows=%d want=7 (spec must cover C1..C7 inclusive)", len(s.Rows))
	}

	// 2. IDs are C1..C7 with no gaps and no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7"}
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
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
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
	raw, _ := plays[0]["tasks"].([]any)
	if len(raw) == 0 || len(raw) > len(s.Rows) {
		t.Errorf("generated tasks=%d, expected 1..%d (dedup <= rows)", len(raw), len(s.Rows))
	}
	// Every spec row must appear in at least one task's SourceIDs,
	// otherwise the playbook can't claim to satisfy that requirement.
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

// TestRegression_PamOidcSshdSpec_BackupBeforeEdit is the targeted
// lockout-safety invariant. The check has nothing to do with YAML
// parsing — it's about the *order* of the rows: C3 (backup file
// present) must be evaluated before C4 (sshd PAM contains the new
// module line). If a future maintainer reorders the markdown table
// naively (alphabetical, newest-first), this test fails and they are
// forced to think about why the order exists.
//
// To prove the test isn't a tautology: temporarily delete the file,
// observe the failure, then restore it.
func TestRegression_PamOidcSshdSpec_BackupBeforeEdit(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	lineOf := map[string]int{}
	for _, r := range s.Rows {
		lineOf[r.ID] = r.Line
	}
	if _, ok := lineOf["C3"]; !ok {
		t.Fatal("C3 row missing")
	}
	if _, ok := lineOf["C4"]; !ok {
		t.Fatal("C4 row missing")
	}
	if lineOf["C3"] >= lineOf["C4"] {
		t.Errorf("lockout-safety order violated: C3 (backup) at line %d, "+
			"C4 (modify sshd) at line %d — C3 MUST come before C4 so a fail "+
			"of C4 still leaves a restorable backup", lineOf["C3"], lineOf["C4"])
	}
}

// TestRegression_PamOidcSshdSpec_IssuerHTTPS is a content-level guard:
// C7 demands that the issuer URL scheme be http(s) in order to keep
// the spec aligned with the "Keycloak Device Flow" requirement that
// the spec calls out. If a future maintainer rewrites the command
// without the `https?` part (e.g. `^issuer:` alone), this fails.
func TestRegression_PamOidcSshdSpec_IssuerHTTPS(t *testing.T) {
	const specPath = "../../docs/verification/pam-oidc-sshd.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	for _, r := range s.Rows {
		if r.ID != "C7" {
			continue
		}
		if !strings.Contains(r.Command, "https?://") {
			t.Errorf("C7 must require an http(s) URL: got %q", r.Command)
		}
		return
	}
	t.Fatal("C7 row missing from spec")
}

func joinFindings(fs []Finding) string {
	var sb strings.Builder
	for _, f := range fs {
		sb.WriteString(f.String())
		sb.WriteByte('\n')
	}
	return sb.String()
}
