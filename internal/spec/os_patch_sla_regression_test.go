package spec

import (
	"strings"
	"testing"
)

// TestRegression_OsPatchSlaSpec locks the structure of the
// `docs/verification/os-patch-sla.md` spec which implements the
// "OS 套件定期更新: Critical 15d / High 30d / Medium 90d" rule.
//
// Pinning the row IDs and content here means a refactor that drops
// a row, renames an ID, or weakens an expected value fails this
// test loudly — instead of silently changing the policy contract.
func TestRegression_OsPatchSlaSpec(t *testing.T) {
	const specPath = "../../docs/verification/os-patch-sla.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	// C1..C8 inclusive, no gaps, no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}
	if len(s.Rows) != 8 {
		t.Fatalf("rows=%d want=8", len(s.Rows))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	// C1 and C4 expect anchored regex `^0$`. Other rows must be
	// concrete values (not vague words like "OK" or "合理").
	for _, r := range s.Rows {
		if strings.Contains(strings.ToLower(strings.TrimSpace(r.Expected)), "ok") {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}
	// C7 is the "no prod-direct-push" marker — its command must
	// mention the marker file path so the safety contract is
	// preserved.
	for _, r := range s.Rows {
		if r.ID == "C7" && !strings.Contains(r.Command, "/etc/no-prod-direct-push") {
			t.Errorf("C7 must guard the /etc/no-prod-direct-push marker; got %q", r.Command)
		}
	}
	// C8 (issue #167) is the package-installed row: it must read dpkg's
	// state for unattended-upgrades and compare the exact `installed` status.
	// `dpkg-query -W` alone exits 0 for a removed-but-not-purged package
	// (`config-files`), so a bare rc check would pass without the package.
	for _, r := range s.Rows {
		if r.ID != "C8" {
			continue
		}
		for _, want := range []string{"dpkg-query", "unattended-upgrades", "grep -qx installed"} {
			if !strings.Contains(r.Command, want) {
				t.Errorf("C8 command %q must contain %q", r.Command, want)
			}
		}
		if strings.TrimSpace(r.Expected) != "0" {
			t.Errorf("C8 expected=%q want 0", r.Expected)
		}
	}
	// Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}
