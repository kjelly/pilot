package spec

import (
	"os"
	"strings"
	"testing"
)

func TestRegression_FreeIPARealmReplacementContract(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-realm-replacement.md"
	const playbookPath = "../../playbooks/apply/freeipa-realm-replacement-apply.yml"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(s.Rows), 6; got != want {
		t.Fatalf("rows=%d, want %d", got, want)
	}
	for i, row := range s.Rows {
		want := "C" + string(rune('1'+i))
		if row.ID != want || strings.TrimSpace(row.Expected) == "" || strings.TrimSpace(row.Command) == "" {
			t.Errorf("row %d = %+v, want contiguous non-empty %s", i, row, want)
		}
	}
	if HasErrors(Lint(s)) {
		t.Fatalf("spec lint errors: %s", fsToString(Lint(s)))
	}
	pb, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(pb)
	for _, required := range []string{
		"freeipa_realm_replacement_confirm | bool",
		"freeipa_realm_replacement_ticket | length >= 3",
		"ipa-client-install, --uninstall, -U",
		"--force-join",
		"freeipa_realm_replacement_backup_archive",
		"restore local pre-migration archive",
		"rebuilt/retired old server",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("migration playbook must contain %q", required)
		}
	}
	if strings.Contains(text, "state: absent\n") && strings.Contains(text, "freeipa_realm_replacement_backup_archive") {
		t.Error("migration playbook must retain its backup archive; do not delete rollback material")
	}
}
