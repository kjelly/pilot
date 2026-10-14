package spec

import (
	"fmt"
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
	// No task may delete the rollback material: the archive, its directory
	// or its link. (Removing /etc/hosts lines is fine.)
	doc, _ := loadYAML(t, playbookPath).([]any)
	for _, item := range doc {
		play, _ := item.(map[string]any)
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			walkTaskTree(play[section], nil, func(task map[string]any, _ []string) {
				for _, key := range []string{"file", "ansible.builtin.file"} {
					args, ok := task[key].(map[string]any)
					if !ok || args["state"] != "absent" {
						continue
					}
					if path := fmt.Sprint(args["path"]); strings.Contains(path, "freeipa_realm_replacement_backup") {
						t.Errorf("%v deletes %s; the migration playbook must retain its rollback material", task["name"], path)
					}
				}
			})
		}
	}
}
