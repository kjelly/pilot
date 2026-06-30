package spec

import (
	"strings"
	"testing"
)

// TestGenerate_GrepRowsAvoidDebug is the regression lock-in for the
// C4 / C7 pam-oidc-sshd upgrade. Before this fix, rows whose command
// started with `grep` collapsed to `ansible.builtin.debug` with a
// human-only message — running the generated playbook produced "ok"
// regardless of whether the assertion was satisfied. After the fix,
// such rows become `ansible.builtin.command` running grep directly so
// the predicate's real rc is captured in spec_checkpoints.
//
// Why this matters:
//   - The generate → verify → status chain depends on the generated
//     playbook being a faithful rendition of the spec row. A debug
//     task would silently make every grep row pass.
//   - This test pins the fix at the generator level so a refactor
//     that strips the upgraded branch will be caught without
//     spinning up real ansible.
//
// To prove the test isn't a tautology: revert the grep branch in
// classifyRow to its previous behavior (return debug). The test
// below fails because both C4 and C7 expectations collapse to debug.
func TestGenerate_GrepRowsAvoidDebug(t *testing.T) {
	body := `# Verification Spec — grep-rows

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C4 | pam | sshd has oidc line | 0 | grep -qE '^auth.+pam_kc_ssh\.so' /etc/pam.d/sshd |
| C7 | config | issuer present | 0 | grep -qE '^issuer:[[:space:]]*https?://' /etc/kc-ssh-pam/config.yaml |
`
	s, err := ParseReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatal(err)
	}
	out := pb.RenderYAML()
	// Both rows must be ansible.builtin.command, not ansible.builtin.debug.
	for _, c := range []string{"C4", "C7"} {
		rowIdx := -1
		for i, r := range s.Rows {
			if r.ID == c {
				rowIdx = i
				break
			}
		}
		if rowIdx < 0 {
			t.Fatalf("spec row %s missing", c)
		}
		dedupIdx := pb.MapIDToTask[c]
		if len(dedupIdx) == 0 {
			t.Fatalf("%s not mapped to any generated task", c)
		}
		mod := pb.Tasks[dedupIdx[0]].Module
		if mod == "ansible.builtin.debug" {
			t.Errorf("row %s degenerated to ansible.builtin.debug — pre-fix regression (was working only with grep-aware classification)", c)
		}
		if mod != "ansible.builtin.command" {
			t.Errorf("row %s produced unexpected module %q (want command)", c, mod)
		}
	}
	if !strings.Contains(out, "grep -qE") {
		t.Errorf("generated playbook does not contain the raw grep command; out:\n%s", out)
	}
}
