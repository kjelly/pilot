package spec

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestRegression_SpecProbesSplitInAnsible applies the same check as
// TestRegression_FreeFormCommandsSplitInAnsible to every docs/verification
// row: `pilot verify` runs a row's command as an ad-hoc shell `-a` argument,
// which Ansible's split_args parses first, shell comment lines included. A
// row whose comment held an apostrophe ("this row's own cache") failed
// before the shell ran, with "failed at splitting arguments, either an
// unbalanced jinja2 block or quotes", and only stdout of Ansible warnings
// reached the matcher (PR #72, 2026-10-14). Spec lint did not catch it.
func TestRegression_SpecProbesSplitInAnsible(t *testing.T) {
	files, err := filepath.Glob("../../docs/verification/*.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := 0
	for _, path := range files {
		s, err := Parse(path)
		if err != nil {
			continue // the spec's own regression test reports parse errors
		}
		for _, r := range s.Rows {
			if strings.TrimSpace(r.Command) == "" {
				continue
			}
			rows++
			if !ansibleSplitArgsBalanced(r.Command) {
				t.Errorf("%s %s: Ansible's split_args rejects the command (an unbalanced quote or Jinja block, comments included); pilot verify would fail before the shell runs", filepath.Base(path), r.ID)
			}
		}
	}
	if rows < 100 {
		t.Fatalf("checked only %d spec rows; the parse is broken", rows)
	}
}
