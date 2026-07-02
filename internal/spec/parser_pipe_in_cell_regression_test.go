package spec

import (
	"strings"
	"testing"
)

// TestRegression_ParserPreservesPipesInCommand is the regression lock
// for the bug where a spec row whose Command column contained a `|`
// was silently truncated to everything before the first pipe. The
// os-patch-sla C2 row had:
//
//	| C2  | security | ... | 0 | apt list --upgradable | grep security | wc -l | tr -d " " |
//
// and the parser picked only the first half. The fix: if a row has
// more than the canonical 5 columns, join the extras back with ` | `
// so the verifier sees the intended full command.
//
// To prove this test isn't a tautology: revert the parser's
// `if len(cols) > 5` join in parser.go, run this test, and watch
// the assertion `strings.Contains(got, "grep security")` fail.
func TestRegression_ParserPreservesPipesInCommand(t *testing.T) {
	body := `# Verification Spec — pipe

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | pkg | dist-upgrade clear | 0 | apt list --upgradable | grep security | wc -l |
`
	s, err := ParseReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(s.Rows))
	}
	got := s.Rows[0].Command
	if !strings.Contains(got, "grep security") {
		t.Errorf("C1 command missing the pipe-rest; got %q (parser dropped everything after `|`). Fix: parser.go joins extra columns back with ` | `", got)
	}
	if !strings.Contains(got, "apt list --upgradable") {
		t.Errorf("C1 command missing the pipe-head; got %q", got)
	}
}
