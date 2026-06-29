package spec

import (
	"strings"
	"testing"
)

func TestCoverageFor(t *testing.T) {
	cps := []Checkpoint{
		{SpecPath: "x", RowID: "C1", TaskIndex: 0, Status: "verified-pass"},
		{SpecPath: "x", RowID: "C2", TaskIndex: 0, Status: "verified-fail"},
		{SpecPath: "x", RowID: "C3", TaskIndex: 0, Status: "applied"},
	}
	c := CoverageFor("x", cps)
	if c.Total != 3 || c.Compiled != 0 || c.Applied != 1 || c.Verified != 2 || c.VerifiedPass != 1 || c.VerifiedFail != 1 {
		t.Errorf("coverage=%+v", c)
	}
	if got, want := c.CoveragePercent(), 50.0; got != want {
		t.Errorf("CoveragePercent=%v want=%v", got, want)
	}
	if !strings.Contains(c.String(), "coverage=50.0%") {
		t.Errorf("String()=%q", c.String())
	}
}

func TestCoverageFor_Empty(t *testing.T) {
	c := CoverageFor("x", nil)
	if c.CoveragePercent() != 0 {
		t.Errorf("empty coverage should be 0, got %v", c.CoveragePercent())
	}
}

// TestMappingSurvivesDedup exercises the user-visible promise: when
// a spec lists C1/C2/C3 with the same command, the generated playbook
// has one task but every row ID is reachable via MapIDToTask. This
// is the contract the `pilot spec --status` command depends on.
func TestMappingSurvivesDedup(t *testing.T) {
	body := `# Verification Spec — m

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| A1 | file | a | present | ` + "`test -f /tmp/x`" + ` |
| A2 | file | b | present | ` + "`test -f /tmp/x`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	pb, _ := Generate(s, GenerateOptions{})
	if len(pb.Tasks) != 1 {
		t.Fatalf("expected 1 task after dedup, got %d", len(pb.Tasks))
	}
	for _, id := range []string{"A1", "A2"} {
		idx, ok := pb.MapIDToTask[id]
		if !ok || len(idx) != 1 || idx[0] != 0 {
			t.Errorf("MapIDToTask[%q]=%v", id, idx)
		}
	}
}
