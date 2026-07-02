package spec

import (
	"strings"
	"testing"
)

func TestLint_OK(t *testing.T) {
	s, err := ParseReader(strings.NewReader(sampleSpec))
	if err != nil {
		t.Fatal(err)
	}
	fs := Lint(s)
	if HasErrors(fs) {
		t.Fatalf("expected no errors, got %v", fs)
	}
}

func TestLint_DuplicateID(t *testing.T) {
	body := `# Verification Spec — x

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | a | present | ` + "`test -f /tmp/a`" + ` |
| C1 | file | b | present | ` + "`test -f /tmp/b`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	fs := Lint(s)
	if !HasErrors(fs) {
		t.Fatal("expected error for duplicate ID")
	}
}

func TestLint_EmptyFields(t *testing.T) {
	body := `# Verification Spec — x

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | a |  | ` + "`test -f /tmp/a`" + ` |
| C2 | file | b | present |  |
|    | file | c | present | ` + "`test -f /tmp/c`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	fs := Lint(s)
	if !HasErrors(fs) {
		t.Fatal("expected errors")
	}
	// expect at least: C1 empty expected, C2 empty command, empty ID
	byID := map[string]Finding{}
	for _, f := range fs {
		byID[f.ID+"|"+f.Message] = f
	}
	if _, ok := byID["C1|expected value is empty"]; !ok {
		t.Errorf("missing C1 empty-expected finding: %v", fs)
	}
	if _, ok := byID["C2|command is empty"]; !ok {
		t.Errorf("missing C2 empty-command finding: %v", fs)
	}
	if _, ok := byID["|row missing ID"]; !ok {
		t.Errorf("missing blank-ID finding: %v", fs)
	}
}

func TestLint_BadIDPattern(t *testing.T) {
	body := `# Verification Spec — x

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| 1bad | file | a | present | ` + "`test -f /tmp/a`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	fs := Lint(s)
	if !HasErrors(fs) {
		t.Fatal("expected error for ID not matching pattern")
	}
}

func TestLint_VagueExpected(t *testing.T) {
	body := `# Verification Spec — x

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file | a | ok | ` + "`test -f /tmp/a`" + ` |
| C2 | file | b | 合理 | ` + "`test -f /tmp/b`" + ` |
`
	s, _ := ParseReader(strings.NewReader(body))
	fs := Lint(s)
	if HasErrors(fs) {
		t.Fatalf("vague expected is warn, not error: %v", fs)
	}
	if len(fs) != 2 {
		t.Fatalf("expected 2 warns, got %d", len(fs))
	}
}

// TestLint_MatcherWarnings covers the three verify matcher-semantics traps.
// All are SeverityWarn (never block generate) but must be surfaced.
func TestLint_MatcherWarnings(t *testing.T) {
	countWarns := func(body, substr string) int {
		s, _ := ParseReader(strings.NewReader(body))
		fs := Lint(s)
		if HasErrors(fs) {
			t.Fatalf("matcher issues must be warnings, not errors: %v", fs)
		}
		n := 0
		for _, f := range fs {
			if f.Severity == SeverityWarn && strings.Contains(f.Message, substr) {
				n++
			}
		}
		return n
	}
	hdr := "# Verification Spec — x\n\n## 2. Checklist\n\n| ID | Category | Check | Expected | Command |\n|----|----------|-------|----------|---------|\n"

	// (a) reverse-logic grep + numeric expected.
	revBody := hdr + "| C1 | service | svc down? | 1 | " + "`sudo ipactl status | grep -q STOPPED`" + " |\n"
	if got := countWarns(revBody, "positive logic"); got != 1 {
		t.Errorf("reverse-grep warn: got %d, want 1", got)
	}
	// A positive-logic grep (no negation token) must NOT warn.
	okBody := hdr + "| C1 | service | up | 0 | " + "`systemctl is-active sssd`" + " |\n"
	if got := countWarns(okBody, "positive logic"); got != 0 {
		t.Errorf("positive-logic must not warn: got %d", got)
	}

	// (b) ^-anchored expected.
	anchorBody := hdr + "| C1 | id | fqdn | " + `^ipa1\.example\.com` + " | `hostname -f` |\n"
	if got := countWarns(anchorBody, "anchored expected"); got != 1 {
		t.Errorf("^-anchor warn: got %d, want 1", got)
	}

	// (c) ~active.
	activeBody := hdr + "| C1 | service | up | ~active | `systemctl is-active docker` |\n"
	if got := countWarns(activeBody, `~active also matches`); got != 1 {
		t.Errorf("~active warn: got %d, want 1", got)
	}
	// rc-based active check must NOT warn.
	if got := countWarns(okBody, "~active also matches"); got != 0 {
		t.Errorf("rc-based is-active must not warn: got %d", got)
	}
}

func TestIsVagueExpected(t *testing.T) {
	cases := map[string]bool{
		"ok":      true,
		"OK":      true,
		"合理":      true,
		"normal":  true,
		"should":  true,
		"present": false,
		"\"0\"":   false,
		"active":  false,
		"0644":    false,
	}
	for in, want := range cases {
		if got := isVagueExpected(in); got != want {
			t.Errorf("isVagueExpected(%q)=%v want=%v", in, got, want)
		}
	}
}
