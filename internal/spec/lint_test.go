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
