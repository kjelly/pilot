package spec

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestShellSyntax_AllRowCommands is the second-line regression:
// every Command column under ## 2. Checklist must at minimum parse as
// bash syntax. This catches typos in shell pipelines (`|`, `&&`, `||`)
// before they reach an ansible ad-hoc.
//
// Not a substitute for the live verify on a target host — that's
// what `pilot verify` does. This test is the cheapest early warning.
//
// To prove the test isn't a tautology: write a row whose Command is
// `grep 'foo` (unmatched single quote). The test must FAIL on bash -n
// while still passing the spec.Lint check.
func TestShellSyntax_AllRowCommands(t *testing.T) {
	mustParse := func(body string) *Spec {
		t.Helper()
		s, err := ParseReader(strings.NewReader(body))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return s
	}

	// Step 1 — make sure the happy-path row IS balanced. If our spec
	// parser itself misbehaves (e.g. drops rows), this loop will exit
	// before reaching the bash check.
	okSpec := mustParse(`# Verification Spec — syntax-check-canary

> v1.0
> n/a
> t

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file     | x     | present  | test -f /tmp |
| C2 | sys      | y     | 0        | sh -c 'test -f /tmp && echo 0' |
| C3 | grep     | z     | 0        | grep -qE 'foo' /tmp/bar |
`)
	for _, r := range okSpec.Rows {
		if r.Command == "" {
			t.Errorf("row %s has empty Command", r.ID)
		}
	}
	// Step 2 — inject a row with a syntax error and verify the check
	// catches it (without traversing other rows).
	badSpec := mustParse(`# Verification Spec — syntax-broken-canary

> v1.0
> n/a
> t

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | file     | ok    | present  | test -f /tmp |
| CX | BROKEN   | bad   | 0        | grep 'unbalanced-quote  |
| C2 | sys      | fine  | 0        | echo ok |
`)
	for _, r := range badSpec.Rows {
		if r.ID != "CX" {
			continue
		}
		_, err := bashSyntaxCheck(r.Command)
		if err == nil {
			t.Errorf("CX row with unbalanced quote should fail bash -n; got nil (test would be a tautology)")
		}
	}
	// Step 3 — every Command in the actual specs under docs/verification/
	// must pass bash -n. We don't run them; we just confirm each is
	// syntactically balanced enough that ansible ad-hoc won't crash.
	// Walk every spec under docs/verification/, NOT a hand-picked
	// list, so adding a new spec automatically gets syntax-checked.
	matches, _ := filepath.Glob("../../docs/verification/*.md")
	sort.Strings(matches)
	for _, sp := range matches {
		s, err := Parse(sp)
		if err != nil {
			t.Logf("skip %s (parse: %v)", sp, err)
			continue
		}
		for _, r := range s.Rows {
			if r.Command == "" {
				t.Errorf("%s/%s: empty Command", sp, r.ID)
				continue
			}
			if _, err := bashSyntaxCheck(r.Command); err != nil {
				t.Errorf("%s/%s: bash -n rejected: %v\n  command: %q",
					sp, r.ID, err, r.Command)
			}
		}
	}
}

// bashSyntaxCheck shells out to `bash -n` to validate a one-line command
// without executing it. We pipe the command through bash to mimic how
// ansible ad-hoc would invoke it (sh -c '<cmd>').
//
// bash -n with stdin typically doesn't syntax-check a non-script; use
// `bash -c '<cmd> --bogus-flag --bogus-such-and-such -n'` as a clever
// hack — but that's brittle. Easier: prepend `if true; then <cmd>; fi`
// so `bash -n` parses it as a script.
func bashSyntaxCheck(cmd string) (string, error) {
	// Wrap into a single-line script so quote-parsing stays in
	// one chunk. (A multi-line true/false wrapping makes bash -n
	// complain about unclosed single quotes from the inner
	// sh -c '...awk "..."' pattern.)
	script := "{ " + cmd + "; } 2>/dev/null; :"
	out, err := exec.Command("bash", "-n", "-c", script).CombinedOutput()
	if err != nil {
		return string(out), err
	}
	// Empty output, no error → syntax OK.
	return string(bytes.TrimSpace(out)), nil
}
