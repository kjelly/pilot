package spec

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Severity of a Lint finding.
type Severity int

const (
	// SeverityError blocks `pilot spec --generate` until fixed.
	SeverityError Severity = iota
	// SeverityWarn is reported but does not block. Use for soft
	// contract smells (vague expected, non-portable commands).
	SeverityWarn
)

// Finding is one issue raised by Lint.
type Finding struct {
	Severity Severity
	Line     int    // 0 if not row-scoped
	ID       string // row ID, or empty if spec-scoped
	Message  string
}

func (f Finding) String() string {
	loc := ""
	if f.Line > 0 {
		loc = fmt.Sprintf(" (line %d", f.Line)
		if f.ID != "" {
			loc += fmt.Sprintf(", id=%s", f.ID)
		}
		loc += ")"
	}
	sev := "warn"
	if f.Severity == SeverityError {
		sev = "error"
	}
	return fmt.Sprintf("%s%s: %s", sev, loc, f.Message)
}

// Lint walks a Spec and returns every issue it finds. The spec is
// not mutated; pass the same *Spec to Generator after addressing
// every SeverityError finding.
//
// Contract enforced:
//
//   - every row has non-empty ID / Expected / Command
//   - IDs are unique within the spec
//   - IDs match IDPattern
//   - "vague" expected values (e.g. "OK", "normal", "合理") are
//     surfaced as SeverityWarn so authors tighten them
//   - Command is non-empty and not just whitespace
func Lint(s *Spec) []Finding {
	var out []Finding
	if s == nil {
		return []Finding{{Severity: SeverityError, Message: "nil spec"}}
	}
	seen := map[string]int{}
	for _, r := range s.Rows {
		if strings.TrimSpace(r.ID) == "" {
			out = append(out, Finding{Severity: SeverityError, Line: r.Line, Message: "row missing ID"})
			continue
		}
		if !IDPattern.MatchString(r.ID) {
			out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID,
				Message: fmt.Sprintf("ID %q does not match pattern %s", r.ID, IDPattern.String())})
		}
		if prev, dup := seen[r.ID]; dup {
			out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID,
				Message: fmt.Sprintf("duplicate ID (first seen line %d)", prev)})
		}
		seen[r.ID] = r.Line

		if strings.TrimSpace(r.Expected) == "" {
			out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID,
				Message: "expected value is empty"})
		} else if isVagueExpected(r.Expected) {
			out = append(out, Finding{Severity: SeverityWarn, Line: r.Line, ID: r.ID,
				Message: fmt.Sprintf("expected %q is vague; tighten to a concrete value or regex", r.Expected)})
		}

		if strings.TrimSpace(r.Command) == "" {
			out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID,
				Message: "command is empty"})
		}

		if s.SchemaVersion == 2 {
			out = append(out, v2RowLint(s, r)...)
			continue
		}

		// Matcher-semantics warnings — the three traps that pass lint but
		// misbehave under `pilot verify`'s ansible ad-hoc path. All are
		// SeverityWarn (guidance, non-blocking).
		out = append(out, matcherWarnings(r)...)
	}
	// Stable order: by line, then by ID.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func v2RowLint(s *Spec, r Row) []Finding {
	var out []Finding
	if strings.Contains(r.Command, "{{") {
		out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID, Message: "v2 probe must not contain Jinja template syntax"})
	}
	if r.Action != nil && r.Action.Mode == "readOnly" && obviousMutation(r.Command) {
		out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID, Message: "readOnly action has an obvious mutation command; declare isolatedMutation with cleanup or move it to apply/fixture"})
	}
	if len(r.NeedsReview) > 0 {
		out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID, Message: "v2 check has unresolved needsReview findings"})
	}
	if r.Expect.Stdout != nil && r.Expect.Stdout.Contains != nil && len(*r.Expect.Stdout.Contains) < 3 {
		out = append(out, Finding{Severity: SeverityWarn, Line: r.Line, ID: r.ID, Message: "v2 stdout.contains shorter than three characters is weak"})
	}
	if r.Action != nil && r.Action.Mode == "readOnly" && looksLikeMutation(r.Command) {
		out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID, Message: "readOnly action uses a known mutation pattern"})
	}
	for _, input := range s.Inputs {
		if !input.Required && probeReferencesInput(r.Command, input.Name) && !applicabilityReferencesInput(r.AppliesWhen, input.Name) {
			out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID, Message: fmt.Sprintf("optional input %q is used by probe without appliesWhen", input.Name)})
		}
		if input.SecretRef != nil && (r.Expect.Stdout != nil || r.Expect.Stderr != nil) {
			out = append(out, Finding{Severity: SeverityError, Line: r.Line, ID: r.ID, Message: "secret-bearing spec must not use stdout/stderr content matcher"})
			break
		}
	}
	return out
}

var v2MutationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|[;&|]\s*|\s)(rm|mv|cp|install|chmod|chown|useradd|userdel|groupadd|groupdel|mkdir|touch|truncate|tee)\s`),
	regexp.MustCompile(`(?i)\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask|daemon-reload)\b`),
	regexp.MustCompile(`(?i)\b(apt|apt-get|dnf|yum|apk)\s+(install|remove|purge|upgrade|update)\b`),
	regexp.MustCompile(`(?i)\bcurl\b[^\n]*(--request|-X)\s*(POST|PUT|PATCH|DELETE)\b`),
}

func looksLikeMutation(command string) bool {
	for _, pattern := range v2MutationPatterns {
		if pattern.MatchString(command) {
			return true
		}
	}
	safeRedirectsRemoved := strings.NewReplacer(
		">/dev/null", "",
		"> /dev/null", "",
		"2>&1", "",
		"1>&2", "",
	).Replace(command)
	return regexp.MustCompile(`(^|\s)>{1,2}\s*\S`).MatchString(safeRedirectsRemoved)
}

func probeReferencesInput(command, name string) bool {
	return strings.Contains(command, "PILOT_VAR_"+inputNameSuffix(name))
}

func inputNameSuffix(name string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func applicabilityReferencesInput(applicability *Applicability, name string) bool {
	if applicability == nil {
		return false
	}
	conditions := applicability.All
	if applicability.Any != nil {
		conditions = applicability.Any
	}
	for _, condition := range conditions {
		if condition.Input != nil && condition.Input.Name == name {
			return true
		}
	}
	return false
}

var obviousMutationRe = regexp.MustCompile(`(?i)(\bcurl\b[^\n]*(?:-X\s*(POST|PUT|PATCH|DELETE)|--request\s*(POST|PUT|PATCH|DELETE))|\b(apt|apt-get|dnf|yum)\b[^\n]*(install|remove|upgrade)|\bsystemctl\b[^\n]*(start|stop|restart|enable|disable)|(^|\s)(>|>>)\s*[^&])`)

func obviousMutation(command string) bool { return obviousMutationRe.MatchString(command) }

// HasErrors returns true when at least one Finding is SeverityError.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// vagueExpectedWords are catch-all terms that mean "the verifier
// must make a judgement call" — exactly what the spec format is
// designed to prevent.
var vagueExpectedWords = []string{
	"ok", "normal", "合理", "足夠", "適當", "should", "may",
}

var (
	// reverseGrepRe matches a command that pipes into grep.
	reverseGrepRe = regexp.MustCompile(`(?i)\|\s*grep\b`)
	// negationTokenRe matches "bad state" words a reverse-logic grep looks
	// for (the healthy path then makes grep exit non-zero).
	negationTokenRe = regexp.MustCompile(`(?i)\b(STOPPED|FAILED|inactive|dead|disabled|not\s+running|not\s+found|error)\b`)
)

// matcherWarnings flags the three verify matcher-semantics traps documented in
// docs/verification-spec-template.md. Each is a real defect seen in practice
// but not a hard error (the row is still runnable), so they are SeverityWarn.
func matcherWarnings(r Row) []Finding {
	var out []Finding
	exp := strings.TrimSpace(r.Expected)
	cmd := r.Command

	// (a) Reverse-logic grep for a bad-state token with an integer expected.
	// Under ansible ad-hoc, a piped command that exits non-zero on the
	// HEALTHY path marks the whole task FAILED and surfaces ansible's own rc
	// (2), never the pipe's rc (1) — so `... | grep -q STOPPED` expected `1`
	// can never match. Use positive logic (assert the healthy string / rc 0).
	if looksNumeric(exp) && reverseGrepRe.MatchString(cmd) && negationTokenRe.MatchString(cmd) {
		out = append(out, Finding{Severity: SeverityWarn, Line: r.Line, ID: r.ID,
			Message: "reverse-logic grep for a failure token with a numeric expected: " +
				"ansible ad-hoc reports rc=2 (task-failed), not the pipe's rc, on the healthy path — " +
				"use positive logic (assert the RUNNING/active string, or rc 0)"})
	}

	// (b) Anchored-regex expected. `pilot verify`'s ad-hoc output keeps the
	// `host | CHANGED | rc=0 >> …` wrapper (stripRunnerPrefix only removes the
	// "(rc=N)" marker), so a `^…`-anchored regex matches the wrapper, not the
	// stdout — it only works in --local mode. Prefer `~contains`.
	if strings.HasPrefix(exp, "^") {
		out = append(out, Finding{Severity: SeverityWarn, Line: r.Line, ID: r.ID,
			Message: "^-anchored expected only matches in --local mode: over ansible ad-hoc the " +
				"`host | CHANGED | rc=0 >>` prefix precedes stdout and defeats the anchor — prefer `~<substring>`"})
	}

	// (c) `~active` also matches "inactive"/"reloading"/"deactivating".
	if strings.EqualFold(exp, "~active") {
		out = append(out, Finding{Severity: SeverityWarn, Line: r.Line, ID: r.ID,
			Message: `~active also matches "inactive" (substring) — a stopped service would pass; ` +
				"prefer a numeric expected `0` with `systemctl is-active <svc>` (exits 0 iff active)"})
	}
	return out
}

// looksNumeric reports whether s (after trimming and stripping surrounding
// quotes) is an optionally-signed integer — an rc-comparison expected value.
func looksNumeric(s string) bool {
	s = strings.Trim(strings.TrimSpace(s), `"'`+"`")
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isVagueExpected(s string) bool {
	low := strings.ToLower(strings.TrimSpace(s))
	// strip surrounding quotes
	low = strings.Trim(low, `"'`+"`")
	for _, w := range vagueExpectedWords {
		if low == w {
			return true
		}
	}
	return false
}
