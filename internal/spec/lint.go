package spec

import (
	"fmt"
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
