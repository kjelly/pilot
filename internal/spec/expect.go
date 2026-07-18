package spec

import (
	"fmt"
	"regexp"
	"strings"
)

// Expect is the typed, shared matcher representation used by both the v1
// compatibility compiler and the Spec v2 parser. Every populated field is an
// AND condition. LegacyRCEcho is intentionally private to v1 compatibility:
// v2 schemas must never emit it.
type Expect struct {
	ExitCode     *int           `yaml:"exitCode,omitempty"`
	Stdout       *StringMatcher `yaml:"stdout,omitempty"`
	Stderr       *StringMatcher `yaml:"stderr,omitempty"`
	LegacyRCEcho *int           `yaml:"-"`
}

// StringMatcher selects exactly one string predicate.
type StringMatcher struct {
	Equals      *string `yaml:"equals,omitempty"`
	Contains    *string `yaml:"contains,omitempty"`
	NotContains *string `yaml:"notContains,omitempty"`
	Regex       *string `yaml:"regex,omitempty"`
}

// ProbeResult is the normalized input to a typed matcher. LegacyExitCode is
// only populated by the v1 historical-output adapter for the rc-echo idiom.
type ProbeResult struct {
	Stdout         string
	Stderr         string
	ExitCode       int
	LegacyExitCode *int
	ProbeStatus    string
}

// Verdict retains a human-readable reason without coupling callers to a
// particular stdout callback format.
type Verdict struct {
	Pass   bool
	Detail string
}

// CompileV1Expected translates the five legacy Expected grammars without
// inspecting runtime output. It is deliberately separate from the historical
// callback adapter so v2 execution never learns one-line parsing rules.
func CompileV1Expected(raw string) (Expect, error) {
	expected := strings.TrimSpace(raw)
	switch {
	case expected == "" || expected == "present":
		return Expect{ExitCode: intPtr(0)}, nil
	case strings.HasPrefix(expected, "^"):
		if _, err := regexp.Compile(expected); err != nil {
			return Expect{}, fmt.Errorf("invalid regex %q: %w", expected, err)
		}
		return Expect{Stdout: &StringMatcher{Regex: stringPtr(expected)}}, nil
	case isV1Integer(expected):
		// Preserve the historical tools.atoi behavior exactly. In particular,
		// isInt accepted a leading minus while atoi returned zero for it; no
		// v1 fixture currently relies on that quirk, but M2.1 must not repair
		// semantics before migration has made the ambiguity explicit.
		value := legacyV1Atoi(expected)
		return Expect{LegacyRCEcho: intPtr(value)}, nil
	case strings.HasPrefix(expected, "~"):
		return Expect{Stdout: &StringMatcher{Contains: stringPtr(strings.TrimPrefix(expected, "~"))}}, nil
	default:
		return Expect{Stdout: &StringMatcher{Equals: stringPtr(expected)}}, nil
	}
}

// Eval evaluates the typed semantics over a normalized probe result.
func (e Expect) Eval(result ProbeResult) Verdict {
	if e.LegacyRCEcho != nil {
		got := result.ExitCode
		source := "rc"
		if result.LegacyExitCode != nil {
			got = *result.LegacyExitCode
			source = "rc-from-stdout"
		}
		if got != *e.LegacyRCEcho {
			return Verdict{Detail: fmt.Sprintf("%s=%d, expected %d", source, got, *e.LegacyRCEcho)}
		}
		return Verdict{Pass: true, Detail: fmt.Sprintf("%s=%d matches expected %d", source, got, *e.LegacyRCEcho)}
	}
	if e.ExitCode != nil && result.ExitCode != *e.ExitCode {
		return Verdict{Detail: fmt.Sprintf("rc=%d, expected %d", result.ExitCode, *e.ExitCode)}
	}
	if e.Stdout != nil {
		if verdict := e.Stdout.eval("stdout", result.Stdout); !verdict.Pass {
			return verdict
		}
	}
	if e.Stderr != nil {
		if verdict := e.Stderr.eval("stderr", result.Stderr); !verdict.Pass {
			return verdict
		}
	}
	if e.ExitCode != nil {
		return Verdict{Pass: true, Detail: fmt.Sprintf("rc=%d matches expected %d", result.ExitCode, *e.ExitCode)}
	}
	return Verdict{Pass: true, Detail: "typed matcher matched"}
}

func (m StringMatcher) eval(field, value string) Verdict {
	set := 0
	if m.Equals != nil {
		set++
	}
	if m.Contains != nil {
		set++
	}
	if m.NotContains != nil {
		set++
	}
	if m.Regex != nil {
		set++
	}
	if set != 1 {
		return Verdict{Detail: fmt.Sprintf("%s matcher must set exactly one predicate", field)}
	}
	switch {
	case m.Equals != nil:
		if value == *m.Equals {
			return Verdict{Pass: true, Detail: fmt.Sprintf("%s matched %q", field, *m.Equals)}
		}
		return Verdict{Detail: fmt.Sprintf("%s=%q, expected %q", field, truncateMatcher(value, 80), *m.Equals)}
	case m.Contains != nil:
		if strings.Contains(value, *m.Contains) {
			return Verdict{Pass: true, Detail: fmt.Sprintf("%s contains %q", field, *m.Contains)}
		}
		return Verdict{Detail: fmt.Sprintf("%s=%q, expected substring %q", field, truncateMatcher(value, 80), *m.Contains)}
	case m.NotContains != nil:
		if !strings.Contains(value, *m.NotContains) {
			return Verdict{Pass: true, Detail: fmt.Sprintf("%s does not contain %q", field, *m.NotContains)}
		}
		return Verdict{Detail: fmt.Sprintf("%s unexpectedly contains %q", field, *m.NotContains)}
	default:
		re, err := regexp.Compile(*m.Regex)
		if err != nil {
			return Verdict{Detail: fmt.Sprintf("invalid regex %q: %v", *m.Regex, err)}
		}
		if re.MatchString(value) {
			return Verdict{Pass: true, Detail: fmt.Sprintf("regex %q matched %q", *m.Regex, truncateMatcher(value, 80))}
		}
		return Verdict{Detail: fmt.Sprintf("regex %q did not match %q", *m.Regex, truncateMatcher(value, 80))}
	}
}

func isV1Integer(value string) bool {
	if value == "" {
		return false
	}
	for i, ch := range value {
		if ch == '-' && i == 0 {
			continue
		}
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
func legacyV1Atoi(value string) int {
	out := 0
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0
		}
		out = out*10 + int(ch-'0')
	}
	return out
}
func intPtr(value int) *int          { return &value }
func stringPtr(value string) *string { return &value }
func truncateMatcher(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit-1] + "…"
}
