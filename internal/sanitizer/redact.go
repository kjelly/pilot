package sanitizer

import (
	"regexp"
	"strings"
)

type Rule struct {
	Pattern     *regexp.Regexp
	Replace     string
	ReplaceFunc func(string) string
	Description string
	// OptIn marks rules that are NOT included by default in
	// NewWith(). Callers that want a more aggressive scrub must
	// explicitly enable these via NewWith(..., Rule{OptIn: true}).
	OptIn bool
}

// AlwaysOnRules are applied by New() and NewWith(). These redact
// things that should never reach the LLM regardless of context:
// secrets, private keys, /etc/shadow root entry, email addresses.
var AlwaysOnRules = []Rule{
	{
		Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd|token|api[_-]?key|secret)(\s*[=:]\s*)(['"]?)([^\s'"]+)(['"]?)`),
		ReplaceFunc: redactSecret,
		Description: "password / token / api key",
	},
	{
		Pattern:     regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
		Replace:     "[REDACTED-PRIVATE-KEY]",
		Description: "PEM private key block",
	},
	{
		Pattern:     regexp.MustCompile(`root:([^:\n]*):([^:\n]*):([^:\n]*):([^:\n]*):([^:\n]*):([^:\n]*):`),
		Replace:     "root:[REDACTED]:[REDACTED]:[REDACTED]:[REDACTED]:[REDACTED]:[REDACTED]:",
		Description: "/etc/shadow root entry",
	},
	{
		Pattern:     regexp.MustCompile(`[\w\.-]+@[\w\.-]+\.\w+`),
		Replace:     "[REDACTED-EMAIL]",
		Description: "email address",
	},
}

// OptInRules are NOT applied by New(). IPv4 redaction in particular
// is aggressive — it strips host IPs from Ansible inventory output,
// SSH config, etc. — which means the LLM loses context. Callers
// that need this (e.g. log scrubbing for third-party sharing) should
// pass Rules... to NewWith().
var OptInRules = []Rule{
	{
		Pattern:     regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		Replace:     "[REDACTED-IP]",
		Description: "IPv4 address",
		OptIn:       true,
	},
}

// Redactor applies a configurable set of regex-based redaction rules.
type Redactor struct {
	rules []Rule
}

// New returns a Redactor that applies all AlwaysOnRules (secrets,
// private keys, shadow, emails) but NOT the IPv4 OptIn rule. This
// matches the historical behaviour that worked correctly for the
// Ubuntu-hardening use case.
func New() *Redactor {
	return NewWith()
}

// NewWith returns a Redactor that applies all AlwaysOnRules plus any
// additional rules the caller passes. Use this when you want IPv4
// redaction or any future OptIn rules.
func NewWith(extra ...Rule) *Redactor {
	rules := make([]Rule, 0, len(AlwaysOnRules)+len(extra))
	rules = append(rules, AlwaysOnRules...)
	rules = append(rules, extra...)
	return &Redactor{rules: rules}
}

// Sanitize applies the configured rules to input and returns the
// redacted result.
func (r *Redactor) Sanitize(input string) string {
	out := input
	for _, rule := range r.rules {
		if rule.ReplaceFunc != nil {
			out = rule.Pattern.ReplaceAllStringFunc(out, rule.ReplaceFunc)
		} else {
			out = rule.Pattern.ReplaceAllString(out, rule.Replace)
		}
	}
	return out
}

// SanitizeBytes is a byte-slice convenience wrapper around Sanitize.
func (r *Redactor) SanitizeBytes(input []byte) []byte {
	return []byte(r.Sanitize(string(input)))
}

// WithExtraRules returns a copy of r with the additional rules
// appended. Useful when a caller wants to start with the default
// behaviour and then layer on more aggressive scrubbing.
func (r *Redactor) WithExtraRules(extra ...Rule) *Redactor {
	combined := make([]Rule, 0, len(r.rules)+len(extra))
	combined = append(combined, r.rules...)
	combined = append(combined, extra...)
	return &Redactor{rules: combined}
}

var secretRegex = regexp.MustCompile(`(?i)(password|passwd|pwd|token|api[_-]?key|secret)(\s*[=:]\s*)(?:"([^"]*)"|'([^']*)'|([^\s'"]+))`)

func redactSecret(match string) string {
	sub := secretRegex.FindStringSubmatch(match)
	if len(sub) < 6 {
		return match
	}
	key := sub[1]
	sep := sub[2]

	var val string
	var quote string

	if strings.Contains(match, "\"") {
		val = sub[3]
		quote = "\""
	} else if strings.Contains(match, "'") {
		val = sub[4]
		quote = "'"
	} else {
		val = sub[5]
		quote = ""
	}

	trimmedVal := strings.TrimSpace(val)

	// 1. If it is a Jinja2 template reference like {{ var }}, don't redact
	if strings.HasPrefix(trimmedVal, "{{") && strings.HasSuffix(trimmedVal, "}}") {
		return match
	}
	// 2. If it is a boolean/trivial value, don't redact
	lowerVal := strings.ToLower(trimmedVal)
	if lowerVal == "true" || lowerVal == "false" || lowerVal == "yes" || lowerVal == "no" || lowerVal == "null" || lowerVal == "none" {
		return match
	}

	return key + sep + quote + "[REDACTED]" + quote
}

