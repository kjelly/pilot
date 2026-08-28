package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"time"
)

// LogMaxMessageBytes is spec1.md §15's per-line length cap — normalization
// truncates anything longer, so one huge log line can never blow up
// memory or the NPU's context budget.
const LogMaxMessageBytes = 4096

// LogEntry is one normalized log line (spec1.md §15).
type LogEntry struct {
	Timestamp time.Time
	PilotHost string
	Site      string
	Severity  string
	// Message is the raw line (ANSI-stripped, length-capped) — kept only
	// for a bounded number of evidence samples (spec1.md §18), never sent
	// to the model in bulk.
	Message string
	// TemplateID is spec1.md §16's SHA256(normalized_template) fingerprint.
	TemplateID string
}

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// Order matters: most specific patterns must run first, or generic
// integer substitution eats the digits a UUID/IP/hex/timestamp pattern
// would otherwise have matched as a single, more meaningful token.
var (
	timestampPattern = regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?\b`)
	uuidPattern      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	ipv4Pattern      = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b`)
	// ipv6Pattern is intentionally permissive and can false-positive on a
	// bare HH:MM:SS time with no date (e.g. "12:30:45" also matches).
	// That only mislabels the placeholder as <IP> instead of <TIME> — the
	// line still collapses to a stable template either way, which is all
	// deduplication/burst/rarity actually depend on.
	ipv6Pattern     = regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b`)
	hexAddrPattern  = regexp.MustCompile(`\b0[xX][0-9a-fA-F]+\b`)
	pidLabelPattern = regexp.MustCompile(`(?i)(\bpid[=:]\s*)\d+`)
	intPattern      = regexp.MustCompile(`\b\d+\b`)
)

// stripANSI removes terminal control sequences (spec1.md §15).
func stripANSI(s string) string { return ansiEscapePattern.ReplaceAllString(s, "") }

// truncateLogMessage caps a message at LogMaxMessageBytes, safely on a
// rune boundary.
func truncateLogMessage(s string) string {
	if len(s) <= LogMaxMessageBytes {
		return s
	}
	b := []byte(s)[:LogMaxMessageBytes]
	for len(b) > 0 && !isUTF8Boundary(b) {
		b = b[:len(b)-1]
	}
	return string(b)
}

func isUTF8Boundary(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	return b[len(b)-1]&0xC0 != 0x80
}

// NormalizeLogTemplate implements spec1.md §16's deterministic template
// extraction: replace variable substrings with fixed placeholders so
// structurally-identical log lines collapse to the same template
// regardless of which UUID/PID/timestamp/etc. they happened to carry.
func NormalizeLogTemplate(message string) string {
	s := message
	s = timestampPattern.ReplaceAllString(s, "<TIME>")
	s = uuidPattern.ReplaceAllString(s, "<UUID>")
	s = ipv4Pattern.ReplaceAllString(s, "<IP>")
	s = ipv6Pattern.ReplaceAllString(s, "<IP>")
	s = hexAddrPattern.ReplaceAllString(s, "<HEX>")
	s = pidLabelPattern.ReplaceAllString(s, "${1}<PID>")
	s = intPattern.ReplaceAllString(s, "<NUM>")
	return s
}

// TemplateFingerprint is spec1.md §16's SHA256(normalized_template),
// hex-encoded.
func TemplateFingerprint(normalizedTemplate string) string {
	sum := sha256.Sum256([]byte(normalizedTemplate))
	return hex.EncodeToString(sum[:])
}

// NormalizeLogEntry builds a full LogEntry from raw Loki fields (spec1.md
// §15): ANSI-stripped, length-capped, and fingerprinted.
func NormalizeLogEntry(ts time.Time, pilotHost, site, severity, rawMessage string) LogEntry {
	clean := truncateLogMessage(stripANSI(rawMessage))
	template := NormalizeLogTemplate(clean)
	return LogEntry{
		Timestamp:  ts,
		PilotHost:  pilotHost,
		Site:       site,
		Severity:   severity,
		Message:    clean,
		TemplateID: TemplateFingerprint(template),
	}
}
