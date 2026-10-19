package loginprobe

import (
	"regexp"
	"strings"
)

// Secrets never belong in the journal or the textfile: the probe's own
// private key, any key material OpenSSH might echo, and base64 blobs that
// look like keys. These patterns are applied to every string the daemon
// logs; stdout of the probe command is never logged at all.
var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN[^-]*-----[\s\S]*?-----END[^-]*-----`),
	regexp.MustCompile(`-----BEGIN[^\n]*`),
	regexp.MustCompile(`(?i)private key[^\n]*`),
	regexp.MustCompile(`\b(?:ssh-(?:ed25519|rsa|dss)|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]{20,}`),
	regexp.MustCompile(`\bAAAA[A-Za-z0-9+/=]{24,}`),
}

// maxSummaryLen bounds the per-attempt summary line kept for logs.
const maxSummaryLen = 240

// Redact replaces anything that looks like key material with [redacted].
func Redact(s string) string {
	for _, re := range redactPatterns {
		s = re.ReplaceAllString(s, "[redacted]")
	}
	return s
}

// Summarize returns the most informative final OpenSSH message from an
// attempt's stderr, redacted and truncated: the last line that is not a
// debug line, or the last debug line when nothing else was printed.
func Summarize(stderr string) string {
	lines := strings.Split(strings.ReplaceAll(stderr, "\r\n", "\n"), "\n")
	var lastDebug, lastPlain string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "debug") {
			lastDebug = l
			continue
		}
		lastPlain = l
	}
	s := lastPlain
	if s == "" {
		s = lastDebug
	}
	s = Redact(s)
	if len(s) > maxSummaryLen {
		s = s[:maxSummaryLen] + "…"
	}
	return s
}
