package cmd

import "strings"

// shortID returns the first 8 characters of s, or s itself if shorter.
// Used for printing run / proposal IDs in tabular output.
func shortID(s string) string {
	if len(s) >= 8 {
		return s[:8]
	}
	return s
}

// truncateForErr returns s trimmed to n characters (with an ellipsis
// suffix if it was longer). Used for printing error/diagnostic text
// without flooding the terminal.
// trimForErr caps a blob of ansible stderr/stdout for inclusion in an
// error message.
func trimForErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return s[:400] + "\n... [truncated]"
	}
	return s
}

func truncateForErr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... [truncated]"
}
