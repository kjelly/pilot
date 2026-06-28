package cmd

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
func truncateForErr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n... [truncated]"
}
