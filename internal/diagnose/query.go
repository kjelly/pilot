package diagnose

import (
	"strconv"
	"strings"
)

// shlexQuote wraps s in single quotes (escaping embedded single quotes via
// the standard '"'"' technique) so ansible's command-module argument
// tokenizer — which follows POSIX-shell/shlex quoting rules even though no
// shell is ever invoked — treats s as one opaque token, regardless of
// spaces, double quotes, or braces inside it (LogQL/PromQL routinely have
// all three). Module stays "command", never "shell": this is purely about
// surviving ansible's own tokenization step, not shell execution.
func shlexQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// httpStatusMarker prefixes the HTTP status curlQueryCommand appends to
// stdout; SplitHTTPStatus looks for this same literal to separate it back
// out from the response body.
const httpStatusMarker = "HTTP_STATUS:"

// curlQueryCommand builds a command-module Command string: curl -sS -G
// url, one --data-urlencode token per non-empty (key, value) pair in
// params (order preserved), plus a trailing -w that appends the HTTP
// status on its own line. Deliberately no -f: a 4xx/5xx response's body
// (often the most useful part of a bad LogQL/PromQL query) is preserved
// instead of being swallowed by curl's own failure handling. The -w
// format's "\n" is a literal two-character escape curl itself substitutes
// for a newline when writing output (see curl(1) -w/--write-out) — not a
// raw newline byte in this command string — so the ad-hoc argument stays
// a single, ordinary line of text.
func curlQueryCommand(url string, params [][2]string) string {
	var b strings.Builder
	b.WriteString("curl -sS -G ")
	b.WriteString(url)
	for _, kv := range params {
		if kv[1] == "" {
			continue
		}
		b.WriteString(" --data-urlencode ")
		b.WriteString(shlexQuote(kv[0] + "=" + kv[1]))
	}
	b.WriteString(" -w ")
	b.WriteString(shlexQuote("\\n" + httpStatusMarker + "%{http_code}"))
	return b.String()
}

// SplitHTTPStatus extracts the "\nHTTP_STATUS:nnn" suffix
// curlQueryCommand's -w appends (curl itself turns the literal "\n" it
// was given into a real newline before writing this), returning the
// response body and status separately. ok is false if the marker isn't
// present (e.g. curl never produced output at all) or the status isn't a
// valid integer.
func SplitHTTPStatus(stdout string) (body string, status int, ok bool) {
	marker := "\n" + httpStatusMarker
	idx := strings.LastIndex(stdout, marker)
	if idx < 0 {
		return stdout, 0, false
	}
	body = stdout[:idx]
	statusStr := strings.TrimSpace(stdout[idx+len(marker):])
	n, err := strconv.Atoi(statusStr)
	if err != nil {
		return stdout, 0, false
	}
	return body, n, true
}
