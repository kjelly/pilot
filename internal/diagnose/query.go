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

// SNMPExporterProbeSteps is the only active network probe exposed by the
// structured diagnosis surface.  The target and module have already been
// resolved from the workspace registry by the caller; the exporter resolves
// credentials from its server-side configuration.
func SNMPExporterProbeSteps(target, module string) []Step {
	return []Step{{
		ID:          "snmp_probe",
		Description: "bounded SNMP exporter probe using the registered target and module",
		Module:      "command",
		Command:     "curl --max-time 5 -sS -G http://127.0.0.1:9116/snmp --data-urlencode " + shlexQuote("target="+target) + " --data-urlencode " + shlexQuote("module="+module) + " -w " + shlexQuote("\\n"+httpStatusMarker+"%{http_code}"),
	}}
}

// ArtifactSteps returns fixed metadata-only commands for contract-declared
// paths. Content is never requested. The caller bounds directory output when
// converting the command results into the MCP response.
func ArtifactSteps(paths []string) []Step {
	steps := make([]Step, 0, len(paths)*3)
	for i, path := range paths {
		quoted := shlexQuote(path)
		prefix := "artifact_" + strconv.Itoa(i)
		steps = append(steps,
			Step{ID: prefix + "_stat", Description: "artifact metadata", Module: "command", Command: "stat -c '%F\\t%Y\\t%s' -- " + quoted},
			Step{ID: prefix + "_hash", Description: "artifact sha256 metadata", Module: "command", Command: "sha256sum -- " + quoted},
			Step{ID: prefix + "_entries", Description: "bounded artifact directory entry sample", Module: "command", Command: "find " + quoted + " -maxdepth 1 -mindepth 1 -printf '%f\\n' -quit"},
		)
	}
	return steps
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
