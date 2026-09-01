package diagnose

import (
	"fmt"
	"strings"
)

// NetworkPathSteps returns the fixed, read-only ad-hoc commands for
// pilot_diagnose_network_path (Agent Monitoring Phase 2 §5), all run
// FROM the source host against a destination the caller has already
// resolved from a contract endpoint — never an arbitrary caller-supplied
// host:port. readinessPath is empty when the destination component has
// no known HTTP readiness path for this endpoint (the application_
// readiness layer is then skipped, not faked).
func NetworkPathSteps(destHost string, destPort int, scheme, readinessPath string) []Step {
	steps := []Step{
		{ID: "name_resolution", Description: "resolve the declared destination via NSS", Module: "command",
			Command: fmt.Sprintf("getent hosts %s", destHost)},
		{ID: "routing", Description: "inspect the route to the destination", Module: "shell",
			Command: fmt.Sprintf("ip route get %s 2>&1", shlexQuote(destHost))},
		// exec 3<>/dev/tcp/... (open, don't read) rather than
		// `cat < /dev/tcp/...` — a plain read blocks waiting for the
		// SERVER to send data first, which no HTTP-like server ever does
		// before it sees a request; that produced a false "closed" on
		// every real HTTP endpoint (confirmed against a live container
		// 2026-09-01), timing out instead of confirming the TCP
		// handshake it actually needs to check.
		{ID: "transport", Description: "TCP connect to the declared contract port", Module: "shell",
			Command: fmt.Sprintf("timeout 2 bash -c 'exec 3<>/dev/tcp/%s/%d' 2>/dev/null && echo open || echo closed", destHost, destPort)},
	}
	if scheme == "https" {
		// -verify_return_error makes openssl exit nonzero on a failed
		// chain instead of silently reporting "Verify return code: 0"
		// only for the trivially-satisfied case — this is the layer
		// spec §5 explicitly forbids turning into an unconditional pass
		// via -k/insecure; there is no -k here at all.
		steps = append(steps, Step{ID: "tls", Description: "validate the TLS certificate chain (never insecure/-k)", Module: "shell",
			Command: fmt.Sprintf("timeout 3 openssl s_client -connect %s:%d -servername %s -verify_return_error </dev/null 2>&1 | grep -E 'Verify return code|verify error'",
				shlexQuote(destHost), destPort, shlexQuote(destHost))})
	}
	if readinessPath != "" {
		url := fmt.Sprintf("%s://%s:%d%s", scheme, destHost, destPort, readinessPath)
		steps = append(steps, Step{ID: "application_readiness", Description: "readiness call to the declared HTTP endpoint/path", Module: "command",
			Command: curlQueryCommand(url, nil)})
	}
	return steps
}

// NetworkPathLayerResult is one layer's evidence — always present for
// every layer NetworkPathSteps() could have produced, even when that
// layer's step didn't run (Configured=false), so a caller can render a
// complete five-layer table without special-casing gaps.
type NetworkPathLayerResult struct {
	Layer      string // name_resolution | routing | transport | tls | application_readiness
	Configured bool
	Passed     bool
	Evidence   string
}

// NetworkPathOutput is pilot_diagnose_network_path's synthesized result.
type NetworkPathOutput struct {
	DestHost string
	DestPort int
	Scheme   string
	Layers   []NetworkPathLayerResult
	Verdict  string // reachable | blocked_at_<layer> | unreachable | insufficient_evidence
	Steps    []StepResult
}

// BuildNetworkPathOutput synthesizes NetworkPathOutput from
// NetworkPathSteps' results, in the exact order NetworkPathSteps
// returned them for the SAME (scheme, readinessPath) inputs.
func BuildNetworkPathOutput(destHost string, destPort int, scheme string, hasTLSStep, hasReadinessStep, reachable bool, results []StepResult) NetworkPathOutput {
	out := NetworkPathOutput{DestHost: destHost, DestPort: destPort, Scheme: scheme, Steps: results}
	if !reachable {
		out.Verdict = "unreachable"
		return out
	}

	find := func(id string) (StepResult, bool) {
		for _, r := range results {
			if r.Step.ID == id {
				return r, true
			}
		}
		return StepResult{}, false
	}
	ok := func(r StepResult) bool { return r.Result.RunErr == nil && !r.Result.Unreachable }

	layer := func(id, name string, configured bool, passed func(rawStdout string) bool) NetworkPathLayerResult {
		res := NetworkPathLayerResult{Layer: name, Configured: configured}
		if !configured {
			return res
		}
		if r, found := find(id); found && ok(r) {
			// passed() gets the RAW stdout — application_readiness's
			// SplitHTTPStatus specifically depends on the literal
			// leading "\n" curlQueryCommand's -w emits before its
			// HTTP_STATUS marker; trimming it first would silently
			// break that match. Evidence (for display) is trimmed
			// separately, after the pass/fail decision is already made.
			res.Passed = passed(r.Result.Stdout)
			res.Evidence = strings.TrimSpace(r.Result.Stdout)
		}
		return res
	}

	out.Layers = []NetworkPathLayerResult{
		layer("name_resolution", "name_resolution", true, func(s string) bool { return s != "" }),
		layer("routing", "routing", true, func(s string) bool { return s != "" && !strings.Contains(s, "unreachable") }),
		layer("transport", "transport", true, func(s string) bool { return strings.TrimSpace(s) == "open" }),
		layer("tls", "tls", hasTLSStep, func(s string) bool {
			return strings.Contains(s, "Verify return code: 0") && !strings.Contains(s, "verify error")
		}),
		layer("application_readiness", "application_readiness", hasReadinessStep, func(s string) bool {
			_, status, split := SplitHTTPStatus(s)
			return split && status >= 200 && status < 300
		}),
	}

	for _, l := range out.Layers {
		if !l.Configured {
			continue
		}
		if !l.Passed && l.Evidence == "" {
			// The step never produced usable evidence (ansible/decode
			// error, not an affirmative "closed"/failed result) — that's
			// a gap in evidence, not confirmed proof this layer blocks
			// the path.
			out.Verdict = "insufficient_evidence"
			return out
		}
		if !l.Passed {
			out.Verdict = "blocked_at_" + l.Layer
			return out
		}
	}
	out.Verdict = "reachable"
	return out
}
