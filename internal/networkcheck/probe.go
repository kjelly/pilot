package networkcheck

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// ProbeStatus is the outcome of one edge's connectivity probe.
type ProbeStatus string

const (
	StatusPass                 ProbeStatus = "PASS"
	StatusFail                 ProbeStatus = "FAIL"
	StatusReachableUnconfirmed ProbeStatus = "REACHABLE-UNCONFIRMED"
	StatusSkip                 ProbeStatus = "SKIP"
	StatusError                ProbeStatus = "ERROR"
)

// Result is one edge's probe outcome. See network-connectivity-preflight-plan
// §4.2 for the field list this mirrors (renamed "route" to "hint" — the
// plan's own worked example labels the actionable-info field "hint:", and
// there is no subnet/mask data available to compute an actual route).
type Result struct {
	Edge       Edge
	Status     ProbeStatus
	Detail     string
	ResolvedIP string
	DurationMs int
	Hint       string
}

// AdHocRunner runs one `ansible <host> ...` ad-hoc invocation and returns
// its combined --one-line stdout, exit code, and any error starting the
// process itself (missing binary, context cancellation, ...). Production
// code shells out to the real `ansible` binary; tests inject a fake.
type AdHocRunner func(ctx context.Context, args []string, timeoutSeconds int) (stdout string, exitCode int, err error)

// ProbeOptions controls how Probe executes.
type ProbeOptions struct {
	Inventory string
	Limit     string
	// TimeoutSeconds is the per-socket-probe timeout on the remote host.
	// Defaults to 3 when <= 0.
	TimeoutSeconds int
}

type probeRequest struct {
	Protocol       string `json:"protocol"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	TimeoutSeconds int    `json:"timeoutSeconds"`
}

type probeResponse struct {
	Status     string `json:"status"`
	Detail     string `json:"detail"`
	ResolvedIP string `json:"resolvedIP"`
	DurationMs int    `json:"durationMs"`
}

// Probe executes every edge's connectivity check, one ansible ad-hoc
// `script` invocation per distinct SourceHost (batching that host's edges
// into a single remote round-trip), and returns one Result per input edge
// in the same order. Edges already resolved to TargetSkip by the planner
// never reach the network — they are reported as StatusSkip directly.
func Probe(ctx context.Context, edges []Edge, opts ProbeOptions, run AdHocRunner) ([]Result, error) {
	timeout := opts.TimeoutSeconds
	if timeout <= 0 {
		timeout = 3
	}

	results := make([]Result, len(edges))
	byHost := make(map[string][]int)
	for i, e := range edges {
		if e.TargetKind == TargetSkip {
			results[i] = Result{Edge: e, Status: StatusSkip, Detail: e.SkipReason}
			continue
		}
		byHost[e.SourceHost] = append(byHost[e.SourceHost], i)
	}
	if len(byHost) == 0 {
		return results, nil
	}

	scriptPath, cleanup, err := materializeProbeScript()
	if err != nil {
		return nil, fmt.Errorf("materialize probe script: %w", err)
	}
	defer cleanup()

	hosts := make([]string, 0, len(byHost))
	for host := range byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	for _, host := range hosts {
		indexes := byHost[host]
		requests := make([]probeRequest, len(indexes))
		for i, idx := range indexes {
			e := edges[idx]
			requests[i] = probeRequest{Protocol: e.Protocol, Host: e.TargetHost, Port: e.Port, TimeoutSeconds: timeout}
		}
		payload, err := json.Marshal(requests)
		if err != nil {
			return nil, fmt.Errorf("encode probe request for %s: %w", host, err)
		}
		encoded := base64.StdEncoding.EncodeToString(payload)

		args := []string{host, "-i", opts.Inventory, "-m", "script", "-a", scriptPath + " " + encoded}
		if opts.Limit != "" {
			args = append(args, "-l", opts.Limit)
		}
		adhocTimeout := timeout*len(requests) + 30

		stdout, exitCode, runErr := run(ctx, args, adhocTimeout)
		if runErr != nil {
			applyError(results, indexes, edges, fmt.Sprintf("could not run probe: %v", runErr))
			continue
		}
		payloadOut, envelopeErr := extractScriptModuleStdout(stdout)
		var responses []probeResponse
		if envelopeErr != nil {
			applyError(results, indexes, edges, fmt.Sprintf("ansible exit=%d: %s", exitCode, envelopeErr))
			continue
		}
		if jsonErr := json.Unmarshal([]byte(payloadOut), &responses); jsonErr != nil || len(responses) != len(indexes) {
			detail := "probe did not produce parseable output"
			if exitCode != 0 {
				detail = fmt.Sprintf("ansible exit=%d: %s", exitCode, strings.TrimSpace(stdout))
			}
			applyError(results, indexes, edges, detail)
			continue
		}
		for i, idx := range indexes {
			results[idx] = toResult(edges[idx], responses[i])
		}
	}
	return results, nil
}

func applyError(results []Result, indexes []int, edges []Edge, detail string) {
	for _, idx := range indexes {
		results[idx] = Result{Edge: edges[idx], Status: StatusError, Detail: detail}
	}
}

func toResult(e Edge, r probeResponse) Result {
	res := Result{Edge: e, Detail: r.Detail, ResolvedIP: r.ResolvedIP, DurationMs: r.DurationMs}
	switch r.Status {
	case "reachable":
		res.Status = StatusPass
	case "reachable-unconfirmed":
		res.Status = StatusReachableUnconfirmed
	case "unreachable":
		res.Status = StatusFail
		res.Hint = fmt.Sprintf("check routing/firewall between %s (%s) and %s:%d [%s]",
			e.SourceHost, e.SourceAddr, e.TargetHost, e.Port, e.EndpointName)
	case "error":
		res.Status = StatusError
	default:
		res.Status = StatusError
		res.Detail = fmt.Sprintf("unrecognized probe status %q", r.Status)
	}
	return res
}

// scriptModuleEnvelope is the JSON object ansible ad-hoc prints after
// "<host> | <STATUS> =>" for modules that return structured results (like
// `script`) — as opposed to the deprecated `--one-line`/`(stdout)` text
// format internal/tools/verify_spec.go parses for `command`/`shell`. This
// package never requests --one-line, so it never needs that format.
type scriptModuleEnvelope struct {
	RC     int    `json:"rc"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// extractScriptModuleStdout locates the JSON envelope in combined ansible
// ad-hoc output (skipping any [WARNING]/[DEPRECATION WARNING] lines before
// it) and returns the module's own stdout — our probe script's single JSON
// line. err is non-nil when no envelope could be found at all (unreachable
// host, connection failure, ...) or the script itself exited non-zero.
func extractScriptModuleStdout(s string) (string, error) {
	idx := strings.Index(s, "=>")
	if idx < 0 {
		return "", fmt.Errorf("no ansible result envelope found: %s", strings.TrimSpace(s))
	}
	var envelope scriptModuleEnvelope
	if err := json.NewDecoder(strings.NewReader(s[idx+len("=>"):])).Decode(&envelope); err != nil {
		return "", fmt.Errorf("could not parse ansible result envelope: %w", err)
	}
	if envelope.RC != 0 {
		return "", fmt.Errorf("probe script exited rc=%d: %s", envelope.RC, strings.TrimSpace(envelope.Stderr))
	}
	return strings.TrimSpace(envelope.Stdout), nil
}

func materializeProbeScript() (path string, cleanup func(), err error) {
	f, err := os.CreateTemp("", "pilot-network-check-probe-*.py")
	if err != nil {
		return "", nil, err
	}
	if _, err := f.WriteString(probeScriptSource); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", nil, err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", nil, err
	}
	if err := os.Chmod(f.Name(), 0o700); err != nil {
		os.Remove(f.Name())
		return "", nil, err
	}
	return f.Name(), func() { os.Remove(f.Name()) }, nil
}
