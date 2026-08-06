package diagnose

import "fmt"

// DashboardGroup is the inventory group Loki lives on — contractually
// hostCardinality: exactly-one (contracts/dashboard.yaml). Exported so
// cmd/pilot/cmd/mcp_diagnose_tools.go can resolve it via
// ResolveSingletonGroupHost without a caller-supplied host parameter.
const DashboardGroup = "dashboard"

// lokiPort is Loki's query API port on the dashboard host's own loopback
// — docs/verification/log-shipping.md §1.5's default and
// docs/network-firewall-matrix.md both confirm 3100.
const lokiPort = 3100

// LogsSteps returns the single ad-hoc step that queries Loki's
// query_range LogQL API on the dashboard host's own loopback — the same
// endpoint docs/verification/log-shipping.md's own C6 self-test already
// exercises. start/end/limit/direction are passed through verbatim when
// non-empty and omitted otherwise, letting Loki apply its own defaults
// (last 1h, now, 100, backward) — no range/size cap is imposed here, the
// caller decides.
func LogsSteps(query, start, end, limit, direction string) []Step {
	url := fmt.Sprintf("http://127.0.0.1:%d/loki/api/v1/query_range", lokiPort)
	params := [][2]string{
		{"query", query},
		{"start", start},
		{"end", end},
		{"limit", limit},
		{"direction", direction},
	}
	return []Step{
		{ID: "query", Description: "LogQL query against Loki", Module: "command", Command: curlQueryCommand(url, params)},
	}
}
