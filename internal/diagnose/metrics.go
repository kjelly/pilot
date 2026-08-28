package diagnose

import "fmt"

// ThanosQueryGroup is the inventory group Thanos Query lives on —
// contractually hostCardinality: exactly-one
// (contracts/thanos-query.yaml). Exported so
// cmd/pilot/cmd/mcp_diagnose_tools.go can resolve it via
// ResolveSingletonGroupHost without a caller-supplied host parameter.
const ThanosQueryGroup = "thanos-query"

// thanosQueryPort is Thanos Query's Prometheus-compatible HTTP API port
// on its own loopback — docs/verification/thanos-query.md v1.1 (the
// 2026-07-17 port fix), docs/network-firewall-matrix.md, and (since the
// detection-engine spec's Stage A-0 fix) contracts/thanos-query.yaml's
// own `endpoints` list all confirm 10912.
const thanosQueryPort = 10912

// MetricsSteps returns the single ad-hoc step that queries Thanos Query's
// Prometheus-compatible HTTP API on its own loopback — the same API
// docs/verification/thanos-query.md's own C9/C10 checks already curl.
// When both start and end are non-empty it runs a range query
// (/api/v1/query_range, with optional step); otherwise an instant query
// (/api/v1/query, with optional evalTime). No range cap is imposed here,
// the caller decides.
func MetricsSteps(query, evalTime, start, end, step string) []Step {
	base := fmt.Sprintf("http://127.0.0.1:%d/api/v1", thanosQueryPort)
	var url string
	var params [][2]string
	if start != "" && end != "" {
		url = base + "/query_range"
		params = [][2]string{{"query", query}, {"start", start}, {"end", end}, {"step", step}}
	} else {
		url = base + "/query"
		params = [][2]string{{"query", query}, {"time", evalTime}}
	}
	return []Step{
		{ID: "query", Description: "PromQL query against Thanos Query", Module: "command", Command: curlQueryCommand(url, params)},
	}
}
