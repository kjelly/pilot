package diagnose

import "strconv"

// SecurityLogsQuery builds the LogQL query pilot_diagnose_security_logs
// runs: always scoped to job="pilot-siem" — by construction this already
// covers nothing but security/audit-relevant events, from either
// log-server's rsyslog (auth/authpriv/local6-auditd) or a co-located
// wazuh-manager's alerts, whichever (or both) this deployment's Promtail
// ships (docs/verification/log-server.md, docs/verification/wazuh-manager.md
// C11's syslog_output forward, playbooks/apply/log-shipping-apply.yml's
// siem_wazuh_manager_container detection — all land under the same fixed
// job label). host and search are both optional, plain-substring line
// filters (LogQL |=, never a regex — free text can't be misread as a
// pattern), chained with AND when both are set. host is deliberately a
// content match, not a path/label match: wazuh's alerts carry the source
// agent's identity inside the JSON line itself, not in a per-host file
// path the way log-server's auth.log/audit.log do, so a content search is
// the one mechanism that finds a host either way — best-effort, not a
// guaranteed precise scope.
func SecurityLogsQuery(host, search string) string {
	query := `{job="pilot-siem"}`
	if host != "" {
		query += " |= " + strconv.Quote(host)
	}
	if search != "" {
		query += " |= " + strconv.Quote(search)
	}
	return query
}

// SecurityLogsSteps composes SecurityLogsQuery(host, search) and defers
// to LogsSteps for the rest — the exact same Loki query_range plumbing
// (dashboard-group loopback curl, HTTP-status capture) pilot_diagnose_logs
// already uses.
func SecurityLogsSteps(host, search, start, end, limit, direction string) []Step {
	return LogsSteps(SecurityLogsQuery(host, search), start, end, limit, direction)
}
