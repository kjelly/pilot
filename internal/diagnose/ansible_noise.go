package diagnose

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/kjelly/pilot/internal/networkcheck"
)

// AnsibleAutomationUsers collects the distinct ansible_user values
// configured across every host in resolved — the SSH identity pilot's own
// ad-hoc diagnose calls and deploy/reconcile playbook runs connect as,
// never a real end-user or service account being investigated. Returns a
// sorted, deduplicated slice (nil if no host sets ansible_user).
func AnsibleAutomationUsers(resolved networkcheck.ResolvedInventory) []string {
	seen := map[string]bool{}
	var users []string
	for _, hv := range resolved.HostVars {
		v, ok := hv["ansible_user"]
		if !ok {
			continue
		}
		user, ok := v.(string)
		if !ok || user == "" || seen[user] {
			continue
		}
		seen[user] = true
		users = append(users, user)
	}
	sort.Strings(users)
	return users
}

// ExcludeAnsibleNoise appends LogQL line filters to query that drop log
// lines pilot's own ansible activity produces, so a query like "who logged
// into host X" isn't polluted by pilot's own ad-hoc/playbook runs against
// that same host:
//
//   - "BECOME-SUCCESS-" is ansible's own become/sudo plugin marker (a
//     hardcoded prefix it echoes to detect a successful privilege
//     escalation), present in the sudo/audit trail for any module ansible
//     executes with become — regardless of ansible_ssh_pipelining, which
//     only affects how the module payload itself is transferred, not the
//     become wrapping.
//   - Each known ansibleUsers entry is pilot's configured SSH login
//     identity for some host in this inventory (ansible_user) — excluded
//     as a plain substring match so it catches both syslog-style
//     "Accepted publickey for <user> from ..." lines and any field in a
//     wazuh JSON alert naming that user, not just one specific log format.
//
// This is a best-effort heuristic, not a scope guarantee: an ansible_user
// value that coincides with a real human account's name (or a log line
// that happens to mention "BECOME-SUCCESS-" for unrelated reasons) would
// also be excluded. Callers that need the unfiltered view should not call
// this.
func ExcludeAnsibleNoise(query string, ansibleUsers []string) string {
	query += ` !~ "BECOME-SUCCESS-"`
	if len(ansibleUsers) == 0 {
		return query
	}
	escaped := make([]string, len(ansibleUsers))
	for i, u := range ansibleUsers {
		escaped[i] = regexp.QuoteMeta(u)
	}
	return query + ` !~ ` + strconv.Quote(strings.Join(escaped, "|"))
}
