package identityreconcile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The pure half of the performance driver of spec §10.2 row P (P2-8): the datasets it creates, the
// statistics it reports, the correctness assertions that every measured run must satisfy and the readers
// of the server-side counters. None of it touches a server or runs pilot, so the unit tests next to it
// (live_perf_logic_unit_test.go) run in CI and show that each assertion fails when the condition it
// guards is broken: a benchmark whose own checks cannot fail measures nothing (AGENTS.md §5.12).

// ---- the datasets ----

// perfPrefix marks every object the benchmark creates, so that a listing by name tells them from the
// lab's own and a clean-up can be verified against the baseline.
const perfPrefix = "p28perf-"

// perfSpec describes one roster of the benchmark: users p28perf-u0001..u<Users> spread over groups
// g000..g<Groups-1>. A user is in two groups, every fifth in a third; every tenth group is a role group
// holding two team groups (the nesting); the groups of category filesystem are non-POSIX. The numbers
// are fixed functions of the indexes, so every run of every scenario builds the same roster.
type perfSpec struct {
	Users, Groups int
	// Shell overrides login_shell for the user with that 1-based index.
	Shell map[int]string
	// Passwords gives the user with that 1-based index password.initial.
	Passwords map[int]string
	// AbsentUsers (1-based) and AbsentGroups (0-based) are declared state: absent, and left out of every membership.
	AbsentUsers, AbsentGroups map[int]bool
	// BigGroup adds one more group, access-p28perf-big, that holds the first BigGroup users.
	BigGroup int
	// Wide gives the sections the identity playbook reads more to do (see perfSections).
	Wide bool
}

func perfUserName(i int) string { return fmt.Sprintf("%su%04d", perfPrefix, i) }

// perfCategory is the category of group g.
func perfCategory(g int) string {
	switch g % 10 {
	case 0:
		return "role"
	case 1, 2:
		return "filesystem"
	case 3:
		return "access"
	}
	return "team"
}

var perfCategoryPrefix = map[string]string{"role": "role-", "filesystem": "data-", "access": "access-", "team": "team-"}

func perfGroupName(g int) string {
	return fmt.Sprintf("%s%sg%03d", perfCategoryPrefix[perfCategory(g)], perfPrefix, g)
}

const perfBigGroup = "access-" + perfPrefix + "big"

// perfUserGroups are the groups (0-based, sorted, distinct) user i belongs to.
func perfUserGroups(i, groups int) []int {
	gs := []int{i % groups, (i*7 + 3) % groups}
	if i%5 == 0 {
		gs = append(gs, (i*13+5)%groups)
	}
	sort.Ints(gs)
	return slices.Compact(gs)
}

// perfNested are the groups role group g holds: the two team groups after it.
func perfNested(g, groups int) []int {
	if perfCategory(g) != "role" {
		return nil
	}
	var out []int
	for _, n := range []int{(g + 4) % groups, (g + 5) % groups} {
		if n != g && perfCategory(n) == "team" {
			out = append(out, n)
		}
	}
	return out
}

// perfShape is what a roster holds, as the plan's §6 asks for the relationship counts.
type perfShape struct {
	Users         int `json:"users"`
	Groups        int `json:"groups"`
	MemberEdges   int `json:"direct_user_memberships"`
	NestedEdges   int `json:"nested_group_memberships"`
	PasswordUsers int `json:"users_with_initial_password"`
	AbsentUsers   int `json:"absent_users,omitempty"`
	AbsentGroups  int `json:"absent_groups,omitempty"`
}

// perfRoster builds the roster of sp, with the sections the identity playbook of a mixed run also
// reads (a host, a host group, an HBAC rule and a sudo rule that name groups of the dataset, never
// its users), and the shape it has.
func perfRoster(sp perfSpec, clientFQDN, clientIP string) (rosterDoc, perfShape) {
	var shape perfShape
	members := make([][]string, sp.Groups)
	var users []any
	for i := 1; i <= sp.Users; i++ {
		name := perfUserName(i)
		if sp.AbsentUsers[i] {
			users = append(users, map[string]any{"name": name, "state": "absent"})
			shape.AbsentUsers++
			continue
		}
		u := map[string]any{"name": name, "first": "P28", "last": fmt.Sprintf("Perf%04d", i), "email": name + "@ipa.pilot.internal"}
		if sh, ok := sp.Shell[i]; ok {
			u["login_shell"] = sh
		}
		if pw, ok := sp.Passwords[i]; ok {
			u["password"] = map[string]any{"initial": pw}
			shape.PasswordUsers++
		}
		users = append(users, u)
		shape.Users++
		for _, g := range perfUserGroups(i, sp.Groups) {
			if !sp.AbsentGroups[g] {
				members[g] = append(members[g], name)
				shape.MemberEdges++
			}
		}
	}
	var groups []any
	for g := 0; g < sp.Groups; g++ {
		name, cat := perfGroupName(g), perfCategory(g)
		if sp.AbsentGroups[g] {
			groups = append(groups, map[string]any{"name": name, "state": "absent", "category": cat})
			shape.AbsentGroups++
			continue
		}
		var nested []string
		for _, n := range perfNested(g, sp.Groups) {
			if !sp.AbsentGroups[n] {
				nested = append(nested, perfGroupName(n))
			}
		}
		shape.NestedEdges += len(nested)
		e := map[string]any{"name": name, "category": cat, "description": "P28 " + name,
			"membership": map[string]any{"users": nonNilList(members[g]), "groups": nonNilList(nested)}}
		if cat == "filesystem" {
			e["type"] = "nonposix"
		}
		groups = append(groups, e)
		shape.Groups++
	}
	if sp.BigGroup > 0 {
		var big []string
		for i := 1; i <= sp.BigGroup && i <= sp.Users; i++ {
			if !sp.AbsentUsers[i] {
				big = append(big, perfUserName(i))
			}
		}
		shape.MemberEdges += len(big)
		groups = append(groups, map[string]any{"name": perfBigGroup, "category": "access", "description": "P28 big group",
			"membership": map[string]any{"users": nonNilList(big), "groups": []string{}}})
		shape.Groups++
	}
	sections := perfSections(sp, clientFQDN, clientIP)
	root := rosterDoc{
		"schema_version": 3,
		"freeipa":        map[string]any{"domain": "ipa.pilot.internal", "server": "ipa1.ipa.pilot.internal", "admin": map[string]any{"principal": "admin"}},
		"users":          users,
		"groups":         groups,
	}
	for k, v := range sections {
		root[k] = v
	}
	return root, shape
}

// perfHostIP is the address of the i-th host of the wide roster: in the client's /24 (FreeIPA wants a reverse zone for a host's
// address and refuses the documentation ranges, "cannot use IANA reserved IP address"), at 200 + i. These are names in the
// server's DNS, not machines.
func perfHostIP(clientIP string, i int) string {
	parts := strings.Split(clientIP, ".")
	if len(parts) != 4 {
		return fmt.Sprintf("198.51.100.%d", 200+i)
	}
	return fmt.Sprintf("%s.%s.%s.%d", parts[0], parts[1], parts[2], 200+i)
}

// perfSections are the sections of the roster that the identity playbook of a mixed run reads and the Go engine only names:
// hosts, host groups, HBAC rules and sudo rules, all of which name groups of the dataset and never its users. The narrow set is one
// host, one host group, two HBAC rules and one sudo rule; Wide adds twenty hosts in eight host groups, twenty HBAC rules
// and twenty-five sudo rules over five command groups, so that the playbook has something of the other sections to do
// (the production roster's counts are not known to this driver: this is a bigger lab roster, not a copy of it).
func perfSections(sp perfSpec, clientFQDN, clientIP string) map[string]any {
	accessGroups, roleGroups := max(sp.Groups/10, 1), max(sp.Groups/10, 1)
	access := func(k int) string { return perfGroupName(3 + 10*(k%accessGroups)) }
	role := func(k int) string { return perfGroupName(10 * (k % roleGroups)) }
	hosts := []any{map[string]any{"name": clientFQDN, "state": "present", "ip_address": clientIP, "description": "P28 client"}}
	hostgroups := []any{map[string]any{"name": perfPrefix + "targets", "state": "present", "description": "P28",
		"membership": map[string]any{"hosts": []string{clientFQDN}, "hostgroups": []string{}}}}
	rules := []any{
		map[string]any{"name": perfPrefix + "ssh", "state": "present", "enabled": true, "subjects": map[string]any{"users": []string{}, "groups": []string{access(0)}},
			"targets": map[string]any{"hosts": []string{}, "hostgroups": []string{perfPrefix + "targets"}}, "services": []string{"sshd", "sudo"}},
		map[string]any{"name": perfPrefix + "admin", "state": "present", "enabled": true, "subjects": map[string]any{"users": []string{"admin"}, "groups": []string{}},
			"targets": map[string]any{"hostcat": "all", "hosts": []string{}, "hostgroups": []string{}}, "services": []string{"sshd"}},
	}
	cmdGroups := []any{map[string]any{"name": perfPrefix + "cmds", "state": "present", "commands": []string{"/usr/bin/true"}}}
	sudoRules := []any{map[string]any{"name": perfPrefix + "sudo", "state": "present", "enabled": true, "subjects": map[string]any{"users": []string{}, "groups": []string{role(0)}},
		"targets": map[string]any{"hostcat": "all", "hosts": []string{}, "hostgroups": []string{}},
		"allow":   map[string]any{"command_groups": []string{perfPrefix + "cmds"}, "commands": []string{}}, "deny": map[string]any{"command_groups": []string{}, "commands": []string{}},
		"run_as": map[string]any{"users": []string{"root"}, "groups": []string{}}, "options": []string{"!authenticate"}}}
	if sp.Wide {
		const nHosts, nHostGroups, nHBAC, nSudo, nCmdGroups = 20, 8, 20, 25, 5
		members := make([][]string, nHostGroups)
		for i := 1; i <= nHosts; i++ {
			name := fmt.Sprintf("%sh%02d.ipa.pilot.internal", perfPrefix, i)
			hosts = append(hosts, map[string]any{"name": name, "state": "present", "ip_address": perfHostIP(clientIP, i), "description": "P28 host"})
			members[i%nHostGroups] = append(members[i%nHostGroups], name)
		}
		for g := 0; g < nHostGroups; g++ {
			hostgroups = append(hostgroups, map[string]any{"name": fmt.Sprintf("%shg%d", perfPrefix, g), "state": "present", "description": "P28",
				"membership": map[string]any{"hosts": members[g], "hostgroups": []string{}}})
		}
		for k := 0; k < nHBAC; k++ {
			rules = append(rules, map[string]any{"name": fmt.Sprintf("%shbac-%02d", perfPrefix, k), "state": "present", "enabled": true,
				"subjects": map[string]any{"users": []string{}, "groups": []string{access(k)}},
				"targets":  map[string]any{"hosts": []string{}, "hostgroups": []string{fmt.Sprintf("%shg%d", perfPrefix, k%nHostGroups)}}, "services": []string{"sshd", "sudo"}})
		}
		for c := 0; c < nCmdGroups; c++ {
			cmdGroups = append(cmdGroups, map[string]any{"name": fmt.Sprintf("%scmds-%d", perfPrefix, c), "state": "present", "commands": []string{"/usr/bin/true", "/usr/bin/id", "/usr/bin/ls"}})
		}
		for k := 0; k < nSudo; k++ {
			sudoRules = append(sudoRules, map[string]any{"name": fmt.Sprintf("%ssudo-%02d", perfPrefix, k), "state": "present", "enabled": true,
				"subjects": map[string]any{"users": []string{}, "groups": []string{role(k)}},
				"targets":  map[string]any{"hosts": []string{}, "hostgroups": []string{fmt.Sprintf("%shg%d", perfPrefix, k%nHostGroups)}},
				"allow":    map[string]any{"command_groups": []string{fmt.Sprintf("%scmds-%d", perfPrefix, k%nCmdGroups)}, "commands": []string{}}, "deny": map[string]any{"command_groups": []string{}, "commands": []string{}},
				"run_as": map[string]any{"users": []string{"root"}, "groups": []string{}}, "options": []string{"!authenticate"}})
		}
	}
	return map[string]any{
		"hosts": hosts, "hostgroups": hostgroups,
		"hbac": map[string]any{"disable_allow_all": true, "services": []any{map[string]any{"name": "sshd", "state": "present"}}, "rules": rules},
		"sudo": map[string]any{"command_groups": cmdGroups, "rules": sudoRules},
	}
}

// ---- statistics ----

// perfStats is the summary of the samples of one scenario. P95 is the nearest-rank percentile (the value
// at rank ceil(0.95 n) of the sorted samples); it is a formal p95 only from 20 samples (plan §6), and the
// report says so rather than calling a smaller sample's maximum a p95.
type perfStats struct {
	N         int     `json:"n"`
	Min       float64 `json:"min"`
	P50       float64 `json:"p50"`
	P95       float64 `json:"p95"`
	Max       float64 `json:"max"`
	Mean      float64 `json:"mean"`
	P95Formal bool    `json:"p95_formal"`
}

// nearestRank is the p-th percentile (1 to 100) of values by the nearest-rank method.
func nearestRank(values []float64, p int) float64 {
	if len(values) == 0 {
		return 0
	}
	s := slices.Clone(values)
	sort.Float64s(s)
	rank := (p*len(s) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	return s[rank-1]
}

func summarize(values []float64) perfStats {
	if len(values) == 0 {
		return perfStats{}
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return perfStats{
		N: len(values), Min: nearestRank(values, 1), P50: nearestRank(values, 50), P95: nearestRank(values, 95),
		Max: nearestRank(values, 100), Mean: sum / float64(len(values)), P95Formal: len(values) >= 20,
	}
}

// ---- one measured run ----

// perfPlaybook is one ansible-playbook process pilot started during a run: which playbook, whether it was a
// check-mode run, and how long it lived (from the first time it was seen to the last, at the poll interval).
type perfPlaybook struct {
	Name    string  `json:"name"`
	Check   bool    `json:"check,omitempty"`
	Seconds float64 `json:"seconds"`
}

// perfBatch is one batch or single call the writer sent, from the run's own journal: how many commands it
// held and how long it took from the event before sending to the event with its answers.
type perfBatch struct {
	Stage   string  `json:"stage"`
	Batch   int     `json:"batch"`
	Ops     int     `json:"operations"`
	Seconds float64 `json:"seconds"`
}

// perfSample is one pilot run of a scenario with everything measured of it.
type perfSample struct {
	Scenario   string  `json:"scenario"`
	Index      int     `json:"index"`
	Kind       string  `json:"kind"` // users-groups, full, legacy, preview
	BatchLimit int     `json:"batch_limit,omitempty"`
	Exit       int     `json:"exit"`
	Verdict    string  `json:"verdict,omitempty"`
	Outcome    string  `json:"outcome,omitempty"`
	Wall       float64 `json:"wall_seconds"`

	// Playbooks are the ansible-playbook processes the run started; EntrySeconds is the sum of the
	// authorization cache entry's (prepare or probe), IdentitySeconds of the identity playbook's.
	Playbooks       []perfPlaybook `json:"playbooks,omitempty"`
	EntrySeconds    float64        `json:"entry_seconds"`
	IdentitySeconds float64        `json:"identity_playbook_seconds"`

	// From the result file (client side). WriteCmds and Reads count batch items one by one.
	HasDoc         bool               `json:"has_result_file"`
	HTTP           int                `json:"http_requests"`
	Reads          int                `json:"reads"`
	WriteCmds      int                `json:"write_commands"`
	Relogins       int                `json:"relogins"`
	ReadRetries    int                `json:"read_retries"`
	PlanOps        int                `json:"plan_operations"`
	PlanKinds      map[string]int     `json:"plan_kinds,omitempty"`
	PlanFields     map[string]int     `json:"plan_fields,omitempty"`
	Outcomes       map[string]int     `json:"outcomes,omitempty"`
	EntryRan       bool               `json:"entry_ran"`
	ProbePending   *bool              `json:"probe_pending,omitempty"`
	VerifyOK       bool               `json:"verify_ok"`
	ObservedUsers  int                `json:"observed_users,omitempty"`
	ObservedGroups int                `json:"observed_groups,omitempty"`
	Batches        []perfBatch        `json:"batches,omitempty"`
	Phases         map[string]float64 `json:"phases,omitempty"`

	// From the server's own logs between the marks taken around the run.
	Server perfServer `json:"server"`

	// The controller's one-minute load average when the run started and ended: the noise of the host the VMs share.
	LoadStart float64 `json:"controller_load_start"`
	LoadEnd   float64 `json:"controller_load_end"`

	JournalBefore string   `json:"journal_before,omitempty"`
	JournalAfter  string   `json:"journal_after,omitempty"`
	Failures      []string `json:"failures,omitempty"`
}

// perfServer is what the server logged of one run, counted without asking pilot.
type perfServer struct {
	// Commands counts the API commands by method (a batch's items one by one, the outer batch line left out).
	Commands      map[string]int `json:"commands,omitempty"`
	WriteN        int            `json:"write_commands"`
	ReadN         int            `json:"read_commands"`
	BatchRequests int            `json:"batch_requests"`
	HTTPPosts     int            `json:"http_posts"`
	Logins        int            `json:"http_logins"`
	// SSH: the sshd's own account (LogLevel VERBOSE): connections accepted, command sessions started over
	// them, and the sessions that rode on a connection another session had already used.
	SSHConnections int `json:"ssh_connections"`
	SSHSessions    int `json:"ssh_sessions"`
	SSHReused      int `json:"ssh_reused_sessions"`
}

// writeMethods are the commands that change the directory; every other command the log shows is a read.
var perfWriteMethods = map[string]bool{
	"user_add": true, "user_mod": true, "user_del": true, "user_enable": true, "user_disable": true, "passwd": true,
	"group_add": true, "group_mod": true, "group_del": true, "group_add_member": true, "group_remove_member": true,
}

// parsePerfServer reads the report of the remote counting script (see perfCountScript): one "key value" per
// line, "cmd <method> <n>" for the commands.
func parsePerfServer(out string) (perfServer, error) {
	s := perfServer{Commands: map[string]int{}}
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.Atoi(f[len(f)-1])
		if err != nil {
			return s, fmt.Errorf("server counters: %q is not a count", line)
		}
		switch {
		case f[0] == "cmd" && len(f) == 3:
			s.Commands[f[1]] += n
			if perfWriteMethods[f[1]] {
				s.WriteN += n
			} else {
				s.ReadN += n
			}
		case f[0] == "batch_requests" && len(f) == 2:
			s.BatchRequests = n
		case f[0] == "http_posts" && len(f) == 2:
			s.HTTPPosts = n
		case f[0] == "http_logins" && len(f) == 2:
			s.Logins = n
		case f[0] == "ssh_connections" && len(f) == 2:
			s.SSHConnections = n
		case f[0] == "ssh_sessions" && len(f) == 2:
			s.SSHSessions = n
		case f[0] == "ssh_reused" && len(f) == 2:
			s.SSHReused = n
		default:
			return s, fmt.Errorf("server counters: unknown line %q", line)
		}
		seen[f[0]] = true
	}
	for _, k := range []string{"batch_requests", "http_posts", "http_logins", "ssh_connections", "ssh_sessions", "ssh_reused"} {
		if !seen[k] {
			return s, fmt.Errorf("server counters: no %s line in %q", k, out)
		}
	}
	return s, nil
}

// perfWrites is the server's write commands by method, the form the arms compare.
func (s perfServer) perfWrites() map[string]int {
	out := map[string]int{}
	for m, n := range s.Commands {
		if perfWriteMethods[m] {
			out[m] = n
		}
	}
	return out
}

// perfCountScript runs on the server with the three offsets (the error log's and the access log's size in
// bytes, the secure log's line count) taken before the run. It counts only what the run caused: commands from
// the API log, round trips from the access log, and from the sshd's log the connections and the command
// sessions, leaving out the connection the script itself runs in (its client port is in SSH_CONNECTION).
const perfCountScript = `set -u
E=$1; A=$2; S=$3
L=${P28_LOG:-/var/log}
own=$(echo "${SSH_CONNECTION:-}" | cut -d' ' -f2)
api=$(mktemp); acc=$(mktemp)
trap 'rm -f "$api" "$acc"' EXIT
tail -c +$((E+1)) "$L/httpd/error_log" | grep -a 'ipa: INFO: ' > "$api" || true
grep -av '\[jsonserver_session\] [^:]*: batch(' "$api" | sed -nE 's/.*ipa: INFO: (\[jsonserver_session\] )?[^ :]+: (batch: )?([a-z_0-9]+)(\/[0-9]+)?\(.*/\3/p' | sort | uniq -c | awk '{print "cmd", $2, $1}'
echo "batch_requests $(grep -ac '\[jsonserver_session\] [^:]*: batch(' "$api")"
tail -c +$((A+1)) "$L/httpd/access_log" > "$acc"
echo "http_posts $(grep -ac 'POST /ipa/session/json' "$acc")"
echo "http_logins $(grep -ac 'POST /ipa/session/login_password' "$acc")"
tail -n +$((S+1)) "$L/secure" | grep -aE 'Accepted publickey|Starting session' | awk -v own="$own" '
/Accepted publickey/ { for (i=1;i<=NF;i++) if ($i=="port") p=$(i+1); if (p!=own) { conn[p]=1; nconn++ } }
/Starting session/ { for (i=1;i<=NF;i++) if ($i=="port") p=$(i+1); if (p!=own) { ses[p]++; nses++ } }
END { reused=0; for (p in ses) if (ses[p]>1) reused+=ses[p]-1; print "ssh_connections", nconn+0; print "ssh_sessions", nses+0; print "ssh_reused", reused }'
`

// ---- the correctness assertions of a measured run ----

// A check returns the reasons a sample does not show what its scenario claims; nil is a pass. They are the
// benchmark's own gates: each has a case that must pass and one that must fail in the unit tests.

// checkWroteNothing: the run changed nothing on the server, by pilot's account and by the server's.
func checkWroteNothing(s perfSample) []string {
	var f []string
	if !s.HasDoc {
		f = append(f, "no result file")
	}
	if s.PlanOps != 0 {
		f = append(f, fmt.Sprintf("the plan holds %d operations, want 0", s.PlanOps))
	}
	if s.WriteCmds != 0 {
		f = append(f, fmt.Sprintf("pilot counted %d write commands, want 0", s.WriteCmds))
	}
	if s.Server.WriteN != 0 {
		f = append(f, fmt.Sprintf("the server logged %d write commands %v, want 0", s.Server.WriteN, s.Server.perfWrites()))
	}
	return f
}

// checkNoDiff: a run on a dataset that is already as the roster says: nothing written, the entry not run,
// the journal as it was, and the exit code the obligation calls for (0 on an acked baseline).
func checkNoDiff(s perfSample, wantExit int) []string {
	f := checkWroteNothing(s)
	if s.EntryRan {
		f = append(f, "the entry ran in a run with nothing to write")
	}
	if s.JournalBefore != s.JournalAfter {
		f = append(f, fmt.Sprintf("the journal changed: %s -> %s", s.JournalBefore, s.JournalAfter))
	}
	if s.Exit != wantExit {
		f = append(f, fmt.Sprintf("exit %d, want %d", s.Exit, wantExit))
	}
	return f
}

// checkOneAttribute: one changed attribute of one user is one user_mod carrying that field, and no other
// write, passwd least of all (plan §6: other users' passwd = 0).
func checkOneAttribute(s perfSample, field string) []string {
	var f []string
	if !s.HasDoc {
		return []string{"no result file"}
	}
	if len(s.PlanKinds) != 1 || s.PlanKinds["user.update"] != 1 {
		f = append(f, fmt.Sprintf("the plan is %v, want exactly one user.update", s.PlanKinds))
	}
	if len(s.PlanFields) != 1 || s.PlanFields[field] != 1 {
		f = append(f, fmt.Sprintf("the user.update carries %v, want only %s", s.PlanFields, field))
	}
	if w := s.Server.perfWrites(); len(w) != 1 || w["user_mod"] != 1 {
		f = append(f, fmt.Sprintf("the server logged writes %v, want exactly one user_mod", w))
	}
	if s.Server.Commands["passwd"] != 0 {
		f = append(f, "a passwd was sent")
	}
	if !s.VerifyOK {
		f = append(f, "the read after the writes is not clean")
	}
	return f
}

// checkCreates: n new users are n user.create operations and n user_add commands at the server, every
// operation applied and the read after the writes clean. The group commands that go with them are not
// counted here: they are what the roster's memberships make.
func checkCreates(s perfSample, n int) []string {
	var f []string
	if !s.HasDoc {
		return []string{"no result file"}
	}
	if s.PlanKinds["user.create"] != n {
		f = append(f, fmt.Sprintf("the plan holds %d user.create, want %d", s.PlanKinds["user.create"], n))
	}
	if s.Server.Commands["user_add"] != n {
		f = append(f, fmt.Sprintf("the server logged %d user_add, want %d", s.Server.Commands["user_add"], n))
	}
	if bad := s.Outcomes["failed"] + s.Outcomes["unknown"] + s.Outcomes["conflict-failed"] + s.Outcomes["not_executed"]; bad != 0 {
		f = append(f, fmt.Sprintf("%d operations did not apply: %v", bad, s.Outcomes))
	}
	if !s.VerifyOK {
		f = append(f, "the read after the writes is not clean")
	}
	return f
}

// checkRerun: the run after a create is a run with nothing to write and no entry (the entry's obligation
// stands from the first run, so it is not the entry that is asked again).
func checkRerun(s perfSample) []string {
	f := checkWroteNothing(s)
	if s.EntryRan {
		f = append(f, "the rerun ran the entry again")
	}
	return f
}

// checkAgree: pilot's own count of what it wrote and the server's agree. A count that only one side
// reports would let a double write or a lost one pass.
func checkAgree(s perfSample) []string {
	if s.WriteCmds != s.Server.WriteN {
		return []string{fmt.Sprintf("pilot counted %d write commands, the server logged %d", s.WriteCmds, s.Server.WriteN)}
	}
	return nil
}

// checkComplete: the read saw every user and group the server has. A read cut short (a truncated find) is an
// error in the engine; this is the independent count from the server that says it was not silently shorter.
func checkComplete(observedUsers, observedGroups, serverUsers, serverGroups, declaredUsers, declaredGroups int) []string {
	var f []string
	if observedUsers != serverUsers {
		f = append(f, fmt.Sprintf("the read saw %d users, the server holds %d", observedUsers, serverUsers))
	}
	if observedGroups != serverGroups {
		f = append(f, fmt.Sprintf("the read saw %d groups, the server holds %d", observedGroups, serverGroups))
	}
	if observedUsers < declaredUsers || observedGroups < declaredGroups {
		f = append(f, fmt.Sprintf("the read saw %d users and %d groups, fewer than the roster's %d and %d", observedUsers, observedGroups, declaredUsers, declaredGroups))
	}
	return f
}

// checkDeletedExactly: after a run that declared some objects absent, the names the server holds are the
// names it held before minus exactly those: nothing else went, and each of them did.
func checkDeletedExactly(before, after, deleted []string) []string {
	want := map[string]bool{}
	for _, n := range before {
		want[n] = true
	}
	var f []string
	for _, n := range deleted {
		if !want[n] {
			f = append(f, fmt.Sprintf("%s was declared absent but the server did not hold it before the run", n))
		}
		delete(want, n)
	}
	got := map[string]bool{}
	for _, n := range after {
		got[n] = true
	}
	for n := range want {
		if !got[n] {
			f = append(f, fmt.Sprintf("%s was deleted and was not declared absent", n))
		}
	}
	for n := range got {
		if !want[n] {
			f = append(f, fmt.Sprintf("%s is on the server after the run and was not before it (or was declared absent and is still there)", n))
		}
	}
	sort.Strings(f)
	return f
}

// ---- the processes and events of a run ----

// playbookFlagsWithValue are the ansible-playbook options that take the next argument as their value: an inventory, an
// extra-vars file or a limit ends in .yml or .yaml too, and none of them is the playbook.
var playbookFlagsWithValue = map[string]bool{
	"-i": true, "--inventory": true, "-e": true, "--extra-vars": true, "-l": true, "--limit": true, "-t": true, "--tags": true,
	"--skip-tags": true, "-u": true, "--user": true, "-f": true, "--forks": true, "--private-key": true, "--key-file": true,
	"-c": true, "--connection": true, "-T": true, "--timeout": true,
}

// classifyPlaybook says which playbook an argv runs and whether it was a check-mode run: the playbook is the first argument
// after ansible-playbook that is not an option or an option's value and names a .yml or .yaml file.
func classifyPlaybook(args []string) (name string, check, ok bool) {
	at := -1
	for i, a := range args {
		if strings.HasSuffix(a, "ansible-playbook") {
			at = i
			break
		}
	}
	if at < 0 {
		return "", false, false
	}
	skip := false
	for _, a := range args[at+1:] {
		switch {
		case skip:
			skip = false
		case a == "--check" || a == "-C":
			check = true
		case playbookFlagsWithValue[a]:
			skip = true
		case strings.HasPrefix(a, "-") || strings.HasPrefix(a, "@"):
		case name == "" && (strings.HasSuffix(a, ".yml") || strings.HasSuffix(a, ".yaml")):
			name = strings.TrimSuffix(strings.TrimSuffix(filepath.Base(a), ".yml"), ".yaml")
		}
	}
	return name, check, name != ""
}

type perfEvent struct {
	ID      int64
	Type    string
	Op      string
	At      time.Time
	Payload string
}

// summarizeEvents reads the journal events of a run: every batch or call the writer sent (from the event before it
// to the event with its answers) and the instants of the run's phases, in seconds from the process start.
func summarizeEvents(evs []perfEvent, start time.Time) ([]perfBatch, map[string]float64) {
	phases := map[string]float64{}
	sent := map[string]perfEvent{}
	var batches []perfBatch
	rel := func(t time.Time) float64 { return t.Sub(start).Seconds() }
	for i, e := range evs {
		if i == 0 {
			phases["first_event"] = rel(e.At)
		}
		phases["last_event"] = rel(e.At)
		switch e.Type {
		case EventAuthCache:
			phases["entry_recorded"] = rel(e.At)
		case EventVerify:
			phases["verify_recorded"] = rel(e.At)
		case EventOp:
			var p struct {
				Phase      string            `json:"phase"`
				Stage      string            `json:"stage"`
				Batch      int               `json:"batch"`
				Operations []json.RawMessage `json:"operations"`
				Results    []json.RawMessage `json:"results"`
			}
			if json.Unmarshal([]byte(e.Payload), &p) != nil {
				continue
			}
			key := fmt.Sprintf("%s/%d", p.Stage, p.Batch)
			switch p.Phase {
			case "sending":
				sent[key] = e
				if _, ok := phases["first_write_sent"]; !ok {
					phases["first_write_sent"] = rel(e.At)
				}
			case "result":
				if s, ok := sent[key]; ok {
					batches = append(batches, perfBatch{Stage: p.Stage, Batch: p.Batch, Ops: len(p.Results), Seconds: e.At.Sub(s.At).Seconds()})
				}
				phases["last_write_answered"] = rel(e.At)
			}
		}
	}
	return batches, phases
}

// ---- passwords and shells of a dataset ----

func passwordsFor(from, to int) map[int]string {
	out := map[int]string{}
	for i := from; i <= to; i++ {
		out[i] = randomPassword()
	}
	return out
}

func shellFor(from, to int, shell string) map[int]string {
	out := map[int]string{}
	for i := from; i <= to; i++ {
		out[i] = shell
	}
	return out
}

// ---- where a playbook's time goes: the profile_tasks recap ----

// perfTaskTime is one line of the profile_tasks callback's recap: a task and the seconds it took in all.
type perfTaskTime struct {
	Task    string  `json:"task"`
	Seconds float64 `json:"seconds"`
}

// profileLine is a recap line of the profile_tasks callback: the task's name, a run of dashes, and the time.
var profileLine = regexp.MustCompile(`^(.+?) -{3,} ([0-9]+\.[0-9]+)s$`)

// parseProfileTasks reads the recap the profile_tasks callback prints after the PLAY RECAP: one "name ---- 12.34s" line per
// task, longest first. Anything else in the output is not a task line.
func parseProfileTasks(out string) []perfTaskTime {
	var tasks []perfTaskTime
	for _, line := range strings.Split(out, "\n") {
		if m := profileLine.FindStringSubmatch(strings.TrimRight(line, " \r")); m != nil {
			sec, err := strconv.ParseFloat(m[2], 64)
			if err == nil {
				tasks = append(tasks, perfTaskTime{Task: strings.TrimSpace(m[1]), Seconds: sec})
			}
		}
	}
	return tasks
}

// profileBuckets sort the tasks of the identity playbook by what the task's own name says it is about; the first bucket
// whose word the name holds takes it, so "Attach hosts to sudo rules" is sudo and "Remove stale hostgroup host memberships"
// is host groups. It is a reading of the names, not of the playbook's structure: the sections are named, not tagged, in the
// recap, and the report says so.
var profileBuckets = []struct {
	name  string
	words []string
}{
	{"sudo", []string{"sudo"}},
	{"hbac", []string{"hbac"}},
	{"netgroups", []string{"netgroup"}},
	{"hostgroups", []string{"hostgroup"}},
	{"hosts", []string{"host"}},
	{"ssh-key-and-authorization-cache", []string{"ssh", "cache"}},
	{"passwords", []string{"password"}},
	{"users", []string{"user"}},
	{"groups", []string{"group"}},
	{"kerberos", []string{"kerberos", "kinit"}},
}

// bucketProfile is the seconds of the profiled tasks by bucket; what no bucket takes is "other" (gates, loading and
// normalizing the roster, reads for the other sections).
func bucketProfile(tasks []perfTaskTime) map[string]float64 {
	out := map[string]float64{}
next:
	for _, t := range tasks {
		name := strings.ToLower(t.Task)
		for _, b := range profileBuckets {
			for _, w := range b.words {
				if strings.Contains(name, w) {
					out[b.name] += t.Seconds
					continue next
				}
			}
		}
		out["other"] += t.Seconds
	}
	return out
}
