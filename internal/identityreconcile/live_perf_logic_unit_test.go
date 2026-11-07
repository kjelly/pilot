package identityreconcile

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/inventory"
)

// Unit tests of the pure half of the performance driver (live_perf_logic_test.go). They run in CI, touch no server, and give
// every assertion of a measured run a case that must pass and a case that must fail: the benchmark's gates are only
// worth their numbers if they can fail.

func perfSpecs() map[string]perfSpec {
	return map[string]perfSpec{
		"d120":         {Users: 120, Groups: 40},
		"d120+100":     {Users: 220, Groups: 40},
		"d120wide":     {Users: 120, Groups: 40, Wide: true},
		"d120wide+100": {Users: 220, Groups: 40, Wide: true},
		"d250":         {Users: 250, Groups: 50},
		"d1000":        {Users: 1000, Groups: 200},
		"d1000+big":    {Users: 1000, Groups: 200, BigGroup: 500},
		"d1000+big-1":  {Users: 1000, Groups: 200, BigGroup: 499},
		"passwords":    {Users: 220, Groups: 40, Passwords: passwordsFor(121, 220)},
		"shell":        {Users: 120, Groups: 40, Shell: map[int]string{17: "/bin/sh"}},
		"absent":       {Users: 1000, Groups: 200, AbsentUsers: map[int]bool{998: true, 999: true, 1000: true}, AbsentGroups: map[int]bool{199: true}},
	}
}

func rosterRoot(t *testing.T, r rosterDoc) map[string]any {
	t.Helper()
	var root map[string]any
	if err := yaml.Unmarshal(r.yaml(), &root); err != nil {
		t.Fatal(err)
	}
	return root
}

// Every roster the benchmark writes is one the real validator and the real adapter accept, and the plan from nothing is
// the creates the scenarios count on: this is what keeps "100 creates" and "120/40" honest.
func TestPerfRostersAreAcceptedByTheEngine(t *testing.T) {
	for name, sp := range perfSpecs() {
		t.Run(name, func(t *testing.T) {
			roster, shape := perfRoster(sp, "client.ipa.pilot.internal", "192.0.2.10")
			root := rosterRoot(t, roster)
			if v := inventory.ValidateRoster(root); len(v) != 0 {
				t.Fatalf("the validator refuses the roster: %s: %s", v[0].Rule, v[0].Detail)
			}
			d, err := FromRosterWithForms(root, roster.yaml())
			if err != nil {
				t.Fatalf("the adapter refuses the roster: %v", err)
			}
			plan := Build(d, nil, nil)
			if len(plan.Blocked) != 0 {
				t.Fatalf("the plan from an empty server blocks %d objects, the first %v", len(plan.Blocked), plan.Blocked[0])
			}
			kinds := map[string]int{}
			for _, op := range plan.Operations {
				kinds[op.Kind]++
			}
			if kinds[KindUserCreate] != shape.Users || kinds[KindGroupCreate] != shape.Groups || kinds[KindMarkerCreate] != shape.Groups {
				t.Errorf("the plan creates %d users, %d groups, %d markers; the shape says %d users and %d groups: %v", kinds[KindUserCreate], kinds[KindGroupCreate], kinds[KindMarkerCreate], shape.Users, shape.Groups, kinds)
			}
			if kinds[KindPasswordInitialize] != shape.PasswordUsers {
				t.Errorf("the plan initializes %d passwords, the shape says %d", kinds[KindPasswordInitialize], shape.PasswordUsers)
			}
			if shape.Users+shape.AbsentUsers != sp.Users {
				t.Errorf("%d users and %d absent do not add up to %d", shape.Users, shape.AbsentUsers, sp.Users)
			}
		})
	}
}

// The shape counts are the roster's own lists, no user is in a group that is absent, no group nests anything but a team group,
// and the same spec gives the same bytes every time (the samples of a scenario all see one roster).
func TestPerfRosterShapeAndDeterminism(t *testing.T) {
	for name, sp := range perfSpecs() {
		t.Run(name, func(t *testing.T) {
			a, shape := perfRoster(sp, "c.ipa.pilot.internal", "192.0.2.10")
			b, _ := perfRoster(sp, "c.ipa.pilot.internal", "192.0.2.10")
			if string(a.yaml()) != string(b.yaml()) {
				t.Fatal("the same spec gave two rosters")
			}
			root := rosterRoot(t, a)
			users := map[string]bool{}
			for _, u := range root["users"].([]any) {
				m := u.(map[string]any)
				if m["state"] != "absent" {
					users[m["name"].(string)] = true
				}
			}
			groups := map[string]string{}
			for _, g := range root["groups"].([]any) {
				m := g.(map[string]any)
				if m["state"] != "absent" {
					groups[m["name"].(string)] = m["category"].(string)
				}
			}
			edges, nested := 0, 0
			for _, g := range root["groups"].([]any) {
				m := g.(map[string]any)
				if m["state"] == "absent" {
					continue
				}
				mem := m["membership"].(map[string]any)
				for _, u := range mem["users"].([]any) {
					if !users[u.(string)] {
						t.Fatalf("%s holds %s, which is not a present user", m["name"], u)
					}
					edges++
				}
				for _, n := range mem["groups"].([]any) {
					if groups[n.(string)] != "team" || m["category"] != "role" {
						t.Fatalf("%s nests %s (%s): only a role group holds team groups", m["name"], n, groups[n.(string)])
					}
					nested++
				}
			}
			if edges != shape.MemberEdges || nested != shape.NestedEdges || len(users) != shape.Users || len(groups) != shape.Groups {
				t.Errorf("counted %d users, %d groups, %d memberships, %d nested; the shape says %+v", len(users), len(groups), edges, nested, shape)
			}
		})
	}
	// A hundred users added to the 120 leave the first 120 as they were: the rosters of d120 and d120+100 differ only by new users and their memberships.
	small, _ := perfRoster(perfSpec{Users: 120, Groups: 40}, "c.ipa.pilot.internal", "192.0.2.10")
	large, _ := perfRoster(perfSpec{Users: 220, Groups: 40}, "c.ipa.pilot.internal", "192.0.2.10")
	su, lu := small["users"].([]any), large["users"].([]any)
	if len(lu)-len(su) != 100 {
		t.Fatalf("the larger roster holds %d more users, want 100", len(lu)-len(su))
	}
	for i := range su {
		x, _ := json.Marshal(su[i])
		y, _ := json.Marshal(lu[i])
		if string(x) != string(y) {
			t.Fatalf("user %d differs between the two rosters", i+1)
		}
	}
}

func TestPerfStats(t *testing.T) {
	var v []float64
	for i := 20; i >= 1; i-- { // descending: the order of the samples is not the order of the ranks
		v = append(v, float64(i))
	}
	s := summarize(v)
	if s.N != 20 || s.Min != 1 || s.P50 != 10 || s.P95 != 19 || s.Max != 20 || !s.P95Formal || s.Mean != 10.5 {
		t.Errorf("20 samples: %+v", s)
	}
	if s := summarize(v[:19]); s.P95Formal || s.N != 19 {
		t.Errorf("19 samples are called a formal p95: %+v", s)
	}
	var hundred []float64
	for i := 1; i <= 100; i++ {
		hundred = append(hundred, float64(i))
	}
	if got := nearestRank(hundred, 95); got != 95 {
		t.Errorf("p95 of 1..100 = %v, want 95", got)
	}
	// Nearest rank rounds the rank up: of nineteen samples the p95 is the nineteenth, the median the tenth.
	if got := nearestRank(v[:19], 95); got != 20 { // v[:19] is 20 down to 2
		t.Errorf("p95 of 2..20 = %v, want 20 (rank 19 of 19)", got)
	}
	if got := nearestRank(v[:19], 50); got != 11 {
		t.Errorf("p50 of 2..20 = %v, want 11 (rank 10 of 19)", got)
	}
	if got := nearestRank([]float64{7}, 95); got != 7 {
		t.Errorf("p95 of one sample = %v", got)
	}
	if got := summarize(nil); got.N != 0 {
		t.Errorf("no samples: %+v", got)
	}
	// A p95 is not the maximum: one slow sample of twenty does not move it.
	slow := append(slices20(1), 100)
	if got := nearestRank(slow[:20], 95); got != 1 {
		t.Errorf("one outlier in twenty moved the p95 to %v", got)
	}
}

func slices20(v float64) []float64 {
	out := make([]float64, 19)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestParsePerfServer(t *testing.T) {
	good := "cmd user_add 100\ncmd group_add_member 12\ncmd user_find 2\ncmd group_find 1\nbatch_requests 9\nhttp_posts 14\nhttp_logins 1\nssh_connections 3\nssh_sessions 7\nssh_reused 4\n"
	s, err := parsePerfServer(good)
	if err != nil {
		t.Fatal(err)
	}
	if s.WriteN != 112 || s.ReadN != 3 || s.BatchRequests != 9 || s.HTTPPosts != 14 || s.Logins != 1 || s.SSHConnections != 3 || s.SSHSessions != 7 || s.SSHReused != 4 {
		t.Errorf("parsed %+v", s)
	}
	if w := s.perfWrites(); len(w) != 2 || w["user_add"] != 100 || w["group_add_member"] != 12 {
		t.Errorf("writes %v", w)
	}
	for name, bad := range map[string]string{
		"a missing counter":            strings.Replace(good, "http_logins 1\n", "", 1),
		"a count that is not a number": strings.Replace(good, "ssh_reused 4", "ssh_reused many", 1),
		"a line it does not know":      good + "surprise 1\n",
	} {
		if _, err := parsePerfServer(bad); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The counting script is run for real (bash, awk, sed) on logs of the shapes the lab's server writes, so the readers of the three
// logs are tested where they are used. The lines are copied from that server: the API log (a read, a batched write and the
// outer batch line), the access log and the sshd's VERBOSE lines of a connection that carried three command sessions.
func TestPerfCountScriptReadsTheRealLogShapes(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "httpd"), 0o755); err != nil {
		t.Fatal(err)
	}
	api := strings.Join([]string{
		`[Sat Nov 07 09:43:03.750687 2026] [:warn] [pid 2971:tid 3022] [client 192.168.122.3:46320] failed to set perms (3140) on file (/run/ipa/ccaches/x)!, referer: https://ipa1/ipa/xml`,
		`[Sat Nov 07 09:43:04.022152 2026] [wsgi:error] [pid 1224:tid 1615] [remote 192.168.122.3:46320] ipa: INFO: [jsonserver_session] admin@IPA.PILOT.INTERNAL: hostgroup_find/1(None, sizelimit=0, version='2.257', pkey_only=True): SUCCESS`,
		`[Sat Nov 07 09:55:12.100000 2026] [wsgi:error] [pid 1225:tid 1609] [remote 127.0.0.1:45072] ipa: INFO: [jsonserver_session] admin@IPA.PILOT.INTERNAL: user_find(None, timelimit=0, sizelimit=0, all=True, version='2.257'): SUCCESS`,
		`[Sat Nov 07 09:55:14.801652 2026] [wsgi:error] [pid 1225:tid 1609] [remote 127.0.0.1:45072] ipa: INFO: admin@IPA.PILOT.INTERNAL: batch: user_add('p28perf-u0001', givenname='P28', sn='Perf0001', homedirectory='/home/p28perf-u0001', loginshell='/bin/bash', mail='p28perf-u0001@ipa.pilot.internal', version='2.257'): SUCCESS`,
		`[Sat Nov 07 09:55:14.900000 2026] [wsgi:error] [pid 1225:tid 1609] [remote 127.0.0.1:45072] ipa: INFO: admin@IPA.PILOT.INTERNAL: batch: user_add('p28perf-u0002', givenname='P28', sn='Perf0002', homedirectory='/home/p28perf-u0002', loginshell='/bin/bash', mail='p28perf-u0002@ipa.pilot.internal', version='2.257'): SUCCESS`,
		`[Sat Nov 07 09:55:17.479321 2026] [wsgi:error] [pid 1225:tid 1609] [remote 127.0.0.1:45072] ipa: INFO: [jsonserver_session] admin@IPA.PILOT.INTERNAL: batch(user_add('p28perf-u0001', givenname='P28', sn='Perf0001', homedirectory='/home/p28perf-u0001', loginshell='/bin/bash', mail='p28perf-u0001@ipa.pilot.internal', version='2.257'), user_add('p28perf-u0002', givenname='P28', sn='Perf0002', homedirectory='/home/p28perf-u0002', loginshell='/bin/bash', mail='p28perf-u0002@ipa.pilot.internal', version='2.257'), version='2.257'): SUCCESS`,
		`[Sat Nov 07 09:55:26.351720 2026] [wsgi:error] [pid 1226:tid 1612] [remote 127.0.0.1:45072] ipa: INFO: admin@IPA.PILOT.INTERNAL: batch: group_add_member('data-p28perf-g001', version='2.257', user=('p28perf-u0001', 'p28perf-u0034')): SUCCESS`,
		`[Sat Nov 07 09:55:27.881926 2026] [wsgi:error] [pid 1226:tid 1612] [remote 127.0.0.1:45072] ipa: INFO: [jsonserver_session] admin@IPA.PILOT.INTERNAL: batch(group_add_member('data-p28perf-g001', version='2.257', user=('p28perf-u0001', 'p28perf-u0034')), version='2.257'): SUCCESS`,
		`[Sat Nov 07 09:55:28.000000 2026] [wsgi:error] [pid 1226:tid 1612] [remote 127.0.0.1:45072] ipa: INFO: [jsonserver_session] admin@IPA.PILOT.INTERNAL: passwd/1('p28perf-u0001', version='2.257'): SUCCESS`,
		`[Sat Nov 07 09:55:29.000000 2026] [wsgi:error] [pid 1226:tid 1612] [remote 127.0.0.1:45072] ipa: INFO: [jsonserver_session] admin@IPA.PILOT.INTERNAL: session_logout(version='2.257'): SUCCESS`,
	}, "\n") + "\n"
	access := strings.Join([]string{
		`192.168.122.3 - - [07/Nov/2026:09:43:02 +0000] "POST /ipa/session/login_password HTTP/1.1" 200 79`,
		`192.168.122.3 - admin@IPA.PILOT.INTERNAL [07/Nov/2026:09:43:03 +0000] "POST /ipa/session/json HTTP/1.1" 200 264`,
		`192.168.122.3 - admin@IPA.PILOT.INTERNAL [07/Nov/2026:09:43:04 +0000] "POST /ipa/session/json HTTP/1.1" 200 334`,
		`192.168.122.3 - admin@IPA.PILOT.INTERNAL [07/Nov/2026:09:43:04 +0000] "GET /ipa/ui/ HTTP/1.1" 200 167`,
	}, "\n") + "\n"
	secure := strings.Join([]string{
		`Nov  7 09:44:41 ipa1 sshd-session[7968]: Connection from 192.168.122.1 port 39162 on 192.168.122.3 port 22 rdomain ""`,
		`Nov  7 09:44:41 ipa1 sshd-session[7968]: Accepted key ED25519 SHA256:abc found at /root/.ssh/authorized_keys:1`,
		`Nov  7 09:44:41 ipa1 sshd-session[7968]: Accepted publickey for root from 192.168.122.1 port 39162 ssh2: ED25519 SHA256:abc`,
		`Nov  7 09:44:41 ipa1 sshd-session[7971]: Starting session: command for root from 192.168.122.1 port 39162 id 0`,
		`Nov  7 09:44:41 ipa1 sshd-session[7971]: Close session: user root from 192.168.122.1 port 39162 id 0`,
		`Nov  7 09:44:41 ipa1 sshd-session[7971]: Starting session: command for root from 192.168.122.1 port 39162 id 0`,
		`Nov  7 09:44:41 ipa1 sshd-session[7971]: Starting session: command for root from 192.168.122.1 port 39162 id 0`,
		`Nov  7 09:44:42 ipa1 sshd-session[8053]: Accepted publickey for root from 192.168.122.1 port 47476 ssh2: ED25519 SHA256:abc`,
		`Nov  7 09:44:42 ipa1 sshd-session[8056]: Starting session: command for root from 192.168.122.1 port 47476 id 0`,
		`Nov  7 09:44:43 ipa1 sshd-session[8060]: Accepted publickey for root from 192.168.122.1 port 47480 ssh2: ED25519 SHA256:abc`,
		`Nov  7 09:44:43 ipa1 sshd-session[8061]: Starting session: command for root from 192.168.122.1 port 47480 id 0`,
	}, "\n") + "\n"
	for name, content := range map[string]string{"httpd/error_log": api, "httpd/access_log": access, "secure": secure} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	count := func(e, a, s int, own string) perfServer {
		t.Helper()
		cmd := exec.Command("bash", "-s", "--", fmt.Sprint(e), fmt.Sprint(a), fmt.Sprint(s))
		cmd.Stdin = strings.NewReader(perfCountScript)
		cmd.Env = append(os.Environ(), "P28_LOG="+dir, "SSH_CONNECTION=192.168.122.1 "+own+" 192.168.122.3 22")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("the script: %v\n%s", err, out)
		}
		got, err := parsePerfServer(string(out))
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return got
	}
	// From the start of the logs, the third connection being the one the script runs in.
	got := count(0, 0, 0, "47480")
	if got.Commands["user_add"] != 2 || got.Commands["group_add_member"] != 1 || got.Commands["hostgroup_find"] != 1 || got.Commands["user_find"] != 1 || got.Commands["passwd"] != 1 || got.Commands["batch"] != 0 {
		t.Errorf("commands %v: a batched item counts once (its line has no jsonserver_session tag), the outer batch line not at all, a /1 version suffix is dropped", got.Commands)
	}
	if got.WriteN != 4 || got.ReadN != 3 || got.BatchRequests != 2 || got.HTTPPosts != 2 || got.Logins != 1 {
		t.Errorf("counts %+v", got)
	}
	// Two connections besides the script's own; the first carried three sessions (two reused), the second one.
	if got.SSHConnections != 2 || got.SSHSessions != 4 || got.SSHReused != 2 {
		t.Errorf("ssh counts %+v, want 2 connections, 4 sessions, 2 reused", got)
	}
	// Only what follows the offsets counts: past the whole of every log nothing is left.
	rest := count(len(api), len(access), strings.Count(secure, "\n"), "47480")
	if rest.WriteN != 0 || rest.ReadN != 0 || rest.HTTPPosts != 0 || rest.SSHConnections != 0 || rest.SSHSessions != 0 {
		t.Errorf("counted past the offsets: %+v", rest)
	}
}

// ---- the checks: each passes a good sample and fails the broken ones ----

func goodNoDiff() perfSample {
	return perfSample{HasDoc: true, Exit: 0, JournalBefore: "pending=false/ab", JournalAfter: "pending=false/ab"}
}

func goodAttr() perfSample {
	return perfSample{HasDoc: true, PlanOps: 1, PlanKinds: map[string]int{"user.update": 1}, PlanFields: map[string]int{"loginshell": 1}, VerifyOK: true,
		WriteCmds: 1, Server: perfServer{Commands: map[string]int{"user_mod": 1}, WriteN: 1}}
}

func goodCreates(n int) perfSample {
	return perfSample{HasDoc: true, PlanOps: n + 8, PlanKinds: map[string]int{"user.create": n, "group.member_user.add": 8}, VerifyOK: true,
		Outcomes: map[string]int{"success": n + 8}, WriteCmds: n + 8, Server: perfServer{Commands: map[string]int{"user_add": n, "group_add_member": 8}, WriteN: n + 8}}
}

func TestPerfChecksFireOnTheirConditions(t *testing.T) {
	type tc struct {
		name   string
		sample func() perfSample
		check  func(perfSample) []string
		fail   bool   // the check must report something
		want   string // and say this
	}
	mut := func(f func(s *perfSample)) func() perfSample {
		return func() perfSample { s := goodNoDiff(); f(&s); return s }
	}
	mutAttr := func(f func(s *perfSample)) func() perfSample {
		return func() perfSample { s := goodAttr(); f(&s); return s }
	}
	mutCreate := func(f func(s *perfSample)) func() perfSample {
		return func() perfSample { s := goodCreates(100); f(&s); return s }
	}
	noDiff := func(s perfSample) []string { return checkNoDiff(s, 0) }
	oneShell := func(s perfSample) []string { return checkOneAttribute(s, "loginshell") }
	hundred := func(s perfSample) []string { return checkCreates(s, 100) }
	tests := []tc{
		{"no diff: a clean run", goodNoDiff, noDiff, false, ""},
		{"no diff: no result file", mut(func(s *perfSample) { s.HasDoc = false }), noDiff, true, "no result file"},
		{"no diff: the plan is not empty", mut(func(s *perfSample) { s.PlanOps = 3 }), noDiff, true, "the plan holds 3 operations"},
		{"no diff: pilot sent a write", mut(func(s *perfSample) { s.WriteCmds = 1 }), noDiff, true, "pilot counted 1 write"},
		{"no diff: the server logged a write pilot did not count", mut(func(s *perfSample) { s.Server.WriteN = 2; s.Server.Commands = map[string]int{"user_mod": 2} }), noDiff, true, "the server logged 2 write"},
		{"no diff: the entry ran", mut(func(s *perfSample) { s.EntryRan = true }), noDiff, true, "the entry ran"},
		{"no diff: the journal changed", mut(func(s *perfSample) { s.JournalAfter = "pending=true/cd" }), noDiff, true, "the journal changed"},
		{"no diff: the wrong exit code", mut(func(s *perfSample) { s.Exit = 4 }), noDiff, true, "exit 4, want 0"},

		{"one attribute: the good run", goodAttr, oneShell, false, ""},
		{"one attribute: two operations", mutAttr(func(s *perfSample) { s.PlanKinds = map[string]int{"user.update": 2} }), oneShell, true, "exactly one user.update"},
		{"one attribute: another kind of operation", mutAttr(func(s *perfSample) { s.PlanKinds = map[string]int{"user.update": 1, "user.disable": 1} }), oneShell, true, "exactly one user.update"},
		{"one attribute: two fields", mutAttr(func(s *perfSample) { s.PlanFields = map[string]int{"loginshell": 1, "givenname": 1} }), oneShell, true, "want only loginshell"},
		{"one attribute: the wrong field", mutAttr(func(s *perfSample) { s.PlanFields = map[string]int{"givenname": 1} }), oneShell, true, "want only loginshell"},
		{"one attribute: the server saw two writes", mutAttr(func(s *perfSample) { s.Server.Commands = map[string]int{"user_mod": 2} }), oneShell, true, "exactly one user_mod"},
		{"one attribute: a passwd went out", mutAttr(func(s *perfSample) { s.Server.Commands = map[string]int{"user_mod": 1, "passwd": 1} }), oneShell, true, "a passwd was sent"},
		{"one attribute: the read after is not clean", mutAttr(func(s *perfSample) { s.VerifyOK = false }), oneShell, true, "not clean"},

		{"creates: the good run", func() perfSample { return goodCreates(100) }, hundred, false, ""},
		{"creates: a user missing from the plan", mutCreate(func(s *perfSample) { s.PlanKinds["user.create"] = 99 }), hundred, true, "99 user.create"},
		{"creates: a user too many in the plan", mutCreate(func(s *perfSample) { s.PlanKinds["user.create"] = 101 }), hundred, true, "101 user.create"},
		{"creates: a user_add short at the server", mutCreate(func(s *perfSample) { s.Server.Commands["user_add"] = 99 }), hundred, true, "99 user_add"},
		{"creates: a duplicate user_add at the server", mutCreate(func(s *perfSample) { s.Server.Commands["user_add"] = 101 }), hundred, true, "101 user_add"},
		{"creates: an operation failed", mutCreate(func(s *perfSample) { s.Outcomes = map[string]int{"success": 107, "failed": 1} }), hundred, true, "did not apply"},
		{"creates: an operation unknown", mutCreate(func(s *perfSample) { s.Outcomes = map[string]int{"success": 107, "unknown": 1} }), hundred, true, "did not apply"},
		{"creates: an operation not executed", mutCreate(func(s *perfSample) { s.Outcomes = map[string]int{"success": 100, "not_executed": 8} }), hundred, true, "did not apply"},
		{"creates: the read after is not clean", mutCreate(func(s *perfSample) { s.VerifyOK = false }), hundred, true, "not clean"},

		{"rerun: nothing written", func() perfSample { s := goodNoDiff(); s.Exit = 4; return s }, checkRerun, false, ""},
		{"rerun: it wrote again", func() perfSample { s := goodNoDiff(); s.WriteCmds = 5; s.Server.WriteN = 5; return s }, checkRerun, true, "pilot counted 5"},
		{"rerun: the server saw a write pilot did not report", func() perfSample { s := goodNoDiff(); s.Server.WriteN = 1; return s }, checkRerun, true, "the server logged 1"},
		{"rerun: the entry again", func() perfSample { s := goodNoDiff(); s.EntryRan = true; return s }, checkRerun, true, "ran the entry again"},

		{"agree: the same count", func() perfSample { return goodAttr() }, checkAgree, false, ""},
		{"agree: pilot reports fewer than the server logged", func() perfSample { s := goodAttr(); s.WriteCmds = 0; return s }, checkAgree, true, "pilot counted 0 write commands, the server logged 1"},
		{"agree: pilot reports more than the server logged", func() perfSample { s := goodAttr(); s.WriteCmds = 2; return s }, checkAgree, true, "pilot counted 2"},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			got := c.check(c.sample())
			switch {
			case c.fail && len(got) == 0:
				t.Fatalf("the check passed a sample it must fail")
			case c.fail && !strings.Contains(strings.Join(got, "; "), c.want):
				t.Fatalf("the check failed for %q, want a reason containing %q", got, c.want)
			case !c.fail && len(got) != 0:
				t.Fatalf("the check failed a good sample: %v", got)
			}
		})
	}
}

func TestPerfCheckComplete(t *testing.T) {
	if f := checkComplete(1138, 2400, 1138, 2400, 1000, 200); len(f) != 0 {
		t.Errorf("a complete read failed: %v", f)
	}
	for name, c := range map[string][]string{
		"the read is shorter than the server's users":   checkComplete(1100, 2400, 1138, 2400, 1000, 200),
		"the read is shorter than the server's groups":  checkComplete(1138, 2300, 1138, 2400, 1000, 200),
		"the read is longer than the server's":          checkComplete(1139, 2400, 1138, 2400, 1000, 200),
		"the read holds fewer than the roster declares": checkComplete(900, 2400, 900, 2400, 1000, 200),
		"a read cut at the server's default limit":      checkComplete(100, 100, 1138, 2400, 1000, 200),
	} {
		if len(c) == 0 {
			t.Errorf("%s: the check passed", name)
		}
	}
}

func TestPerfCheckDeletedExactly(t *testing.T) {
	before := []string{"a", "b", "c", "d"}
	if f := checkDeletedExactly(before, []string{"a", "b"}, []string{"c", "d"}); len(f) != 0 {
		t.Errorf("an exact delete failed: %v", f)
	}
	cases := map[string]struct{ after, deleted []string }{
		"a delete that was not declared":            {[]string{"a", "b"}, []string{"c"}},
		"a declared object that is still there":     {[]string{"a", "b", "c", "d"}, []string{"c"}},
		"a declared object the server did not hold": {[]string{"a", "b", "c", "d"}, []string{"z"}},
		"an object that appeared":                   {[]string{"a", "b", "c", "d", "e"}, nil},
		"nothing declared and one gone":             {[]string{"a", "b", "c"}, nil},
	}
	for name, c := range cases {
		if f := checkDeletedExactly(before, c.after, c.deleted); len(f) == 0 {
			t.Errorf("%s: the check passed", name)
		}
	}
}

// The events of a run are summarized from the payloads the writer records: built here with the writer's own event types.
func TestPerfSummarizeEvents(t *testing.T) {
	start := time.Date(2026, 11, 7, 10, 0, 0, 0, time.UTC)
	at := func(s float64) time.Time { return start.Add(time.Duration(s * float64(time.Second))) }
	enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	evs := []perfEvent{
		{ID: 1, Type: EventAuthCache, At: at(3.5), Payload: "{}"},
		{ID: 2, Type: EventOp, At: at(4), Payload: enc(sendEvent{Phase: "sending", Stage: "S3", Batch: 1, Operations: make([]Operation, 25)})},
		{ID: 3, Type: EventOp, At: at(6.5), Payload: enc(resultEvent{Phase: "result", Stage: "S3", Batch: 1, Results: make([]OpResult, 25)})},
		{ID: 4, Type: EventOp, At: at(6.6), Payload: enc(sendEvent{Phase: "sending", Stage: "S3", Batch: 2, Operations: make([]Operation, 5)})},
		{ID: 5, Type: EventOp, At: at(7.1), Payload: enc(resultEvent{Phase: "result", Stage: "S3", Batch: 2, Results: make([]OpResult, 5)})},
		{ID: 6, Type: EventVerify, At: at(9), Payload: "{}"},
	}
	batches, phases := summarizeEvents(evs, start)
	if len(batches) != 2 || batches[0].Ops != 25 || batches[0].Seconds != 2.5 || batches[1].Ops != 5 || batches[1].Seconds < 0.49 || batches[1].Seconds > 0.51 {
		t.Errorf("batches %+v", batches)
	}
	if phases["entry_recorded"] != 3.5 || phases["first_write_sent"] != 4 || phases["last_write_answered"] != 7.1 || phases["verify_recorded"] != 9 {
		t.Errorf("phases %v", phases)
	}
}

// The playbooks pilot starts are told apart by the playbook's file name and the --check flag, from the argv of the process. The
// first argv is the one of a real process of the lab (an identity playbook run of a mixed run, read from /proc): its inventory
// and its extra-vars file end in .yml and .yaml too, and neither is the playbook.
func TestPerfClassifyPlaybook(t *testing.T) {
	real := []string{"/home/linuxbrew/.linuxbrew/Cellar/ansible/12.0.0/libexec/bin/python", "/home/linuxbrew/.linuxbrew/bin/ansible-playbook",
		"playbooks/apply/freeipa-identity-apply.yml", "-i", "/tmp/x/ws-58/inventory.yml", "--limit", "ipa1,client.ipa.pilot.internal", "-e", "stage=sandbox",
		"-e", "pilot_deferred_hosts=[]", "-e", "pilot_identity_users_groups_engine=go", "-e", "@/tmp/x/ws-58/.vault/main.yaml",
		"-e", `{"pilot_identity_auth_cache_output":"/tmp/pilot-auth-cache-487970-1884498176/result.json"}`}
	name, check, ok := classifyPlaybook(real)
	if !ok || name != "freeipa-identity-apply" || check {
		t.Errorf("real identity run: %q %v %v", name, check, ok)
	}
	name, check, ok = classifyPlaybook(append([]string{"ansible-playbook", "--check", "--diff"}, real[2:]...))
	if !ok || name != "freeipa-identity-apply" || !check {
		t.Errorf("check run: %q %v %v", name, check, ok)
	}
	name, check, ok = classifyPlaybook([]string{"ansible-playbook", "-i", "inv.yml", "-e", "@vars.yaml", "playbooks/apply/freeipa-identity-auth-cache.yml"})
	if !ok || name != "freeipa-identity-auth-cache" || check {
		t.Errorf("entry with the playbook last: %q %v %v", name, check, ok)
	}
	if _, _, ok := classifyPlaybook([]string{"ssh", "-W", "ipa1:443", "root@host"}); ok {
		t.Error("an ssh process was taken for a playbook")
	}
	if _, _, ok := classifyPlaybook([]string{"ansible-inventory", "--list", "-i", "inventory.yml"}); ok {
		t.Error("ansible-inventory was taken for a playbook")
	}
	if _, _, ok := classifyPlaybook([]string{"ansible-playbook", "-i", "inventory.yml"}); ok {
		t.Error("a run without a playbook was taken for one")
	}
}

// The batch sweep builds pilot with the one constant changed; the build is anchored on that constant's declaration, so a change
// of its spelling or value must break this test rather than silently build four copies of the same binary.
func TestPerfBatchOverlayAnchor(t *testing.T) {
	data, err := os.ReadFile("execute.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(data), "const MaxBatch = 25"); n != 1 {
		t.Fatalf("execute.go declares %q %d times; the batch sweep (buildWithBatchLimit) needs exactly one", "const MaxBatch = 25", n)
	}
	if MaxBatch != 25 {
		t.Fatalf("MaxBatch is %d; the sweep's anchor and its default limit say 25", MaxBatch)
	}
}

// The buckets read the names of the identity playbook's own tasks (copied from playbooks/apply/freeipa-identity-apply.yml).
func TestPerfBucketProfile(t *testing.T) {
	tasks := []perfTaskTime{
		{"Attach hosts to sudo rules", 4}, {"Ensure sudo command objects exist", 1}, {"Attach services to HBAC rules", 3},
		{"Ensure IPA netgroups exist", 2}, {"Remove stale hostgroup host memberships", 5}, {"Delete the FreeIPA host object for each roster host marked absent (spec.md §16.3 step 5)", 7},
		{"Settle SSH key cache work after IPA reconciliation", 11}, {"Ensure IPA users exist", 13}, {"Gate: roster supplies at least one data list (catches the wrong -e file)", 17},
		{"Ensure user group membership", 19}, {"Obtain a Kerberos ticket for the admin", 23},
	}
	got := bucketProfile(tasks)
	want := map[string]float64{"sudo": 5, "hbac": 3, "netgroups": 2, "hostgroups": 5, "hosts": 7, "ssh-key-and-authorization-cache": 11, "users": 32, "other": 17, "kerberos": 23}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("bucket %s = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
	var sum float64
	for _, v := range got {
		sum += v
	}
	if sum != 105 {
		t.Errorf("the buckets hold %v seconds of the 105 there were: a task fell out of every bucket", sum)
	}
}

// The recap of the profile_tasks callback as ansible-core 2.19.2 with the ansible.posix collection printed it for a
// three-task play of this lab (PROFILE_TASKS_TASK_OUTPUT_LIMIT=all, descending): the lines that are not task lines (the play recap, the
// timestamp line, the rule of equals signs) are not read as tasks.
const realProfileRecap = `PLAY RECAP *********************************************************************
localhost                  : ok=3    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   


TASKS RECAP ********************************************************************
Saturday 07 November 2026  19:41:43 +0800 (0:00:02.021)       0:00:03.420 ***** 
=============================================================================== 
Normalize canonical users for the compatibility reconciler -------------- 2.02s
Attach services to HBAC rules ------------------------------------------- 1.02s
Gate - canonical user objects are structurally valid -------------------- 0.37s
`

func TestPerfParseProfileTasks(t *testing.T) {
	got := parseProfileTasks(realProfileRecap)
	want := []perfTaskTime{{"Normalize canonical users for the compatibility reconciler", 2.02}, {"Attach services to HBAC rules", 1.02}, {"Gate - canonical user objects are structurally valid", 0.37}}
	if len(got) != len(want) {
		t.Fatalf("parsed %d task lines %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("task %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if got := parseProfileTasks("no recap here\n=== ---- 1.0s extra\n"); len(got) != 0 {
		t.Errorf("read task lines out of text that has none: %v", got)
	}
}

// FreeIPA refuses a host address in a documentation range ("cannot use IANA reserved IP address", seen when the first wide
// mixed run failed in host-add) and wants a reverse zone for it: the wide roster's addresses are in the client's own /24.
func TestPerfWideHostsStayInTheClientsSubnet(t *testing.T) {
	if got := perfHostIP("192.168.122.17", 5); got != "192.168.122.205" {
		t.Errorf("perfHostIP = %q, want 192.168.122.205", got)
	}
	roster, _ := perfRoster(perfSpec{Users: 10, Groups: 10, Wide: true}, "client.ipa.pilot.internal", "192.168.122.17")
	hosts := roster["hosts"].([]any)
	if len(hosts) != 21 {
		t.Fatalf("the wide roster holds %d hosts, want the client and twenty", len(hosts))
	}
	seen := map[string]bool{}
	for _, h := range hosts[1:] {
		ip := h.(map[string]any)["ip_address"].(string)
		if !strings.HasPrefix(ip, "192.168.122.") || seen[ip] {
			t.Errorf("address %q is outside the client's /24 or repeated", ip)
		}
		seen[ip] = true
	}
}
