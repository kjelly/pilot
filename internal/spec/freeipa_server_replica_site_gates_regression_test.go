package spec

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #362: playbooks/site.yml now runs freeipa-server-replica-apply.yml,
// so three behaviors of that playbook that a deliberate operator could
// work around by hand became routine failures. The gates that now stop them
// carry these names (they are not the playbook's R1/R2/R3 row tags, which are
// enroll, promote and day-2 DNS):
//
//	G-ip       ipa_server_ip defaulted to the replica's OWN ansible_host, so
//	           an inventory without freeipa_server_ip (valid for
//	           freeipa-server and freeipa-client, which derive it) failed
//	           "must not be the primary itself" with a misleading message;
//	G-pool     two replica hosts without their own freeipa_replica_fqdn both
//	           defaulted to ipa2.<domain>; the pool gates that catch it live
//	           in tasks/freeipa-server-pool.yml and run from dns-apply.yml
//	           and freeipa-client-apply.yml, which site.yml runs AFTER the
//	           replica;
//	G-resolve  with a primary that runs no native DNS the playbook changed
//	           the hostname, installed packages and enrolled the host, then
//	           failed inside ipa-replica-install with the reason hidden by
//	           no_log.
//
// And the play is serial: 1 (review F1, refs #110): with forks=20 site.yml
// would otherwise promote every replica host at once against one primary.
//
// These tests run the playbook's real pre_tasks (by name, with its real play
// vars and its real serial) on localhost with ansible-playbook. The primary
// and the replicas are inventory hosts with ansible_connection=local, so the
// delegated getent runs through the real delegate_to machinery against a test
// double of getent. The harness covers the pre_tasks only: it proves the
// gates fire and pass on the right inputs, not the install tasks, and a fake
// getent proves the gate's reading of getent's output, not that a real
// primary resolves the name. `make site-day2-roles-test` (CI's Playbook
// integration job) runs them with PILOT_REQUIRE_CONTAINER_TESTS=1, so a
// missing ansible-playbook fails instead of skipping.

const replicaSiteGatesPlaybook = "freeipa-server-replica-apply.yml"

// The replica play's own pre_tasks the harness runs, in play order. A task
// renamed or removed fails findNamedTask, so the harness cannot silently
// stop covering it.
var replicaSiteGateTasks = []string{
	"Gate: required vars present (fail early, before any mutation)",
	"Gate: this host must not be the primary itself",
	"Resolve inventory-overridable defaults added to the input contract",
	"FreeIPA replica pool — each replica host's effective FQDN and the hosts that leave it unset",
	"Gate: more than one replica host means each sets its own freeipa_replica_fqdn",
	"Gate: replica FQDNs are unique and none is the primary's",
	"FreeIPA replica — resolve whether the primary provides native DNS + who to delegate DNS registration to",
	"FreeIPA replica — ask the PRIMARY to resolve this replica's FQDN (read-only; only when the primary has no native DNS)",
	"Gate: the PRIMARY resolves {{ ipa_replica_fqdn }} to this replica's address (MANUAL PRE-STEP when it runs no native DNS)",
}

const (
	gateRequiredVars  = "Gate: required vars present (fail early, before any mutation)"
	gateNotThePrimary = "Gate: this host must not be the primary itself"
	gateReplicaUnset  = "Gate: more than one replica host means each sets its own freeipa_replica_fqdn"
	gateReplicaUnique = "Gate: replica FQDNs are unique and none is the primary's"
	// The name of this gate is templated; the callback reports it rendered,
	// so a failure is matched on the part before the FQDN.
	gatePrimaryResolve = "Gate: the PRIMARY resolves "
)

// getentDoubleDir installs a fake `getent` first on PATH for the whole test
// and returns the directory it reads its answers from. A name resolves when
// <dir>/<name> exists, holding the address(es) to return, separated by
// spaces; every call is appended to <dir>/<name>.log. Keying by name keeps
// parallel subtests apart. The output shape is what glibc 2.43 `getent
// ahostsv4` printed on 2026-11-17: per address a STREAM, a DGRAM and a RAW
// line, the address padded to 15 columns; the name only on the first STREAM
// line (captured for localhost, and for dns.google, which has two addresses:
// the second address's STREAM line has an empty name); an unknown name prints
// nothing and exits 2. The real command on the EL9 primary of the VM run is
// not covered here.
func getentDoubleDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" != ahostsv4 ]; then echo "unexpected: $*" >&2; exit 3; fi
printf '%s\n' "$*" >> "` + dir + `/$2.log"
if [ ! -f "` + dir + `/$2" ]; then exit 2; fi
name="$2"
for ip in $(cat "` + dir + `/$2"); do
  printf '%-15s STREAM %s\n' "$ip" "$name"
  printf '%-15s DGRAM  \n' "$ip"
  printf '%-15s RAW    \n' "$ip"
  name=""
done
`
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "getent"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

func requireAnsibleForReplicaGates(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("ansible-playbook not installed: %v (PILOT_REQUIRE_CONTAINER_TESTS=1)", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
}

type replicaGateCase struct {
	name string
	// replicas are the freeipa-server-replica hosts; "localhost" is always
	// present (the harness reads the play's result on it) with the address
	// 192.0.2.12 unless given here.
	replicas map[string]map[string]any
	// noPrimary leaves the freeipa-server group out (a single-host
	// `-e target_group=all` run).
	noPrimary bool
	// primaryVars are host vars of the primary ipa1 (192.0.2.11).
	primaryVars map[string]any
	// groupVars are inventory-wide vars (all.vars) on top of freeipa_domain.
	groupVars map[string]any
	extraArgs []string
	// resolvable is the address the primary's getent returns for the
	// replica FQDN, "" when the name does not resolve there.
	resolvable string

	// Expectations: wantFail is the name of the task that must fail ("" =
	// the pre_tasks must all pass); wantMsg must all appear in its message;
	// wantShow is checked on the show task's JSON when they pass.
	wantFail string
	wantMsg  []string
	wantShow map[string]any
	// wantGetent is the number of getent calls the primary must have seen
	// for the replica FQDN.
	wantGetent int
}

// replicaTaskRun is one task execution of an ansible-playbook run (the JSON
// callback flattened: with serial, a task appears once per batch), with the
// outcome on every host it ran on.
type replicaTaskRun struct {
	Name  string
	Hosts map[string]replicaHostResult
}

type replicaHostResult struct {
	Failed bool
	Msg    string
}

// replicaFailure is a failed task on one host.
type replicaFailure struct{ Task, Host, Msg string }

// runReplicaPlaybook writes inv and plays to a temp directory, runs
// ansible-playbook with the JSON callback (forks 20 like ansible.cfg, so
// hosts really would run together unless the play says serial) and returns
// every task execution in order and ansible-playbook's exit code. Unlike
// tryInventoryPlaysIn it keeps the result of every host: under serial: 1 the
// first host's failure is not on localhost.
func runReplicaPlaybook(t *testing.T, inv map[string]any, plays []map[string]any, args ...string) ([]replicaTaskRun, int) {
	t.Helper()
	dir := t.TempDir()
	write := func(path string, v any) {
		body, err := yaml.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "inventory.yml"), inv)
	write(filepath.Join(dir, "play.yml"), plays)
	cmd := exec.Command("ansible-playbook", append([]string{"-f", "20", "-i", filepath.Join(dir, "inventory.yml"), filepath.Join(dir, "play.yml")}, args...)...)
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, runErr := cmd.Output()
	exit := 0
	if runErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(runErr, &exitErr) {
			t.Fatalf("ansible-playbook did not run: %v", runErr)
		}
		exit = exitErr.ExitCode()
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed bool        `json:"failed"`
					Msg    callbackMsg `json:"msg"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse JSON callback output (exit %d): %v\n%s", exit, err, out)
	}
	var runs []replicaTaskRun
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			run := replicaTaskRun{Name: task.Task.Name, Hosts: map[string]replicaHostResult{}}
			for host, res := range task.Hosts {
				run.Hosts[host] = replicaHostResult{Failed: res.Failed, Msg: string(res.Msg)}
			}
			runs = append(runs, run)
		}
	}
	return runs, exit
}

// replicaFailures lists the failed tasks of a run in order (hosts of one task
// sorted by name).
func replicaFailures(runs []replicaTaskRun) []replicaFailure {
	var failures []replicaFailure
	for _, run := range runs {
		var hosts []string
		for host := range run.Hosts {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		for _, host := range hosts {
			if run.Hosts[host].Failed {
				failures = append(failures, replicaFailure{run.Name, host, run.Hosts[host].Msg})
			}
		}
	}
	return failures
}

// replicaGatePlay is the replica play as the harness runs it: the real play
// vars, the real serial (withSerial false drops it: the control of the
// serial tests) and the named pre_tasks of the real playbook, then tasks.
func replicaGatePlay(t *testing.T, withSerial bool, tasks ...map[string]any) map[string]any {
	t.Helper()
	realPlay := loadFirstPlay(t, replicaSiteGatesPlaybook)
	playbook := loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", replicaSiteGatesPlaybook))
	var all []any
	for _, name := range replicaSiteGateTasks {
		all = append(all, findNamedTask(t, playbook, name))
	}
	for _, task := range tasks {
		all = append(all, task)
	}
	play := map[string]any{
		"name": "replica pre_tasks", "hosts": "freeipa-server-replica", "gather_facts": false, "become": false,
		"vars": realPlay["vars"], "tasks": all,
	}
	if serial, ok := realPlay["serial"]; ok && withSerial {
		play["serial"] = serial
	}
	return play
}

// runReplicaGates runs the real pre_tasks on the case's inventory and
// returns the show task's JSON (or the first failed task and message) plus
// how many times the primary resolved the replica name.
func runReplicaGates(t *testing.T, double string, c replicaGateCase, replicaFQDN string) (map[string]any, string, int) {
	t.Helper()
	host := func(ip string, extra map[string]any) map[string]any {
		m := localHostVars()
		m["ansible_host"] = ip
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	replicas := map[string]any{}
	if _, ok := c.replicas["localhost"]; !ok {
		replicas["localhost"] = host("192.0.2.12", map[string]any{"freeipa_replica_fqdn": replicaFQDN})
	}
	for name, vars := range c.replicas {
		replicas[name] = host(fmt.Sprint(vars["ansible_host"]), vars)
	}
	children := map[string]any{"freeipa-server-replica": map[string]any{"hosts": replicas}}
	if !c.noPrimary {
		children["freeipa-server"] = map[string]any{"hosts": map[string]any{"ipa1": host("192.0.2.11", c.primaryVars)}}
	}
	allVars := map[string]any{"freeipa_domain": "example.test"}
	for k, v := range c.groupVars {
		allVars[k] = v
	}
	inv := map[string]any{"all": map[string]any{"vars": allVars, "children": children}}

	if c.resolvable != "" {
		if err := os.WriteFile(filepath.Join(double, replicaFQDN), []byte(c.resolvable), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	play := replicaGatePlay(t, true, showTask([]string{"ipa_server_ip", "ipa_replica_fqdn", "freeipa_replica_pool_fqdns", "freeipa_replica_primary_native_dns"}))
	args := append([]string{"-e", "ipa_admin_password=" + strings.Repeat("s", 12)}, c.extraArgs...)
	runs, exit := runReplicaPlaybook(t, inv, []map[string]any{play}, args...)

	calls := 0
	if raw, err := os.ReadFile(filepath.Join(double, replicaFQDN+".log")); err == nil {
		calls = len(strings.Split(strings.TrimSpace(string(raw)), "\n"))
	}
	if failures := replicaFailures(runs); len(failures) > 0 {
		return nil, failures[0].Task + ": " + failures[0].Msg, calls
	}
	if exit != 0 {
		t.Fatalf("ansible-playbook exited %d without a failed task", exit)
	}
	for _, run := range runs {
		if res, ok := run.Hosts["localhost"]; ok && run.Name == "show" {
			var got map[string]any
			if err := json.Unmarshal([]byte(res.Msg), &got); err != nil {
				t.Fatalf("decode %q: %v", res.Msg, err)
			}
			return got, "", calls
		}
	}
	t.Fatalf("no output from the show task on localhost: %+v", runs)
	return nil, "", calls
}

func TestRegression_SiteDay2RolesReplicaPreTasks(t *testing.T) {
	requireAnsibleForReplicaGates(t)
	double := getentDoubleDir(t)

	cases := []replicaGateCase{
		// ── G-ip: ipa_server_ip ──────────────────────────────────────────
		{name: "G-ip derives the primary's address from the inventory when freeipa_server_ip is unset",
			wantShow: map[string]any{"ipa_server_ip": "192.0.2.11"}},
		{name: "G-ip an explicit freeipa_server_ip still wins over the inventory",
			groupVars: map[string]any{"freeipa_server_ip": "192.0.2.77"},
			wantShow:  map[string]any{"ipa_server_ip": "192.0.2.77"}},
		{name: "G-ip an -e ipa_server_ip (the documented single-host form) wins too",
			noPrimary: true, extraArgs: []string{"-e", "ipa_server_ip=192.0.2.55"},
			wantShow: map[string]any{"ipa_server_ip": "192.0.2.55"}},
		{name: "G-ip with no primary and no freeipa_server_ip the required-vars gate fails clearly",
			noPrimary: true,
			wantFail:  gateRequiredVars, wantMsg: []string{"freeipa_server_ip", "freeipa-server inventory host", "target_group=all"}},

		// ── G-pool: replica FQDNs ────────────────────────────────────────
		{name: "G-pool one replica may keep the ipa2.<domain> default",
			replicas: map[string]map[string]any{"localhost": {"ansible_host": "192.0.2.12"}},
			wantShow: map[string]any{"freeipa_replica_pool_fqdns": []any{"ipa2.example.test"}}},
		{name: "G-pool two replicas with their own distinct FQDNs pass",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "gpool-ok-a.example.test"},
				"ipa3":      {"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "gpool-ok-b.example.test"},
			}},
		{name: "G-pool two replicas that both leave freeipa_replica_fqdn unset fail before any change",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12"},
				"ipa3":      {"ansible_host": "192.0.2.13"},
			},
			wantFail: gateReplicaUnset, wantMsg: []string{"ipa3", "localhost", "ipa2.example.test", "Nothing was changed"}},
		{name: "G-pool one replica explicit and one on the default still fails (the pool gate would reject it later)",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "gpool-mixed.example.test"},
				"ipa3":      {"ansible_host": "192.0.2.13"},
			},
			wantFail: gateReplicaUnset, wantMsg: []string{"ipa3"}},
		{name: "G-pool the same explicit FQDN on two replicas (set once at group level) fails",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12"},
				"ipa3":      {"ansible_host": "192.0.2.13"},
			},
			groupVars: map[string]any{"freeipa_replica_fqdn": "gpool-dup.example.test"},
			wantFail:  gateReplicaUnique, wantMsg: []string{"gpool-dup.example.test", "unique"}},
		{name: "G-pool compares FQDNs case-insensitively",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "G-Pool-Case.example.test"},
				"ipa3":      {"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "g-pool-case.EXAMPLE.test"},
			},
			wantFail: gateReplicaUnique, wantMsg: []string{"g-pool-case.example.test"}},
		{name: "G-pool another replica that takes the primary's FQDN fails",
			// The offender sorts after localhost, so localhost's batch is the
			// first one: its own per-host gates pass and the group-wide G-pool
			// gate is what stops the run, before any replica changes.
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "gpool-primary-clash-ok.example.test"},
				"zz-ipa3":   {"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "ipa1.example.test"},
			},
			wantFail: gateReplicaUnique, wantMsg: []string{"ipa1.example.test", "differ from the primary"}},
		{name: "per-host: a replica that takes the primary's FQDN and is batched first is stopped by its own 'not the primary itself' gate",
			// Under serial: 1 the first host's per-host gates run before the
			// group-wide pool gate would see the clash from another host.
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "gpool-primary-clash-ok2.example.test"},
				"aa-ipa3":   {"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "ipa1.example.test"},
			},
			wantFail: gateNotThePrimary, wantMsg: []string{"must differ from ipa_server_fqdn"}},

		// ── G-resolve: the primary must find the replica by name ─────────
		{name: "G-resolve native DNS on the primary: the gate does not run, whatever getent would say",
			// The primary leaves freeipa_setup_dns unset (default true) and the
			// double does not resolve the name; the self-register task handles it.
			wantShow: map[string]any{"freeipa_replica_primary_native_dns": true}, wantGetent: 0},
		{name: "G-resolve native DNS stated explicitly: the gate does not run",
			primaryVars: map[string]any{"freeipa_setup_dns": true},
			wantShow:    map[string]any{"freeipa_replica_primary_native_dns": true}, wantGetent: 0},
		{name: "G-resolve no native DNS and the primary resolves the replica to its address: passes",
			primaryVars: map[string]any{"freeipa_setup_dns": false}, resolvable: "192.0.2.12",
			wantShow: map[string]any{"freeipa_replica_primary_native_dns": false}, wantGetent: 1},
		{name: "G-resolve no native DNS and the primary cannot resolve the replica: fails before any change",
			primaryVars: map[string]any{"freeipa_setup_dns": false},
			wantFail:    gatePrimaryResolve, wantMsg: []string{"MANUAL PRE-STEP", "getent ahostsv4", "rc=2", "192.0.2.12", "/etc/hosts", "Nothing was changed"}, wantGetent: 1},
		{name: "G-resolve no native DNS and the primary resolves the name to another address: fails",
			primaryVars: map[string]any{"freeipa_setup_dns": false}, resolvable: "192.0.2.99",
			wantFail: gatePrimaryResolve, wantMsg: []string{"192.0.2.99", "MANUAL PRE-STEP"}, wantGetent: 1},
		{name: "G-resolve the primary's answer lists several addresses and one is the replica's: passes (the match is containment, not equality)",
			primaryVars: map[string]any{"freeipa_setup_dns": false}, resolvable: "192.0.2.99 192.0.2.12",
			wantShow: map[string]any{"freeipa_replica_primary_native_dns": false}, wantGetent: 1},
		{name: "G-resolve freeipa_replica_ip is the address the primary must return when the replica is known by another one: passes",
			replicas:    map[string]map[string]any{"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "gresolve-multihomed-ok.example.test", "freeipa_replica_ip": "192.0.2.88"}},
			primaryVars: map[string]any{"freeipa_setup_dns": false}, resolvable: "192.0.2.88",
			wantShow: map[string]any{"freeipa_replica_primary_native_dns": false}, wantGetent: 1},
		{name: "G-resolve freeipa_replica_ip set: the primary resolving only the ansible_host address fails",
			replicas:    map[string]map[string]any{"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "gresolve-multihomed-bad.example.test", "freeipa_replica_ip": "192.0.2.88"}},
			primaryVars: map[string]any{"freeipa_setup_dns": false}, resolvable: "192.0.2.12",
			wantFail: gatePrimaryResolve, wantMsg: []string{"192.0.2.88", "freeipa_replica_ip", "CONTAINS", "every apply", "already-promoted"}, wantGetent: 1},
		{name: "G-resolve the gate also fails under a row tag (always-tagged)",
			// R2 here is the playbook's real row tag (promote), not a gate name.
			primaryVars: map[string]any{"freeipa_setup_dns": false}, extraArgs: []string{"--tags", "R2"},
			wantFail: gatePrimaryResolve, wantMsg: []string{"MANUAL PRE-STEP"}, wantGetent: 1},
		{name: "G-resolve a single-host run without a freeipa-server group has no primary to ask: skipped",
			noPrimary: true, extraArgs: []string{"-e", "ipa_server_ip=192.0.2.11"},
			wantShow: map[string]any{"freeipa_replica_primary_native_dns": false}, wantGetent: 0},
	}
	for i, c := range cases {
		c := c
		fqdn := fmt.Sprintf("r%d.example.test", i)
		if got, ok := c.replicas["localhost"]["freeipa_replica_fqdn"]; ok {
			fqdn = fmt.Sprint(got)
		} else if c.groupVars["freeipa_replica_fqdn"] != nil {
			fqdn = fmt.Sprint(c.groupVars["freeipa_replica_fqdn"])
		} else if _, defaulted := c.replicas["localhost"]; defaulted {
			fqdn = "ipa2.example.test"
		}
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got, failed, calls := runReplicaGates(t, double, c, fqdn)
			if c.wantFail == "" {
				if failed != "" {
					t.Fatalf("a pre_task failed: %s", failed)
				}
				for k, want := range c.wantShow {
					if !jsonEqual(got[k], want) {
						t.Errorf("%s = %v, want %v", k, got[k], want)
					}
				}
			} else {
				if !strings.HasPrefix(failed, c.wantFail) {
					t.Fatalf("want %q to fail, got failure %q (show: %v)", c.wantFail, failed, got)
				}
				for _, want := range c.wantMsg {
					if !strings.Contains(failed, want) {
						t.Errorf("failure message lacks %q:\n%s", want, failed)
					}
				}
			}
			if calls != c.wantGetent {
				t.Errorf("the primary resolved %s %d times, want %d", fqdn, calls, c.wantGetent)
			}
		})
	}
}

// The setter of the two primary facts moved from tasks: to pre_tasks, tagged
// always, so every tag run has them for the self-register block and for the
// new gate; the new gate tasks are always-tagged too (AGENTS.md section
// 4.4). The repository-wide lints cover the general rule; this pins the
// shape of this playbook.
func TestRegression_SiteDay2RolesReplicaGatesAreAlwaysTagged(t *testing.T) {
	play := loadFirstPlay(t, replicaSiteGatesPlaybook)
	inPre := map[string]map[string]any{}
	for _, raw := range play["pre_tasks"].([]any) {
		task := raw.(map[string]any)
		if name, ok := task["name"].(string); ok {
			inPre[name] = task
		}
	}
	for _, name := range replicaSiteGateTasks {
		task, ok := inPre[name]
		if !ok {
			t.Errorf("%q is not a pre_task of %s", name, replicaSiteGatesPlaybook)
			continue
		}
		tags, _ := task["tags"].([]any)
		if len(tags) != 1 || tags[0] != "always" {
			t.Errorf("%q has tags %v, want [always]", name, tags)
		}
	}
	for _, raw := range play["tasks"].([]any) {
		task := raw.(map[string]any)
		if _, setsFact := task["ansible.builtin.set_fact"]; !setsFact {
			continue
		}
		facts, _ := task["ansible.builtin.set_fact"].(map[string]any)
		for name := range facts {
			if name == "freeipa_replica_primary_native_dns" || name == "freeipa_replica_primary_inventory_host" {
				t.Errorf("%q is set again in tasks:; it must only be set in pre_tasks (always)", name)
			}
		}
	}
}

// The replica play promotes one host at a time (review F1 of issue #362; refs
// #110). docs/verification/freeipa-server-replica.md section 5 ("permanent")
// says several ipa-replica-install against one primary must not run in
// parallel (389-ds replication segments race), and playbooks/site.yml, with
// ansible.cfg's forks=20, would otherwise run every freeipa-server-replica
// host together. This pins the play keyword itself; the test below proves what
// it does to a run.
func TestRegression_SiteDay2RolesReplicaPlayIsSerial(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "playbooks", "apply", replicaSiteGatesPlaybook))
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	if len(plays) != 1 {
		t.Fatalf("%s has %d plays; the serial guard assumes the single replica play, update it", replicaSiteGatesPlaybook, len(plays))
	}
	if serial := plays[0]["serial"]; serial != 1 {
		t.Fatalf("the replica play has serial: %v (%T), want the integer 1: site.yml would promote every freeipa-server-replica host at once against one primary, which docs/verification/freeipa-server-replica.md section 5 forbids (389-ds replication race; refs #110)", serial, serial)
	}
}

// replicaSerialCase is one run of the serial test: two replica hosts, ipa-a
// first and ipa-b second (the inventory is written with sorted keys, which is
// the order Ansible batches them in), a primary that runs no native DNS (so
// the G-resolve gate asks it), and the getent double resolving only the names
// listed in resolves.
type replicaSerialCase struct {
	name       string
	withSerial bool
	resolves   []string // "a" and/or "b": which replica names the primary resolves
	// Expectations.
	wantExit       int
	wantFailedHost string // "" = nothing fails
	wantPassed     []string
	wantNotPassed  []string
	wantLater      []string
	wantNotLater   []string
}

// TestRegression_SiteDay2RolesReplicasPromoteOneAtATime runs the real play
// (its pre_tasks, vars and serial) over two replica hosts followed by a later
// play on the same group, standing in for the plays site.yml runs after the
// replica tier, and checks the effective result through marker files each
// play leaves per host:
//   - with the real serial, a replica that fails its gate stops everything:
//     the second replica never starts and the later play does not run;
//   - the same inventory without serial is the control: the second replica
//     runs its tasks and the later play runs for it, so the first rows prove
//     serial and not an artifact of the harness;
//   - G-resolve is per host: a second replica that fails it does so after the
//     first one's whole batch ran.
//
// ansible-core 2.19.2 executor/playbook_executor.py: a serial batch in which
// every host failed (or was unreachable) sets break_play, and break_play
// leaves the loop over all plays of the playbook file, imported plays
// included, so a one-host batch that fails ends the run with exit code 2.
func TestRegression_SiteDay2RolesReplicasPromoteOneAtATime(t *testing.T) {
	requireAnsibleForReplicaGates(t)
	double := getentDoubleDir(t)

	cases := []replicaSerialCase{
		{name: "serial: the first replica fails G-resolve, the second never starts and the later play does not run",
			withSerial: true, resolves: []string{"b"},
			wantExit: 2, wantFailedHost: "ipa-a",
			wantNotPassed: []string{"ipa-a", "ipa-b"}, wantNotLater: []string{"ipa-a", "ipa-b"}},
		{name: "control without serial: the same failure leaves the second replica running and the later play runs for it",
			withSerial: false, resolves: []string{"b"},
			wantExit: 2, wantFailedHost: "ipa-a",
			wantPassed: []string{"ipa-b"}, wantNotPassed: []string{"ipa-a"},
			wantLater: []string{"ipa-b"}, wantNotLater: []string{"ipa-a"}},
		{name: "serial: the second replica fails G-resolve after the first one ran, and nothing runs after it",
			withSerial: true, resolves: []string{"a"},
			wantExit: 2, wantFailedHost: "ipa-b",
			wantPassed: []string{"ipa-a"}, wantNotPassed: []string{"ipa-b"}, wantNotLater: []string{"ipa-a", "ipa-b"}},
		{name: "serial: both replicas pass, both run in turn and the later play runs for both",
			withSerial: true, resolves: []string{"a", "b"},
			wantExit:   0,
			wantPassed: []string{"ipa-a", "ipa-b"}, wantLater: []string{"ipa-a", "ipa-b"}},
	}
	for i, c := range cases {
		c := c
		prefix := fmt.Sprintf("s%d", i)
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			markers := t.TempDir()
			marker := func(kind string) map[string]any {
				return map[string]any{
					"name": "marker " + kind,
					"ansible.builtin.file": map[string]any{
						"path": filepath.Join(markers, kind+"-{{ inventory_hostname }}"), "state": "touch",
					},
				}
			}
			fqdn := func(r string) string { return prefix + "-" + r + ".example.test" }
			host := func(ip, r string) map[string]any {
				m := localHostVars()
				m["ansible_host"] = ip
				m["freeipa_replica_fqdn"] = fqdn(r)
				return m
			}
			primary := localHostVars()
			primary["ansible_host"] = "192.0.2.11"
			primary["freeipa_setup_dns"] = false
			inv := map[string]any{"all": map[string]any{
				"vars": map[string]any{"freeipa_domain": "example.test"},
				"children": map[string]any{
					"freeipa-server":         map[string]any{"hosts": map[string]any{"ipa1": primary}},
					"freeipa-server-replica": map[string]any{"hosts": map[string]any{"ipa-a": host("192.0.2.21", "a"), "ipa-b": host("192.0.2.22", "b")}},
				},
			}}
			ips := map[string]string{"a": "192.0.2.21", "b": "192.0.2.22"}
			for _, r := range c.resolves {
				if err := os.WriteFile(filepath.Join(double, fqdn(r)), []byte(ips[r]), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			later := map[string]any{
				"name": "later play (stands in for dns, freeipa-client, ...)", "hosts": "freeipa-server-replica",
				"gather_facts": false, "become": false, "tasks": []any{marker("later")},
			}
			runs, exit := runReplicaPlaybook(t, inv,
				[]map[string]any{replicaGatePlay(t, c.withSerial, marker("passed")), later},
				"-e", "ipa_admin_password="+strings.Repeat("s", 12))

			if exit != c.wantExit {
				t.Errorf("ansible-playbook exit code %d, want %d", exit, c.wantExit)
			}
			failures := replicaFailures(runs)
			switch {
			case c.wantFailedHost == "" && len(failures) > 0:
				t.Errorf("unexpected failure: %+v", failures)
			case c.wantFailedHost != "":
				if len(failures) != 1 || failures[0].Host != c.wantFailedHost || !strings.HasPrefix(failures[0].Task, gatePrimaryResolve) {
					t.Errorf("want exactly the %q gate to fail on %s, got %+v", gatePrimaryResolve, c.wantFailedHost, failures)
				}
			}
			exists := func(kind, host string) bool {
				_, err := os.Stat(filepath.Join(markers, kind+"-"+host))
				return err == nil
			}
			for _, h := range c.wantPassed {
				if !exists("passed", h) {
					t.Errorf("%s did not get through the pre_tasks, want it to", h)
				}
			}
			for _, h := range c.wantNotPassed {
				if exists("passed", h) {
					t.Errorf("%s got through the pre_tasks, want it to stop before", h)
				}
			}
			for _, h := range c.wantLater {
				if !exists("later", h) {
					t.Errorf("the later play did not run on %s, want it to", h)
				}
			}
			for _, h := range c.wantNotLater {
				if exists("later", h) {
					t.Errorf("the later play ran on %s, want the failed replica tier to stop it", h)
				}
			}
		})
	}
}

// The G-resolve gate is deliberately NOT skipped for an already-promoted
// replica (Root decision on review finding F4 of issue #362): with a primary
// that runs no native DNS, a primary that no longer resolves the replica's
// name is a real inconsistency for a promoted replica too, and keeping the
// gate unconditional keeps it provable on the target. Its only conditions are
// "there is a primary to ask" and "the primary has no native DNS".
func TestRegression_SiteDay2RolesReplicaResolveGateRunsOnEveryApply(t *testing.T) {
	play := loadFirstPlay(t, replicaSiteGatesPlaybook)
	want := []any{
		"freeipa_replica_primary_inventory_host != inventory_hostname",
		"not (freeipa_replica_primary_native_dns | bool)",
	}
	found := 0
	for _, raw := range play["pre_tasks"].([]any) {
		task := raw.(map[string]any)
		name, _ := task["name"].(string)
		if !strings.HasPrefix(name, gatePrimaryResolve) && !strings.HasPrefix(name, "FreeIPA replica — ask the PRIMARY") {
			continue
		}
		found++
		if got := task["when"]; !jsonEqual(got, want) {
			t.Errorf("%q has when: %v, want exactly %v (no promotion marker: the gate also runs on every later apply of a promoted replica)", name, got, want)
		}
	}
	if found != 2 {
		t.Errorf("found %d of the 2 G-resolve tasks (the primary lookup and the gate)", found)
	}
}
