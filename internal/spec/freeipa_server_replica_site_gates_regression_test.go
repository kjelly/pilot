package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #362: playbooks/site.yml now runs freeipa-server-replica-apply.yml,
// so three behaviors of that playbook that a deliberate operator could
// work around by hand became routine failures:
//
//	R1  ipa_server_ip defaulted to the replica's OWN ansible_host, so an
//	    inventory without freeipa_server_ip (valid for freeipa-server and
//	    freeipa-client, which derive it) failed "must not be the primary
//	    itself" with a misleading message;
//	R2  two replica hosts without their own freeipa_replica_fqdn both
//	    defaulted to ipa2.<domain>; the pool gates that catch it live in
//	    tasks/freeipa-server-pool.yml and run from dns-apply.yml and
//	    freeipa-client-apply.yml, which site.yml runs AFTER the replica;
//	R3  with a primary that runs no native DNS the playbook changed the
//	    hostname, installed packages and enrolled the host, then failed
//	    inside ipa-replica-install with the reason hidden by no_log.
//
// These tests run the playbook's real pre_tasks (by name, with its real play
// vars) on localhost with ansible-playbook. The primary and the replicas are
// inventory hosts with ansible_connection=local, so the delegated getent runs
// through the real delegate_to machinery against a test double of getent.
// The harness covers the pre_tasks only: it proves the gates fire and pass
// on the right inputs, not the install tasks, and a fake getent proves the
// gate's reading of getent's output, not that a real primary resolves the
// name. `make site-day2-roles-test` (CI's Playbook integration job) runs them
// with PILOT_REQUIRE_CONTAINER_TESTS=1, so a missing ansible-playbook fails
// instead of skipping.

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
// <dir>/<name> exists, holding the address to return; every call is appended
// to <dir>/<name>.log. Keying by name keeps parallel subtests apart. The
// output shape (address padded to 15 columns, then STREAM, DGRAM and RAW lines
// per address; an unknown name prints nothing and exits 2) is what glibc 2.43
// `getent ahostsv4` printed on 2026-11-17 for localhost and for an unknown
// name; the real command on the EL9 primary of the VM run is not covered here.
func getentDoubleDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
if [ "$1" != ahostsv4 ]; then echo "unexpected: $*" >&2; exit 3; fi
printf '%s\n' "$*" >> "` + dir + `/$2.log"
if [ ! -f "` + dir + `/$2" ]; then exit 2; fi
ip=$(cat "` + dir + `/$2")
printf '%-15s STREAM %s\n' "$ip" "$2"
printf '%-15s DGRAM  \n' "$ip"
printf '%-15s RAW    \n' "$ip"
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

// runReplicaGates runs the real pre_tasks on the case's inventory and
// returns the show task's JSON (or the failed task and message) plus how many
// times the primary resolved the replica name.
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

	playbook := loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", replicaSiteGatesPlaybook))
	var tasks []any
	for _, name := range replicaSiteGateTasks {
		tasks = append(tasks, findNamedTask(t, playbook, name))
	}
	tasks = append(tasks, showTask([]string{"ipa_server_ip", "ipa_replica_fqdn", "freeipa_replica_pool_fqdns", "freeipa_replica_primary_native_dns"}))
	play := map[string]any{
		"name": "replica pre_tasks", "hosts": "freeipa-server-replica", "gather_facts": false, "become": false,
		"vars": loadFirstPlay(t, replicaSiteGatesPlaybook)["vars"], "tasks": tasks,
	}
	args := append([]string{"-e", "ipa_admin_password=" + strings.Repeat("s", 12)}, c.extraArgs...)
	got, failed := tryInventoryPlaysIn(t, inv, nil, []map[string]any{play}, args...)

	calls := 0
	if raw, err := os.ReadFile(filepath.Join(double, replicaFQDN+".log")); err == nil {
		calls = len(strings.Split(strings.TrimSpace(string(raw)), "\n"))
	}
	return got, failed, calls
}

func TestRegression_SiteDay2RolesReplicaPreTasks(t *testing.T) {
	requireAnsibleForReplicaGates(t)
	double := getentDoubleDir(t)

	cases := []replicaGateCase{
		// ── R1: ipa_server_ip ────────────────────────────────────────────
		{name: "R1 derives the primary's address from the inventory when freeipa_server_ip is unset",
			wantShow: map[string]any{"ipa_server_ip": "192.0.2.11"}},
		{name: "R1 an explicit freeipa_server_ip still wins over the inventory",
			groupVars: map[string]any{"freeipa_server_ip": "192.0.2.77"},
			wantShow:  map[string]any{"ipa_server_ip": "192.0.2.77"}},
		{name: "R1 an -e ipa_server_ip (the documented single-host form) wins too",
			noPrimary: true, extraArgs: []string{"-e", "ipa_server_ip=192.0.2.55"},
			wantShow: map[string]any{"ipa_server_ip": "192.0.2.55"}},
		{name: "R1 with no primary and no freeipa_server_ip the required-vars gate fails clearly",
			noPrimary: true,
			wantFail:  gateRequiredVars, wantMsg: []string{"freeipa_server_ip", "freeipa-server inventory host", "target_group=all"}},

		// ── R2: replica FQDNs ────────────────────────────────────────────
		{name: "R2 one replica may keep the ipa2.<domain> default",
			replicas: map[string]map[string]any{"localhost": {"ansible_host": "192.0.2.12"}},
			wantShow: map[string]any{"freeipa_replica_pool_fqdns": []any{"ipa2.example.test"}}},
		{name: "R2 two replicas with their own distinct FQDNs pass",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "r2-ok-a.example.test"},
				"ipa3":      {"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "r2-ok-b.example.test"},
			}},
		{name: "R2 two replicas that both leave freeipa_replica_fqdn unset fail before any change",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12"},
				"ipa3":      {"ansible_host": "192.0.2.13"},
			},
			wantFail: gateReplicaUnset, wantMsg: []string{"ipa3", "localhost", "ipa2.example.test", "Nothing was changed"}},
		{name: "R2 one replica explicit and one on the default still fails (the pool gate would reject it later)",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "r2-mixed.example.test"},
				"ipa3":      {"ansible_host": "192.0.2.13"},
			},
			wantFail: gateReplicaUnset, wantMsg: []string{"ipa3"}},
		{name: "R2 the same explicit FQDN on two replicas (set once at group level) fails",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12"},
				"ipa3":      {"ansible_host": "192.0.2.13"},
			},
			groupVars: map[string]any{"freeipa_replica_fqdn": "r2-dup.example.test"},
			wantFail:  gateReplicaUnique, wantMsg: []string{"r2-dup.example.test", "unique"}},
		{name: "R2 compares FQDNs case-insensitively",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "R2-Case.example.test"},
				"ipa3":      {"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "r2-case.EXAMPLE.test"},
			},
			wantFail: gateReplicaUnique, wantMsg: []string{"r2-case.example.test"}},
		{name: "R2 another replica that takes the primary's FQDN fails",
			replicas: map[string]map[string]any{
				"localhost": {"ansible_host": "192.0.2.12", "freeipa_replica_fqdn": "r2-primary-clash-ok.example.test"},
				"ipa3":      {"ansible_host": "192.0.2.13", "freeipa_replica_fqdn": "ipa1.example.test"},
			},
			wantFail: gateReplicaUnique, wantMsg: []string{"ipa1.example.test", "differ from the primary"}},

		// ── R3: the primary must find the replica by name ────────────────
		{name: "R3 native DNS on the primary: the gate does not run, whatever getent would say",
			// The primary leaves freeipa_setup_dns unset (default true) and the
			// double does not resolve the name; the self-register task handles it.
			wantShow: map[string]any{"freeipa_replica_primary_native_dns": true}, wantGetent: 0},
		{name: "R3 native DNS stated explicitly: the gate does not run",
			primaryVars: map[string]any{"freeipa_setup_dns": true},
			wantShow:    map[string]any{"freeipa_replica_primary_native_dns": true}, wantGetent: 0},
		{name: "R3 no native DNS and the primary resolves the replica to its address: passes",
			primaryVars: map[string]any{"freeipa_setup_dns": false}, resolvable: "192.0.2.12",
			wantShow: map[string]any{"freeipa_replica_primary_native_dns": false}, wantGetent: 1},
		{name: "R3 no native DNS and the primary cannot resolve the replica: fails before any change",
			primaryVars: map[string]any{"freeipa_setup_dns": false},
			wantFail:    gatePrimaryResolve, wantMsg: []string{"MANUAL PRE-STEP", "getent ahostsv4", "rc=2", "192.0.2.12", "/etc/hosts", "Nothing was changed"}, wantGetent: 1},
		{name: "R3 no native DNS and the primary resolves the name to another address: fails",
			primaryVars: map[string]any{"freeipa_setup_dns": false}, resolvable: "192.0.2.99",
			wantFail: gatePrimaryResolve, wantMsg: []string{"192.0.2.99", "MANUAL PRE-STEP"}, wantGetent: 1},
		{name: "R3 the gate also fails under a row tag (always-tagged)",
			primaryVars: map[string]any{"freeipa_setup_dns": false}, extraArgs: []string{"--tags", "R2"},
			wantFail: gatePrimaryResolve, wantMsg: []string{"MANUAL PRE-STEP"}, wantGetent: 1},
		{name: "R3 a single-host run without a freeipa-server group has no primary to ask: skipped",
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
