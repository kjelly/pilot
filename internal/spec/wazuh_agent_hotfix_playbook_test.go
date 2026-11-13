package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// These tests run the REAL wazuh-fim-agent-skew-hotfix.yml (byte for byte, with its two real task
// files) through a real ansible-playbook on localhost connections, and only replace what talks to
// the outside: the two helper scripts and `docker` are fakes that write one line per call into an
// event log. The point is the ORDER of events: which refusals happen before the first mutating call,
// and that a refused run leaves no mutating call at all. What the real helper decides is covered by
// testdata/wazuh_agent_hotfix_test.py; what the fake says here is just the inspect JSON the playbook
// reads (its keys are locked to the real helper's below).

const hotfixFakeTransaction = `import json, os, pathlib, sys
d = pathlib.Path(os.environ['HOTFIX_TEST_DIR'])
action = sys.argv[1]
if action == 'manager-version':
    print(json.dumps({'version': '4.14.1'}))
else:
    with open(d / 'events.log', 'a') as log:
        log.write('transaction ' + action + '\n')
    print(json.dumps({}))
`

// The helper runs on every host; the playbook gives each its own ansible_remote_tmp, so the script's
// own path says which host called it.
const hotfixFakeHelper = `import json, os, pathlib, sys
d = pathlib.Path(os.environ['HOTFIX_TEST_DIR'])
parts = pathlib.Path(__file__).resolve().parts
host = parts[parts.index('remote') + 1]
action = sys.argv[1]
with open(d / 'events.log', 'a') as log:
    log.write(host + ' ' + action + '\n')
if action == 'inspect':
    sys.stdout.write((d / 'state' / (host + '.json')).read_text())
elif action in ('quiesce', 'remove'):
    print(json.dumps({'changed': True}))
else:
    print(json.dumps({'removed': True}))
`

// A fake docker: manage_agents -l answers from registry.txt (or registry.<n>.txt for the n-th listing),
// manage_agents -r <id> drops that entry. Every call is logged.
const hotfixFakeDocker = `#!/usr/bin/env python3
import os, pathlib, re, sys
d = pathlib.Path(os.environ['HOTFIX_TEST_DIR'])
args = sys.argv[1:]
reg = d / 'registry.txt'
if args[-2:] == ['/var/ossec/bin/manage_agents', '-l'] or args[-1] == '-l':
    counter = d / 'listings'
    n = (int(counter.read_text()) if counter.exists() else 0) + 1
    counter.write_text(str(n))
    numbered = d / ('registry.%d.txt' % n)
    with open(d / 'events.log', 'a') as log:
        log.write('docker list\n')
    sys.stdout.write((numbered if numbered.exists() else reg).read_text())
elif '-r' in args:
    agent = args[args.index('-r') + 1]
    sys.stdin.read()
    with open(d / 'events.log', 'a') as log:
        log.write('docker remove ' + agent + '\n')
    keep = [line for line in reg.read_text().splitlines(True) if not re.search(r'ID: ' + re.escape(agent) + ',', line)]
    reg.write_text(''.join(keep))
    print("Agent '" + agent + "' removed.")
else:
    sys.exit('unexpected docker call: ' + ' '.join(args))
`

type hotfixHost struct {
	name   string
	groups []string       // inventory groups besides wazuh-fim / wazuh-manager, e.g. "staging"
	state  map[string]any // what the helper's inspect prints; nil for the manager
}

// agentState is the inspect JSON of one agent host, with the keys the real helper emits.
func agentState(installed string, skewed, residue bool, registration map[string]string) map[string]any {
	state := map[string]any{
		"family": "Debian", "installed": installed, "release": strings.SplitN(installed, "-", 2)[0], "manager": "4.14.1",
		"skewed": skewed, "residue": residue, "enrolled": registration != nil, "audit_orphaned": residue,
		"policy": map[string]any{"owned": false, "foreign_overlap": false, "held": false},
	}
	if registration != nil {
		state["registration"] = registration
	} else {
		state["registration"] = nil
	}
	return state
}

func skewedState(host string) map[string]any {
	return agentState("4.14.9-1", true, false, map[string]string{"id": "001", "name": host + ".example"})
}

var compatibleState = agentState("4.14.1-1", false, false, nil)

type hotfixPlaybookRun struct {
	t        *testing.T
	rc       int
	events   []string
	failures []hotfixFailure
	tasks    map[string][]string // task name -> hosts for which it really ran (not skipped)
	skipped  map[string][]string // task name -> hosts for which it was skipped
	msgs     []string            // every debug message
	stdout   string
}

type hotfixFailure struct {
	play, task, host, msg string
}

// mutations are the events that change a host or the manager. Everything else (inspect, manager-version,
// the manager registry listing) only reads.
func (r *hotfixPlaybookRun) mutations() []string {
	var out []string
	for _, event := range r.events {
		switch {
		case strings.HasPrefix(event, "docker remove"), strings.HasPrefix(event, "transaction "):
			if event != "transaction manager-version" {
				out = append(out, event)
			}
		case strings.HasSuffix(event, " quiesce"), strings.HasSuffix(event, " remove"), strings.HasSuffix(event, " verify"):
			out = append(out, event)
		}
	}
	return out
}

func (r *hotfixPlaybookRun) docker() []string {
	var out []string
	for _, event := range r.events {
		if strings.HasPrefix(event, "docker ") {
			out = append(out, event)
		}
	}
	return out
}

func (r *hotfixPlaybookRun) eventsOf(host string) []string {
	var out []string
	for _, event := range r.events {
		if strings.HasPrefix(event, host+" ") {
			out = append(out, strings.TrimPrefix(event, host+" "))
		}
	}
	return out
}

func requireHotfixAnsible(t *testing.T) string {
	t.Helper()
	for _, tool := range []string{"ansible-playbook", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
				t.Fatalf("%s is required (PILOT_REQUIRE_CONTAINER_TESTS=1): %v", tool, err)
			}
			t.Skipf("%s not installed: %v", tool, err)
		}
	}
	python, _ := exec.LookPath("python3")
	return python
}

// runHotfixPlaybook builds the world in a temp dir and runs the real playbook in it. registry is the
// `manage_agents -l` text the manager answers with; numbered answers the n-th listing differently.
func runHotfixPlaybook(t *testing.T, hosts []hotfixHost, registry string, numbered map[int]string, args ...string) hotfixPlaybookRun {
	t.Helper()
	python := requireHotfixAnsible(t)
	root := t.TempDir()
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	playDir := filepath.Join(root, "play")
	// the real playbook and the real task files it includes, unmodified
	for _, rel := range []string{"wazuh-fim-agent-skew-hotfix.yml", "tasks/wazuh-agent-hotfix-deregister.yml", "tasks/wazuh-agent-hotfix-registry-check.yml"} {
		write(filepath.Join(playDir, rel), readHotfixFile(t, filepath.Join("../../playbooks/apply", rel)), 0o644)
	}
	write(filepath.Join(playDir, "files/wazuh-transaction.py"), hotfixFakeTransaction, 0o644)
	write(filepath.Join(playDir, "files/wazuh-agent-hotfix.py"), hotfixFakeHelper, 0o644)
	write(filepath.Join(root, "bin/docker"), hotfixFakeDocker, 0o755)
	write(filepath.Join(root, "registry.txt"), registry, 0o644)
	for n, text := range numbered {
		write(filepath.Join(root, fmt.Sprintf("registry.%d.txt", n)), text, 0o644)
	}
	write(filepath.Join(root, "events.log"), "", 0o644)

	groups := map[string][]string{}
	var inventory strings.Builder
	for _, h := range hosts {
		kind := "wazuh-fim"
		if h.state == nil {
			kind = "wazuh-manager"
		} else {
			data, err := json.Marshal(h.state)
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(root, "state", h.name+".json"), string(data), 0o644)
		}
		groups[kind] = append(groups[kind], h.name)
		for _, g := range h.groups {
			groups[g] = append(groups[g], h.name)
		}
		fmt.Fprintf(&inventory, "%s ansible_connection=local ansible_python_interpreter=%s ansible_remote_tmp=%s\n",
			h.name, python, filepath.Join(root, "remote", h.name))
	}
	inventory.WriteString("\n")
	for g, names := range groups {
		fmt.Fprintf(&inventory, "[%s]\n%s\n\n", g, strings.Join(names, "\n"))
	}
	write(filepath.Join(root, "inventory.ini"), inventory.String(), 0o644)

	// ansible_become=false: the real play says become: true, the test runs as an ordinary user. The
	// facts the playbook gates on are pinned so the result does not depend on the machine running it.
	cmdArgs := append([]string{"-i", filepath.Join(root, "inventory.ini"), filepath.Join(playDir, "wazuh-fim-agent-skew-hotfix.yml"),
		"-e", "ansible_become=false", "-e", "ansible_architecture=x86_64", "-e", "ansible_os_family=Debian"}, args...)
	cmd := exec.Command("ansible-playbook", cmdArgs...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOTFIX_TEST_DIR="+root,
		"ANSIBLE_CONFIG="+filepath.Join(root, "ansible.cfg"),
		"ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False",
		"ANSIBLE_INVENTORY_UNPARSED_WARNING=False", "ANSIBLE_DEPRECATION_WARNINGS=False",
		"ANSIBLE_HOME="+filepath.Join(root, "ansible-home"), "ANSIBLE_LOCAL_TEMP="+filepath.Join(root, "ansible-local"),
		"ANSIBLE_CACHE_PLUGIN=memory", "ANSIBLE_GATHER_SUBSET=min", "ANSIBLE_FORKS=1")
	write(filepath.Join(root, "ansible.cfg"), "[defaults]\nhost_key_checking = False\n", 0o644)
	out, runErr := cmd.Output()
	run := hotfixPlaybookRun{t: t, tasks: map[string][]string{}, skipped: map[string][]string{}, stdout: string(out)}
	if ee, ok := runErr.(*exec.ExitError); ok {
		run.rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var doc struct {
		Plays []struct {
			Play  struct{ Name string } `json:"play"`
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]map[string]any
			}
		}
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("no ansible JSON on stdout (rc=%d): %v\n%s", run.rc, err, out)
	}
	for _, play := range doc.Plays {
		for _, task := range play.Tasks {
			for host, result := range task.Hosts {
				if failed, _ := result["failed"].(bool); failed {
					msg, _ := result["msg"].(string)
					run.failures = append(run.failures, hotfixFailure{play: play.Play.Name, task: task.Task.Name, host: host, msg: msg})
				}
				if skipped, _ := result["skipped"].(bool); skipped {
					run.skipped[task.Task.Name] = append(run.skipped[task.Task.Name], host)
				} else {
					run.tasks[task.Task.Name] = append(run.tasks[task.Task.Name], host)
				}
				if msg, ok := result["msg"].(string); ok && strings.Contains(msg, "PILOT_HOTFIX_") {
					run.msgs = append(run.msgs, strings.Join(strings.Fields(msg), " "))
				}
			}
		}
	}
	events, err := os.ReadFile(filepath.Join(root, "events.log"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(events)), "\n") {
		if line != "" {
			run.events = append(run.events, line)
		}
	}
	return run
}

func agentRegistry(entries ...string) string {
	return "Available agents: \n" + strings.Join(entries, "")
}

func entry(id, name string) string { return fmt.Sprintf("   ID: %s, Name: %s, IP: any\n", id, name) }

const (
	playA = "Wazuh agent skew hotfix — observe which agents are newer than the manager, and refuse before any change (read-only)"
	playB = "Wazuh agent skew hotfix — remove the actionable agents, one at a time"
)

// refusedBeforeAnyChange asserts the whole class this change fixes: the run failed in Play A on the named
// task and host, and not one mutating call happened on any host or on the manager.
func (r hotfixPlaybookRun) refusedBeforeAnyChange(task, host string) {
	r.t.Helper()
	if r.rc == 0 || len(r.failures) == 0 {
		r.t.Fatalf("the run was not refused (rc=%d), events %v", r.rc, r.events)
	}
	var found bool
	for _, f := range r.failures {
		if f.play != playA {
			r.t.Errorf("failed in %q (%s on %s), want Play A so that nothing was changed first", f.play, f.task, f.host)
		}
		if strings.Contains(f.task, task) && (host == "" || f.host == host) {
			found = true
		}
	}
	if !found {
		r.t.Errorf("no failure of %q on %q in %+v", task, host, r.failures)
	}
	if m := r.mutations(); len(m) != 0 {
		r.t.Errorf("a refused run changed something: %v (all events %v)", m, r.events)
	}
}

// agentsWithOwnIDs is the shared fixture of the cases below: agent1 (ID 001) and agent2 (ID 002) both need
// the hotfix, mgr is the manager, each with the extra inventory groups given.
func agentsWithOwnIDs(agent1, agent2, manager []string) []hotfixHost {
	return []hotfixHost{
		{name: "mgr", groups: manager},
		{name: "agent1", groups: agent1, state: skewedState("agent1")},
		{name: "agent2", groups: agent2, state: agentState("4.14.9-1", true, false, map[string]string{"id": "002", "name": "agent2.example"})},
	}
}

var twoAgentRegistry = agentRegistry(entry("001", "agent1.example"), entry("002", "agent2.example"))

var (
	staging = []string{"staging"}
	prod    = []string{"prod"}
)

// Play B is serial, so a gate in its pre_tasks runs for the second host after the first host was already
// changed (AGENTS.md section 4.3). Every stage refusal below must come from Play A with not one mutating
// call, whichever host is the wrong one, and under --tags as well.
func TestWazuhAgentHotfixStageRefusalsComeBeforeTheFirstChange(t *testing.T) {
	requireHotfixAnsible(t)
	cases := []struct {
		name  string
		hosts []hotfixHost
		args  []string
		task  string
		host  string
	}{
		{"second host sits in the staging group but the run is sandbox", agentsWithOwnIDs(nil, staging, nil),
			[]string{"-e", "stage=sandbox"}, "stage must match this host's inventory environment group", "agent2"},
		{"first host is the wrong one", agentsWithOwnIDs(staging, nil, nil),
			[]string{"-e", "stage=sandbox"}, "stage must match this host's inventory environment group", "agent1"},
		{"same mixed inventory under a row tag", agentsWithOwnIDs(nil, staging, nil),
			[]string{"-e", "stage=sandbox", "--tags", "C5"}, "stage must match this host's inventory environment group", "agent2"},
		{"staging without the confirm flag", agentsWithOwnIDs(staging, staging, staging),
			[]string{"-e", "stage=staging"}, "staging or prod requires explicit confirm", ""},
		{"the manager is the one in staging", agentsWithOwnIDs(nil, nil, staging),
			[]string{"-e", "stage=sandbox"}, "stage must also match the manager", ""},
		{"staging hosts but a manager that is in no environment group", agentsWithOwnIDs(staging, staging, nil),
			[]string{"-e", "stage=staging", "-e", "confirm_staging=true"}, "stage must also match the manager", ""},
		{"prod with a stale staging attestation", agentsWithOwnIDs(prod, prod, prod),
			[]string{"-e", "stage=prod", "-e", "confirm_prod=true", "-e", "staging_attested_within_hours=200"}, "prod requires recent staging attestation", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runHotfixPlaybook(t, tc.hosts, twoAgentRegistry, nil, tc.args...).refusedBeforeAnyChange(tc.task, tc.host)
		})
	}
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// The passing twins of every refusal: the same inventories, made acceptable, run to the end. Without them
// the refusal tests could be passing because the harness never reaches a mutation at all.
func TestWazuhAgentHotfixTwinsOfTheRefusalsRunToCompletion(t *testing.T) {
	requireHotfixAnsible(t)
	cases := []struct {
		name     string
		hosts    []hotfixHost
		registry string
		args     []string
		removed  []string // hosts whose remove ran
		docker   []string // the manager registry removals
	}{
		{"all sandbox", agentsWithOwnIDs(nil, nil, nil), twoAgentRegistry, []string{"-e", "stage=sandbox"},
			[]string{"agent1", "agent2"}, []string{"docker remove 001", "docker remove 002"}},
		{"a staging host that needs nothing does not block a sandbox run",
			[]hotfixHost{{name: "mgr"}, {name: "agent1", state: skewedState("agent1")}, {name: "agent2", groups: staging, state: compatibleState}},
			twoAgentRegistry, []string{"-e", "stage=sandbox"}, []string{"agent1"}, []string{"docker remove 001"}},
		{"everything in staging with the confirm flag", agentsWithOwnIDs(staging, staging, staging), twoAgentRegistry,
			[]string{"-e", "stage=staging", "-e", "confirm_staging=true"}, []string{"agent1", "agent2"}, []string{"docker remove 001", "docker remove 002"}},
		{"everything in prod with a fresh attestation", agentsWithOwnIDs(prod, prod, prod), twoAgentRegistry,
			[]string{"-e", "stage=prod", "-e", "confirm_prod=true", "-e", "staging_attested_within_hours=12"}, []string{"agent1", "agent2"},
			[]string{"docker remove 001", "docker remove 002"}},
		{"a staging manager is not consulted when the run does not deregister", agentsWithOwnIDs(nil, nil, staging), twoAgentRegistry,
			[]string{"-e", "stage=sandbox", "-e", "pilot_hotfix_deregister=false"}, []string{"agent1", "agent2"}, nil},
		{"the confirmed list names every host that needs the hotfix", agentsWithOwnIDs(nil, nil, nil), twoAgentRegistry,
			[]string{"-e", `{"pilot_hotfix_confirmed_hosts": ["agent1", "agent2"]}`}, []string{"agent1", "agent2"},
			[]string{"docker remove 001", "docker remove 002"}},
		{"an ID the manager no longer lists is already removed", agentsWithOwnIDs(nil, nil, nil), agentRegistry(entry("002", "agent2.example")),
			[]string{"-e", "stage=sandbox"}, []string{"agent1", "agent2"}, []string{"docker remove 002"}},
		{"the registry spells the name in another case", agentsWithOwnIDs(nil, nil, nil),
			agentRegistry(entry("001", "AGENT1.Example"), entry("002", "agent2.example")), []string{"-e", "stage=sandbox"},
			[]string{"agent1", "agent2"}, []string{"docker remove 001", "docker remove 002"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			run := runHotfixPlaybook(t, tc.hosts, tc.registry, nil, tc.args...)
			if run.rc != 0 {
				t.Fatalf("rc=%d failures=%+v events=%v", run.rc, run.failures, run.events)
			}
			var removed []string
			for _, h := range tc.hosts {
				if h.state != nil && containsString(run.eventsOf(h.name), "remove") {
					removed = append(removed, h.name)
				}
			}
			if strings.Join(removed, ",") != strings.Join(tc.removed, ",") {
				t.Errorf("removed %v, want %v (events %v)", removed, tc.removed, run.events)
			}
			var docker []string
			for _, event := range run.docker() {
				if strings.HasPrefix(event, "docker remove") {
					docker = append(docker, event)
				}
			}
			if strings.Join(docker, ",") != strings.Join(tc.docker, ",") {
				t.Errorf("registry removals %v, want %v", docker, tc.docker)
			}
			// every Play A read comes before the first Play B event
			claim := -1
			for i, event := range run.events {
				if event == "transaction writer-claim" {
					claim = i
					break
				}
			}
			for i, event := range run.events {
				if strings.HasSuffix(event, " inspect") && claim >= 0 && i > claim {
					t.Errorf("an inspection ran after the first writer claim: %v", run.events)
				}
			}
		})
	}
}

// The manager-registry checks are made in Play A, so a registry that contradicts a host's client.keys
// refuses the whole run before the first host is touched: an entry under the recorded ID with another name,
// and the recorded name registered under another ID (with or without the recorded ID also listed).
func TestWazuhAgentHotfixRegistryRefusalsComeBeforeTheFirstChange(t *testing.T) {
	requireHotfixAnsible(t)
	cases := []struct {
		name     string
		registry string
		host     string
	}{
		{"another name under the recorded ID", agentRegistry(entry("001", "agent1.example"), entry("002", "somebody-else.example")), "agent2"},
		{"the recorded name under a second ID", agentRegistry(entry("001", "agent1.example"), entry("002", "agent2.example"), entry("007", "agent1.example")), "agent1"},
		{"the recorded ID is gone but the name lives on under another ID", agentRegistry(entry("002", "agent2.example"), entry("009", "agent1.example")), "agent1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			run := runHotfixPlaybook(t, agentsWithOwnIDs(nil, nil, nil), tc.registry, nil, "-e", "stage=sandbox")
			run.refusedBeforeAnyChange("an entry under the recorded ID carries the recorded name, and no other entry carries that name", tc.host)
			if removals := strings.Join(run.docker(), ","); strings.Contains(removals, "remove") {
				t.Errorf("the manager registry was touched: %s", removals)
			}
		})
	}
}

// Play A checked the registry, but it can change before Play B gets to a host. Play B repeats the same
// read-only check right before it removes the registration, so a registry that turned inconsistent in
// between refuses there: the agent was only quiesced (reversible), nothing was deregistered or purged, and
// the writer is still released.
func TestWazuhAgentHotfixRegistryIsCheckedAgainRightBeforeTheRemoval(t *testing.T) {
	requireHotfixAnsible(t)
	// listing 1 is Play A's check of agent1; listing 2 is Play B's re-check of agent1
	run := runHotfixPlaybook(t, agentsWithOwnIDs(nil, nil, nil)[:2], agentRegistry(entry("001", "agent1.example")),
		map[int]string{2: agentRegistry(entry("001", "somebody-else.example"))}, "-e", "stage=sandbox")
	if run.rc == 0 || len(run.failures) == 0 {
		t.Fatalf("rc=%d failures=%+v events=%v", run.rc, run.failures, run.events)
	}
	// the re-check fails first; the rescue then ends in its own fail task (a rescue never turns a failure into success)
	f := run.failures[0]
	if f.play != playB || f.host != "agent1" || !strings.Contains(f.task, "an entry under the recorded ID carries the recorded name") {
		t.Errorf("first failure = %+v, want Play B's re-check on agent1", f)
	}
	for _, other := range run.failures {
		if other.play != playB || other.host != "agent1" {
			t.Errorf("unexpected failure %+v", other)
		}
	}
	for _, event := range run.events {
		if strings.HasPrefix(event, "docker remove") || event == "agent1 remove" || event == "agent1 verify" {
			t.Errorf("%q ran although the re-check refused (events %v)", event, run.events)
		}
	}
	if !containsString(run.events, "agent1 quiesce") || run.events[len(run.events)-1] != "transaction writer-release" {
		t.Errorf("the agent should have been quiesced and the writer released: %v", run.events)
	}
}

// pilot hotfix hands the confirmed hosts to the apply run; a host that became actionable after the plan
// was confirmed refuses the run before anything is changed. Without the variable (a vm-target run) there
// is no restriction (the twin in TestWazuhAgentHotfixTwinsOfTheRefusalsRunToCompletion).
func TestWazuhAgentHotfixConfirmedHostsRefuseALateComerBeforeAnyChange(t *testing.T) {
	requireHotfixAnsible(t)
	t.Run("a skewed host that was not confirmed", func(t *testing.T) {
		t.Parallel()
		run := runHotfixPlaybook(t, agentsWithOwnIDs(nil, nil, nil), twoAgentRegistry, nil,
			"-e", `{"pilot_hotfix_confirmed_hosts": ["agent1"]}`)
		run.refusedBeforeAnyChange("in the plan the operator confirmed", "agent2")
		if msg := run.failures[0].msg; !strings.Contains(msg, "agent2") || !strings.Contains(msg, "Rerun `pilot hotfix") {
			t.Errorf("the refusal does not tell the operator what to do: %q", msg)
		}
	})
	t.Run("a residue host is changed too, so it needs to be confirmed as well", func(t *testing.T) {
		t.Parallel()
		hosts := append(agentsWithOwnIDs(nil, nil, nil)[:2], hotfixHost{name: "agent3", state: agentState("", false, true, nil)})
		runHotfixPlaybook(t, hosts, twoAgentRegistry, nil, "-e", `{"pilot_hotfix_confirmed_hosts": ["agent1"]}`).
			refusedBeforeAnyChange("in the plan the operator confirmed", "agent3")
	})
}

// The observation (what pilot hotfix runs to print the plan, before it asks for a stage or a confirmation)
// must not evaluate any apply gate, so a mixed-stage inventory can still be planned; it changes nothing and
// still reports each host's state.
func TestWazuhAgentHotfixObserveModeEvaluatesNoApplyGate(t *testing.T) {
	requireHotfixAnsible(t)
	run := runHotfixPlaybook(t, agentsWithOwnIDs(nil, staging, staging), twoAgentRegistry, nil,
		"-e", "pilot_hotfix_mode=observe", "-e", `{"pilot_hotfix_confirmed_hosts": []}`)
	if run.rc != 0 || len(run.failures) != 0 {
		t.Fatalf("observe refused: rc=%d %+v", run.rc, run.failures)
	}
	if m := run.mutations(); len(m) != 0 {
		t.Errorf("the observation changed something: %v", m)
	}
	for _, gate := range []string{"explicit confirm", "inventory environment group", "also match the manager", "recent staging attestation", "in the plan the operator confirmed"} {
		var ranOn, skippedOn []string
		for name, hosts := range run.tasks {
			if strings.HasPrefix(name, "Gate: ") && strings.Contains(name, gate) {
				ranOn = append(ranOn, hosts...)
			}
		}
		for name, hosts := range run.skipped {
			if strings.HasPrefix(name, "Gate: ") && strings.Contains(name, gate) {
				skippedOn = append(skippedOn, hosts...)
			}
		}
		if len(ranOn) != 0 || len(skippedOn) == 0 {
			t.Errorf("gate %q: ran on %v, skipped on %v; the observation must skip it everywhere", gate, ranOn, skippedOn)
		}
	}
	for _, event := range run.docker() {
		if event != "docker list" {
			t.Errorf("the observation made a manager call that is not a read-only listing: %q", event)
		}
	}
	got := strings.Join(run.msgs, "\n")
	for _, want := range []string{"PILOT_HOTFIX_MANAGER host=mgr version=4.14.1", "PILOT_HOTFIX_STATE host=agent1 installed=4.14.9-1 skewed=true residue=false registration=001:agent1.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("the observation did not report %q:\n%s", want, got)
		}
	}
	// the observation still refuses what would make it unreliable: a registry that contradicts client.keys
	bad := runHotfixPlaybook(t, agentsWithOwnIDs(nil, nil, nil), agentRegistry(entry("001", "somebody-else.example"), entry("002", "agent2.example")), nil,
		"-e", "pilot_hotfix_mode=observe")
	bad.refusedBeforeAnyChange("an entry under the recorded ID carries the recorded name", "agent1")
}

// AGENTS.md section 4.4, the reverse direction: a step that must precede a mutation carries the mutation's
// tags, so a --tags run never reaches a mutation without the steps that guard it. --tags C6 (the manager
// registration) must still quiesce the agent first; --tags C5 (client.keys) must still deregister first.
func TestWazuhAgentHotfixTagsKeepEachGuardWithItsMutation(t *testing.T) {
	requireHotfixAnsible(t)
	one := agentsWithOwnIDs(nil, nil, nil)[:2]
	registry := agentRegistry(entry("001", "agent1.example"))
	cases := []struct {
		tag  string
		want []string // from the writer claim on
	}{
		{"C6", []string{"transaction writer-claim", "agent1 quiesce", "docker list", "docker remove 001", "docker list", "transaction writer-release"}},
		{"C5", []string{"transaction writer-claim", "agent1 quiesce", "docker list", "docker remove 001", "docker list", "agent1 remove", "agent1 verify", "transaction writer-release"}},
		{"C7", []string{"transaction writer-claim", "transaction writer-release"}},
	}
	for _, tc := range cases {
		t.Run(tc.tag, func(t *testing.T) {
			t.Parallel()
			run := runHotfixPlaybook(t, one, registry, nil, "-e", "stage=sandbox", "--tags", tc.tag)
			if run.rc != 0 {
				t.Fatalf("rc=%d failures=%+v events=%v", run.rc, run.failures, run.events)
			}
			claim := -1
			for i, event := range run.events {
				if event == "transaction writer-claim" {
					claim = i
					break
				}
			}
			if claim < 0 {
				t.Fatalf("no writer claim: %v", run.events)
			}
			if got := run.events[claim:]; strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("--tags %s ran\n  %v\nwant\n  %v", tc.tag, got, tc.want)
			}
		})
	}
}

// A residue host (no package, the audit plugin still running) is treated like any host that gets changed:
// the same gates, and a removal run that cleans it, with no registration to remove.
func TestWazuhAgentHotfixResidueHostIsGatedAndCleanedLikeAnyOther(t *testing.T) {
	requireHotfixAnsible(t)
	residue := agentState("", false, true, nil)
	t.Run("cleaned", func(t *testing.T) {
		t.Parallel()
		run := runHotfixPlaybook(t, []hotfixHost{{name: "mgr"}, {name: "left", state: residue}, {name: "fine", state: compatibleState}},
			agentRegistry(), nil, "-e", "stage=sandbox")
		if run.rc != 0 {
			t.Fatalf("rc=%d failures=%+v events=%v", run.rc, run.failures, run.events)
		}
		if got := strings.Join(run.eventsOf("left"), ","); got != "inspect,quiesce,remove,verify" {
			t.Errorf("residue host events = %s", got)
		}
		if got := strings.Join(run.eventsOf("fine"), ","); got != "inspect" {
			t.Errorf("a compatible host was touched: %s", got)
		}
		if len(run.docker()) != 0 {
			t.Errorf("a residue host has no registration, yet the manager was called: %v", run.docker())
		}
		if !strings.Contains(strings.Join(run.msgs, "\n"), "PILOT_HOTFIX_RESULT host=left outcome=removed residue=true registration=none") {
			t.Errorf("the result does not say this was a residue host:\n%s", strings.Join(run.msgs, "\n"))
		}
	})
	t.Run("refused by the stage cross-check before anything changes", func(t *testing.T) {
		t.Parallel()
		hosts := []hotfixHost{{name: "mgr"}, {name: "agent1", state: skewedState("agent1")}, {name: "left", groups: staging, state: residue}}
		runHotfixPlaybook(t, hosts, agentRegistry(entry("001", "agent1.example")), nil, "-e", "stage=sandbox").
			refusedBeforeAnyChange("stage must match this host's inventory environment group", "left")
	})
}

// The fake inspect above must say what the real helper's inspect says, or these tests prove nothing about
// the playbook's reads of it (AGENTS.md section 5.7).
func TestWazuhAgentHotfixFakeInspectHasTheRealHelpersKeys(t *testing.T) {
	hot := readHotfixFile(t, hotfixScriptPath)
	start := strings.Index(hot, "        return {'family': self.family,")
	if start < 0 {
		t.Fatal("cannot find inspect's return value")
	}
	block := hot[start : start+strings.Index(hot[start:], "}\n")]
	var real []string
	for _, m := range regexp.MustCompile(`'([a-z_]+)':`).FindAllStringSubmatch(block, -1) {
		real = append(real, m[1])
	}
	var fake []string
	for key := range skewedState("agent1") {
		fake = append(fake, key)
	}
	sort.Strings(real)
	sort.Strings(fake)
	if strings.Join(real, ",") != strings.Join(fake, ",") {
		t.Errorf("the helper's inspect keys %v differ from the fake's %v", real, fake)
	}
}
