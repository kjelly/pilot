package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The guard of the mixed run (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §8.4, D29). `pilot reconcile --engine golang --scope full` writes the users and groups of the
// roster itself and hands freeipa-identity-apply.yml `-e pilot_identity_users_groups_engine=go`,
// so that two ranges of the playbook's tasks do nothing: from "List existing IPA groups" to
// "Gate: every password this run set was accepted", and from "Ensure user group membership" to
// "Delete canonical groups explicitly marked absent". The SSH key block between them stays, since
// Go only reads SSH keys. Two things make that safe, and they are locked here:
//
//   - static: every task of the two ranges, and no other task, has the guard as the first
//     element of its `when`, so a task added to a range later cannot be left out and a task
//     outside it cannot be skipped by accident; the variable is an `-e` variable only, never
//     an inventory input;
//   - runtime, with real Ansible and a stateful fake `ipa`: with the variable `go`, under every
//     tag selection that reaches the ranges, each of their tasks is skipped, nothing mutates users or groups,
//     and the SSH key task still runs; with it unset (or `ansible`) the calls are the ones the
//     playbook made before the guard existed (a golden log recorded from that playbook).

const (
	engineVar        = "pilot_identity_users_groups_engine"
	engineGuard      = "pilot_identity_users_groups_engine | default('ansible') != 'go'"
	engineSSHKeyTask = "Set SSH public keys for users (declarative replace)"
	engineGateTask   = "Gate: the users/groups engine is ansible or go, and go brings the observation file"
)

var (
	engineSeg1 = [2]string{"List existing IPA groups", "Gate: every password this run set was accepted"}
	engineSeg2 = [2]string{"Ensure user group membership", "Delete canonical groups explicitly marked absent"}
	// engineSSHBlock is the SSH key block between the two ranges: it keeps running under `go`.
	engineSSHBlock = [2]string{"Resolve enrolled SSH key cache targets", "Acknowledge verified SSH key cache pairs"}
)

// identityPlays parses the playbook at path.
func identityPlays(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plays []map[string]any
	if err := yaml.Unmarshal(raw, &plays); err != nil {
		t.Fatal(err)
	}
	return plays
}

// identityReconcileBlock is the list of tasks of the private-Kerberos-cache block, where every
// reconcile task sits (issue #69).
func identityReconcileBlock(plays []map[string]any) ([]map[string]any, error) {
	tasks, _ := plays[0]["tasks"].([]any)
	for _, raw := range tasks {
		task, _ := raw.(map[string]any)
		if inner, ok := task["block"].([]any); ok && len(inner) > 20 {
			var out []map[string]any
			for _, r := range inner {
				if m, ok := r.(map[string]any); ok {
					out = append(out, m)
				}
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("the reconcile block (the private Kerberos cache block) is not in the playbook")
}

func taskName(task map[string]any) string {
	name, _ := task["name"].(string)
	return name
}

// engineRange returns the names of the tasks of block from the task called first to the task
// called last, both included, in playbook order.
func engineRange(block []map[string]any, rng [2]string) ([]string, error) {
	start, end := -1, -1
	for i, task := range block {
		switch taskName(task) {
		case rng[0]:
			if start != -1 {
				return nil, fmt.Errorf("the anchor %q is in the playbook twice", rng[0])
			}
			start = i
		case rng[1]:
			if end != -1 {
				return nil, fmt.Errorf("the anchor %q is in the playbook twice", rng[1])
			}
			end = i
		}
	}
	if start == -1 || end == -1 || end < start {
		return nil, fmt.Errorf("the range %q .. %q is not in the playbook (anchors found at %d and %d): the guard is anchored on these task names, so renaming one means updating this test", rng[0], rng[1], start, end)
	}
	var names []string
	for _, task := range block[start : end+1] {
		names = append(names, taskName(task))
	}
	return names, nil
}

// whenList is a task's `when` as a list of conditions.
func whenList(task map[string]any) []string {
	switch w := task["when"].(type) {
	case nil:
		return nil
	case string:
		return []string{w}
	case bool:
		return []string{fmt.Sprint(w)}
	case []any:
		var out []string
		for _, c := range w {
			out = append(out, fmt.Sprint(c))
		}
		return out
	}
	return []string{fmt.Sprint(task["when"])}
}

// guardedFirst reports whether the guard is the first condition of the task's `when`: first,
// because the conditions after it read facts that only the skipped tasks set, and Ansible stops
// at the first condition that is false.
func guardedFirst(task map[string]any) bool {
	w := whenList(task)
	return len(w) > 0 && strings.TrimSpace(w[0]) == engineGuard
}

// mentionsEngineVar reports whether any of the task's `when` conditions names the variable.
func mentionsEngineVar(task map[string]any) bool {
	return slices.ContainsFunc(whenList(task), func(c string) bool { return strings.Contains(c, engineVar) })
}

// engineGuardProblems is the static half: what is wrong with the guard in the parsed playbook.
func engineGuardProblems(plays []map[string]any) []string {
	block, err := identityReconcileBlock(plays)
	if err != nil {
		return []string{err.Error()}
	}
	seg1, err1 := engineRange(block, engineSeg1)
	seg2, err2 := engineRange(block, engineSeg2)
	ssh, err3 := engineRange(block, engineSSHBlock)
	var problems []string
	for _, e := range []error{err1, err2, err3} {
		if e != nil {
			problems = append(problems, e.Error())
		}
	}
	if len(problems) > 0 {
		return problems
	}
	guarded := map[string]bool{}
	for _, n := range append(slices.Clone(seg1), seg2...) {
		guarded[n] = true
	}
	for _, task := range block {
		name := taskName(task)
		switch {
		case guarded[name] && !guardedFirst(task):
			problems = append(problems, fmt.Sprintf("%q is in a range that the Go engine writes (users and groups) and its `when` does not start with `%s` (its when: %q): a mixed run would run it too", name, engineGuard, whenList(task)))
		case !guarded[name] && mentionsEngineVar(task):
			problems = append(problems, fmt.Sprintf("%q is outside the two ranges and its `when` names %s: only the users and groups tasks are skipped under the Go engine", name, engineVar))
		}
	}
	for _, name := range ssh {
		for _, task := range block {
			if taskName(task) == name && mentionsEngineVar(task) {
				problems = append(problems, fmt.Sprintf("%q is in the SSH key block, which keeps running under the Go engine (Go only reads SSH keys)", name))
			}
		}
	}
	// The ranges do not overlap the SSH block.
	for _, n := range ssh {
		if guarded[n] {
			problems = append(problems, fmt.Sprintf("%q is in the SSH key block and in a guarded range", n))
		}
	}
	// The gate: it is a pre_task, `always`, and says what the spec says.
	pre, _ := plays[0]["pre_tasks"].([]any)
	var gate map[string]any
	for _, raw := range pre {
		if task, ok := raw.(map[string]any); ok && taskName(task) == engineGateTask {
			gate = task
		}
	}
	switch {
	case gate == nil:
		problems = append(problems, fmt.Sprintf("pre_tasks has no %q: a bad value of %s would be taken for `ansible`, and `go` without the observation file would skip users and groups with nobody to write them", engineGateTask, engineVar))
	default:
		tags, _ := gate["tags"].([]any)
		if len(tags) != 1 || fmt.Sprint(tags[0]) != "always" {
			problems = append(problems, "the engine gate is not tagged `always`: a --tags run would skip it")
		}
		raw, _ := yaml.Marshal(gate)
		for _, want := range []string{"['ansible', 'go']", "pilot_identity_auth_cache_output"} {
			if !strings.Contains(string(raw), want) {
				problems = append(problems, "the engine gate does not check "+want)
			}
		}
		if _, ok := gate["when"]; ok {
			problems = append(problems, "the engine gate has a `when`: it must refuse in every run")
		}
	}
	// Nothing else of the play (its own vars, the other play-level places) declares it.
	vars, _ := plays[0]["vars"].(map[string]any)
	if _, ok := vars[engineVar]; ok {
		problems = append(problems, engineVar+" is declared in the play's vars: an `-e` variable only, so that nothing but pilot's own run switches users and groups off")
	}
	sort.Strings(problems)
	return problems
}

func TestRegression_IdentityUsersGroupsEngineGuard(t *testing.T) {
	plays := identityPlays(t, identityApplyPath)
	if problems := engineGuardProblems(plays); len(problems) != 0 {
		t.Fatalf("the Go-engine guard of the identity playbook:\n%s", strings.Join(problems, "\n"))
	}
	block, _ := identityReconcileBlock(plays)
	seg1, _ := engineRange(block, engineSeg1)
	seg2, _ := engineRange(block, engineSeg2)
	// The scan finds what it is meant to: the ranges are the ones of the spec (35 tasks at the time of
	// writing), not an empty range that would pass for nothing.
	if len(seg1) < 15 || len(seg2) < 15 {
		t.Fatalf("the ranges hold %d and %d tasks", len(seg1), len(seg2))
	}
}

// The variable is never an inventory input: a contract groupVars key, or a group_vars example line, would
// switch users and groups off in every run of the playbook.
func TestRegression_IdentityUsersGroupsEngineIsNotAnInventoryInput(t *testing.T) {
	var hits []string
	roots := []string{"../../contracts", "../../group_vars", "../../playbooks/apply/tasks", "../../playbooks/check", "../../playbooks/decommission", "../../playbooks/site.yml"}
	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			data, rerr := os.ReadFile(path)
			if rerr == nil && strings.Contains(string(data), engineVar) {
				hits = append(hits, path)
			}
			return nil
		})
	}
	if len(hits) != 0 {
		t.Fatalf("%s is named in %v: it is an `-e` variable of pilot's mixed run only, and the other playbooks must not read it (or an inventory file set it)", engineVar, hits)
	}
}

// The static check fails on what it is for.
func TestEngineGuardLintFiresOnItsCases(t *testing.T) {
	load := func(t *testing.T) []map[string]any { return identityPlays(t, identityApplyPath) }
	block := func(plays []map[string]any) []map[string]any {
		b, err := identityReconcileBlock(plays)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	byName := func(b []map[string]any, name string) map[string]any {
		for _, task := range b {
			if taskName(task) == name {
				return task
			}
		}
		t.Fatalf("no task %q", name)
		return nil
	}
	cases := []struct {
		name   string
		mutate func(t *testing.T, plays []map[string]any)
		want   string
	}{
		{"a task of the first range loses its guard", func(t *testing.T, p []map[string]any) {
			delete(byName(block(p), "Reconcile IPA group descriptions"), "when")
		}, `"Reconcile IPA group descriptions" is in a range that the Go engine writes`},
		{"a task of the second range loses its guard", func(t *testing.T, p []map[string]any) {
			byName(block(p), "Delete canonical groups explicitly marked absent")["when"] = "freeipa_roster.schema_version is defined"
		}, `"Delete canonical groups explicitly marked absent"`},
		{"the guard is not the first condition", func(t *testing.T, p []map[string]any) {
			task := byName(block(p), "Ensure canonical direct user membership")
			w := whenList(task)
			task["when"] = []any{w[1], w[0]}
		}, `"Ensure canonical direct user membership"`},
		{"a new task in a range", func(t *testing.T, p []map[string]any) {
			b := block(p)
			// Insert it into the live block list: the block is a slice of the parsed play.
			tasks := p[0]["tasks"].([]any)
			inner := tasks[0].(map[string]any)["block"].([]any)
			for i, raw := range inner {
				if taskName(raw.(map[string]any)) == "Ensure IPA users exist" {
					inner = slices.Insert(inner, i, any(map[string]any{"name": "A new users task", "ansible.builtin.command": map[string]any{"argv": []any{"true"}}}))
					break
				}
			}
			tasks[0].(map[string]any)["block"] = inner
			_ = b
		}, `"A new users task" is in a range that the Go engine writes`},
		{"a task of the SSH key block gets the guard", func(t *testing.T, p []map[string]any) {
			byName(block(p), "Acknowledge verified SSH key cache pairs")["when"] = []any{engineGuard, "not ansible_check_mode"}
		}, `"Acknowledge verified SSH key cache pairs"`},
		{"a task outside the ranges gets the guard", func(t *testing.T, p []map[string]any) {
			byName(block(p), "Look up canonical FreeIPA host objects")["when"] = engineGuard
		}, `"Look up canonical FreeIPA host objects" is outside the two ranges`},
		{"an anchor is renamed", func(t *testing.T, p []map[string]any) {
			byName(block(p), "List existing IPA groups")["name"] = "List the IPA groups"
		}, "is not in the playbook"},
		{"the gate is gone", func(t *testing.T, p []map[string]any) {
			pre := p[0]["pre_tasks"].([]any)
			var kept []any
			for _, raw := range pre {
				if taskName(raw.(map[string]any)) != engineGateTask {
					kept = append(kept, raw)
				}
			}
			p[0]["pre_tasks"] = kept
		}, "pre_tasks has no"},
		{"the gate is not always", func(t *testing.T, p []map[string]any) {
			for _, raw := range p[0]["pre_tasks"].([]any) {
				if task := raw.(map[string]any); taskName(task) == engineGateTask {
					task["tags"] = []any{"users"}
				}
			}
		}, "not tagged `always`"},
		{"the variable is declared in the play's vars", func(t *testing.T, p []map[string]any) {
			p[0]["vars"].(map[string]any)[engineVar] = "ansible"
		}, "declared in the play's vars"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plays := load(t)
			tc.mutate(t, plays)
			problems := strings.Join(engineGuardProblems(plays), "\n")
			if !strings.Contains(problems, tc.want) {
				t.Fatalf("problems = %q, want one containing %q", problems, tc.want)
			}
		})
	}
	t.Run("the real playbook is clean", func(t *testing.T) {
		if p := engineGuardProblems(load(t)); len(p) != 0 {
			t.Fatalf("%v", p)
		}
	})
}

// ---- runtime: the real tasks, real Ansible, a stateful fake `ipa` ----

// fakeIPAScript is a stateful stand-in for the `ipa` command: a small directory of users and
// groups in $FAKE_IPA_DIR/state.json that the commands the two ranges and the SSH key task send
// read and change, and every call logged. It answers in the shapes the tasks parse (the listings'
// "Number of entries returned" line, "Added group", "Modified user", "Number of members added 1",
// "group not found"); it fails an unknown call.
const fakeIPAScript = `#!/usr/bin/env python3
import json, os, sys
d = os.environ["FAKE_IPA_DIR"]
args = sys.argv[1:]
with open(d + "/calls.log", "a") as f:
    f.write(" ".join(args) + "\n")
st = json.load(open(d + "/state.json"))
def done(out="", rc=0, err=""):
    json.dump(st, open(d + "/state.json", "w"))
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(rc)
def value(prefix):
    for a in args:
        if a.startswith(prefix):
            return a[len(prefix):]
    return None
def listing(noun, label, names):
    s = "---------------\n%d %s matched\n---------------\n" % (len(names), noun)
    for n in sorted(names):
        s += "  %s: %s\n" % (label, n)
    return s + "\n----------------------------\nNumber of entries returned %d\n----------------------------\n" % len(names)
cmd = args[0]
name = args[1] if len(args) > 1 else ""
users, groups = st["users"], st["groups"]
if cmd == "group-find":
    done(listing("groups", "Group name", groups))
if cmd == "user-find":
    if "--disabled=True" in args:
        names = [u for u, v in users.items() if v.get("disabled")]
        done(listing("users", "User login", names), 0 if names else 1)
    done(listing("users", "User login", users))
if cmd == "group-add":
    if name in groups:
        done("", 1, 'ipa: ERROR: group with name "%s" already exists\n' % name)
    groups[name] = {"desc": value("--desc=") or "", "users": [], "groups": []}
    done('-----------\nAdded group "%s"\n-----------\n  Group name: %s\n' % (name, name))
if cmd == "group-mod":
    if name not in groups:
        done("", 2, "ipa: ERROR: %s: group not found\n" % name)
    desc = value("--desc=")
    if desc is None or desc == groups[name]["desc"]:
        done("", 1, "ipa: ERROR: no modifications to be performed\n")
    groups[name]["desc"] = desc
    done('Modified group "%s"\n' % name)
if cmd == "group-show":
    if name not in groups:
        done("", 2, "ipa: ERROR: %s: group not found\n" % name)
    g = groups[name]
    s = "  Group name: %s\n  Description: %s\n" % (name, g["desc"])
    if "--no-members" not in args:
        if g["users"]:
            s += "  Member users: %s\n" % ", ".join(g["users"])
        if g["groups"]:
            s += "  Member groups: %s\n" % ", ".join(g["groups"])
    done(s)
if cmd in ("group-add-member", "group-remove-member"):
    if name not in groups:
        done("", 2, "ipa: ERROR: %s: group not found\n" % name)
    kind, key = ("--users=", "users") if value("--users=") is not None else ("--groups=", "groups")
    member = value(kind)
    if cmd == "group-add-member":
        if member in groups[name][key]:
            done("  Group name: %s\n  Number of members added 0\n" % name, 1, "ipa: ERROR: %s: already a member\n" % member)
        groups[name][key].append(member)
        done("  Group name: %s\n  Number of members added 1\n" % name)
    if member not in groups[name][key]:
        done("  Number of members removed 0\n", 1, "ipa: ERROR: This entry is not a member\n")
    groups[name][key].remove(member)
    done("  Group name: %s\n  Number of members removed 1\n" % name)
if cmd == "group-del":
    if name not in groups:
        done("", 2, "ipa: ERROR: %s: group not found\n" % name)
    del groups[name]
    done('Deleted group "%s"\n' % name)
if cmd == "user-add":
    if name in users:
        done("", 1, 'ipa: ERROR: user with name "%s" already exists\n' % name)
    users[name] = {}
    done('Added user "%s"\n' % name)
if cmd == "user-mod":
    if name not in users:
        done("", 2, "ipa: ERROR: %s: user not found\n" % name)
    keys = [a[len("--sshpubkey="):] for a in args if a.startswith("--sshpubkey=")]
    if keys:
        keys = [k for k in keys if k]
        if keys == users[name].get("keys", []):
            done("", 1, "ipa: ERROR: no modifications to be performed\n")
        users[name]["keys"] = keys
    done('Modified user "%s"\n' % name)
if cmd in ("user-enable", "user-disable"):
    if name not in users:
        done("", 2, "ipa: ERROR: %s: user not found\n" % name)
    want_disabled = cmd == "user-disable"
    if bool(users[name].get("disabled")) == want_disabled:
        done("", 1, "ipa: ERROR: This entry is already %s\n" % ("disabled" if want_disabled else "enabled"))
    users[name]["disabled"] = want_disabled
    done('%s user account "%s"\n' % ("Disabled" if want_disabled else "Enabled", name))
if cmd == "user-del":
    if name not in users:
        done("", 2, "ipa: ERROR: %s: user not found\n" % name)
    del users[name]
    done('Deleted user "%s"\n' % name)
sys.stderr.write("fake ipa: unexpected call: %s\n" % " ".join(args))
sys.exit(99)
`

// engineRun is one run of the extracted tasks.
type engineRun struct {
	rc     int
	raw    string
	status map[string]string // task name -> skipped | ok | changed | failed
	calls  []string          // what the fake ipa was called with, in order
	passwd []string          // the users a replaced `ipa passwd` was reached for
}

const (
	engineFixturePassword = "Roster-Initial-1" // the test password of the other identity regressions: never a real one
)

// engineTasks returns the tasks the runtime test runs: both ranges and the SSH key task, with the
// password lookup and `ipa passwd` replaced as the password regression does (a captured user-show
// for the lookup, a debug line for the reset), and `no_log` dropped so the results can be read.
func engineTasks(t *testing.T, path, fixtureDir string) []any {
	t.Helper()
	plays := identityPlays(t, path)
	block, err := identityReconcileBlock(plays)
	if err != nil {
		t.Fatal(err)
	}
	seg1, err := engineRange(block, engineSeg1)
	if err != nil {
		t.Fatal(err)
	}
	seg2, err := engineRange(block, engineSeg2)
	if err != nil {
		t.Fatal(err)
	}
	names := append(append(slices.Clone(seg1), seg2...), engineSSHKeyTask)
	var out []any
	for _, task := range namedTasks(plays[0]["tasks"].([]any), names) {
		c := map[string]any{}
		for k, v := range task {
			if k != "no_log" {
				c[k] = v
			}
		}
		switch taskName(c) {
		case identityPwLookupTask:
			c["ansible.builtin.command"] = map[string]any{"argv": []any{"cat", fixtureDir + "/{{ item.name }}.txt"}}
		case identityPwSetTask:
			for _, k := range []string{"ansible.builtin.shell", "ansible.builtin.command", "register", "changed_when", "failed_when"} {
				delete(c, k)
			}
			c["ansible.builtin.debug"] = map[string]any{"msg": "PASSWD {{ item.name }}"}
		}
		out = append(out, c)
	}
	if len(out) != len(names) {
		t.Fatalf("extracted %d tasks, want %d", len(out), len(names))
	}
	return out
}

// engineVars is a roster the tasks have something to do for in every one of their steps: groups to
// add, change, fill and drain, users to add, rename, disable and give a password and an SSH key,
// a user and a group to delete.
func engineVars() map[string]any {
	return map[string]any{
		"freeipa_roster": map[string]any{"schema_version": 3},
		"ipa_active_groups": []any{
			map[string]any{"name": "team-a", "desc": "Team A", "membership": map[string]any{"authoritative": true, "users": []any{"u1", "u2"}, "groups": []any{}}},
			map[string]any{"name": "team-b", "desc": "Team B", "membership": map[string]any{"authoritative": true, "users": []any{"u1"}, "groups": []any{"team-a"}}},
			map[string]any{"name": "team-old", "desc": "Changed description", "membership": map[string]any{"authoritative": true, "users": []any{"u1"}, "groups": []any{}}},
		},
		"ipa_active_users": []any{
			map[string]any{"name": "u1", "first": "User", "last": "One", "enabled": true, "password": engineFixturePassword, "preserve_existing": true, "force_password": false,
				"ssh_keys": []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEngineTestKeyOne u1"}},
			map[string]any{"name": "u2", "first": "User", "last": "Two", "enabled": false, "ssh_keys": []any{}},
			map[string]any{"name": "u3", "first": "User", "last": "Three", "enabled": true,
				"ssh_keys": []any{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEngineTestKeyThree u3"}},
		},
		"ipa_users":  []any{map[string]any{"name": "gone", "state": "absent"}},
		"ipa_groups": []any{map[string]any{"name": "team-retired", "state": "absent"}},
	}
}

// engineInitialState is the fake server before the run. Under the Go engine the users exist already,
// since the Go writer made them before this playbook runs; for the playbook's own run, u1 and u3 are
// missing, and a user and a group are there to be deleted.
func engineInitialState(goEngine bool) string {
	users := map[string]any{"admin": map[string]any{}, "u2": map[string]any{}, "gone": map[string]any{}}
	if goEngine {
		users = map[string]any{"admin": map[string]any{}, "u1": map[string]any{}, "u2": map[string]any{}, "u3": map[string]any{}}
	}
	state := map[string]any{
		"users": users,
		"groups": map[string]any{
			"admins":       map[string]any{"desc": "Account administrators group", "users": []any{"admin"}, "groups": []any{}},
			"team-old":     map[string]any{"desc": "An old description", "users": []any{"u2"}, "groups": []any{}},
			"team-retired": map[string]any{"desc": "To be deleted", "users": []any{}, "groups": []any{}},
		},
	}
	b, _ := json.Marshal(state)
	return string(b)
}

// runEngineTasks runs the tasks on localhost with the fake ipa; extra are ansible-playbook arguments.
func runEngineTasks(t *testing.T, playbook string, extraVars map[string]any, args ...string) engineRun {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "fixtures")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	noKey, err := os.ReadFile(userShowNoKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtures, "u1.txt"), noKey, 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ipa"), []byte(fakeIPAScript), 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "ipa")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "state.json"), []byte(engineInitialState(extraVars[engineVar] == "go")), 0o644); err != nil {
		t.Fatal(err)
	}
	// The playbook sits next to the tasks directory of the real one, for the include of the group
	// history marker.
	play := filepath.Join(dir, "play")
	if err := os.MkdirAll(play, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mustAbs(t, "../../playbooks/apply/tasks"), filepath.Join(play, "tasks")); err != nil {
		t.Fatal(err)
	}
	vars := engineVars()
	for k, v := range extraVars {
		vars[k] = v
	}
	body, err := yaml.Marshal([]map[string]any{{
		"name": "the users and groups range", "hosts": "localhost", "connection": "local", "gather_facts": false, "become": false,
		"vars": vars, "tasks": engineTasks(t, playbook, fixtures),
	}})
	if err != nil {
		t.Fatal(err)
	}
	pb := filepath.Join(play, "engine.yml")
	if err := os.WriteFile(pb, body, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", append([]string{"-i", "localhost,", pb}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_STDOUT_CALLBACK=json", "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False",
		"ANSIBLE_INVENTORY_UNPARSED_WARNING=False", "ANSIBLE_PYTHON_INTERPRETER=/usr/bin/python3",
		"FAKE_IPA_DIR="+state, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, runErr := cmd.Output()
	res := engineRun{raw: string(out) + stderr.String(), status: map[string]string{}}
	if ee, ok := runErr.(*exec.ExitError); ok {
		res.rc = ee.ExitCode()
	} else if runErr != nil {
		t.Fatalf("ansible-playbook did not run: %v", runErr)
	}
	var cb struct {
		Plays []struct {
			Tasks []struct {
				Task  struct{ Name string } `json:"task"`
				Hosts map[string]struct {
					Failed  bool `json:"failed"`
					Changed bool `json:"changed"`
					Skipped bool `json:"skipped"`
					Msg     any  `json:"msg"`
					Results []struct {
						Skipped bool `json:"skipped"`
						Msg     any  `json:"msg"`
					} `json:"results"`
				} `json:"hosts"`
			} `json:"tasks"`
		} `json:"plays"`
	}
	if err := json.Unmarshal(out, &cb); err != nil {
		t.Fatalf("parse the JSON callback output: %v\n%s", err, out)
	}
	for _, p := range cb.Plays {
		for _, task := range p.Tasks {
			for _, h := range task.Hosts {
				status := "ok"
				switch {
				case h.Failed:
					status = "failed"
				case h.Skipped:
					status = "skipped"
				case h.Changed:
					status = "changed"
				}
				res.status[task.Task.Name] = status
				if m, ok := h.Msg.(string); ok && status != "failed" {
					if user, found := strings.CutPrefix(m, "PASSWD "); found {
						res.passwd = append(res.passwd, user)
					}
				}
				for _, r := range h.Results {
					if m, ok := r.Msg.(string); ok && !r.Skipped {
						if user, found := strings.CutPrefix(m, "PASSWD "); found {
							res.passwd = append(res.passwd, user)
						}
					}
				}
			}
		}
	}
	if raw, err := os.ReadFile(filepath.Join(state, "calls.log")); err == nil {
		res.calls = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	return res
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

// engineGolden is the call log (and the passwords reached) of the playbook before the guard existed,
// run over the same roster, the same fake and no variable: the baseline "unset behaves as today"
// is compared with. PILOT_IDENTITY_ENGINE_GOLDEN=update rewrites it from the playbook under test, which
// is how it was made, from the playbook of the commit before the guard.
const engineGolden = "testdata/freeipa-identity-users-groups-engine/ansible-calls.txt"

func engineGoldenText(res engineRun) string {
	return strings.Join(res.calls, "\n") + "\n--- passwords reached\n" + strings.Join(res.passwd, "\n") + "\n"
}

// mutationVerbs are the ipa commands that change a user or a group, but for the SSH key task's
// user-mod --sshpubkey. A listing or a lookup is not one, but under `go` those are skipped too.
var mutationVerbs = []string{"user-add", "user-mod", "user-del", "user-enable", "user-disable", "group-add", "group-mod", "group-del", "group-add-member", "group-remove-member"}

func isSSHKeyCall(call string) bool {
	return strings.HasPrefix(call, "user-mod ") && strings.Contains(call, "--sshpubkey=")
}

func TestRegression_IdentityUsersGroupsEngineRuntime(t *testing.T) {
	plays := identityPlays(t, identityApplyPath)
	block, _ := identityReconcileBlock(plays)
	seg1, _ := engineRange(block, engineSeg1)
	seg2, _ := engineRange(block, engineSeg2)
	guarded := append(slices.Clone(seg1), seg2...)

	// The baseline: no variable, no tags. It is the playbook as it ran before the guard.
	t.Run("the variable unset is what the playbook did before", func(t *testing.T) {
		res := runEngineTasks(t, identityApplyPath, nil)
		if res.rc != 0 {
			t.Fatalf("rc=%d\n%s", res.rc, tail(res.raw, 3000))
		}
		got := engineGoldenText(res)
		if os.Getenv("PILOT_IDENTITY_ENGINE_GOLDEN") == "update" {
			if err := os.MkdirAll(filepath.Dir(engineGolden), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(engineGolden, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("rewrote %s", engineGolden)
			return
		}
		want, err := os.ReadFile(engineGolden)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Fatalf("the calls changed with the variable unset:\n%s\nwant (the playbook before the guard):\n%s", got, want)
		}
		// Every guarded task ran at least once or skipped for its own reasons, none for the guard: the guarded tasks that
		// mutate did run.
		for _, task := range []string{"Ensure IPA groups exist", "Ensure IPA users exist", "Ensure canonical direct user membership", "Delete canonical users explicitly marked absent", "Delete canonical groups explicitly marked absent"} {
			if res.status[task] != "changed" {
				t.Errorf("%q was %q with the variable unset, want changed (the roster has work for it)", task, res.status[task])
			}
		}
		if !slices.Contains(res.passwd, "u1") {
			t.Errorf("the password of u1 was not reached with the variable unset: %v", res.passwd)
		}
	})

	t.Run("ansible is the same as unset", func(t *testing.T) {
		if os.Getenv("PILOT_IDENTITY_ENGINE_GOLDEN") == "update" {
			t.Skip("rewriting the golden")
		}
		res := runEngineTasks(t, identityApplyPath, map[string]any{engineVar: "ansible"})
		want, err := os.ReadFile(engineGolden)
		if err != nil {
			t.Fatal(err)
		}
		if res.rc != 0 || engineGoldenText(res) != string(want) {
			t.Fatalf("rc=%d, calls:\n%s\nwant:\n%s", res.rc, engineGoldenText(res), want)
		}
	})

	// The Go engine's run: under every selection, every task of the two ranges is skipped and nothing
	// mutates users or groups. The SSH key task runs where its tags select it, and does what it does.
	sshTags := map[string]bool{"": true, "users": true, "identity": true, "sshkeys": true}
	for _, tags := range []string{"", "users", "groups", "identity", "passwords", "C11", "sshkeys"} {
		name := "go, tags " + tags
		if tags == "" {
			name = "go, no tags"
		}
		t.Run(name, func(t *testing.T) {
			if os.Getenv("PILOT_IDENTITY_ENGINE_GOLDEN") == "update" {
				t.Skip("rewriting the golden")
			}
			var args []string
			if tags != "" {
				args = []string{"--tags", tags}
			}
			res := runEngineTasks(t, identityApplyPath, map[string]any{engineVar: "go"}, args...)
			if res.rc != 0 {
				t.Fatalf("rc=%d\n%s", res.rc, tail(res.raw, 3000))
			}
			for _, task := range guarded {
				// A task of a range that the tag selection does not reach is not in the output at all.
				if status, ran := res.status[task]; ran && status != "skipped" {
					t.Errorf("%q is %q under the Go engine: a mixed run would do the Go engine's work twice", task, status)
				}
			}
			for _, call := range res.calls {
				if isSSHKeyCall(call) {
					continue
				}
				kind := "a lookup or a listing of the ranges"
				for _, verb := range mutationVerbs {
					if strings.HasPrefix(call, verb+" ") {
						kind = "a users or groups mutation"
					}
				}
				t.Errorf("the Go engine's run called `ipa %s`, %s: nothing of the two ranges runs under it", call, kind)
			}
			if len(res.passwd) != 0 {
				t.Errorf("a password was reached under the Go engine: %v", res.passwd)
			}
			sshCalls := 0
			for _, call := range res.calls {
				if isSSHKeyCall(call) {
					sshCalls++
				}
			}
			switch {
			case sshTags[tags] && sshCalls != 3:
				t.Errorf("the SSH key task made %d calls under tags %q, want 3 (u1 and u3 have a key; u2's empty list is a call that clears): %v", sshCalls, tags, res.calls)
			case !sshTags[tags] && sshCalls != 0:
				t.Errorf("the SSH key task ran under tags %q, which do not select it: %v", tags, res.calls)
			}
			if sshTags[tags] && res.status[engineSSHKeyTask] == "skipped" {
				t.Errorf("the SSH key task was skipped under the Go engine: Go only reads keys, this playbook still sets them")
			}
		})
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}
