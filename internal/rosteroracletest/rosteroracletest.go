// Package rosteroracletest runs the real freeipa-identity-apply.yml and
// freeipa-nfs-server-apply.yml pre_tasks under ansible-playbook, on localhost,
// with no_log removed so Ansible says which variable it could not resolve. It
// is the oracle of the roster reference check (issue #165): the tests of
// internal/inventory and of cmd/pilot/cmd both compare pilot's verdict with
// what Ansible does with the same roster and variables, from one copy of the
// harness (AGENTS.md section 5.7). Test support only: nothing in the binary
// imports it.
package rosteroracletest

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"go.yaml.in/yaml/v3"
)

// ApplyDir is the repository's playbooks/apply directory.
func ApplyDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the rosteroracletest source")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "playbooks", "apply")
}

// RequireAnsiblePlaybook skips the test without ansible-playbook; with
// PILOT_REQUIRE_CONTAINER_TESTS=1 (CI) its absence is a failure.
func RequireAnsiblePlaybook(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		if os.Getenv("PILOT_REQUIRE_CONTAINER_TESTS") == "1" {
			t.Fatalf("required ansible-playbook not installed: %v", err)
		}
		t.Skipf("ansible-playbook not installed: %v", err)
	}
}

// UndefinedName matches the variable name in Ansible's "'x' is undefined".
var UndefinedName = regexp.MustCompile(`'([A-Za-z_][A-Za-z0-9_]*)' is undefined`)

// Play is one real apply playbook's pre_tasks as a play that runs on
// localhost: what stays of the playbook is only what the roster reaches before
// the first mutation.
type Play struct {
	File        string // playbooks/apply/<file>
	LastPreTask string // the last pre_task kept
	ExtraVars   []string
	// AdminGate: the playbook has a gate that renders the admin password with
	// `is defined` first, so an undefined reference in it fails the gate
	// ("Missing ipa_admin_password and canonical roster fallback") and does not
	// name the variable. The oracle reports it as AdminGateMarker.
	AdminGate string
	// AfterTasks is the YAML text of a list of tasks appended after LastPreTask: what an
	// oracle asks of the play's state at that point (IdentityCapture's dump).
	AfterTasks string
}

// AdminGateMarker stands for "an admin password reference is undefined" where
// Ansible does not name the variable.
const AdminGateMarker = "<admin password>"

var (
	// Identity is freeipa-identity-apply.yml up to its admin credential gate.
	Identity = Play{
		File:        "freeipa-identity-apply.yml",
		LastPreTask: "Gate: admin credential present (fail early, before any mutation)",
		AdminGate:   "Missing ipa_admin_password and canonical roster fallback",
	}
	// IdentityCapture is freeipa-identity-apply.yml up to and including the include
	// that captures every user's password.initial into ipa_users ("Normalize
	// canonical users and groups (shared with drift)"), the point at which the
	// password the playbook SENDS is rendered, followed by a task that writes, for
	// every user the passwd call would set a password for, what that call reads on
	// stdin: the same expression, in the same module, over ipa_users. (Not over
	// ipa_active_users: only ipa_users is what that include captured, and nothing
	// between it and the passwd call changes the password.) The files are
	// <oracle_out>/<n>.json, oracle_out being an -e variable of the run. The run's
	// play is not expected to fail: a password that does not render fails it
	// before the dump, which is what the harness reports.
	IdentityCapture = Play{
		File:        "freeipa-identity-apply.yml",
		LastPreTask: "Normalize canonical users and groups (shared with drift)",
		AfterTasks:  captureDump,
	}
	// NFS is freeipa-nfs-server-apply.yml up to the gate that renders the
	// roster's admin password.
	NFS = Play{
		File:        "freeipa-nfs-server-apply.yml",
		LastPreTask: "Gate: roster admin password matches the vault's ipa_admin_password",
		// The play gathers facts; the localhost harness does not.
		ExtraVars: []string{"ansible_os_family=Debian"},
	}
)

// captureDump writes what the identity playbook's passwd call would read on stdin for each
// user it sets a password for: `stdin: "{{ {'principal': item.name, 'password': item.password}
// | to_json }}"` of the "Set password for users that need one" task, as the command module's
// own stdin, over the users that task loops over (those with a password that is not none).
const captureDump = `
- name: "ORACLE: what the passwd call reads on stdin, per user"
  ansible.builtin.command:
    argv:
      - /bin/sh
      - -c
      - 'cat > "$0"'
      - "{{ oracle_out }}/{{ oracle_index }}.json"
    stdin: "{{ {'principal': item.name, 'password': item.password} | to_json }}"
  loop: "{{ ipa_users | selectattr('password', 'defined') | rejectattr('password', 'none') | list }}"
  loop_control:
    index_var: oracle_index
    label: "{{ item.name }}"
  changed_when: false
`

// stripNoLog removes every no_log from node, in place.
func stripNoLog(node *yaml.Node) {
	if node.Kind == yaml.MappingNode {
		kept := node.Content[:0]
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "no_log" {
				continue
			}
			kept = append(kept, node.Content[i], node.Content[i+1])
		}
		node.Content = kept
	}
	for _, child := range node.Content {
		stripNoLog(child)
	}
}

// YAMLKey is key's value in the mapping node, nil when it has none.
func YAMLKey(mapping *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1]
		}
	}
	return nil
}

func scalarNode(value string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
}

// WriteHarness writes the harness for play into dir: harness.yml, the
// include_tasks files its pre_tasks use (no_log removed) and the files/ dir
// the play's vars read. It fails the test when the playbook no longer has the
// task the harness stops after, so a rename cannot make the oracle vacuous.
func WriteHarness(t *testing.T, dir string, play Play) {
	t.Helper()
	applyDir := ApplyDir(t)
	data, err := os.ReadFile(filepath.Join(applyDir, play.File))
	if err != nil {
		t.Fatalf("the oracle needs the real playbook: %v", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	real := doc.Content[0].Content[0] // the first play
	preTasks := YAMLKey(real, "pre_tasks")
	cut := -1
	for i, task := range preTasks.Content {
		if name := YAMLKey(task, "name"); name != nil && name.Value == play.LastPreTask {
			cut = i
			break
		}
	}
	if cut < 0 {
		t.Fatalf("%s has no pre_task %q: update the oracle with the playbook", play.File, play.LastPreTask)
	}
	kept := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: append([]*yaml.Node{}, preTasks.Content[:cut+1]...)}
	if play.AfterTasks != "" {
		var extra yaml.Node
		if err := yaml.Unmarshal([]byte(play.AfterTasks), &extra); err != nil {
			t.Fatal(err)
		}
		kept.Content = append(kept.Content, extra.Content[0].Content...)
	}

	harness := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	add := func(key string, value *yaml.Node) {
		harness.Content = append(harness.Content, scalarNode(key), value)
	}
	add("name", scalarNode("roster reference oracle for "+play.File))
	add("hosts", scalarNode("localhost"))
	add("connection", scalarNode("local"))
	add("gather_facts", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "false"})
	if vars := YAMLKey(real, "vars"); vars != nil {
		add("vars", vars)
	}
	add("pre_tasks", kept)
	stripNoLog(harness)
	out, err := yaml.Marshal(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{harness}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "harness.yml"), out, 0o600); err != nil {
		t.Fatal(err)
	}

	// The include_tasks files of the kept pre_tasks, with no_log removed.
	var includes []string
	var collect func(*yaml.Node)
	collect = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "ansible.builtin.include_tasks" {
					if file := YAMLKey(n.Content[i+1], "file"); file != nil {
						includes = append(includes, file.Value)
					} else if n.Content[i+1].Kind == yaml.ScalarNode {
						includes = append(includes, n.Content[i+1].Value)
					}
				}
			}
		}
		for _, c := range n.Content {
			collect(c)
		}
	}
	collect(kept)
	for _, file := range includes {
		raw, err := os.ReadFile(filepath.Join(applyDir, file))
		if err != nil {
			t.Fatal(err)
		}
		var inc yaml.Node
		if err := yaml.Unmarshal(raw, &inc); err != nil {
			t.Fatal(err)
		}
		stripNoLog(&inc)
		body, err := yaml.Marshal(&inc)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, file)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := filepath.Abs(filepath.Join(applyDir, "files"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(files, filepath.Join(dir, "files")); err != nil {
		t.Fatal(err)
	}
}

// Env isolates ansible-playbook from the machine's configuration and
// gives the play's `hostname -f` an answer wherever the tests run.
func Env(t *testing.T, dir string) []string {
	t.Helper()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "hostname"), []byte("#!/bin/sh\necho ipa.oracle.test\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "ansible.cfg")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"ANSIBLE_CONFIG="+cfg,
		"ANSIBLE_HOME="+filepath.Join(dir, "home"),
		"ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"),
		"ANSIBLE_NOCOLOR=1",
		"ANSIBLE_LOCALHOST_WARNING=False",
		"ANSIBLE_INVENTORY_UNPARSED_WARNING=False",
		// The output has no_log removed and can quote roster values: it must
		// never reach a real controller log, whatever the machine configures.
		"ANSIBLE_LOG_PATH=",
	)
}

var taskLine = regexp.MustCompile(`TASK \[([^\]]*)\]`)

// Outcome is one run of the harness.
type Outcome struct {
	// OK: the play went through every pre_task.
	OK bool
	// AdminGate: the play's admin-credential gate fired, without naming a variable.
	AdminGate bool
	// Undefined is the variable Ansible named undefined, "" when it named none.
	Undefined string
	// Task is the task that failed.
	Task string
	// Output is everything ansible-playbook printed. It can quote what the
	// play renders: a caller must not print it where a roster value could leak.
	Output string
}

// Run runs the harness written in dir (WriteHarness) once, on rosterPath and
// the vars file varsPath, as `-e freeipa_roster_file=` and `-e @file`, with
// the play's own extra vars. An exit that is not a failure of the play (no
// ansible-playbook, a crash) fails the test.
func Run(t *testing.T, dir string, play Play, rosterPath, varsPath string) Outcome {
	t.Helper()
	return RunWith(t, dir, play, RunOptions{RosterPath: rosterPath, VarsPath: varsPath})
}

// RunOptions are the ways a run of the harness differs from Run's.
type RunOptions struct {
	RosterPath, VarsPath string
	// Inventory is the inventory file the play runs on (a host named localhost with
	// ansible_connection: local, and the group_vars and host_vars next to it); empty
	// is the inline `localhost,`.
	Inventory string
	// WorkDir is the working directory of ansible-playbook; empty is dir, where the
	// harness is, so the group_vars next to the playbook are the working directory's.
	WorkDir string
	// VaultPasswordFile is the ambient vault secret (ANSIBLE_VAULT_PASSWORD_FILE).
	VaultPasswordFile string
	// ExtraVars are more -e values, as pilot passes its own (target_group and the like).
	ExtraVars []string
}

// RunWith is Run with options.
func RunWith(t *testing.T, dir string, play Play, opts RunOptions) Outcome {
	t.Helper()
	inventory := opts.Inventory
	if inventory == "" {
		inventory = "localhost,"
	}
	args := []string{"-i", inventory, filepath.Join(dir, "harness.yml"), "-e", "@" + opts.VarsPath, "-e", "freeipa_roster_file=" + opts.RosterPath}
	for _, extra := range append(append([]string{}, play.ExtraVars...), opts.ExtraVars...) {
		args = append(args, "-e", extra)
	}
	cmd := exec.Command("ansible-playbook", args...)
	cmd.Dir = dir
	if opts.WorkDir != "" {
		cmd.Dir = opts.WorkDir
	}
	cmd.Env = Env(t, dir)
	if opts.VaultPasswordFile != "" {
		cmd.Env = append(cmd.Env, "ANSIBLE_VAULT_PASSWORD_FILE="+opts.VaultPasswordFile)
	}
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	// Every Ansible command runs while its log is held (TestAnsibleCommandsHoldTheLog);
	// Env sets an empty ANSIBLE_LOG_PATH, so there is no log, and the hold is a no-op.
	release, err := ansible.HoldCommandLog(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Run()
	release()
	res := Outcome{Output: out.String()}
	if err == nil {
		res.OK = true
		return res
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatal(err)
	}
	if i := strings.Index(res.Output, "fatal:"); i > 0 {
		if all := taskLine.FindAllStringSubmatch(res.Output[:i], -1); len(all) > 0 {
			res.Task = all[len(all)-1][1]
		}
	}
	if play.AdminGate != "" && strings.Contains(res.Output, play.AdminGate) {
		res.AdminGate = true
		return res
	}
	if m := UndefinedName.FindStringSubmatch(res.Output); m != nil {
		res.Undefined = m[1]
	}
	return res
}
