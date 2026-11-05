package identityreconcile

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const identityPlaybook = "playbooks/apply/freeipa-identity-apply.yml"

// The playbook tasks whose result FromRoster must reproduce.
const (
	normalizeUsersTask  = "Normalize canonical users for the compatibility reconciler"
	normalizeGroupsTask = "Normalize canonical groups for the compatibility reconciler"
	staleMembershipTask = "Compute stale canonical group membership"
)

// adapterRosters are rosters the validator accepts, each exercising other
// defaults. Every one must give the same desired state in Go and Ansible.
var adapterRosters = map[string]string{
	"declared and defaulted": validRoster,
	"explicit enabled, keys, empty membership": `
schema_version: 3
users:
  - {name: erin, state: disabled, enabled: false}
  - {name: finn, enabled: false}
  - name: gail
    password: {initial: "x-not-read"}
    ssh_keys:
      values:
        - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZ9+QE2iKNtS+LFb/lqfS8SSnYDXllLjMScjupDeT8Y gail@laptop
        - "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAINZ9+QE2iKNtS+LFb/lqfS8SSnYDXllLjMScjupDeT8Y  "
groups:
  - name: team-b
    category: team
    gid: 4200
    membership: {users: [erin, finn], groups: []}
  - name: role-b
    category: role
    description: Role B
    membership: {authoritative: true, groups: [team-b]}
  - {name: team-empty, category: team}
`,
}

// TestAdapterDefaultsMatchThePlaybook runs the playbook's own normalize
// tasks, and its authoritative-membership expressions, in a localhost play
// on the roster FromRoster reads, and compares the two (spec §10.1). The
// tasks are taken from the playbook, not copied, so a change there is
// compared here without editing this test.
func TestAdapterDefaultsMatchThePlaybook(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	tasks := playbookTasks(t, normalizeUsersTask, normalizeGroupsTask)
	members := membershipExpressions(t)
	for name, doc := range adapterRosters {
		t.Run(name, func(t *testing.T) {
			root := roster(t, doc)
			d, err := FromRoster(root)
			if err != nil {
				t.Fatal(err)
			}
			got := runNormalize(t, root, tasks, members)
			compareUsers(t, d, got.Users)
			compareGroups(t, d, got.Groups, got.Members)
		})
	}
}

type ansibleUser struct {
	Name             string   `json:"name"`
	State            string   `json:"state"`
	First            *string  `json:"first"`
	Last             *string  `json:"last"`
	DisplayName      *string  `json:"display_name"`
	Email            *string  `json:"email"`
	UID              *int64   `json:"uid"`
	GID              *int64   `json:"gid"`
	LoginShell       *string  `json:"login_shell"`
	HomeDirectory    *string  `json:"home_directory"`
	Enabled          any      `json:"enabled"`
	Password         *string  `json:"password"`
	PreserveExisting any      `json:"preserve_existing"`
	SSHKeys          []string `json:"ssh_keys"`
}

type ansibleGroup struct {
	Name  string  `json:"name"`
	State string  `json:"state"`
	Desc  *string `json:"desc"`
	Type  *string `json:"type"`
	GID   *int64  `json:"gid"`
}

type ansibleMembers struct {
	Name          string   `json:"name"`
	Authoritative any      `json:"authoritative"`
	Users         []string `json:"users"`
	Groups        []string `json:"groups"`
}

type ansibleNormalized struct {
	Users   []ansibleUser    `json:"users"`
	Groups  []ansibleGroup   `json:"groups"`
	Members []ansibleMembers `json:"members"`
}

// playbookTasks returns the named tasks of the identity playbook without
// no_log (it would hide a failure) and tags.
func playbookTasks(t *testing.T, names ...string) []any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", identityPlaybook))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	found := map[string]map[string]any{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			if n, ok := x["name"].(string); ok && slices.Contains(names, n) {
				if _, dup := found[n]; dup {
					t.Fatalf("%s has two tasks named %q", identityPlaybook, n)
				}
				found[n] = x
			}
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	var out []any
	for _, n := range names {
		task, ok := found[n]
		if !ok {
			t.Fatalf("%s has no task %q: update this test with the playbook", identityPlaybook, n)
		}
		task = clone(task)
		delete(task, "no_log")
		delete(task, "tags")
		out = append(out, task)
	}
	return out
}

func clone(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// membershipExpr holds the playbook's expressions that decide, for one
// registered group lookup (item.item is the normalized group), whether its
// membership is authoritative and which users and groups it keeps.
type membershipExpr struct{ authoritative, users, groups string }

var memberExprPattern = regexp.MustCompile(`'(users|groups)': live_(?:users|groups) \| difference\((.+?)\),?\n`)

func membershipExpressions(t *testing.T) membershipExpr {
	t.Helper()
	task := playbookTasks(t, staleMembershipTask)[0].(map[string]any)
	var e membershipExpr
	when, _ := task["when"].([]any)
	for _, w := range when {
		if s, _ := w.(string); strings.Contains(s, "authoritative") {
			e.authoritative = s
		}
	}
	setFact, _ := task["ansible.builtin.set_fact"].(map[string]any)
	removals, _ := setFact["canonical_group_removals"].(string)
	for _, m := range memberExprPattern.FindAllStringSubmatch(removals, -1) {
		if m[1] == "users" {
			e.users = m[2]
		} else {
			e.groups = m[2]
		}
	}
	if e.authoritative == "" || e.users == "" || e.groups == "" {
		t.Fatalf("%q no longer has the expected shape (%+v): update this test with the playbook", staleMembershipTask, e)
	}
	return e
}

func runNormalize(t *testing.T, root map[string]any, tasks []any, m membershipExpr) ansibleNormalized {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "normalized.json")
	members := "{{ ipa_identity_members + [{'name': item.item.name, " +
		"'authoritative': (" + m.authoritative + "), " +
		"'users': (" + m.users + "), " +
		"'groups': (" + m.groups + ")}] }}"
	play := []any{map[string]any{
		"hosts":        "localhost",
		"connection":   "local",
		"gather_facts": false,
		"tasks": append(append([]any{
			map[string]any{"name": "start", "ansible.builtin.set_fact": map[string]any{"ipa_users": []any{}, "ipa_groups": []any{}, "ipa_identity_members": []any{}}},
		}, tasks...),
			map[string]any{
				"name":                     "membership as the prune task reads it",
				"ansible.builtin.set_fact": map[string]any{"ipa_identity_members": members},
				"loop":                     "{{ ipa_groups | selectattr('state', 'ne', 'absent') | list }}",
				"loop_control":             map[string]any{"loop_var": "group"},
				"vars":                     map[string]any{"item": map[string]any{"item": "{{ group }}"}},
			},
			map[string]any{
				"name": "dump",
				"ansible.builtin.copy": map[string]any{
					"content": "{{ {'users': ipa_users, 'groups': ipa_groups, 'members': ipa_identity_members} | to_json }}\n",
					"dest":    out,
				},
			}),
	}}
	pb, err := yaml.Marshal(play)
	if err != nil {
		t.Fatal(err)
	}
	vars, err := json.Marshal(map[string]any{"freeipa_roster": root})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"play.yml": pb, "vars.json": vars} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", "-e", "@vars.json", "play.yml")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False", "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var got ansibleNormalized
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	return got
}

func compareUsers(t *testing.T, d Desired, users []ansibleUser) {
	t.Helper()
	var absent []string
	var present []ansibleUser
	for _, u := range users {
		if u.State == "absent" {
			absent = append(absent, u.Name)
		} else {
			present = append(present, u)
		}
	}
	if !slices.Equal(absent, d.AbsentUsers) {
		t.Errorf("absent users: ansible %v, go %v", absent, d.AbsentUsers)
	}
	if len(present) != len(d.Users) {
		t.Fatalf("users: ansible %d, go %d", len(present), len(d.Users))
	}
	for i, a := range present {
		g := d.Users[i]
		check := func(field string, ansible, goValue any) {
			if !jsonEqual(ansible, goValue) {
				t.Errorf("user %s %s: ansible %s, go %s", a.Name, field, js(ansible), js(goValue))
			}
		}
		check("name", a.Name, g.Name)
		check("first", a.First, g.First)
		check("last", a.Last, g.Last)
		check("display_name", a.DisplayName, g.DisplayName)
		check("email", a.Email, g.Email)
		check("uid", a.UID, g.UID)
		check("gid", a.GID, g.GID)
		check("login_shell", a.LoginShell, g.Shell)
		check("home_directory", a.HomeDirectory, g.Home)
		check("enabled", a.Enabled, g.Enabled)
		check("password declared", a.Password != nil, g.HasInitialPassword)
		check("preserve_existing", a.PreserveExisting, g.PreserveExisting)
		check("ssh_keys managed", a.SSHKeys != nil, g.SSHKeys != nil)
		if a.SSHKeys != nil {
			var norm []string
			for _, k := range a.SSHKeys {
				if n, err := NormalizeSSHKey(k); err == nil {
					norm = appendUnique(norm, n)
				}
			}
			sort.Strings(norm)
			check("ssh_keys", nonNil(norm), nonNil(g.SSHKeys))
		}
	}
}

func compareGroups(t *testing.T, d Desired, groups []ansibleGroup, members []ansibleMembers) {
	t.Helper()
	var absent []string
	var present []ansibleGroup
	for _, g := range groups {
		if g.State == "absent" {
			absent = append(absent, g.Name)
		} else {
			present = append(present, g)
		}
	}
	if !slices.Equal(absent, d.AbsentGroups) {
		t.Errorf("absent groups: ansible %v, go %v", absent, d.AbsentGroups)
	}
	if len(present) != len(d.Groups) || len(members) != len(d.Groups) {
		t.Fatalf("groups: ansible %d (%d membership), go %d", len(present), len(members), len(d.Groups))
	}
	for i, a := range present {
		g, m := d.Groups[i], members[i]
		check := func(field string, ansible, goValue any) {
			if !jsonEqual(ansible, goValue) {
				t.Errorf("group %s %s: ansible %s, go %s", a.Name, field, js(ansible), js(goValue))
			}
		}
		check("name", a.Name, g.Name)
		check("description", a.Desc, g.Description)
		check("type", a.Type, g.Type)
		check("gid", a.GID, g.GID)
		check("authoritative", m.Authoritative, g.Authoritative)
		check("users", sortedUnique(m.Users), nonNil(g.Users))
		check("groups", sortedUnique(m.Groups), nonNil(g.Groups))
	}
}

func sortedUnique(s []string) []string {
	out := []string{}
	for _, v := range s {
		out = appendUnique(out, v)
	}
	sort.Strings(out)
	return out
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func jsonEqual(a, b any) bool { return js(a) == js(b) }
