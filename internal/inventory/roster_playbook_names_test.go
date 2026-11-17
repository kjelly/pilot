package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// loadFirstPlay is the first play of the real apply playbook file.
func loadFirstPlay(t *testing.T, file string) *yaml.Node {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "playbooks", "apply", file))
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Content[0].Content[0]
}

func scalarList(n *yaml.Node) []string {
	var out []string
	if n == nil {
		return out
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		out = append(out, n.Content[i].Value)
	}
	return out
}

// taskNames are the variable names a task defines: the keys of its set_fact
// (but cacheable), its register and the name of its include_vars, blocks
// included.
func taskNames(task *yaml.Node) []string {
	var out []string
	if task.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(task.Content); i += 2 {
		key, value := task.Content[i].Value, task.Content[i+1]
		switch key {
		case "set_fact", "ansible.builtin.set_fact":
			for _, name := range scalarList(value) {
				if name != "cacheable" {
					out = append(out, name)
				}
			}
		case "register":
			out = append(out, value.Value)
		case "include_vars", "ansible.builtin.include_vars":
			if name := yamlKey(value, "name"); name != nil {
				out = append(out, name.Value)
			}
		case "block", "rescue", "always":
			for _, child := range value.Content {
				out = append(out, taskNames(child)...)
			}
		}
	}
	return out
}

func preTaskIndex(t *testing.T, preTasks *yaml.Node, name string) int {
	t.Helper()
	for i, task := range preTasks.Content {
		if n := yamlKey(task, "name"); n != nil && n.Value == name {
			return i
		}
	}
	t.Fatalf("the playbook has no pre_task %q: update roster_playbook_names.go and the oracle with it", name)
	return -1
}

// definedBefore is the play's vars plus the names of the pre_tasks before index.
func definedBefore(play, preTasks *yaml.Node, index int) map[string]bool {
	set := nameSet(scalarList(yamlKey(play, "vars")))
	for _, task := range preTasks.Content[:index] {
		for _, name := range taskNames(task) {
			set[name] = true
		}
	}
	return set
}

// The names the check knows for each playbook are what the real playbook has
// defined when it first renders a roster string — read here from the playbook
// itself, so a changed pre_task, a new set_fact or a new play var fails this
// test until the lists (and, through the oracle test, Ansible's behaviour) are
// brought along.
func TestRosterPlaybookNamesMatchThePlaybooks(t *testing.T) {
	identity := loadFirstPlay(t, "freeipa-identity-apply.yml")
	identityPre := yamlKey(identity, "pre_tasks")
	// The three places the identity play first renders a roster string, and the
	// whole point of the lists: they see the same names.
	for site, task := range map[string]string{
		"the users' passwords (the first gate that loops over the users)": "Gate: canonical user objects are structurally valid",
		"the admin password, when the roster has no freeipa.server":       "Fill canonical roster freeipa.server for this reconcile",
		"the admin password, as ipa_admin_password's fallback":            "Normalize canonical FreeIPA settings",
	} {
		got := definedBefore(identity, identityPre, preTaskIndex(t, identityPre, task))
		if want := playbookDefinedNames(RosterConsumerFreeIPAIdentity); !reflect.DeepEqual(got, want) {
			t.Errorf("identity, %s: the playbook defines %v before %q; roster_playbook_names.go lists %v",
				site, sortedNameSet(got), task, sortedNameSet(want))
		}
	}

	nfs := loadFirstPlay(t, "freeipa-nfs-server-apply.yml")
	nfsPre := yamlKey(nfs, "pre_tasks")
	gate := "Gate: required roster and stage authorization"
	got := definedBefore(nfs, nfsPre, preTaskIndex(t, nfsPre, gate))
	if want := playbookDefinedNames(RosterConsumerFreeIPANFSServer); !reflect.DeepEqual(got, want) {
		t.Errorf("nfs-server: the playbook defines %v before %q; roster_playbook_names.go lists %v", sortedNameSet(got), gate, sortedNameSet(want))
	}

	if want := nameSet(sortedNameSet(playbookDefinedNames(RosterConsumerFreeIPAIdentity)), sortedNameSet(playbookDefinedNames(RosterConsumerFreeIPANFSServer))); !reflect.DeepEqual(RosterPlaybookKnownNames(), want) {
		t.Errorf("RosterPlaybookKnownNames is not the union of the two playbooks' names")
	}
}

// The facts RosterVarReferencesRenderedBy and RosterFreeIPAServerDeclared
// rest on are read from the playbooks too: the conditions and the gate that
// make each field render. They are checked against ansible-core by the oracle
// test; this one notices the playbook text changing first.
func TestRosterRenderSitesAreStillInThePlaybooks(t *testing.T) {
	identity := loadFirstPlay(t, "freeipa-identity-apply.yml")
	pre := yamlKey(identity, "pre_tasks")
	task := func(name string) *yaml.Node { return pre.Content[preTaskIndex(t, pre, name)] }
	whenText := func(n *yaml.Node) string {
		var b strings.Builder
		if w := yamlKey(n, "when"); w != nil {
			out, _ := yaml.Marshal(w)
			b.Write(out)
		}
		return b.String()
	}
	// RosterFreeIPAServerDeclared: the detect and fill-in tasks ask for an empty
	// trimmed string of default('')'d server, and the fill-in renders the whole
	// freeipa mapping with a recursive combine.
	const declared = `.server | default('') | string | trim | length == 0`
	if w := whenText(task("Detect FreeIPA server FQDN when roster omits freeipa.server")); !strings.Contains(w, declared) {
		t.Errorf("the hostname probe's condition no longer is %q:\n%s", declared, w)
	}
	fill, _ := yaml.Marshal(task("Fill canonical roster freeipa.server for this reconcile"))
	if !strings.Contains(string(fill), "combine") || !strings.Contains(string(fill), "recursive=True") {
		t.Errorf("the server fill-in no longer is a recursive combine over the freeipa mapping:\n%s", fill)
	}
	// RosterVarReferencesRenderedBy: ipa_admin_password falls back to the roster
	// with a boolean default, and the users' passwords render in a loop.
	settings, _ := yaml.Marshal(task("Normalize canonical FreeIPA settings"))
	if !strings.Contains(string(settings), "ipa_admin_password | default((freeipa_roster.freeipa.admin | default({})).password | default(''), true)") {
		t.Errorf("identity_admin_password no longer falls back to the roster's admin password the way the check assumes:\n%s", settings)
	}
	users, _ := yaml.Marshal(task("Gate: canonical user objects are structurally valid"))
	if !strings.Contains(string(users), "loop:") || !strings.Contains(string(users), "freeipa_roster.users") {
		t.Errorf("the user gate no longer loops over the roster's users:\n%s", users)
	}

	nfs := loadFirstPlay(t, "freeipa-nfs-server-apply.yml")
	nfsPre := yamlKey(nfs, "pre_tasks")
	gate, _ := yaml.Marshal(nfsPre.Content[preTaskIndex(t, nfsPre, "Gate: required roster and stage authorization")])
	if !strings.Contains(string(gate), "freeipa_roster.freeipa.admin.password | length >= 8") {
		t.Errorf("the NFS gate no longer renders freeipa.admin.password first:\n%s", gate)
	}
}
