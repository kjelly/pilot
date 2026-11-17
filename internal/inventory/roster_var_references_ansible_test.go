package inventory

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/rosteroracletest"
)

// The oracle for the roster reference check: real ansible-playbook, running the
// real freeipa-identity-apply.yml and freeipa-nfs-server-apply.yml pre_tasks
// (the plays' own vars and every pre_task up to the admin-credential gate,
// with no_log removed so Ansible says which variable it could not resolve).
// Go's verdict — which names a roster references that nothing defines, and
// which of them the consuming playbook renders — must equal the names Ansible
// reports as undefined, one fixture at a time (AGENTS.md §5.12: every
// fixture is either one Ansible fails on, or one it accepts).
//
// Skipped without ansible-playbook, as the other real-Ansible tests are; with
// PILOT_REQUIRE_CONTAINER_TESTS=1 (CI) its absence is a failure.

// The harness itself (the real pre_tasks under ansible-playbook) lives in
// rosteroracletest, which cmd/pilot/cmd's tests use too.
type oraclePlay = rosteroracletest.Play

var (
	identityOraclePlay = rosteroracletest.Identity
	nfsOraclePlay      = rosteroracletest.NFS
	yamlKey            = rosteroracletest.YAMLKey
)

const adminGateMarker = rosteroracletest.AdminGateMarker

func requireAnsiblePlaybook(t *testing.T) {
	t.Helper()
	rosteroracletest.RequireAnsiblePlaybook(t)
}

func writeOracleHarness(t *testing.T, dir string, play oraclePlay) {
	t.Helper()
	rosteroracletest.WriteHarness(t, dir, play)
}

func oracleEnv(t *testing.T, dir string) []string {
	t.Helper()
	return rosteroracletest.Env(t, dir)
}

// oracleFixture is a roster and the variables of one run.
type oracleFixture struct {
	name string
	// roster is the roster; %[1]s is the run's literal password.
	roster string
	// defined are the variables the vars file defines (with a value),
	// null the ones it defines with a null value.
	defined, null []string
	// attr are the variables that are mappings with a "sub" key (the roster
	// reads them as attr.sub), defined that way when the oracle defines them.
	attr []string
	// adminRefs are the variables the roster's admin password refers to.
	adminRefs []string
	// ipaAdmin is the vars file's ipa_admin_password: "" is not defined,
	// "empty" is defined and empty, "set" is defined and non-empty.
	ipaAdmin string
}

// oracleRoster is a roster the playbooks' structural gates accept, with the
// admin password and the users' initial passwords as given (YAML scalars),
// and freeipa.server declared or not.
func oracleRoster(server bool, admin string, users ...string) string {
	if server {
		return oracleRosterServer("ipa.oracle.test", admin, users...)
	}
	return oracleRosterServer("", admin, users...)
}

// oracleRosterServer is oracleRoster with freeipa.server as the given YAML
// scalar, or no freeipa.server key at all for "".
func oracleRosterServer(server, admin string, users ...string) string {
	var b strings.Builder
	b.WriteString("schema_version: 3\nfreeipa:\n")
	if server != "" {
		b.WriteString("  server: " + server + "\n")
	}
	b.WriteString("  admin:\n    principal: admin\n    password: " + admin + "\nusers:\n")
	for i, initial := range users {
		fmt.Fprintf(&b, "  - name: user%d\n    first: User\n    last: Number%d\n    password:\n      initial: %s\n", i, i, initial)
	}
	return b.String()
}

func (f oracleFixture) varsNames() map[string]bool {
	names := map[string]bool{}
	for _, name := range append(append([]string{}, f.defined...), f.null...) {
		names[name] = true
	}
	if f.ipaAdmin != "" {
		names["ipa_admin_password"] = true
	}
	return names
}

// oracleFacts are the render facts of fixture f for roster: the roster's own,
// and ipa_admin_password as the fixture's vars file defines it.
func oracleFacts(f oracleFixture, roster string) RosterRenderFacts {
	server, _ := RosterFreeIPAServerDeclared([]byte(roster))
	facts := RosterRenderFacts{SchemaVersionDefined: RosterSchemaVersionDefined([]byte(roster)), ServerDeclared: server, AdminPasswordProvided: RosterFactNo}
	if f.ipaAdmin == "set" {
		facts.AdminPasswordProvided = RosterFactYes
	}
	return facts
}

// goVerdict is the names pilot would report as missing for consumer.
func goVerdict(t *testing.T, consumer RosterVarConsumer, f oracleFixture, roster string) []string {
	t.Helper()
	refs, _, err := RosterSecretVarReferences([]byte(roster))
	if err != nil {
		t.Fatal(err)
	}
	facts := oracleFacts(f, roster)
	set := map[string]bool{}
	for _, ref := range MissingRosterVarReferencesFor(consumer, refs, facts, f.varsNames()) {
		if ref.Admin && consumer == RosterConsumerFreeIPAIdentity {
			set[adminGateMarker] = true
			continue
		}
		set[ref.Name] = true
	}
	return sortedNameSet(set)
}

// referencing is a YAML scalar whose value is a concatenation of {{ name }}
// for every name of set but the left out ones.
func referencing(set map[string]bool, leaveOut ...string) string {
	var b strings.Builder
	b.WriteString(`"`)
	for _, name := range sortedNameSet(set) {
		if slicesContains(leaveOut, name) {
			continue
		}
		b.WriteString("{{ " + name + " }}")
	}
	b.WriteString(`"`)
	return b.String()
}

func slicesContains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func sortedNameSet(set map[string]bool) []string {
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ansibleVerdict runs the harness until it stops failing: each failure names
// one undefined variable, which is then defined, so what is collected is every
// variable the play needed and nothing defined.
func ansibleVerdict(t *testing.T, play oraclePlay, f oracleFixture, roster, value string) []string {
	t.Helper()
	// Not t.TempDir(): its name carries the subtest's name, and a "{{" in a
	// path is a template to Ansible.
	dir, err := os.MkdirTemp("", "roster-oracle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	writeOracleHarness(t, dir, play)
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(roster), 0o600); err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	defined := append([]string{}, f.defined...)
	for round := 0; round < 12; round++ {
		// An empty -e file is "invalid extra vars data".
		var vars strings.Builder
		vars.WriteString("oracle_marker: 1\n")
		for _, name := range defined {
			if slicesContains(f.attr, name) {
				fmt.Fprintf(&vars, "%s: {sub: %q}\n", name, value)
				continue
			}
			fmt.Fprintf(&vars, "%s: %q\n", name, value)
		}
		for _, name := range f.null {
			fmt.Fprintf(&vars, "%s:\n", name)
		}
		switch f.ipaAdmin {
		case "set":
			fmt.Fprintf(&vars, "ipa_admin_password: %q\n", value)
		case "empty":
			vars.WriteString("ipa_admin_password: \"\"\n")
		}
		varsPath := filepath.Join(dir, "vars.yml")
		if err := os.WriteFile(varsPath, []byte(vars.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		res := rosteroracletest.Run(t, dir, play, rosterPath, varsPath)
		if res.OK {
			return sortedNameSet(found)
		}
		if res.AdminGate {
			// The admin gate named nothing: note it and define what the roster's
			// admin password refers to, so the run can go on.
			found[adminGateMarker] = true
			defined = append(defined, f.adminRefs...)
			continue
		}
		if res.Undefined == "" {
			t.Fatalf("the harness failed for a reason other than an undefined variable (task %q):\n%s", res.Task, res.Output)
		}
		if play.AdminGate != "" && slicesContains(f.adminRefs, res.Undefined) {
			found[adminGateMarker] = true
		} else {
			found[res.Undefined] = true
		}
		defined = append(defined, res.Undefined)
	}
	t.Fatalf("still failing after 12 rounds, found %v", sortedNameSet(found))
	return nil
}

// Go's verdict equals Ansible's, for every fixture, for the consumer that
// renders it. A fixture Ansible fails on has a non-empty verdict; one it
// accepts has an empty one: both directions are in the table.
func TestRosterRenderedFieldsMatchAnsible(t *testing.T) {
	requireAnsiblePlaybook(t)
	value := sentinelSecret(t)
	lit := `"` + value + `"`
	type row struct {
		consumer RosterVarConsumer
		play     oraclePlay
		f        oracleFixture
		wantAny  bool // Ansible must fail on it (guards the table's own meaning)
	}
	id, nfs := RosterConsumerFreeIPAIdentity, RosterConsumerFreeIPANFSServer
	idp, nfsp := identityOraclePlay, nfsOraclePlay
	// The names the play has defined at each site, read from the playbook itself
	// (not from the Go lists, so a name missing from them makes Go report what
	// Ansible resolves).
	identityPlay := loadFirstPlay(t, "freeipa-identity-apply.yml")
	identityPre := yamlKey(identityPlay, "pre_tasks")
	atIdentity := func(task string) map[string]bool {
		return definedBefore(identityPlay, identityPre, preTaskIndex(t, identityPre, task))
	}
	nfsPlay := loadFirstPlay(t, "freeipa-nfs-server-apply.yml")
	nfsPre := yamlKey(nfsPlay, "pre_tasks")
	nfsNames := definedBefore(nfsPlay, nfsPre, preTaskIndex(t, nfsPre, "Gate: required roster and stage authorization"))
	usersSite := atIdentity("Gate: canonical user objects are structurally valid")
	fallbackSite := atIdentity("Normalize canonical FreeIPA settings")
	fillInSite := atIdentity("Fill canonical roster freeipa.server for this reconcile")
	rows := []row{
		// ---- freeipa-identity: users' initial passwords ----
		{id, idp, oracleFixture{name: "a missing bare reference", roster: oracleRoster(true, lit, `"{{ u1 }}"`)}, true},
		{id, idp, oracleFixture{name: "every reference form", roster: oracleRoster(true, lit, `"{{ f1 }}"`, `"{{- f2 -}}"`, `"x{{f3}}"`, `"{{ f4.sub }}-{{ f5 }}"`, `"{{- f6 }}suffix"`), attr: []string{"f4"}}, true},
		{id, idp, oracleFixture{name: "an unquoted plain scalar", roster: oracleRoster(true, lit, `abc{{u1}}`)}, true},
		{id, idp, oracleFixture{name: "a state: absent user is rendered too", roster: "schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin: {principal: admin, password: " + lit + "}\nusers:\n  - name: gone\n    state: absent\n    password: {initial: \"{{ u1 }}\"}\n"}, true},
		{id, idp, oracleFixture{name: "an aliased password mapping", roster: "schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin: {principal: admin, password: " + lit + "}\nusers:\n  - {name: alice, first: A, last: B, password: &pw {initial: \"{{ u1 }}\"}}\n  - {name: bob, first: B, last: C, password: *pw}\n"}, true},
		{id, idp, oracleFixture{name: "a password mapping from a merge key", roster: "schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin: {principal: admin, password: " + lit + "}\nusers:\n  - {name: alice, first: A, last: B, password: &pw {initial: \"{{ u1 }}\"}}\n  - name: carol\n    first: C\n    last: D\n    password:\n      <<: *pw\n"}, true},
		{id, idp, oracleFixture{name: "one defined and one not", roster: oracleRoster(true, lit, `"{{ have }}-{{ lack }}"`), defined: []string{"have"}}, true},
		{id, idp, oracleFixture{name: "a defined variable", roster: oracleRoster(true, lit, `"{{ u1 }}"`), defined: []string{"u1"}}, false},
		{id, idp, oracleFixture{name: "a variable defined with a null value", roster: oracleRoster(true, lit, `"x{{ u1 }}"`), null: []string{"u1"}}, false},
		{id, idp, oracleFixture{name: "a default filter", roster: oracleRoster(true, lit, `"{{ u1 | default('') }}"`)}, false},
		{id, idp, oracleFixture{name: "literals, hostname and a mapping root", roster: oracleRoster(true, lit, `"{{ none }}{{ true }}{{ False }}{{ inventory_hostname }}"`)}, false},
		{id, idp, oracleFixture{name: "an !unsafe value", roster: oracleRoster(true, lit, `!unsafe "{{ u1 }}"`)}, false},
		{id, idp, oracleFixture{name: "a raw block", roster: oracleRoster(true, lit, `"{% raw %}{{ u1 }}{% endraw %}"`)}, false},
		{id, idp, oracleFixture{name: "a literal", roster: oracleRoster(true, lit, lit)}, false},

		// ---- freeipa-identity: the admin password ----
		{id, idp, oracleFixture{name: "admin reference, no ipa_admin_password", roster: oracleRoster(true, `"{{ adm }}"`, lit), adminRefs: []string{"adm"}}, true},
		{id, idp, oracleFixture{name: "admin reference, ipa_admin_password empty", roster: oracleRoster(true, `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "empty"}, true},
		{id, idp, oracleFixture{name: "admin reference, ipa_admin_password set, server declared: never rendered", roster: oracleRoster(true, `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, false},
		{id, idp, oracleFixture{name: "admin reference, ipa_admin_password set, no server: the server fill-in renders it", roster: oracleRoster(false, `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, true},
		{id, idp, oracleFixture{name: "admin reference defined", roster: oracleRoster(true, `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, defined: []string{"adm"}}, false},
		{id, idp, oracleFixture{name: "admin is {{ ipa_admin_password }}", roster: oracleRoster(true, `"{{ ipa_admin_password }}"`, lit), ipaAdmin: "set"}, false},
		{id, idp, oracleFixture{name: "admin is {{ ipa_admin_password }} but the vars file has none", roster: oracleRoster(true, `"{{ ipa_admin_password }}"`, lit), adminRefs: []string{"ipa_admin_password"}}, true},
		{id, idp, oracleFixture{name: "admin and users together", roster: oracleRoster(true, `"{{ adm }}"`, `"{{ u1 }}"`, `"{{ u2 }}"`), adminRefs: []string{"adm"}}, true},

		// ---- freeipa-nfs-server: the admin password only ----
		{nfs, nfsp, oracleFixture{name: "nfs admin reference", roster: oracleRoster(true, `"{{ adm }}"`, lit)}, true},
		{nfs, nfsp, oracleFixture{name: "nfs admin reference with ipa_admin_password set", roster: oracleRoster(true, `"{{ adm }}"`, lit), ipaAdmin: "set"}, true},
		{nfs, nfsp, oracleFixture{name: "nfs admin is {{ ipa_admin_password }}", roster: oracleRoster(true, `"{{ ipa_admin_password }}"`, lit), ipaAdmin: "set"}, false},
		{nfs, nfsp, oracleFixture{name: "nfs admin reference defined", roster: oracleRoster(true, `"{{ adm }}"`, lit), defined: []string{"adm"}}, false},
		{nfs, nfsp, oracleFixture{name: "nfs user references are never rendered", roster: oracleRoster(true, lit, `"{{ u1 }}"`, `"{{ u2 }}"`)}, false},
		{nfs, nfsp, oracleFixture{name: "nfs admin literal", roster: oracleRoster(true, lit, lit)}, false},

		// ---- freeipa.server: when the fill-in renders the admin password ----
		// (ipa_admin_password is set, so only the fill-in can render it.)
		{id, idp, oracleFixture{name: "server key missing: the fill-in renders the admin password", roster: oracleRosterServer("", `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, true},
		{id, idp, oracleFixture{name: "server: null counts as declared, the fill-in is skipped", roster: oracleRosterServer("null", `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, false},
		{id, idp, oracleFixture{name: "server: ~ counts as declared too", roster: oracleRosterServer("~", `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, false},
		{id, idp, oracleFixture{name: "server: empty string is not declared", roster: oracleRosterServer(`""`, `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, true},
		{id, idp, oracleFixture{name: "server: blank string is not declared", roster: oracleRosterServer(`"   "`, `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, true},
		{id, idp, oracleFixture{name: "server: a name is declared", roster: oracleRosterServer("ipa.oracle.test", `"{{ adm }}"`, lit), adminRefs: []string{"adm"}, ipaAdmin: "set"}, false},
		{id, idp, oracleFixture{name: "server: null, no ipa_admin_password: the fallback gate still renders it", roster: oracleRosterServer("null", `"{{ adm }}"`, lit), adminRefs: []string{"adm"}}, true},

		// ---- names the playbook defines for itself ----
		// Every name the playbook has defined when it first renders a field (read
		// from the playbook) is referenced from that field, in one roster: Ansible
		// must resolve every one of them, and Go must not report any. freeipa_roster (a reference to the roster itself) is left
		// out: it recurses, a failure of another kind than an undefined name.
		{id, idp, oracleFixture{name: "the names the play defines, in a user's password", roster: oracleRoster(true, lit, referencing(usersSite, "freeipa_roster"))}, false},
		{id, idp, oracleFixture{name: "the names the play defines, in the admin password the settings task renders", roster: oracleRoster(true, referencing(fallbackSite, "freeipa_roster"), lit), adminRefs: sortedNameSet(fallbackSite)}, false},
		{id, idp, oracleFixture{name: "the names the play defines, in the admin password the server fill-in renders", roster: oracleRosterServer("", referencing(fillInSite, "freeipa_roster"), lit), adminRefs: sortedNameSet(fillInSite), ipaAdmin: "set"}, false},
		{nfs, nfsp, oracleFixture{name: "the names the nfs play defines, in the admin password", roster: oracleRoster(true, referencing(nfsNames, "freeipa_roster"), lit)}, false},
		// What the identity play's settings task sets, and what comes after it, is
		// not visible to a roster string: undefined to Ansible, reported by Go. The
		// admin password through the settings task's default() is an empty password
		// that the admin gate refuses without naming (adminGateMarker).
		{id, idp, oracleFixture{name: "names set by the settings task are undefined in a user's password", roster: oracleRoster(true, lit, `"{{ identity_admin_principal }}{{ identity_admin_password }}{{ ipa_hbac_services }}{{ ipa_sudo_command_groups }}{{ ipa_active_users }}{{ ipa_active_groups }}{{ ipa_active_netgroups }}"`)}, true},
		{id, idp, oracleFixture{name: "a name set by the settings task is undefined in the admin password too", roster: oracleRoster(true, `"{{ ipa_hbac_services }}"`, lit), adminRefs: []string{"ipa_hbac_services"}}, true},
		{id, idp, oracleFixture{name: "a name set by the settings task is undefined for the server fill-in", roster: oracleRosterServer("", `"{{ ipa_hbac_services }}"`, lit), adminRefs: []string{"ipa_hbac_services"}, ipaAdmin: "set"}, true},
		{nfs, nfsp, oracleFixture{name: "a name only the identity play defines is undefined for the nfs play", roster: oracleRoster(true, `"{{ ipa_realm }}"`, lit)}, true},
		{id, idp, oracleFixture{name: "a name only the nfs play defines is undefined for the identity play", roster: oracleRoster(true, lit, `"{{ nfs_pseudo_root }}"`)}, true},
	}
	for _, r := range rows {
		r := r
		name := "identity/"
		if r.consumer == nfs {
			name = "nfs-server/"
		}
		t.Run(name+r.f.name, func(t *testing.T) {
			t.Parallel()
			want := ansibleVerdict(t, r.play, r.f, r.f.roster, value)
			if r.wantAny != (len(want) > 0) {
				t.Fatalf("the table says Ansible fails=%v, Ansible reported undefined %v", r.wantAny, want)
			}
			got := goVerdict(t, r.consumer, r.f, r.f.roster)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("pilot reports missing %v, Ansible reports undefined %v", got, want)
			}
		})
	}
}

// The implicit names: nothing in implicitVarNames may be an undefined variable
// to Ansible, and the capitalised literals and a handful of ordinary
// names must be (they are what the check reports).
func TestImplicitVarNamesAreNeverUndefinedInAnsible(t *testing.T) {
	requireAnsiblePlaybook(t)
	names := make([]string, 0, len(implicitVarNames)+4)
	for name := range implicitVarNames {
		names = append(names, name)
	}
	// One of each family the prefixes stand for that Ansible defines for a play.
	names = append(names, "ansible_check_mode", "ansible_version", "ansible_facts", "ansible_play_hosts", "role_names")
	sort.Strings(names)
	reported := []string{"TRUE", "FALSE", "NONE", "item", "loop", "stage_not_a_magic_name"}

	var play strings.Builder
	play.WriteString("- hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n")
	for _, name := range append(append([]string{}, names...), reported...) {
		fmt.Fprintf(&play, "    - name: \"probe %s\"\n      ansible.builtin.debug:\n        msg: \"{{ %s }}\"\n      ignore_errors: true\n", name, name)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "play.yml"), []byte(play.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", filepath.Join(dir, "play.yml"))
	cmd.Dir = dir
	// The default output, as ansibleVerdict reads it: the json stdout callback is
	// not part of ansible-core 2.19.15 (it moved to the ansible.posix collection),
	// and oracleEnv gives Ansible a home of its own where no collection is found.
	cmd.Env = oracleEnv(t, dir)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out.String())
	}
	// Each probe's block starts at its "TASK [probe NAME]" line; the name is
	// undefined when that block says so.
	undefined := map[string]bool{}
	blocks := strings.Split(out.String(), "TASK [probe ")
	if len(blocks) != len(names)+len(reported)+1 {
		t.Fatalf("expected %d probe tasks in the ansible-playbook output, found %d:\n%s", len(names)+len(reported), len(blocks)-1, out.String())
	}
	for _, block := range blocks[1:] {
		name, rest, ok := strings.Cut(block, "]")
		if !ok {
			t.Fatalf("unexpected ansible-playbook output:\n%s", out.String())
		}
		// Up to the next play-level banner, which only the last block reaches.
		if i := strings.Index(rest, "PLAY RECAP"); i >= 0 {
			rest = rest[:i]
		}
		if strings.Contains(rest, "'"+name+"' is undefined") {
			undefined[name] = true
		}
	}
	for _, name := range names {
		if undefined[name] {
			t.Errorf("%s is in the implicit names (or a family of them) but Ansible says it is undefined", name)
		}
		if !implicitVarName(name) {
			t.Errorf("%s is expected to be implicit and is not", name)
		}
	}
	for _, name := range reported {
		if !undefined[name] {
			t.Errorf("%s was expected to be undefined in Ansible (a name the check reports)", name)
		}
		if implicitVarName(name) {
			t.Errorf("%s is undefined in Ansible but the check treats it as implicit", name)
		}
	}
}
