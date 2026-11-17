package inventory

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// !unsafe marks everything below the node it tags (and a document it tags
// whole) as text that is never templated, and the loader builds one object per
// YAML node, so an alias or merge key can hand one scalar to an !unsafe part
// and a normal part (yamlTrust). This is the oracle for that: every row is a
// roster run through the real pre_tasks of the identity and NFS playbooks, and
//
//   - a row Ansible accepts or fails on for certain (the scalar is only in the
//     !unsafe part, or only in the normal one) must get exactly Ansible's
//     verdict from pilot;
//   - a row whose scalar is shared (ambiguous) must never be refused for a
//     variable Ansible does not fail on (pilot's set is a subset of Ansible's),
//     and its fields must be listed as unchecked, so the operator is told.
//
// The plain (not !unsafe) rows must trigger: a check that never fires proves
// nothing (AGENTS.md section 5.12). Skipped without ansible-playbook.
func TestRosterUnsafeScopeMatchesAnsible(t *testing.T) {
	requireAnsiblePlaybook(t)
	value := sentinelSecret(t)
	lit := `"` + value + `"`
	id, nfs := RosterConsumerFreeIPAIdentity, RosterConsumerFreeIPANFSServer
	idp, nfsp := identityOraclePlay, nfsOraclePlay
	const user0, user1, admin = "users[user0].password.initial", "users[user1].password.initial", "freeipa.admin.password"

	user := func(i int, pw string) string {
		return fmt.Sprintf("  - name: user%d\n    first: U\n    last: N\n    password: %s\n", i, pw)
	}
	// head is a roster whose admin password is a literal; headAdmin one whose
	// admin password is the given scalar.
	headAdmin := func(adminPassword string) string {
		return "schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin:\n    principal: admin\n    password: " + adminPassword + "\nusers:\n"
	}
	head := headAdmin(lit)
	ref := `{initial: "{{ m }}"}`
	adminRef := `"{{ madm }}"`

	type row struct {
		name      string
		consumer  RosterVarConsumer
		roster    string
		ipaAdmin  string
		adminRefs []string // the variables the admin password refers to (the identity admin gate does not name them)
		wantFail  []string // what Ansible reports undefined
		ambiguous bool
		unchecked []string // for an ambiguous row: the fields that must be listed
	}
	rows := []row{
		// ---- !unsafe at each level above the value: literal, certain ----
		{name: "control: the leaf is !unsafe", consumer: id, roster: head + user(0, `{initial: !unsafe "{{ m }}"}`), ipaAdmin: "set"},
		{name: "users: !unsafe", consumer: id, roster: strings.Replace(head, "users:", "users: !unsafe", 1) + user(0, ref), ipaAdmin: "set"},
		{name: "a user item is !unsafe", consumer: id, roster: head + "  - !unsafe\n    name: user0\n    first: U\n    last: N\n    password: " + ref + "\n", ipaAdmin: "set"},
		{name: "password: !unsafe", consumer: id, roster: head + user(0, `!unsafe `+ref), ipaAdmin: "set"},
		{name: "the whole document is !unsafe", consumer: id, roster: "--- !unsafe\n" + head + user(0, ref), ipaAdmin: "set"},
		{name: "freeipa: !unsafe (the admin password)", consumer: id, roster: "schema_version: 3\nfreeipa: !unsafe\n  server: ipa.oracle.test\n  admin:\n    principal: admin\n    password: " + adminRef + "\nusers:\n" + user(0, "{initial: "+lit+"}")},
		{name: "admin: !unsafe (the admin password)", consumer: id, roster: "schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin: !unsafe\n    principal: admin\n    password: " + adminRef + "\nusers:\n" + user(0, "{initial: "+lit+"}")},
		{name: "nfs: freeipa: !unsafe", consumer: nfs, roster: "schema_version: 3\nfreeipa: !unsafe\n  server: ipa.oracle.test\n  admin:\n    principal: admin\n    password: " + adminRef + "\nusers:\n" + user(0, "{initial: "+lit+"}")},
		{name: "nfs: admin: !unsafe", consumer: nfs, roster: "schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin: !unsafe\n    principal: admin\n    password: " + adminRef + "\nusers:\n" + user(0, "{initial: "+lit+"}")},
		{name: "nfs: the whole document is !unsafe", consumer: nfs, roster: "--- !unsafe\nschema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin:\n    principal: admin\n    password: " + adminRef + "\nusers:\n" + user(0, "{initial: "+lit+"}")},
		// An alias to an !unsafe mapping: every use of the node is !unsafe.
		{name: "an alias to an !unsafe password mapping", consumer: id, roster: head + user(0, `&pw !unsafe `+ref) + user(1, `*pw`), ipaAdmin: "set"},

		// ---- the plain forms must trigger ----
		{name: "control: no !unsafe, a user's password", consumer: id, roster: head + user(0, ref), ipaAdmin: "set", wantFail: []string{"m"}},
		{name: "control: no !unsafe, the admin password", consumer: id, roster: headAdmin(adminRef) + user(0, "{initial: "+lit+"}"), adminRefs: []string{"madm"}, wantFail: []string{"<admin password>"}},
		{name: "control: !unsafe on a sibling only", consumer: id, roster: head + user(0, ref) + user(1, `{initial: !unsafe "{{ m }}"}`), ipaAdmin: "set", wantFail: []string{"m"}},
		{name: "control: nfs without !unsafe", consumer: nfs, roster: headAdmin(adminRef) + user(0, "{initial: "+lit+"}"), wantFail: []string{"madm"}},

		// ---- shared between !unsafe and normal YAML: ambiguous, never refused ----
		{name: "a merge from an !unsafe anchor", consumer: id, roster: head + user(0, `&pw !unsafe `+ref) + user(1, `{<<: *pw}`), ipaAdmin: "set", ambiguous: true, unchecked: []string{user0, user1}},
		{name: "an !unsafe consumer merging a normal source", consumer: id, roster: head + user(0, `&pw `+ref) + user(1, `!unsafe {<<: *pw}`), ipaAdmin: "set", ambiguous: true, unchecked: []string{user0, user1}},
		{name: "a normal admin scalar aliased into an !unsafe user (freeipa first)", consumer: id,
			roster:   "schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin:\n    principal: admin\n    password: &p " + adminRef + "\nusers:\n" + user(0, `!unsafe {initial: *p}`),
			wantFail: []string{"madm"}, ambiguous: true, unchecked: []string{admin, user0}},
		{name: "an !unsafe user scalar aliased into the admin password (users first)", consumer: id,
			roster:    "schema_version: 3\nusers:\n" + user(0, `!unsafe {initial: &p "{{ madm }}"}`) + "freeipa:\n  server: ipa.oracle.test\n  admin:\n    principal: admin\n    password: *p\n",
			ambiguous: true, unchecked: []string{admin, user0}},

		// ---- the identity playbook ignores a roster that has no schema_version ----
		{name: "no schema_version: nothing of the roster is rendered", consumer: id, roster: strings.Replace(head, "schema_version: 3\n", "", 1) + user(0, ref), ipaAdmin: "set"},
		{name: "no schema_version: the server fill-in does not render the admin password either", consumer: id, roster: strings.Replace(strings.Replace(headAdmin(adminRef), "schema_version: 3\n", "", 1), "  server: ipa.oracle.test\n", "", 1) + user(0, "{initial: "+lit+"}"), ipaAdmin: "set"},
	}
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			play := idp
			if r.consumer == nfs {
				play = nfsp
			}
			f := oracleFixture{name: r.name, roster: r.roster, ipaAdmin: r.ipaAdmin, adminRefs: r.adminRefs}
			want := ansibleVerdict(t, play, f, r.roster, value)
			// What Ansible reports for a roster it fails on is a fact about
			// the table: a row that stops failing means the oracle changed.
			wantFail := append([]string(nil), r.wantFail...)
			if len(wantFail) == 0 {
				wantFail = nil
			}
			if !reflect.DeepEqual(want, wantFail) {
				t.Fatalf("the table says Ansible reports undefined %v, Ansible reported %v", wantFail, want)
			}
			got := goVerdict(t, r.consumer, f, r.roster)
			if !r.ambiguous {
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("pilot reports missing %v, Ansible reports undefined %v", got, want)
				}
				return
			}
			// Ambiguous: never a refusal Ansible would not back, and the
			// operator is told the fields were not judged.
			for _, name := range got {
				if !slicesContains(want, name) {
					t.Fatalf("pilot refuses %q, which Ansible does not fail on (Ansible: %v)", name, want)
				}
			}
			_, unchecked, err := RosterSecretVarReferences([]byte(r.roster))
			if err != nil {
				t.Fatal(err)
			}
			for _, field := range r.unchecked {
				if !slicesContains(unchecked, field) {
					t.Fatalf("%s is not listed as unchecked: %v", field, unchecked)
				}
			}
		})
	}
}
