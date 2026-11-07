package identityreconcile

import (
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// Issue #273: password, ssh_keys and membership were read only when they
// were mappings, so a value of another type was "not declared". For a group's
// membership that is an authoritative group with no members. These rows are
// the roster values inventory.ValidateRoster lets through (every row checks
// that first: a row another gate refuses would not prove the adapter) and the
// Go engine must refuse, naming the field and the roster object.

// pwSentinel stands in for a password in the rows that prove no value reaches
// an error message.
const pwSentinel = "pw-sentinel-not-a-real-secret"

func userDoc(field, value string) string {
	return "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob, " + field + ": " + value + "}\n"
}

func groupDoc(membership string) string {
	return "schema_version: 3\nusers: [{name: alice}]\ngroups:\n  - {name: team-a, category: team, membership: " + membership + "}\n"
}

// refusedByAdapter fails unless the roster passes the validator and
// FromRoster refuses it with every want.
func refusedByAdapter(t *testing.T, doc string, want ...string) {
	t.Helper()
	root := roster(t, doc)
	if v := inventory.ValidateRoster(root); len(v) != 0 {
		t.Fatalf("the validator already refuses this roster (%s: %s): the row would not reach the adapter", v[0].Rule, v[0].Detail)
	}
	_, err := FromRoster(root)
	if err == nil {
		t.Fatalf("FromRoster accepted:\n%s", doc)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("err = %q, want it to contain %q", err, w)
		}
	}
	if strings.Contains(err.Error(), pwSentinel) {
		t.Fatalf("the error carries the value: %q", err)
	}
}

func TestFromRosterRefusesANonMappingPasswordSshKeysOrMembership(t *testing.T) {
	// The Go type each YAML form decodes to, which the message names.
	forms := []struct{ name, yaml, typ string }{
		{"string", `"` + pwSentinel + `"`, "string"},
		{"list", "[" + pwSentinel + "]", "[]interface {}"},
		{"number", "5", "int"},
		{"bool", "true", "bool"},
	}
	for _, field := range []string{"password", "ssh_keys"} {
		for _, f := range forms {
			t.Run(field+" is a "+f.name, func(t *testing.T) {
				refusedByAdapter(t, userDoc(field, f.yaml),
					"users[1] (bob): "+field+" must be a mapping, not "+f.typ)
			})
		}
	}
	for _, f := range forms {
		t.Run("membership is a "+f.name, func(t *testing.T) {
			refusedByAdapter(t, groupDoc(f.yaml),
				"groups[0] (team-a): membership must be a mapping, not "+f.typ)
		})
	}
	// The case the issue names: the members written as the value itself.
	t.Run("membership is the list of its members", func(t *testing.T) {
		refusedByAdapter(t, groupDoc("[alice]"), "groups[0] (team-a): membership must be a mapping")
	})
	t.Run("ssh_keys is the list of its keys", func(t *testing.T) {
		refusedByAdapter(t, userDoc("ssh_keys", "[ssh-ed25519 AAAA key]"), "users[1] (bob): ssh_keys must be a mapping")
	})
}

// An unmanaged object must not be hidden behind the first one that is
// refused: the object that is wrong is the one named.
func TestFromRosterNamesTheObjectWithTheWrongType(t *testing.T) {
	refusedByAdapter(t,
		"schema_version: 3\nusers:\n  - {name: alice, password: {preserve_existing: true}}\n  - {name: bob}\n  - {name: carol, ssh_keys: nope}\n",
		"users[2] (carol): ssh_keys must be a mapping, not string")
	refusedByAdapter(t,
		"schema_version: 3\nusers: [{name: alice}]\ngroups:\n  - {name: team-a, category: team, membership: {users: [alice]}}\n  - {name: team-b, category: team, membership: [alice]}\n",
		"groups[1] (team-b): membership must be a mapping")
}

// password.initial is never loaded, but a value that is not a string is not
// a password: it is refused, by type only.
func TestFromRosterRefusesANonStringInitialPassword(t *testing.T) {
	for _, tc := range []struct{ name, yaml, typ string }{
		{"number", "5", "int"},
		{"bool", "true", "bool"},
		{"list", "[" + pwSentinel + "]", "[]interface {}"},
		{"mapping", "{value: " + pwSentinel + "}", "map[string]interface {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusedByAdapter(t, userDoc("password", "{initial: "+tc.yaml+"}"),
				"users[1] (bob): password: initial must be a string, not "+tc.typ+" (quote the password so it stays a string)")
		})
	}
}

func TestFromRosterRefusesANonBoolSshKeysAuthoritative(t *testing.T) {
	for _, tc := range []struct{ name, yaml, typ string }{
		{"string", `"no"`, "string"},
		{"number", "0", "int"},
		{"list", "[false]", "[]interface {}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusedByAdapter(t, userDoc("ssh_keys", "{authoritative: "+tc.yaml+"}"),
				"users[1] (bob): ssh_keys: authoritative must be true or false")
		})
	}
	// A literal false is the validator's to refuse; the adapter holds the
	// same line when it is called without it.
	t.Run("false", func(t *testing.T) {
		root := roster(t, userDoc("ssh_keys", "{authoritative: false}"))
		if v := inventory.ValidateRoster(root); len(v) == 0 || v[0].Rule != "user ssh_keys authoritative" {
			t.Fatalf("validator = %v, want the ssh_keys authoritative rule", v)
		}
		_, err := desiredUser(root["users"].([]any)[1].(map[string]any), "bob", "present")
		if err == nil || !strings.Contains(err.Error(), "ssh_keys: authoritative must be true") {
			t.Fatalf("err = %v", err)
		}
	})
}

// users and groups are lists; any other type used to be an empty one.
func TestFromRosterRefusesUsersOrGroupsThatAreNotLists(t *testing.T) {
	for _, key := range []string{"users", "groups"} {
		for _, tc := range []struct{ name, yaml, typ string }{
			{"string", "bob", "string"},
			{"mapping", "{name: bob}", "map[string]interface {}"},
			{"number", "5", "int"},
			{"bool", "true", "bool"},
		} {
			t.Run(key+" is a "+tc.name, func(t *testing.T) {
				refusedByAdapter(t, "schema_version: 3\n"+key+": "+tc.yaml+"\n", key+" must be a list, not "+tc.typ)
			})
		}
	}
}

// A null password, ssh_keys or membership is refused too, not read as "not
// declared": the playbook's gate `(item.X | default({})).keys()` fails on None
// (default() replaces an undefined value, not null), and for membership "not
// declared" is an authoritative group with no members. The forms: the explicit
// null, and the stanza left empty, the way it is written by hand.
func TestFromRosterRefusesANullPasswordSshKeysOrMembership(t *testing.T) {
	for _, field := range []string{"password", "ssh_keys"} {
		t.Run(field+" is ~", func(t *testing.T) {
			refusedByAdapter(t, userDoc(field, "~"), "users[1] (bob): "+field+" must be a mapping, not null")
		})
		t.Run(field+" is an empty stanza", func(t *testing.T) {
			refusedByAdapter(t, "schema_version: 3\nusers:\n  - name: alice\n  - name: bob\n    "+field+":\n",
				"users[1] (bob): "+field+" must be a mapping, not null")
		})
	}
	t.Run("membership is ~", func(t *testing.T) {
		refusedByAdapter(t, groupDoc("~"), "groups[0] (team-a): membership must be a mapping, not null")
	})
	t.Run("membership is an empty stanza", func(t *testing.T) {
		refusedByAdapter(t, "schema_version: 3\nusers:\n  - name: alice\ngroups:\n  - name: team-a\n    category: team\n    membership:\n",
			"groups[0] (team-a): membership must be a mapping, not null")
	})
	// The object that is wrong is the one named, also when only a later group
	// carries the empty stanza.
	t.Run("a later group", func(t *testing.T) {
		refusedByAdapter(t, "schema_version: 3\nusers:\n  - name: alice\ngroups:\n  - {name: team-a, category: team, membership: {users: [alice]}}\n  - name: team-b\n    category: team\n    membership:\n",
			"groups[1] (team-b): membership must be a mapping, not null")
	})
}

// A null inside these mappings is refused too, where Go would otherwise take
// its own default. How the playbook's expressions read it (ansible-core 2.19.2,
// the same expressions replayed; freeipa-identity-apply.yml line numbers):
//
//	key                       playbook with null                          Go before
//	membership.authoritative  :1600 `| default(true) | bool` = false:     true: prunes
//	                          no pruning
//	membership.users          :1662 subelements fails ("got None"), after prunes as undeclared
//	                          the removals (:1580, :1635) ran
//	membership.groups         :427 gate fails ("NoneType is not iterable") undeclared
//	ssh_keys.values           normalize `.get('values', none)` = absent   unmanaged
//	ssh_keys.authoritative    :391 gate fails (= false)                   true
//	password.preserve_existing :387 gate fails (`is boolean`)             default true
//	password.force_change     :386 gate fails (`is boolean`)              default false
//	password.initial          :1214 selection drops it = no password      no password
//
// Only password.initial stays accepted. The two password flags are refused by
// inventory.ValidateRoster first (rule "user password flag"), so they are
// exercised on desiredUser.
func TestFromRosterRefusesANullInsideThePasswordSshKeysAndMembershipMappings(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"membership.users", groupDoc("{users: ~}"), "groups[0] (team-a): membership: users must be a list, not null"},
		{"membership.groups", groupDoc("{groups: ~}"), "groups[0] (team-a): membership: groups must be a list, not null"},
		{"membership.authoritative", groupDoc("{authoritative: ~}"), "groups[0] (team-a): membership: authoritative must be true or false, not null"},
		{"ssh_keys.values", userDoc("ssh_keys", "{values: ~}"), "users[1] (bob): ssh_keys: values must be a list, not null"},
		{"ssh_keys.authoritative", userDoc("ssh_keys", "{authoritative: ~}"), "users[1] (bob): ssh_keys: authoritative must be true or false, not null"},
		// The way it is written by hand: the key with nothing after it.
		{"membership.users as an empty line", "schema_version: 3\nusers:\n  - name: alice\ngroups:\n  - name: team-a\n    category: team\n    membership:\n      users:\n",
			"groups[0] (team-a): membership: users must be a list, not null"},
		{"membership.authoritative as an empty line", "schema_version: 3\nusers:\n  - name: alice\ngroups:\n  - name: team-a\n    category: team\n    membership:\n      authoritative:\n      users: [alice]\n",
			"groups[0] (team-a): membership: authoritative must be true or false, not null"},
		{"ssh_keys.values as an empty line", "schema_version: 3\nusers:\n  - name: alice\n  - name: bob\n    ssh_keys:\n      values:\n",
			"users[1] (bob): ssh_keys: values must be a list, not null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusedByAdapter(t, tc.doc, tc.want)
		})
	}
	for _, key := range []string{"preserve_existing", "force_change"} {
		t.Run("password."+key+" on the adapter", func(t *testing.T) {
			_, err := desiredUser(map[string]any{"password": map[string]any{key: nil}}, "bob", "present")
			if err == nil || !strings.Contains(err.Error(), "password: "+key+" must be true or false, not null") {
				t.Fatalf("err = %v", err)
			}
		})
		t.Run("password."+key+" through FromRoster", func(t *testing.T) {
			// Refused by the validator, whose rule is not the adapter's.
			_, err := FromRoster(roster(t, userDoc("password", "{"+key+": ~}")))
			if err == nil || !strings.Contains(err.Error(), "user password flag") {
				t.Fatalf("err = %v, want the validator's password flag rule", err)
			}
		})
	}
}

func groupWith(field string) string {
	return "schema_version: 3\nusers: [{name: alice}]\ngroups:\n  - {name: team-a, category: team, " + field + "}\n"
}

// A null user or group scalar, and a null top-level users or groups, is
// refused too, except the keys Go does not manage (uid, gid, display_name,
// email: see TestFromRosterReadsANullIdOrDisplayNameAsNotManaged): Go used to
// read it as its default. How the playbook reads each
// (ansible-core 2.19.2, the normalize expressions of
// tasks/freeipa-identity-normalize-users-groups.yml and the consumers in
// freeipa-identity-apply.yml replayed; lines in the commit message):
//
//	enabled                 `None | bool` = false: ipa user-disable    Go: enabled
//	first, last             `--first=None`, `--last=None`              Go: the name
//	description             `--desc=None`                              Go: the name
//	login_shell             no --shell (FreeIPA's default)             Go: /bin/bash
//	home_directory          no --homedir                               Go: /home/<name>
//	state, type             gate fails (not in the list)               Go: present, posix
//	users, groups           `loop` must resolve to a list, not None    Go: empty list
//
// (uid, gid, display_name, email: `is none`, left out, the same as absent,
// and Go does not manage them either: accepted, not a row here.)
func TestFromRosterRefusesANullScalarOrList(t *testing.T) {
	str, boolean := "a string", "true or false"
	for _, tc := range []struct{ field, want string }{
		{"state", str}, {"enabled", boolean}, {"first", str}, {"last", str},
		{"login_shell", str}, {"home_directory", str},
	} {
		t.Run("user "+tc.field, func(t *testing.T) {
			refusedByAdapter(t, userDoc(tc.field, "~"),
				"users[1] (bob): "+tc.field+" must be "+tc.want+", not null (leave it out, or give a value)")
		})
	}
	for _, tc := range []struct{ field, want string }{
		{"state", str}, {"type", str}, {"description", str},
	} {
		t.Run("group "+tc.field, func(t *testing.T) {
			refusedByAdapter(t, groupWith(tc.field+": ~"),
				"groups[0] (team-a): "+tc.field+" must be "+tc.want+", not null (leave it out, or give a value)")
		})
	}
	// The way it is written by hand: the key with nothing after it.
	t.Run("user enabled as an empty line", func(t *testing.T) {
		refusedByAdapter(t, "schema_version: 3\nusers:\n  - name: alice\n  - name: bob\n    enabled:\n",
			"users[1] (bob): enabled must be true or false, not null")
	})
	t.Run("group type as an empty line", func(t *testing.T) {
		refusedByAdapter(t, "schema_version: 3\ngroups:\n  - name: team-a\n    category: team\n    type:\n",
			"groups[0] (team-a): type must be a string, not null")
	})
	for _, key := range []string{"users", "groups"} {
		t.Run(key+" is ~", func(t *testing.T) {
			refusedByAdapter(t, "schema_version: 3\n"+key+": ~\n", key+" must be a list, not null (leave it out, or write [])")
		})
		t.Run(key+" is an empty line", func(t *testing.T) {
			refusedByAdapter(t, "schema_version: 3\n"+key+":\n", key+" must be a list, not null")
		})
	}
}

// The keys Go does not manage when they are not declared (uid, gid,
// display_name, email, group gid) read a null as "not managed": the playbook
// leaves the argument out for null and for absent alike (`is none`,
// freeipa-identity-apply.yml :1006, :1128-:1134), and the roster editor writes
// a null for a blank integer field (edit_tui_roster.go, "留空 = 未設定"), so
// refusing it would refuse rosters pilot itself writes and the shipped example.
func TestFromRosterReadsANullIdOrDisplayNameAsNotManaged(t *testing.T) {
	for _, field := range []string{"uid", "gid", "display_name", "email"} {
		for _, form := range []struct{ name, doc string }{
			{"~", userDoc(field, "~")},
			{"an empty line", "schema_version: 3\nusers:\n  - name: alice\n  - name: bob\n    " + field + ":\n"},
			{"absent", userDoc2("")},
		} {
			t.Run("user "+field+" "+form.name, func(t *testing.T) {
				root := roster(t, form.doc)
				if v := inventory.ValidateRoster(root); len(v) != 0 {
					t.Fatalf("validator: %v", v)
				}
				d, err := FromRoster(root)
				if err != nil {
					t.Fatal(err)
				}
				bob := d.Users[1]
				if bob.UID != nil || bob.GID != nil || bob.DisplayName != nil || bob.Email != nil {
					t.Fatalf("not managed means nil: %+v", bob)
				}
			})
		}
	}
	for _, form := range []struct{ name, doc string }{
		{"~", groupWith("gid: ~")},
		{"an empty line", "schema_version: 3\ngroups:\n  - name: team-a\n    category: team\n    gid:\n"},
	} {
		t.Run("group gid "+form.name, func(t *testing.T) {
			g := desired(t, form.doc).Groups[0]
			if g.GID != nil {
				t.Fatalf("not managed means nil: %+v", g)
			}
		})
	}
	// A value is still read, and a wrong type is still refused.
	if bob := desired(t, userDoc("uid", "1200")).Users[1]; bob.UID == nil || *bob.UID != 1200 {
		t.Fatalf("uid = %v", bob.UID)
	}
	refusedByAdapter(t, userDoc("uid", `"12x"`), "uid must be a non-negative integer")
	refusedByAdapter(t, userDoc("email", "5"), "email must be a string")
}

// An entry with `state: absent` is not reconciled, but the playbook's gates
// (`.keys()` on password, ssh_keys and membership) loop over every entry, so
// Ansible refuses a wrong shape there too; Go checks the shape of these keys
// (nothing inside them) and refuses the same.
func TestFromRosterRefusesAWrongShapeOnAnAbsentEntry(t *testing.T) {
	for _, tc := range []struct{ name, doc, want string }{
		{"user password string", "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob, state: absent, password: \"" + pwSentinel + "\"}\n",
			"users[1] (bob): password must be a mapping, not string"},
		{"user password null", "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob, state: absent, password: ~}\n",
			"users[1] (bob): password must be a mapping, not null"},
		{"user ssh_keys list", "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob, state: absent, ssh_keys: [x]}\n",
			"users[1] (bob): ssh_keys must be a mapping, not []interface {}"},
		{"user ssh_keys null", "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob, state: absent, ssh_keys: ~}\n",
			"users[1] (bob): ssh_keys must be a mapping, not null"},
		{"group membership list", groupWith("state: absent, membership: [alice]"),
			"groups[0] (team-a): membership must be a mapping, not []interface {}"},
		{"group membership null", groupWith("state: absent, membership: ~"),
			"groups[0] (team-a): membership must be a mapping, not null"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refusedByAdapter(t, tc.doc, tc.want)
		})
	}
	// The shape is all that is checked: an absent entry with mappings, or
	// with none, is still a removal, and what is inside is not read.
	d := desired(t, "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob, state: absent, password: {}, ssh_keys: {values: ~}}\ngroups:\n  - {name: team-a, category: team, state: absent, membership: {users: ~}}\n")
	if len(d.AbsentUsers) != 1 || d.AbsentUsers[0] != "bob" || len(d.AbsentGroups) != 1 || d.AbsentGroups[0] != "team-a" {
		t.Fatalf("absent = %v %v", d.AbsentUsers, d.AbsentGroups)
	}
}

// The values that are accepted, and what they mean: an absent or empty
// section is "not declared" (the playbook's own default), a mapping is read.
func TestFromRosterAcceptsAbsentEmptyAndMappingSections(t *testing.T) {
	for _, tc := range []struct{ name, yaml string }{
		{"absent", ""},
		{"empty mapping", "password: {}"},
	} {
		t.Run("password "+tc.name, func(t *testing.T) {
			d := desired(t, userDoc2(tc.yaml))
			bob := d.Users[1]
			if bob.HasInitialPassword || !bob.PreserveExisting || bob.SSHKeys != nil {
				t.Fatalf("bob = %+v", bob)
			}
		})
	}
	t.Run("password mapping", func(t *testing.T) {
		bob := desired(t, userDoc("password", `{initial: "`+pwSentinel+`", preserve_existing: false}`)).Users[1]
		if !bob.HasInitialPassword || bob.PreserveExisting {
			t.Fatalf("bob = %+v", bob)
		}
	})
	t.Run("password with a null initial", func(t *testing.T) {
		if bob := desired(t, userDoc("password", "{initial: ~}")).Users[1]; bob.HasInitialPassword {
			t.Fatalf("a null initial declares no password: %+v", bob)
		}
	})
	for _, tc := range []struct{ name, yaml string }{
		{"absent", ""},
		{"empty mapping", "ssh_keys: {}"},
		{"only authoritative", "ssh_keys: {authoritative: true}"},
	} {
		t.Run("ssh_keys "+tc.name, func(t *testing.T) {
			if bob := desired(t, userDoc2(tc.yaml)).Users[1]; bob.SSHKeys != nil || bob.SSHKeysInvalid != 0 {
				t.Fatalf("an undeclared ssh_keys is unmanaged (nil): %+v", bob)
			}
		})
	}
	t.Run("ssh_keys mapping", func(t *testing.T) {
		bob := desired(t, userDoc("ssh_keys", "{authoritative: true, values: []}")).Users[1]
		if bob.SSHKeys == nil || len(bob.SSHKeys) != 0 {
			t.Fatalf("values: [] means clear (non-nil, empty): %#v", bob.SSHKeys)
		}
	})
	for _, tc := range []struct{ name, membership string }{
		{"absent", ""},
		{"empty mapping", "membership: {}"},
	} {
		t.Run("membership "+tc.name, func(t *testing.T) {
			doc := "schema_version: 3\nusers: [{name: alice}]\ngroups:\n  - {name: team-a, category: team}\n"
			if tc.membership != "" {
				doc = "schema_version: 3\nusers: [{name: alice}]\ngroups:\n  - {name: team-a, category: team, " + tc.membership + "}\n"
			}
			g := desired(t, doc).Groups[0]
			// Not declared means authoritative with no declared members:
			// the playbook's `membership | default({})`.
			if !g.Authoritative || g.UsersDeclared || g.GroupsDeclared || len(g.Users)+len(g.Groups) != 0 {
				t.Fatalf("team-a = %+v", g)
			}
		})
	}
	t.Run("membership mapping", func(t *testing.T) {
		g := desired(t, groupDoc("{authoritative: false, users: [alice]}")).Groups[0]
		if g.Authoritative || !g.UsersDeclared || len(g.Users) != 1 || g.Users[0] != "alice" {
			t.Fatalf("team-a = %+v", g)
		}
	})
	// Absent and [] are an empty roster; a null list is refused (TestFromRosterRefusesANullScalarOrList).
	t.Run("users and groups absent or empty", func(t *testing.T) {
		for _, doc := range []string{
			"schema_version: 3\nusers: []\ngroups: []\n",
			"schema_version: 3\n",
		} {
			d := desired(t, doc)
			if len(d.Users)+len(d.Groups) != 0 {
				t.Fatalf("%q: %+v", doc, d)
			}
		}
	})
}

// userDoc2 is a roster with alice and bob, bob carrying the given field (or
// none when it is empty).
func userDoc2(field string) string {
	if field == "" {
		return "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob}\n"
	}
	return "schema_version: 3\nusers:\n  - {name: alice}\n  - {name: bob, " + field + "}\n"
}
