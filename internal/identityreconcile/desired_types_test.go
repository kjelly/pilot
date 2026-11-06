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
				"users[1] (bob): password: initial must be a string, not "+tc.typ)
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
	// A null users or groups list is still an empty one: null is refused only
	// for the three mappings above (not captured for the lists).
	t.Run("users and groups null or empty", func(t *testing.T) {
		for _, doc := range []string{
			"schema_version: 3\nusers:\ngroups:\n",
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
