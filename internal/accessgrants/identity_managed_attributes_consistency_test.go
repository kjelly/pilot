package accessgrants

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"testing"

	"github.com/kjelly/pilot/internal/accessgrants/fakeipatest"
	"go.yaml.in/yaml/v3"
)

// AGENTS.md section 5.7 (one fact kept in several places needs a consistency
// test): the set of user and group attributes that `pilot identity drift
// --include-users-groups` compares is written down in four places.
//
//  1. the shared normalization that gives apply (and the drift probe) the keys
//     of each user and group (tasks/freeipa-identity-normalize-users-groups.yml);
//  2. the options apply passes to `ipa user-add`, `user-mod`, `group-add`,
//     `group-mod` (freeipa-identity-apply.yml), each fed by one of those keys;
//  3. the observer's USER_FIELDS and GROUP_FIELDS, which map each key to the
//     LDAP attribute it reads back from user_find/group_find;
//  4. this package's managedIdentityAttributes allowlist.
//
// A field that apply sets but the observer does not compare is drift nobody can
// see; one that the observer compares but apply never sets is drift apply can
// never fix and a permanent finding. The relation key -> option -> attribute is
// FreeIPA knowledge no file derives (the attribute names are the ones in the
// captured user-find-states and group-find-states replies), so this table is
// the oracle the four places are compared with.
type managedIdentityField struct {
	key       string // key in the normalized user or group
	option    string // `ipa` option apply passes for it
	attribute string // LDAP attribute as user_find/group_find report it
}

var managedUserFields = []managedIdentityField{
	{"first", "--first", "givenname"},
	{"last", "--last", "sn"},
	{"display_name", "--displayname", "displayname"},
	{"email", "--email", "mail"},
	{"uid", "--uid", "uidnumber"},
	{"gid", "--gidnumber", "gidnumber"},
	{"login_shell", "--shell", "loginshell"},
	{"home_directory", "--homedir", "homedirectory"},
}

var managedGroupFields = []managedIdentityField{
	{"desc", "--desc", "description"},
	{"gid", "--gid", "gidnumber"},
}

// Keys of a normalized object that are deliberately not compared as attributes,
// with the reason: they are handled by their own comparison, or not an
// attribute at all. A new key must be one of these or a managed field.
var (
	userKeysNotAttributes = map[string]string{
		"name":              "the identity of the object",
		"state":             "present/absent/disabled, compared as existence and enabled state",
		"enabled":           "compared as nsaccountlock (user_enabled)",
		"ssh_keys":          "compared as key digests (user_ssh_keys)",
		"password":          "a credential: never produced for the drift probe",
		"force_password":    "a credential option: never produced for the drift probe",
		"preserve_existing": "a credential option: never produced for the drift probe",
	}
	groupKeysNotAttributes = map[string]string{
		"name":       "the identity of the object",
		"state":      "present/absent, compared as existence",
		"type":       "posix/nonposix/external: fixed when the group is created, not modifiable",
		"membership": "compared as direct members (member_missing, member_unexpected)",
	}
)

// findTasks returns every task named name anywhere in a decoded playbook.
func findTasks(node any, name string) []map[string]any {
	var found []map[string]any
	switch v := node.(type) {
	case []any:
		for _, item := range v {
			found = append(found, findTasks(item, name)...)
		}
	case map[string]any:
		if v["name"] == name {
			found = append(found, v)
		}
		for _, child := range v {
			found = append(found, findTasks(child, name)...)
		}
	}
	return found
}

func loadYAMLFile(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc
}

// taskString returns the string value of module.field of the only task named
// name; a renamed or duplicated task fails the test instead of passing it.
func taskString(t *testing.T, doc any, file, name, module, field string) string {
	t.Helper()
	tasks := findTasks(doc, name)
	if len(tasks) != 1 {
		t.Fatalf("%s: %d tasks named %q, want exactly 1 (renamed? update this test)", file, len(tasks), name)
	}
	args, ok := tasks[0][module].(map[string]any)
	if !ok {
		t.Fatalf("%s: task %q has no %s", file, name, module)
	}
	text, ok := args[field].(string)
	if !ok {
		t.Fatalf("%s: task %q: %s.%s is %T, want a template string", file, name, module, field, args[field])
	}
	return text
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fieldKeys(fields []managedIdentityField) []string {
	var keys []string
	for _, f := range fields {
		keys = append(keys, f.key)
	}
	sort.Strings(keys)
	return keys
}

func fieldAttributes(fields ...[]managedIdentityField) []string {
	var attrs []string
	for _, list := range fields {
		for _, f := range list {
			if !slices.Contains(attrs, f.attribute) {
				attrs = append(attrs, f.attribute)
			}
		}
	}
	sort.Strings(attrs)
	return attrs
}

// optionPairs returns the `--option=` ... item.<key> pairs of an `ipa` argv
// template, and fails if an option is passed that is not fed by an item key
// (an option whose value this test cannot attribute to a normalized field).
func optionPairs(t *testing.T, label, argv string) []string {
	t.Helper()
	options := regexp.MustCompile(`'(--[a-z-]+)='`).FindAllStringSubmatch(argv, -1)
	pairs := regexp.MustCompile(`'(--[a-z-]+)=' ~ \(?\s*item\.([a-z_]+)`).FindAllStringSubmatch(argv, -1)
	if len(pairs) == 0 || len(pairs) != len(options) {
		t.Fatalf("%s: %d valued options but %d of them fed by item.<key>: %s", label, len(options), len(pairs), argv)
	}
	var out []string
	for _, p := range pairs {
		out = append(out, p[1]+"<-"+p[2])
	}
	sort.Strings(out)
	return out
}

func wantPairs(fields []managedIdentityField) []string {
	var out []string
	for _, f := range fields {
		out = append(out, f.option+"<-"+f.key)
	}
	sort.Strings(out)
	return out
}

func TestManagedIdentityAttributesAgreeAcrossObserverGoAndApply(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is required to read the observer's field maps")
	}
	root := filepath.Join("..", "..", "playbooks")

	// 3. The observer's USER_FIELDS and GROUP_FIELDS, read by importing it.
	observer := filepath.Join(root, "check", "files", "freeipa-identity-object-observer.py")
	script := "import importlib.util, json, sys\n" +
		"s = importlib.util.spec_from_file_location('observer', sys.argv[1])\n" +
		"m = importlib.util.module_from_spec(s)\n" +
		"s.loader.exec_module(m)\n" +
		"json.dump({'user': m.USER_FIELDS, 'group': m.GROUP_FIELDS}, sys.stdout)\n"
	out, err := exec.Command(python, "-I", "-c", script, observer).Output()
	if err != nil {
		t.Fatalf("read the observer's field maps: %v", err)
	}
	var observed map[string]map[string]string
	if err := json.Unmarshal(out, &observed); err != nil {
		t.Fatal(err)
	}
	for kind, fields := range map[string][]managedIdentityField{"user": managedUserFields, "group": managedGroupFields} {
		want := map[string]string{}
		for _, f := range fields {
			want[f.key] = f.attribute
		}
		if !reflect.DeepEqual(observed[kind], want) {
			t.Errorf("observer %s fields (key -> attribute) = %v, want %v", kind, observed[kind], want)
		}
	}

	// 4. This package's allowlist (users and groups together).
	if got, want := slices.Sorted(slices.Values(managedIdentityAttributes)), fieldAttributes(managedUserFields, managedGroupFields); !slices.Equal(got, want) {
		t.Errorf("managedIdentityAttributes = %v, want %v", got, want)
	}

	// 1. The keys of the shared normalization, apart from the declared ones.
	normFile := filepath.Join(root, "apply", "tasks", "freeipa-identity-normalize-users-groups.yml")
	norm := loadYAMLFile(t, normFile)
	keyRE := regexp.MustCompile(`(?m)^\s*'([a-z_]+)':`)
	for _, c := range []struct {
		kind, task, fact string
		notAttrs         map[string]string
		fields           []managedIdentityField
	}{
		{"user", "Normalize canonical users for the compatibility reconciler", "ipa_users", userKeysNotAttributes, managedUserFields},
		{"group", "Normalize canonical groups for the compatibility reconciler", "ipa_groups", groupKeysNotAttributes, managedGroupFields},
	} {
		template := taskString(t, norm, normFile, c.task, "ansible.builtin.set_fact", c.fact)
		have := map[string]bool{}
		for _, m := range keyRE.FindAllStringSubmatch(template, -1) {
			have[m[1]] = true
		}
		var attributes []string
		for key := range have {
			if _, declared := c.notAttrs[key]; !declared {
				attributes = append(attributes, key)
			}
		}
		sort.Strings(attributes)
		if want := fieldKeys(c.fields); !slices.Equal(attributes, want) {
			t.Errorf("normalized %s keys that are neither declared non-attributes nor managed fields differ: have %v, want %v "+
				"(a new key must be compared by the observer and set by apply, or be declared in %sKeysNotAttributes)", c.kind, attributes, want, c.kind)
		}
		for key := range c.notAttrs {
			if !have[key] {
				t.Errorf("%s key %q is declared as not an attribute but the normalization no longer produces it", c.kind, key)
			}
		}
	}

	// 2. The options apply passes: each one is the managed field's option, fed by its key.
	apply := loadYAMLFile(t, filepath.Join(root, "apply", "freeipa-identity-apply.yml"))
	applyFile := "freeipa-identity-apply.yml"
	for _, c := range []struct {
		task   string
		fields []managedIdentityField
	}{
		{"Ensure IPA users exist", managedUserFields},
		{"Reconcile user first/last names", managedUserFields},
		{"Ensure IPA groups exist", managedGroupFields},
		{"Reconcile IPA group descriptions", managedGroupFields},
	} {
		argv := taskString(t, apply, applyFile, c.task, "ansible.builtin.command", "argv")
		if got, want := optionPairs(t, c.task, argv), wantPairs(c.fields); !slices.Equal(got, want) {
			t.Errorf("%s passes options %v, want %v", c.task, got, want)
		}
	}

	// The attribute names are FreeIPA's: each one is in a real reply of
	// user_find / group_find --all (a name that is not would compare nothing).
	for _, c := range []struct {
		fixture string
		fields  []managedIdentityField
	}{{"user-find-states", managedUserFields}, {"group-find-states", managedGroupFields}} {
		seen := map[string]bool{}
		for _, entry := range fakeipatest.Capture(t, c.fixture)["result"].([]any) {
			for attr := range entry.(map[string]any) {
				seen[attr] = true
			}
		}
		for _, f := range c.fields {
			if !seen[f.attribute] {
				t.Errorf("attribute %q is in no entry of the captured %s reply (have %v)", f.attribute, c.fixture, sortedKeys(seen))
			}
		}
	}
}

// TestIdentityObjectDriftComparesExactlyTheManagedAttributes: the allowlist is
// what ComputeIdentityObjectDrift accepts. Every managed attribute is compared
// (a difference is reported by name, no value); an attribute outside the list
// is refused rather than silently ignored.
func TestIdentityObjectDriftComparesExactlyTheManagedAttributes(t *testing.T) {
	for _, attr := range managedIdentityAttributes {
		s := objectSnapshot()
		s.DesiredUsers = []IdentityObject{{Name: "u", State: "present", Enabled: true, Attributes: map[string][]string{attr: {"wanted"}}}}
		s.LiveUsers = []IdentityObject{{Name: "u", Enabled: true, Attributes: map[string][]string{attr: {"live"}}}}
		items, err := ComputeIdentityObjectDrift(s)
		if err != nil {
			t.Fatalf("%s: %v", attr, err)
		}
		if len(items) != 1 || items[0].Category != "user_attribute" || items[0].Detail != "managed attribute differs: "+attr {
			t.Errorf("%s: items = %+v", attr, items)
		}
	}
	s := objectSnapshot()
	s.DesiredUsers = []IdentityObject{{Name: "u", State: "present", Enabled: true, Attributes: map[string][]string{"telephonenumber": {"1"}}}}
	s.LiveUsers = []IdentityObject{{Name: "u", Enabled: true, Attributes: map[string][]string{"telephonenumber": {"1"}}}}
	if _, err := ComputeIdentityObjectDrift(s); err == nil {
		t.Error("an attribute outside the allowlist was compared instead of refused")
	}
}
