package inventory

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// sentinelSecret is a value generated for one test run, so no fixture in the
// repository carries a credential-shaped literal. It is long enough for the
// 8-character password rules.
func sentinelSecret(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return "Sn-" + hex.EncodeToString(buf)
}

// refRoster is a canonical roster whose admin password and users' initial
// passwords are the given YAML scalars (as written: the caller quotes).
func refRoster(admin string, userInitials ...string) string {
	var b strings.Builder
	b.WriteString("schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n")
	if admin != "" {
		b.WriteString("    password: " + admin + "\n")
	}
	if len(userInitials) > 0 {
		b.WriteString("users:\n")
	}
	for i, initial := range userInitials {
		fmt.Fprintf(&b, "  - name: user%d\n    password:\n      initial: %s\n", i, initial)
	}
	return b.String()
}

// missingOf is what a lint of roster against the vars file text varsYAML
// reports: "<field> <name>" for every missing reference, sorted.
func missingOf(t *testing.T, roster, varsYAML string) []string {
	t.Helper()
	refs, _, err := RosterSecretVarReferences([]byte(roster))
	if err != nil {
		t.Fatal(err)
	}
	names, err := VarsFileNames([]byte(varsYAML))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, ref := range MissingRosterVarReferences(refs, names) {
		out = append(out, ref.Field+" "+ref.Name)
	}
	sort.Strings(out)
	return out
}

// The references a roster holds, and which of them a vars file does not
// define: a table with both directions (AGENTS.md §5.12) — every shape that
// must be reported, and every shape that must not. TestRosterRenderedFieldsMatchAnsible
// checks the same verdicts against ansible-core.
func TestRosterSecretVarReferencesMissing(t *testing.T) {
	const initial = "users[user0].password.initial"
	lit := sentinelSecret(t) // a literal password of this run
	cases := []struct {
		name   string
		roster string
		vars   string
		want   []string
	}{
		// ---- reported ----
		{"bare reference", refRoster("", `"{{x}}"`), "other: 1\n", []string{initial + " x"}},
		{"spaced reference", refRoster("", `"{{ x }}"`), "other: 1\n", []string{initial + " x"}},
		{"whitespace control minus", refRoster("", `"{{- x -}}"`), "other: 1\n", []string{initial + " x"}},
		{"literal prefix", refRoster("", `"abc{{x}}"`), "other: 1\n", []string{initial + " x"}},
		{"literal suffix", refRoster("", `"{{ x }}-suffix"`), "other: 1\n", []string{initial + " x"}},
		{"two references", refRoster("", `"{{ a }}-{{ b.c }}"`), "other: 1\n", []string{initial + " a", initial + " b"}},
		{"one defined one not", refRoster("", `"{{ a }}-{{ b }}"`), "a: v\n", []string{initial + " b"}},
		{"attribute access names its root", refRoster("", `"{{ creds.initial }}"`), "other: 1\n", []string{initial + " creds"}},
		{"repeated reference is one finding", refRoster("", `"{{ x }}{{ x }}"`), "other: 1\n", []string{initial + " x"}},
		{"admin password", refRoster(`"{{ ipa_admin_password }}"`), "other: 1\n", []string{"freeipa.admin.password ipa_admin_password"}},
		{"admin and users together", refRoster(`"{{ a }}"`, `"{{ b }}"`, `"{{ c }}"`), "other: 1\n",
			[]string{"freeipa.admin.password a", "users[user0].password.initial b", "users[user1].password.initial c"}},
		{"unquoted plain scalar with a prefix", "schema_version: 3\nusers:\n  - name: u\n    password:\n      initial: abc{{x}}\n", "other: 1\n", []string{"users[u].password.initial x"}},
		{"state absent user", "schema_version: 3\nusers:\n  - name: gone\n    state: absent\n    password:\n      initial: \"{{ x }}\"\n", "other: 1\n", []string{"users[gone].password.initial x"}},
		{"user without a name is labelled by position", "schema_version: 3\nusers:\n  - password:\n      initial: \"{{ x }}\"\n", "other: 1\n", []string{"users[0].password.initial x"}},
		{"repeated user name is labelled by position", "schema_version: 3\nusers:\n  - name: dup\n    password: {initial: \"{{ x }}\"}\n  - name: dup\n    password: {initial: \"{{ y }}\"}\n", "other: 1\n",
			[]string{"users[0].password.initial x", "users[1].password.initial y"}},
		{"a name that is not a plain name is labelled by position", "schema_version: 3\nusers:\n  - name: \"has space\"\n    password: {initial: \"{{ x }}\"}\n", "other: 1\n", []string{"users[0].password.initial x"}},
		{"aliased user", "schema_version: 3\nusers:\n  - &u {name: alice, password: {initial: \"{{ x }}\"}}\n  - *u\n", "other: 1\n",
			[]string{"users[0].password.initial x", "users[1].password.initial x"}},
		{"user from a merge key", "base: &base {password: {initial: \"{{ x }}\"}}\nschema_version: 3\nusers:\n  - name: carol\n    <<: *base\n", "other: 1\n", []string{"users[carol].password.initial x"}},
		{"password mapping from a merge key", "pw: &pw {initial: \"{{ x }}\"}\nschema_version: 3\nusers:\n  - name: dave\n    password:\n      <<: *pw\n", "other: 1\n", []string{"users[dave].password.initial x"}},
		{"the capitalised TRUE is a variable", refRoster("", `"{{ TRUE }}"`), "other: 1\n", []string{initial + " TRUE"}},
		{"the vars file's key set is exact", refRoster("", `"{{ x }}"`), "X: 1\nx_y: 2\n", []string{initial + " x"}},
		{"tagged !!str is templated", refRoster("", `!!str "{{ x }}"`), "other: 1\n", []string{initial + " x"}},
		{"a reference next to a filtered one", refRoster("", `"{{ x }}{{ y | default('') }}"`), "other: 1\n", []string{initial + " x"}},

		// ---- not reported ----
		{"defined", refRoster("", `"{{ x }}"`), "x: value\n", nil},
		{"defined with a null value", refRoster("", `"{{ x }}"`), "x:\n", nil},
		{"defined with a tilde", refRoster("", `"{{ x }}"`), "x: ~\n", nil},
		{"defined by a merge key", refRoster("", `"{{ x }}"`), "base: &b {x: 1}\n<<: *b\n", nil},
		{"defined by a merge of a list of mappings", refRoster("", `"{{ x }}"`), "a: &a {p: 1}\nb: &b {x: 1}\n<<: [*a, *b]\n", nil},
		{"all defined", refRoster(`"{{ a }}"`, `"{{ b }}"`), "a: 1\nb: 2\n", nil},
		{"default filter", refRoster("", `"{{ x | default('') }}"`), "other: 1\n", nil},
		{"default filter without spaces", refRoster("", `"{{ x|default('') }}"`), "other: 1\n", nil},
		{"a call", refRoster("", `"{{ lookup('env', 'HOME') }}"`), "other: 1\n", nil},
		{"a subscript", refRoster("", `"{{ creds['initial'] }}"`), "other: 1\n", nil},
		{"an operator", refRoster("", `"{{ a ~ b }}"`), "other: 1\n", nil},
		{"a test", refRoster("", `"{{ x is defined }}"`), "other: 1\n", nil},
		{"a plus is not whitespace control in a variable tag", refRoster("", `"{{+ x +}}"`), "other: 1\n", nil},
		{"none", refRoster("", `"{{ none }}"`), "other: 1\n", nil},
		{"true and False", refRoster("", `"{{ true }}{{ False }}"`), "other: 1\n", nil},
		{"inventory_hostname", refRoster("", `"{{ inventory_hostname }}"`), "other: 1\n", nil},
		{"hostvars", refRoster("", `"{{ hostvars }}"`), "other: 1\n", nil},
		{"an ansible_ fact", refRoster("", `"{{ ansible_hostname }}"`), "other: 1\n", nil},
		{"a role_ variable", refRoster("", `"{{ role_path }}"`), "other: 1\n", nil},
		{"omit", refRoster("", `"{{ omit }}"`), "other: 1\n", nil},
		{"a Jinja word", refRoster("", `"{{ not }}"`), "other: 1\n", nil},
		{"!unsafe is never templated", refRoster("", `!unsafe "{{ x }}"`), "other: 1\n", nil},
		{"raw block", refRoster("", `"{% raw %}{{ x }}{% endraw %}"`), "other: 1\n", nil},
		{"block tag around a reference", refRoster("", `"{% if y %}{{ x }}{% endif %}"`), "other: 1\n", nil},
		{"comment tag", refRoster("", `"{# {{ x }} #}"`), "other: 1\n", nil},
		{"unclosed delimiter", refRoster("", `"{{ x"`), "other: 1\n", nil},
		{"inline !vault", refRoster("", "!vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162636465"), "other: 1\n", nil},
		{"a literal", refRoster("", `"`+lit+`"`), "other: 1\n", nil},
		{"a literal with a single brace", refRoster("", `"`+lit+`{x}"`), "other: 1\n", nil},
		{"empty", refRoster("", `""`), "other: 1\n", nil},
		{"null", refRoster("", `null`), "other: 1\n", nil},
		{"an unquoted number", refRoster("", `12345678`), "other: 1\n", nil},
		{"a list", refRoster("", `[a, b]`), "other: 1\n", nil},
		{"a password that is not a mapping", "schema_version: 3\nusers:\n  - name: u\n    password: \"{{ x }}\"\n", "other: 1\n", nil},
		{"no users and no admin", "schema_version: 3\n", "other: 1\n", nil},
		{"users that is not a list", "schema_version: 3\nusers: \"{{ x }}\"\n", "other: 1\n", nil},
		{"a field the apply never reads as a secret", "schema_version: 3\nusers:\n  - name: u\n    first: \"{{ x }}\"\n    password: {initial: " + lit + ", force_change: true}\n", "other: 1\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := missingOf(t, tc.roster, tc.vars)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("missing = %q, want %q", got, tc.want)
			}
		})
	}
}

// What the reader cannot judge is listed, never reported: a field with a
// filter, an operator or a block is "unchecked".
func TestRosterSecretVarReferencesUnchecked(t *testing.T) {
	cases := []struct {
		name   string
		scalar string
		want   []string
	}{
		{"filter", `"{{ x | default('') }}"`, []string{"users[user0].password.initial"}},
		{"block", `"{% if y %}{{ x }}{% endif %}"`, []string{"users[user0].password.initial"}},
		{"comment", `"{# note #}pw"`, []string{"users[user0].password.initial"}},
		{"unclosed", `"{{ x"`, []string{"users[user0].password.initial"}},
		{"mixed bare and filtered is checked and unchecked", `"{{ x }}{{ y | default('') }}"`, []string{"users[user0].password.initial"}},
		{"only bare references", `"{{ x }}-{{ y.z }}"`, nil},
		{"a literal", `"plain"`, nil},
		{"!unsafe", `!unsafe "{{ x | default('') }}"`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, unchecked, err := RosterSecretVarReferences([]byte(refRoster("", tc.scalar)))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(unchecked, tc.want) {
				t.Fatalf("unchecked = %q, want %q", unchecked, tc.want)
			}
		})
	}
}

// The consumer decides which of the references it renders.
func TestRosterVarReferencesRenderedBy(t *testing.T) {
	refs, _, err := RosterSecretVarReferences([]byte(refRoster(`"{{ a }}"`, `"{{ u }}"`)))
	if err != nil {
		t.Fatal(err)
	}
	field := func(refs []RosterVarRef) []string {
		var out []string
		for _, ref := range refs {
			out = append(out, ref.Field)
		}
		return out
	}
	admin, user := "freeipa.admin.password", "users[user0].password.initial"
	for _, tc := range []struct {
		name     string
		consumer RosterVarConsumer
		facts    RosterRenderFacts
		want     []string
	}{
		{"identity with no ipa_admin_password and no server renders both", RosterConsumerFreeIPAIdentity, RosterRenderFacts{}, []string{admin, user}},
		{"identity with no ipa_admin_password renders both", RosterConsumerFreeIPAIdentity, RosterRenderFacts{ServerDeclared: true}, []string{admin, user}},
		{"identity with ipa_admin_password but no server renders both (the server fill-in combine)", RosterConsumerFreeIPAIdentity, RosterRenderFacts{AdminPasswordProvided: true}, []string{admin, user}},
		{"identity with ipa_admin_password and a server renders the users only", RosterConsumerFreeIPAIdentity, RosterRenderFacts{AdminPasswordProvided: true, ServerDeclared: true}, []string{user}},
		{"nfs-server renders the admin password only", RosterConsumerFreeIPANFSServer, RosterRenderFacts{}, []string{admin}},
		{"nfs-server renders it whatever the facts", RosterConsumerFreeIPANFSServer, RosterRenderFacts{AdminPasswordProvided: true, ServerDeclared: true}, []string{admin}},
		{"an unknown consumer renders nothing", 0, RosterRenderFacts{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := field(RosterVarReferencesRenderedBy(tc.consumer, refs, tc.facts)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rendered = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRosterFreeIPAServerDeclared(t *testing.T) {
	for _, tc := range []struct {
		name   string
		roster string
		want   bool
	}{
		{"a name", "freeipa: {server: ipa.example.test}\n", true},
		{"a quoted name", "freeipa:\n  server: \"ipa.example.test\"\n", true},
		{"a template is declared", "freeipa: {server: \"{{ ipa_server_fqdn }}\"}\n", true},
		{"missing", "freeipa: {admin: {principal: admin}}\n", false},
		{"no freeipa mapping", "schema_version: 3\n", false},
		{"null counts as declared (None | string is the text None)", "freeipa: {server: null}\n", true},
		{"a bare key is a null", "freeipa:\n  server:\n  admin: {principal: admin}\n", true},
		{"a tilde is a null", "freeipa: {server: ~}\n", true},
		{"a number is declared", "freeipa: {server: 12}\n", true},
		{"a list is declared", "freeipa: {server: [a]}\n", true},
		{"empty", "freeipa: {server: \"\"}\n", false},
		{"blank", "freeipa: {server: \"  \"}\n", false},
		{"through a merge key", "base: &b {server: ipa.example.test}\nfreeipa:\n  <<: *b\n", true},
		{"not YAML", "freeipa: [1\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RosterFreeIPAServerDeclared([]byte(tc.roster)); got != tc.want {
				t.Fatalf("declared = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestVarsFileNames(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
		err  error
	}{
		{"keys", "a: 1\nb: two\n", []string{"a", "b"}, nil},
		{"a null value is defined", "a:\nb: ~\nc: null\n", []string{"a", "b", "c"}, nil},
		{"only top-level keys", "a: {b: 1}\nc: [d]\n", []string{"a", "c"}, nil},
		{"merge key", "base: &b {x: 1}\n<<: *b\ny: 2\n", []string{"base", "x", "y"}, nil},
		{"merge list", "a: &a {p: 1}\nb: &b {q: 1}\n<<: [*a, *b]\n", []string{"a", "b", "p", "q"}, nil},
		{"nested merge", "a: &a {p: 1}\nb: &b {<<: *a, q: 1}\n<<: *b\n", []string{"a", "b", "p", "q"}, nil},
		{"an inline !vault value is defined", "a: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162636465\n", []string{"a"}, nil},
		{"an empty file defines nothing", "", nil, nil},
		{"comments only define nothing", "# nothing here\n", nil, nil},
		{"a null document defines nothing", "~\n", nil, nil},
		{"a list is not a vars file", "- a\n- b\n", nil, ErrVarsFileNotMapping},
		{"a scalar is not a vars file", "just text\n", nil, ErrVarsFileNotMapping},
		{"an encrypted file", "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n", nil, ErrVarsFileEncrypted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VarsFileNames([]byte(tc.yaml))
			if !errors.Is(err, tc.err) {
				t.Fatalf("error = %v, want %v", err, tc.err)
			}
			var names []string
			for name := range got {
				names = append(names, name)
			}
			sort.Strings(names)
			if !reflect.DeepEqual(names, tc.want) {
				t.Fatalf("names = %q, want %q", names, tc.want)
			}
		})
	}
}

// A vars file or roster YAML error never repeats the file's text, whatever
// the error of the YAML library quotes, and keeps only where it is.
func TestYAMLErrorsAreWithheld(t *testing.T) {
	secret := sentinelSecret(t)
	// Each of these fails to parse in a way that quotes text in yaml.v3's own
	// message or sits next to a secret.
	bad := map[string]string{
		"unclosed flow":     "key: " + secret + "\nother: {a: [1, 2\n",
		"tab indentation":   "key: " + secret + "\n\tother: 1\n",
		"duplicated anchor": "a: &x " + secret + "\nb: [*x, *missing]\n",
		"bad escape":        "key: \"" + secret + "\\q\"\n",
		"mapping in scalar": "key: " + secret + ": " + secret + "\n",
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := VarsFileNames([]byte(doc)); err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("vars file: error = %v (nil, or it quotes the file)", err)
			}
			if _, _, err := RosterSecretVarReferences([]byte(doc)); err == nil || strings.Contains(err.Error(), secret) {
				t.Fatalf("roster: error = %v (nil, or it quotes the file)", err)
			}
		})
	}
	_, err := VarsFileNames([]byte("a: [1\nb: " + secret + "\n"))
	if err == nil || !strings.Contains(err.Error(), "line ") {
		t.Fatalf("error = %v, want the line numbers kept", err)
	}
	if !strings.Contains(err.Error(), "withheld") {
		t.Fatalf("error = %v, want it to say the YAML error is withheld", err)
	}
}

// A document whose aliases refer to themselves is refused without walking it
// (AGENTS.md §5.11), for the roster and for the vars file.
func TestVarReferenceReadersRefuseACyclicDocument(t *testing.T) {
	cyc := "freeipa: &f {<<: *f}\nusers: []\n"
	if _, _, err := RosterSecretVarReferences([]byte(cyc)); !errors.Is(err, errCyclicYAML) {
		t.Fatalf("roster: error = %v, want errCyclicYAML", err)
	}
	if _, err := VarsFileNames([]byte(cyc)); !errors.Is(err, errCyclicYAML) {
		t.Fatalf("vars file: error = %v, want errCyclicYAML", err)
	}
}

func TestRosterSecretVarReferencesEncryptedRoster(t *testing.T) {
	_, _, err := RosterSecretVarReferences([]byte("$ANSIBLE_VAULT;1.1;AES256\n6162636465\n"))
	if !errors.Is(err, ErrRosterEncrypted) {
		t.Fatalf("error = %v, want ErrRosterEncrypted", err)
	}
}

// Nothing a reader returns, and no finding it prints, holds a scalar of the
// roster or the vars file: not a literal, not the literal part of a mixed
// value, not the value of a defined variable.
func TestVarReferencesNeverCarryValues(t *testing.T) {
	literal := sentinelSecret(t)
	mixed := sentinelSecret(t)
	defined := sentinelSecret(t)
	roster := refRoster(`"`+literal+`"`, `"`+mixed+`{{ missing_one }}"`, `"{{ defined_one }}"`, `"`+mixed+`{{ filtered | default('`+mixed+`') }}"`, `"{{ missing_two }}`+mixed+`"`)
	refs, unchecked, err := RosterSecretVarReferences([]byte(roster))
	if err != nil {
		t.Fatal(err)
	}
	names, err := VarsFileNames([]byte("defined_one: " + defined + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	missing := MissingRosterVarReferences(refs, names)
	if len(missing) != 2 {
		t.Fatalf("missing = %+v, want two findings (missing_one and missing_two)", missing)
	}
	var shown strings.Builder
	for _, ref := range missing {
		shown.WriteString(ref.Violation("vars.yml").String() + "\n")
	}
	fmt.Fprintf(&shown, "%+v %q %v %v", refs, unchecked, names, missing)
	for _, secret := range []string{literal, mixed, defined} {
		if strings.Contains(shown.String(), secret) {
			t.Fatalf("what the readers return holds a scalar of the files:\n%s", shown.String())
		}
	}
	if got := missing[0].Violation("vars.yml").String(); got != "[roster-reference] users[user0].password.initial references missing_one, which vars.yml does not define" {
		t.Fatalf("finding = %q", got)
	}
}

// ReadVarsFileNames reads a plain file, and a missing, empty-named or
// directory path is an error the caller can show.
func TestReadVarsFileNamesPlain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := ReadVarsFileNames(path, "")
	if err != nil || !names["a"] || len(names) != 1 {
		t.Fatalf("names = %v, err = %v", names, err)
	}
	// A vault password file is not read for a plain file.
	if _, err := ReadVarsFileNames(path, filepath.Join(dir, "no-such-password-file")); err != nil {
		t.Fatalf("a plain vars file needed the password file: %v", err)
	}
	if _, err := ReadVarsFileNames(filepath.Join(dir, "missing.yaml"), ""); err == nil {
		t.Fatal("a missing vars file was not an error")
	}
	if _, err := ReadVarsFileNames(dir, ""); err == nil {
		t.Fatal("a directory was not an error")
	}
}

// Real ansible-vault: an encrypted vars file reads like the plain one, a
// wrong password is an error that holds none of the content, no password is
// ErrVarsFileEncrypted, and no plaintext is left on disk.
func TestReadVarsFileNamesEncrypted(t *testing.T) {
	requireAnsibleVault(t)
	tmp := t.TempDir()
	ansibleTmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("ANSIBLE_LOCAL_TEMP", ansibleTmp)
	dir := t.TempDir()
	secret := sentinelSecret(t)
	marker := "marker" + strings.ToLower(hexString(t))
	plain := "ipa_default_initial_password: " + secret + "\n" + marker + ": 1\nnull_key:\n"
	vars := filepath.Join(dir, "main.yaml")
	if err := os.WriteFile(vars, []byte(plain), 0o600); err != nil {
		t.Fatal(err)
	}
	password := writeVaultPasswordFile(t, filepath.Join(dir, "pw"), sentinelSecret(t))
	wrong := writeVaultPasswordFile(t, filepath.Join(dir, "wrong"), sentinelSecret(t))
	want, err := ReadVarsFileNames(vars, "")
	if err != nil {
		t.Fatal(err)
	}
	encryptFileForTest(t, vars, password)

	got, err := ReadVarsFileNames(vars, password)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || !got[marker] || !got["null_key"] {
		t.Fatalf("encrypted names = %v, plain names = %v", got, want)
	}
	if _, err := ReadVarsFileNames(vars, ""); !errors.Is(err, ErrVarsFileEncrypted) {
		t.Fatalf("no password: error = %v, want ErrVarsFileEncrypted", err)
	}
	_, err = ReadVarsFileNames(vars, wrong)
	if err == nil {
		t.Fatal("a wrong password was not an error")
	}
	for _, leaked := range []string{secret, marker} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("the wrong-password error holds file content: %v", err)
		}
	}
	for _, leaked := range []string{secret, marker} {
		if hits := filesWithContent(t, leaked, tmp, ansibleTmp); len(hits) > 0 {
			t.Fatalf("decrypted content was left on disk: %v", hits)
		}
	}
	// The encrypted file itself is untouched.
	if raw, err := os.ReadFile(vars); err != nil || !strings.HasPrefix(string(raw), "$ANSIBLE_VAULT") {
		t.Fatalf("the vars file was changed (err %v)", err)
	}
}

func hexString(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 6)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(buf)
}

// filesWithContent lists the regular files under dirs whose bytes contain needle.
func filesWithContent(t *testing.T, needle string, dirs ...string) []string {
	t.Helper()
	var hits []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !entry.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), needle) {
				hits = append(hits, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return hits
}

// The names the consuming playbooks define for themselves are known to the
// check, each to its own playbook (and to a lint that does not know the
// consumer); the ones its settings task sets afterwards are not. The oracle
// test checks every one of these against ansible-core.
func TestMissingRosterVarReferencesForKnowsThePlaybooksOwnNames(t *testing.T) {
	refs, _, err := RosterSecretVarReferences([]byte(refRoster(`"{{ stage }}-{{ ipa_realm }}-{{ nfs_pseudo_root }}-{{ ipa_hbac_services }}"`, `"{{ stage }}"`)))
	if err != nil {
		t.Fatal(err)
	}
	facts := RosterRenderFacts{}
	names := func(missing []RosterVarRef) []string {
		var out []string
		for _, ref := range missing {
			out = append(out, ref.Field+" "+ref.Name)
		}
		return out
	}
	for _, tc := range []struct {
		name     string
		consumer RosterVarConsumer
		want     []string
	}{
		{"identity", RosterConsumerFreeIPAIdentity, []string{"freeipa.admin.password nfs_pseudo_root", "freeipa.admin.password ipa_hbac_services"}},
		{"nfs-server", RosterConsumerFreeIPANFSServer, []string{"freeipa.admin.password ipa_realm", "freeipa.admin.password ipa_hbac_services"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := names(MissingRosterVarReferencesFor(tc.consumer, refs, facts)); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("missing = %q, want %q", got, tc.want)
			}
		})
	}
	// A run's own variables still count.
	if got := MissingRosterVarReferencesFor(RosterConsumerFreeIPANFSServer, refs, facts, map[string]bool{"ipa_realm": true, "ipa_hbac_services": true}); len(got) != 0 {
		t.Fatalf("missing = %+v, want none once the run defines them", got)
	}
	// A lint that does not know the consumer takes both playbooks' names as known.
	known := RosterPlaybookKnownNames()
	var lint []string
	for _, ref := range MissingRosterVarReferences(refs, known) {
		lint = append(lint, ref.Field+" "+ref.Name)
	}
	if want := []string{"freeipa.admin.password ipa_hbac_services"}; !reflect.DeepEqual(lint, want) {
		t.Fatalf("lint missing = %q, want %q", lint, want)
	}
}
