package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/rosteroracletest"
)

// The oracle of the password the Go engine sends for a bare {{ name }} (issue #394): real
// ansible-playbook runs the real freeipa-identity-apply.yml pre_tasks up to and including the
// include that captures every user's password.initial, then writes what the passwd call would
// read on stdin for each user (rosteroracletest.IdentityCapture); the Go side lists the same
// run's variables with a real `ansible-inventory --list -e @vault --playbook-dir <playbook
// dir>` (the arguments golangRunVars passes, which TestGolangRunVarsListsWithTheDefaultsVaultInput
// pins) and reads the same roster through RosterUserPasswords.
//
// The invariant, one row at a time (AGENTS.md section 5.12: a row that passes and rows that
// trigger):
//
//   - every row Go resolves is a string Ansible sends byte for byte (and the row says which
//     string, so two empty answers cannot agree by accident);
//   - every row Go refuses says, and the test checks, what Ansible does with it: sends the
//     same value (Go refuses by design: it cannot prove it), sends another one (the trap the
//     refusal is for), sends a value that is not a string, sends none, or fails.
//
// Each source of a variable is a row: the vault vars file (-e @file, plain and whole-file
// encrypted with the ambient secret), the inventory, group_vars and host_vars next to it,
// group_vars next to the playbook and, which neither loads, the working directory's.

// ansibleDoes is what the real playbook does with a row's password.
type ansibleDoes struct {
	kind  string // sends, sendsJSON, differs, oneOf, none, fails
	text  string // sends: the string; differs: the string it must not send
	json  string // sendsJSON: the JSON of the password, compact
	oneOf []string
	// fails: the variable Ansible names undefined ("" when another failure), and a text its fatal
	// message holds (the failure is the one the row is about, not another that fails the same play).
	undefined string
	failsWith string
}

func sends(s string) ansibleDoes       { return ansibleDoes{kind: "sends", text: s} }
func sendsJSON(s string) ansibleDoes   { return ansibleDoes{kind: "sendsJSON", json: s} }
func differsFrom(s string) ansibleDoes { return ansibleDoes{kind: "differs", text: s} }

// pwOracleRow is one user of the roster and the variables around it.
type pwOracleRow struct {
	name        string
	scalar      string // the YAML of password.initial
	passwordTag string // "!unsafe " puts the tag on the password mapping
	// vars by source: lines of YAML, the names unique to the row.
	vault, inventory, group, host, playbook, cwd string
	// The Go side.
	goValue string // the string Go resolves; "" when it refuses
	goWhy   string // when it refuses: the form (ambiguous, inline-vault) or the reason (shadowed, ...)
	// The Ansible side.
	ansible ansibleDoes
}

type oracleSecrets struct {
	vault, group, host, inv, play, over, c2, nested, admin, inventoryAdmin, inlineVault, rosterInline, chain, item, roster, role string
}

func newOracleSecrets(t *testing.T) oracleSecrets {
	t.Helper()
	g := func() string { return sentinelSecret(t) }
	return oracleSecrets{
		vault: g(), group: g(), host: g(), inv: g(), play: g(), over: g(), c2: g(), nested: g(), admin: g(),
		inventoryAdmin: g(), inlineVault: g(), rosterInline: g(), chain: g(), item: g(), roster: g(), role: g(),
	}
}

func q(s string) string { raw, _ := json.Marshal(s); return string(raw) }

func chainLines(prefix string, names int, value string) (lines, first string) {
	var b strings.Builder
	for i := 1; i < names; i++ {
		fmt.Fprintf(&b, "%s%d: \"{{ %s%d }}\"\n", prefix, i, prefix, i+1)
	}
	fmt.Fprintf(&b, "%s%d: %s\n", prefix, names, q(value))
	return b.String(), prefix + "1"
}

// pwOracleRows are the rows of the oracle, with the values this run's secrets give them. The
// inline !vault rows take the encrypted text of their plaintext as arguments.
func pwOracleRows(s oracleSecrets, encryptedVaultVar, encryptedRosterScalar, capturedRosterPath, authCacheOutput string) []pwOracleRow {
	resolved := func(name, scalar, value string, vars map[string]string) pwOracleRow {
		r := pwOracleRow{name: name, scalar: scalar, goValue: value, ansible: sends(value)}
		r.vault, r.inventory, r.group, r.host, r.playbook, r.cwd = vars["vault"], vars["inventory"], vars["group"], vars["host"], vars["playbook"], vars["cwd"]
		return r
	}
	refused := func(name, scalar, why string, does ansibleDoes, vars map[string]string) pwOracleRow {
		r := pwOracleRow{name: name, scalar: scalar, goWhy: why, ansible: does}
		r.vault, r.inventory, r.group, r.host, r.playbook, r.cwd = vars["vault"], vars["inventory"], vars["group"], vars["host"], vars["playbook"], vars["cwd"]
		return r
	}
	ref := func(n string) string { return `"{{ ` + n + ` }}"` }
	chain9, first9 := chainLines("n", maxRunVarHops+1, s.chain)
	chain10, first10 := chainLines("m", maxRunVarHops+2, s.chain)
	chain30, first30 := chainLines("k", 30, s.chain)
	two := "c2a: \"{{ c2b }}\"\nc2b: " + q(s.c2) + "\n"
	rows := []pwOracleRow{
		// ---- the sources of a variable, and what outranks what ----
		resolved("vault vars file", ref("v_vault"), s.vault, map[string]string{"vault": "v_vault: " + q(s.vault) + "\n"}),
		resolved("no spaces in the braces", `"{{v_vault}}"`, s.vault, nil),
		resolved("whitespace control", `"{{- v_vault -}}"`, s.vault, nil),
		resolved("group_vars next to the inventory", ref("v_group"), s.group, map[string]string{"group": "v_group: " + q(s.group) + "\n"}),
		resolved("host_vars next to the inventory", ref("v_host"), s.host, map[string]string{"host": "v_host: " + q(s.host) + "\n"}),
		resolved("a host variable of the inventory", ref("v_inv"), s.inv, map[string]string{"inventory": "v_inv: " + q(s.inv) + "\n"}),
		resolved("group_vars next to the playbook", ref("v_play"), s.play, map[string]string{"playbook": "v_play: " + q(s.play) + "\n"}),
		resolved("the vault outranks group_vars", ref("v_over"), s.over, map[string]string{"group": "v_over: from-group\n", "vault": "v_over: " + q(s.over) + "\n"}),
		resolved("a chain of two", ref("c2a"), s.c2, map[string]string{"vault": two}),
		resolved("a chain with whitespace control", ref("w1"), s.c2, map[string]string{"vault": "w1: \"{{- w2 -}}\"\nw2: " + q(s.c2) + "\n"}),
		resolved("a chain across sources", ref("x1"), s.group, map[string]string{"group": "x1: \"{{ x2 }}\"\n", "vault": "x2: " + q(s.group) + "\n"}),
		resolved(fmt.Sprintf("a chain of %d names, the bound", maxRunVarHops+1), ref(first9), s.chain, map[string]string{"vault": chain9}),
		// A date in vars: ansible-inventory lists it as its ISO text and Ansible's to_json sends the
		// same text, so Go's resolved value is what Ansible sends.
		resolved("a YAML date in the vars file", ref("v_date"), "2024-01-02", map[string]string{"vault": "v_date: 2024-01-02\n"}),
		// !unsafe in the roster: the text Ansible sends is the template itself.
		resolved("the initial tagged !unsafe", `!unsafe "{{ v_vault }}"`, "{{ v_vault }}", nil),
		{name: "the password mapping tagged !unsafe", scalar: ref("v_vault"), passwordTag: "!unsafe ", goValue: "{{ v_vault }}", ansible: sends("{{ v_vault }}")},
		// hostile values: byte for byte, whatever they hold.
		resolved("leading and trailing spaces", ref("h_sp"), "  lead and trail  ", map[string]string{"vault": "h_sp: \"  lead and trail  \"\n"}),
		resolved("a leading-zero number as a string", ref("h_zero"), "0123", map[string]string{"vault": "h_zero: \"0123\"\n"}),
		resolved("True as a string", ref("h_true"), "True", map[string]string{"vault": "h_true: \"True\"\n"}),
		resolved("a list written as a string", ref("h_list"), "[1, 2]", map[string]string{"vault": "h_list: \"[1, 2]\"\n"}),
		resolved("a mapping written as a string", ref("h_dict"), "{'a': 1}", map[string]string{"vault": "h_dict: \"{'a': 1}\"\n"}),
		resolved("CJK and an emoji", ref("h_cjk"), "密碼-🔑", map[string]string{"vault": "h_cjk: " + q("密碼-🔑") + "\n"}),
		resolved("backticks, $HOME, %s and a backslash", ref("h_sh"), "a\\b`x`$HOME%s", map[string]string{"vault": "h_sh: " + q("a\\b`x`$HOME%s") + "\n"}),
		resolved("an embedded newline", ref("h_nl"), "line1\nline2", map[string]string{"vault": "h_nl: " + q("line1\nline2") + "\n"}),

		// ---- names the playbook defines before it captures the password: not the inventory's ----
		// (E3 of the SA report: the inventory says one thing, the playbook sends another.)
		refused("identity_admin_password in the inventory: the settings set_fact wins", ref("identity_admin_password"), "shadowed",
			differsFrom(s.inventoryAdmin), map[string]string{"inventory": "identity_admin_password: " + q(s.inventoryAdmin) + "\n"}),
		refused("identity_admin_principal in the inventory", ref("identity_admin_principal"), "shadowed",
			sends("admin"), map[string]string{"inventory": "identity_admin_principal: from-inventory\n"}),
		refused("ipa_hbac_services in the inventory", ref("ipa_hbac_services"), "shadowed",
			sendsJSON("[]"), map[string]string{"inventory": "ipa_hbac_services: from-inventory\n"}),
		refused("ipa_sudo_command_groups in the inventory", ref("ipa_sudo_command_groups"), "shadowed",
			sendsJSON("[]"), map[string]string{"inventory": "ipa_sudo_command_groups: from-inventory\n"}),
		refused("ipa_domain, a play var, in the inventory", ref("ipa_domain"), "shadowed",
			sends("ipa.pilot.internal"), map[string]string{"inventory": "ipa_domain: from-inventory\n"}),
		// The roster's templates are rendered when the loop's items are, before the loop variable
		// exists: `item` is the inventory's value there, so refusing the name is the conservative
		// choice and not a guard against a wrong value (Ansible sends the inventory's text here).
		refused("item, the loop variable, in the inventory", ref("item"), "shadowed",
			sends(s.item), map[string]string{"inventory": "item: " + q(s.item) + "\n"}),
		// A task var is in scope then, and it is a template over `item`: Ansible sends the
		// `item` value above, not the inventory's pilot_identity_roster_user. (A trap, and it
		// leans on the row before: both rows share one inventory.)
		refused("pilot_identity_roster_user, a task var, in the inventory", ref("pilot_identity_roster_user"), "shadowed",
			sends(s.item), map[string]string{"inventory": "pilot_identity_roster_user: from-inventory\n"}),
		refused("pilot_identity_with_credentials, a task var, in the inventory", ref("pilot_identity_with_credentials"), "shadowed",
			sendsJSON("true"), map[string]string{"inventory": "pilot_identity_with_credentials: from-inventory\n"}),
		refused("freeipa_roster_file, passed with -e, in the inventory", ref("freeipa_roster_file"), "shadowed",
			sends(capturedRosterPath), map[string]string{"inventory": "freeipa_roster_file: from-inventory\n"}),
		refused("target_group, passed with -e, in the inventory", ref("target_group"), "shadowed",
			sends("oracle-target"), map[string]string{"inventory": "target_group: from-inventory\n"}),
		refused("pilot_identity_users_groups_engine, passed with -e, in the inventory", ref("pilot_identity_users_groups_engine"), "shadowed",
			sends("go"), map[string]string{"inventory": "pilot_identity_users_groups_engine: from-inventory\n"}),
		refused("pilot_identity_auth_cache_output, passed with -e, in the inventory", ref("pilot_identity_auth_cache_output"), "shadowed",
			sends(authCacheOutput), map[string]string{"inventory": "pilot_identity_auth_cache_output: from-inventory\n"}),
		refused("pilot_deferred_hosts, passed with -e, in the inventory", ref("pilot_deferred_hosts"), "shadowed",
			differsFrom("from-inventory"), map[string]string{"inventory": "pilot_deferred_hosts: from-inventory\n"}),
		refused("inventory_hostname, a magic variable", ref("inventory_hostname"), "reserved", sends("localhost"), nil),
		// Ansible sends the inventory's value here too: Go refuses it by design (it cannot prove a
		// magic variable is the inventory's).
		refused("ansible_host, a fact-family name", ref("ansible_host"), "reserved", sends("192.0.2.1"),
			map[string]string{"inventory": "ansible_host: 192.0.2.1\n"}),
		// The same for a role_ name, refused by its prefix: Ansible sends the inventory's value.
		refused("role_default_password, a role_ variable", ref("role_default_password"), "reserved", sends(s.role),
			map[string]string{"inventory": "role_default_password: " + q(s.role) + "\n"}),
		// The vault's own ipa_admin_password is no name the playbook defines: Go resolves it.
		resolved("ipa_admin_password, the vault's own", ref("ipa_admin_password"), s.admin, nil),

		// ---- values Go cannot prove ----
		refused("an inline !vault value in the vars file", ref("v_inline"), "inline-vault", sends(s.inlineVault), map[string]string{"vault": encryptedVaultVar}),
		refused("a value that is a template that is not bare", ref("v_nested"), "nested-template", sends("a"+s.vault+"c"),
			map[string]string{"vault": "v_nested: \"a{{ v_vault }}c\"\n"}),
		refused(fmt.Sprintf("a chain of %d names, past the bound", maxRunVarHops+2), ref(first10), "chain", sends(s.chain), map[string]string{"vault": chain10}),
		// Ansible resolves chains far longer than pilot follows (the bound is pilot's, not Ansible's).
		refused("a chain of 30 names, far past the bound", ref(first30), "chain", sends(s.chain), map[string]string{"vault": chain30}),
		refused("an empty string", ref("v_empty"), "empty", sends(""), map[string]string{"vault": "v_empty: \"\"\n"}),
		refused("null: Ansible sets no password", ref("v_null"), "not-a-string", ansibleDoes{kind: "none"}, map[string]string{"vault": "v_null:\n"}),
		refused("a number: Ansible sends a JSON number", ref("v_num"), "not-a-string", sendsJSON("12345678"), map[string]string{"vault": "v_num: 12345678\n"}),
		refused("a boolean", ref("v_bool"), "not-a-string", sendsJSON("true"), map[string]string{"vault": "v_bool: true\n"}),
		refused("a list", ref("v_lst"), "not-a-string", sendsJSON(`["a"]`), map[string]string{"vault": "v_lst: [a]\n"}),
		refused("a mapping", ref("v_map"), "not-a-string", sendsJSON(`{"a":"b"}`), map[string]string{"vault": "v_map: {a: b}\n"}),

		// ---- the __ansible_unsafe marker (the merge-gate finding of #394, F1) ----
		// ansible-inventory --list prints a genuine !unsafe string and a literal YAML mapping
		// {__ansible_unsafe: x} identically, as {"__ansible_unsafe": "x"}. Ansible holds the first as
		// text and sends it as written, the second as a dict and sends its JSON. Go cannot tell
		// them apart from the listing, so it refuses all of them (Ansible's behaviour, which differs
		// by row, is recorded per row; Go never sends what Ansible does not).
		refused("an !unsafe value holding {{", ref("v_unsafe"), "unsafe-marker", sends("a{{ not_a_reference }}c"),
			map[string]string{"vault": "v_unsafe: !unsafe \"a{{ not_a_reference }}c\"\n"}),
		refused("an !unsafe value holding plain text", ref("v_unsafe_plain"), "unsafe-marker", sends("unsafe-plain-text"),
			map[string]string{"vault": "v_unsafe_plain: !unsafe \"unsafe-plain-text\"\n"}),
		refused("a literal {__ansible_unsafe: x} mapping in the vars file", ref("v_lit_vault"), "unsafe-marker",
			sendsJSON(`{"__ansible_unsafe":"lit-vault-text"}`), map[string]string{"vault": "v_lit_vault: {__ansible_unsafe: lit-vault-text}\n"}),
		refused("a literal {__ansible_unsafe: x} mapping in group_vars next to the inventory", ref("v_lit_group"), "unsafe-marker",
			sendsJSON(`{"__ansible_unsafe":"lit-group-text"}`), map[string]string{"group": "v_lit_group: {__ansible_unsafe: lit-group-text}\n"}),
		refused("a literal {__ansible_unsafe: \"\"} mapping", ref("v_lit_empty"), "unsafe-marker",
			sendsJSON(`{"__ansible_unsafe":""}`), map[string]string{"vault": "v_lit_empty: {__ansible_unsafe: \"\"}\n"}),
		refused("a chain that ends in an !unsafe value", ref("ue1"), "unsafe-marker", sends("chain-unsafe-text"),
			map[string]string{"vault": "ue1: \"{{ ue2 }}\"\nue2: !unsafe \"chain-unsafe-text\"\n"}),
		refused("a chain that ends in a literal {__ansible_unsafe: x} mapping", ref("le1"), "unsafe-marker",
			sendsJSON(`{"__ansible_unsafe":"chain-lit-text"}`), map[string]string{"vault": "le1: \"{{ le2 }}\"\nle2: {__ansible_unsafe: chain-lit-text}\n"}),
		// Not the marker: a number under the key, or a second key, is a mapping like any other.
		refused("a mapping with __ansible_unsafe holding a number", ref("v_lit_num"), "not-a-string",
			sendsJSON(`{"__ansible_unsafe":5}`), map[string]string{"vault": "v_lit_num: {__ansible_unsafe: 5}\n"}),
		refused("a mapping with __ansible_unsafe and another key", ref("v_lit_two"), "not-a-string",
			sendsJSON(`{"__ansible_unsafe":"x","other":"y"}`), map[string]string{"vault": "v_lit_two: {__ansible_unsafe: x, other: y}\n"}),

		// ---- what is not one bare reference ----
		refused("a filter", `"{{ v_vault | upper }}"`, "not-bare", sends(strings.ToUpper(s.vault)), nil),
		refused("text after the reference", `"{{ v_vault }}-tail"`, "not-bare", sends(s.vault+"-tail"), nil),
		refused("text before the reference", `"head-{{ v_vault }}"`, "not-bare", sends("head-"+s.vault), nil),
		refused("an inline !vault value in the roster", encryptedRosterScalar, "inline-vault", sends(s.rosterInline), nil),
	}
	// A template shared by an alias between !unsafe and normal YAML is ambiguous: Ansible sends the
	// literal text or the rendered value depending on its loader's build order, so Go refuses both.
	rows = append(rows, pwOracleRow{
		name: "a template shared between !unsafe and normal YAML", scalar: ref("v_vault"), goWhy: "ambiguous",
		ansible: ansibleDoes{kind: "oneOf", oneOf: []string{"{{ v_vault }}", s.vault}},
	})
	return rows
}

// vaultEncryptString is the ansible-vault encrypt_string text of plaintext as a YAML mapping entry
// named name (the lines of a vars file), or, with no name, as the scalar of a roster: `!vault |`
// and its lines.
func vaultEncryptString(t *testing.T, passFile, name, plaintext string) string {
	t.Helper()
	args := []string{"encrypt_string", "--vault-password-file", passFile}
	if name != "" {
		args = append(args, "--name", name)
	}
	out, err := exec.Command("ansible-vault", append(args, plaintext)...).Output()
	if err != nil {
		t.Fatalf("ansible-vault encrypt_string: %v", err)
	}
	return strings.TrimRight(string(out), "\n") + "\n"
}

func writeOracleFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// oracleWorld is one run's directories: the playbook directory (the harness), the workspace (the
// inventory and the vault), the working directory and the dump.
type oracleWorld struct {
	dir, ws, cwd, out, pass string
}

func newOracleWorld(t *testing.T, play rosteroracletest.Play) oracleWorld {
	t.Helper()
	// Not t.TempDir(): its name carries the test's, and "{{" in a path is a template to Ansible.
	root, err := os.MkdirTemp("", "pw-oracle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	w := oracleWorld{dir: filepath.Join(root, "playbooks"), ws: filepath.Join(root, "ws"), cwd: filepath.Join(root, "cwd"), out: filepath.Join(root, "out"), pass: filepath.Join(root, "vault-pass")}
	for _, d := range []string{w.dir, w.ws, w.cwd, w.out} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rosteroracletest.WriteHarness(t, w.dir, play)
	writeOracleFile(t, w.pass, sentinelSecret(t)+"\n")
	return w
}

// stage writes the inventory, its group_vars and host_vars, the playbook's and the working
// directory's group_vars and the vault vars file (encrypted when asked) of the rows.
func (w oracleWorld) stage(t *testing.T, rows []pwOracleRow, adminVault string, encrypt bool) (vaultPath string) {
	t.Helper()
	join := func(pick func(pwOracleRow) string) string {
		var b strings.Builder
		for _, r := range rows {
			b.WriteString(pick(r))
		}
		return b.String()
	}
	indent := func(s string) string {
		var b strings.Builder
		for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
			if l != "" {
				b.WriteString("      " + l + "\n")
			}
		}
		return b.String()
	}
	writeOracleFile(t, filepath.Join(w.ws, "inventory.yml"), "all:\n  hosts:\n    localhost:\n      ansible_connection: local\n"+indent(join(func(r pwOracleRow) string { return r.inventory })))
	if g := join(func(r pwOracleRow) string { return r.group }); g != "" {
		writeOracleFile(t, filepath.Join(w.ws, "group_vars", "all.yml"), g)
	}
	if h := join(func(r pwOracleRow) string { return r.host }); h != "" {
		writeOracleFile(t, filepath.Join(w.ws, "host_vars", "localhost.yml"), h)
	}
	if p := join(func(r pwOracleRow) string { return r.playbook }); p != "" {
		writeOracleFile(t, filepath.Join(w.dir, "group_vars", "all.yml"), p)
	}
	if c := join(func(r pwOracleRow) string { return r.cwd }); c != "" {
		writeOracleFile(t, filepath.Join(w.cwd, "group_vars", "all.yml"), c)
	}
	vaultPath = filepath.Join(w.ws, ".vault", "main.yaml")
	writeOracleFile(t, vaultPath, "oracle_marker: 1\nipa_admin_password: "+q(adminVault)+"\n"+join(func(r pwOracleRow) string { return r.vault }))
	if encrypt {
		if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", w.pass, vaultPath).CombinedOutput(); err != nil {
			t.Fatalf("ansible-vault encrypt: %v\n%s", err, out)
		}
	}
	return vaultPath
}

// rosterOf writes the roster of the rows: one user each (u0, u1, ...), the alias rows' extra users after.
func (w oracleWorld) rosterOf(t *testing.T, rows []pwOracleRow) (path string, names []string) {
	t.Helper()
	var b strings.Builder
	b.WriteString("schema_version: 3\nfreeipa:\n  server: ipa.oracle.test\n  admin:\n    principal: admin\n    password: \"roster-admin-literal\"\nusers:\n")
	for i, r := range rows {
		name := fmt.Sprintf("u%d", i)
		names = append(names, name)
		if r.name == "a template shared between !unsafe and normal YAML" {
			// Two users share one password mapping; the second has it under an !unsafe mapping.
			fmt.Fprintf(&b, "  - name: %s\n    password: &shared%d\n      initial: %s\n", name, i, r.scalar)
			fmt.Fprintf(&b, "  - name: %sb\n    password: !unsafe\n      <<: *shared%d\n", name, i)
			names = append(names, name+"b")
			continue
		}
		fmt.Fprintf(&b, "  - name: %s\n    password: %s\n      initial: %s\n", name, r.passwordTag, r.scalar)
	}
	path = filepath.Join(w.dir, "roster.yaml")
	writeOracleFile(t, path, b.String())
	return path, names
}

func (w oracleWorld) env(t *testing.T) []string {
	return append(rosteroracletest.Env(t, w.dir), "ANSIBLE_VAULT_PASSWORD_FILE="+w.pass)
}

// goSide is what Go makes of the roster with the variables of the run: the listing the way
// golangRunVars asks for it (the -e of the vault file and the playbook directory as the base
// directory, from the working directory pilot happens to run in), then RosterUserPasswords.
func (w oracleWorld) goSide(t *testing.T, vaultPath, roster string) map[string]RosterUserPassword {
	t.Helper()
	cmd := exec.Command("ansible-inventory", "-i", filepath.Join(w.ws, "inventory.yml"), "--list", "-e", "@"+vaultPath, "--playbook-dir", w.dir)
	cmd.Dir = w.cwd
	cmd.Env = w.env(t)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ansible-inventory: %v\n%s", err, stderr.String())
	}
	var doc struct {
		Meta struct {
			HostVars map[string]map[string]any `json:"hostvars"`
		} `json:"_meta"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &doc); err != nil {
		t.Fatal(err)
	}
	hv, ok := doc.Meta.HostVars["localhost"]
	if !ok {
		t.Fatal("the listing has no localhost")
	}
	data, err := os.ReadFile(roster)
	if err != nil {
		t.Fatal(err)
	}
	got, err := RosterUserPasswords(data, &RosterRunVars{HostVars: hv, Consumer: RosterConsumerFreeIPAIdentity})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// ansibleSent is the password each user's passwd call would send, as the JSON of the field; a
// user with no entry has none.
func (w oracleWorld) ansibleSent(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(w.out, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	sent := map[string]json.RawMessage{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var call struct {
			Principal string          `json:"principal"`
			Password  json.RawMessage `json:"password"`
		}
		if err := json.Unmarshal(data, &call); err != nil {
			t.Fatalf("the dump %s is not the passwd call's JSON: %v", filepath.Base(f), err)
		}
		sent[call.Principal] = call.Password
	}
	return sent
}

// checkDoes asserts what Ansible did for a row: the JSON of what it sent ("" for none).
func checkDoes(t *testing.T, does ansibleDoes, sent json.RawMessage, hadEntry bool) {
	t.Helper()
	asString := func() (string, bool) {
		var s string
		if json.Unmarshal(sent, &s) != nil {
			return "", false
		}
		return s, true
	}
	switch does.kind {
	case "sends":
		if s, ok := asString(); !hadEntry || !ok || s != does.text {
			t.Fatalf("Ansible sent %s (a string: %v, equal to the row's: %v), the row says it sends a string (%d bytes)", describeSent(sent, hadEntry), ok, s == does.text, len(does.text))
		}
	case "sendsJSON":
		var buf strings.Builder
		if hadEntry {
			var v any
			_ = json.Unmarshal(sent, &v)
			raw, _ := json.Marshal(v)
			buf.Write(raw)
		}
		if !hadEntry || buf.String() != does.json {
			t.Fatalf("Ansible sent %s, the row says the JSON %s", describeSent(sent, hadEntry), does.json)
		}
	case "differs":
		if s, ok := asString(); hadEntry && ok && s == does.text {
			t.Fatalf("Ansible sent the value the inventory holds: the row is not a trap")
		}
		if !hadEntry {
			t.Fatalf("Ansible sent no password where the row says it sends another one")
		}
	case "oneOf":
		s, ok := asString()
		if !hadEntry || !ok || !containsString(does.oneOf, s) {
			t.Fatalf("Ansible sent %s, the row says one of %d strings", describeSent(sent, hadEntry), len(does.oneOf))
		}
	case "none":
		if hadEntry {
			t.Fatalf("Ansible sent %s, the row says it sets no password", describeSent(sent, hadEntry))
		}
	default:
		t.Fatalf("the row has no expectation of Ansible: %q", does.kind)
	}
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// describeSent says what Ansible sent without printing it (it can be a secret of the run).
func describeSent(sent json.RawMessage, had bool) string {
	if !had {
		return "no password"
	}
	var v any
	_ = json.Unmarshal(sent, &v)
	return fmt.Sprintf("a %T", v)
}

// oracleRun is one run of the real playbook over rows, and what Go makes of the same roster.
type oracleRun struct {
	w       oracleWorld
	outcome rosteroracletest.Outcome
	sent    map[string]json.RawMessage
	got     map[string]RosterUserPassword
	names   []string // the users of the rows, in order (an alias row owns two)
}

const sharedRowName = "a template shared between !unsafe and normal YAML"

// authCacheOutputOf is the path pilot's mixed run passes as pilot_identity_auth_cache_output.
func (w oracleWorld) authCacheOutput() string { return filepath.Join(w.out, "auth-cache.json") }

// runOracle stages rows in w, runs the real playbook with what pilot passes with -e besides the vault
// (the Ansible engine's names), and reads what Go makes of the roster. encrypt makes the vault
// vars file a whole-file ansible-vault file, read with the ambient secret by both sides.
func runOracle(t *testing.T, w oracleWorld, rows []pwOracleRow, s oracleSecrets, encrypt bool) oracleRun {
	t.Helper()
	vaultPath := w.stage(t, rows, s.admin, encrypt)
	roster, names := w.rosterOf(t, rows)
	outcome := rosteroracletest.RunWith(t, w.dir, rosteroracletest.IdentityCapture, rosteroracletest.RunOptions{
		RosterPath: roster, VarsPath: vaultPath, Inventory: filepath.Join(w.ws, "inventory.yml"), WorkDir: w.cwd, VaultPasswordFile: w.pass,
		ExtraVars: []string{"oracle_out=" + w.out, "target_group=oracle-target", "pilot_identity_users_groups_engine=go",
			"pilot_identity_auth_cache_output=" + w.authCacheOutput(), "pilot_deferred_hosts=[\"h1\"]"},
	})
	return oracleRun{w: w, outcome: outcome, sent: w.ansibleSent(t), got: w.goSide(t, vaultPath, roster), names: names}
}

// check asserts every row of the run: Go's verdict, Ansible's behaviour and, for a row Go resolves,
// that the two are the same bytes.
func (r oracleRun) check(t *testing.T, rows []pwOracleRow) {
	t.Helper()
	next := 0
	for _, row := range rows {
		owned := []string{r.names[next]}
		next++
		if row.name == sharedRowName {
			owned = append(owned, r.names[next])
			next++
		}
		t.Run(row.name, func(t *testing.T) {
			for _, user := range owned {
				pw, ok := r.got[user]
				if !ok {
					t.Fatalf("Go does not see %s", user)
				}
				raw, had := r.sent[user]
				if row.goValue != "" {
					if !pw.Sendable() || pw.Value != row.goValue {
						t.Fatalf("Go refused (%s, %s) or resolved another value (equal: %v), the row says it resolves", pw.Form, pw.Reason, pw.Value == row.goValue)
					}
					// The invariant: the same bytes.
					var s string
					if !had || json.Unmarshal(raw, &s) != nil || s != pw.Value {
						t.Fatalf("Go would send a value Ansible does not (Ansible sent %s)", describeSent(raw, had))
					}
				} else {
					if pw.Sendable() || pw.Value != "" {
						t.Fatalf("Go resolves (%s, %s) where the row says it refuses", pw.Form, pw.Reason)
					}
					why := pw.Form.String()
					if pw.Form == PasswordTemplate {
						why = pw.Reason.String()
					}
					if why != row.goWhy {
						t.Fatalf("Go refuses for %q, the row says %q", why, row.goWhy)
					}
				}
				if row.ansible.kind == "fails" {
					if r.outcome.OK {
						t.Fatal("the real playbook rendered the password: the row says it fails")
					}
					if r.outcome.Undefined != row.ansible.undefined {
						t.Fatalf("Ansible named %q undefined, the row says %q (task %q)", r.outcome.Undefined, row.ansible.undefined, r.outcome.Task)
					}
					if !strings.Contains(r.outcome.Output, row.ansible.failsWith) {
						t.Fatalf("Ansible's failure does not hold %q (task %q)", row.ansible.failsWith, r.outcome.Task)
					}
					if len(r.sent) != 0 {
						t.Fatalf("Ansible sent %d passwords from a play that failed", len(r.sent))
					}
					continue
				}
				checkDoes(t, row.ansible, raw, had)
			}
		})
	}
}

// TestRosterUserPasswordValuesMatchAnsible is the oracle (see the top of the file): for every row
// Go's verdict and Ansible's behaviour, with the vault vars file plain and encrypted.
func TestRosterUserPasswordValuesMatchAnsible(t *testing.T) {
	rosteroracletest.RequireAnsiblePlaybook(t)
	for _, mode := range []struct {
		name    string
		encrypt bool
	}{{"a plain vault vars file", false}, {"a whole-file encrypted vault vars file and the ambient secret", true}} {
		t.Run(mode.name, func(t *testing.T) {
			s := newOracleSecrets(t)
			w := newOracleWorld(t, rosteroracletest.IdentityCapture)
			rows := pwOracleRows(s,
				vaultEncryptString(t, w.pass, "v_inline", s.inlineVault),
				strings.TrimRight(vaultEncryptString(t, w.pass, "", s.rosterInline), "\n"),
				filepath.Join(w.dir, "roster.yaml"), w.authCacheOutput())
			run := runOracle(t, w, rows, s, mode.encrypt)
			if !run.outcome.OK {
				t.Fatalf("the real playbook did not get through the capture (task %q, undefined %q)", run.outcome.Task, run.outcome.Undefined)
			}
			run.check(t, rows)
		})
	}
}

// pwIsolatedRows are the rows that cannot share a run: the play fails on them (a variable nothing
// defines, a cycle, one that only the working directory's group_vars hold, which neither Ansible
// nor the listing, given the playbook directory, loads), or they change what every other row means
// (a name the vault passes with -e). Each is its own run; Go refuses each, naming why.
func pwIsolatedRows(s oracleSecrets) []pwOracleRow {
	lines100, first100 := chainLines("z", 100, s.chain)
	return []pwOracleRow{
		{name: "a variable nothing defines", scalar: `"{{ v_undefined }}"`, goWhy: "undefined",
			ansible: ansibleDoes{kind: "fails", undefined: "v_undefined", failsWith: "is undefined"}},
		{name: "a variable only the working directory's group_vars hold", scalar: `"{{ v_cwd_only }}"`, goWhy: "undefined",
			cwd: "v_cwd_only: from-the-working-directory\n", ansible: ansibleDoes{kind: "fails", undefined: "v_cwd_only", failsWith: "is undefined"}},
		{name: "a cycle", scalar: `"{{ cy1 }}"`, goWhy: "chain", vault: "cy1: \"{{ cy2 }}\"\ncy2: \"{{ cy1 }}\"\n",
			ansible: ansibleDoes{kind: "fails", failsWith: "Recursive loop detected in template"}},
		// A long enough chain is more than Ansible's own template recursion allows: the play fails and
		// nothing is sent. Go refuses it long before.
		{name: "a chain of 100 names: Ansible's own limit", scalar: `"{{ ` + first100 + ` }}"`, goWhy: "chain", vault: lines100,
			ansible: ansibleDoes{kind: "fails", failsWith: "Recursive loop detected in template"}},
		// -e outranks the settings set_fact: with identity_admin_password in the vault (not the
		// inventory) Ansible sends the vault's value. Go refuses the name all the same.
		{name: "identity_admin_password in the vault: -e outranks set_fact", scalar: `"{{ identity_admin_password }}"`, goWhy: "shadowed",
			vault: "identity_admin_password: " + q(s.vault) + "\n", ansible: sends(s.vault)},
	}
}

func TestRosterUserPasswordValuesInIsolatedRuns(t *testing.T) {
	rosteroracletest.RequireAnsiblePlaybook(t)
	s := newOracleSecrets(t)
	for _, row := range pwIsolatedRows(s) {
		t.Run(row.name, func(t *testing.T) {
			w := newOracleWorld(t, rosteroracletest.IdentityCapture)
			run := runOracle(t, w, []pwOracleRow{row}, s, false)
			if row.ansible.kind != "fails" && !run.outcome.OK {
				t.Fatalf("the real playbook failed (task %q, undefined %q)", run.outcome.Task, run.outcome.Undefined)
			}
			run.check(t, []pwOracleRow{row})
		})
	}
}

// The oracle rows are not vacuous: the table has both kinds of row in number, every row says what Go and
// Ansible do, and the names are unique (a duplicated row would hide a missing one).
func TestRosterUserPasswordOracleRowsAreWellFormed(t *testing.T) {
	s := newOracleSecrets(t)
	rows := append(pwOracleRows(s, "v_inline: x\n", "!vault |\n          x", "/p", "/o"), pwIsolatedRows(s)...)
	seen := map[string]bool{}
	resolved, refused := 0, 0
	for _, r := range rows {
		if seen[r.name] {
			t.Errorf("row %q twice", r.name)
		}
		seen[r.name] = true
		switch {
		case r.goValue != "" && r.goWhy == "":
			resolved++
		case r.goValue == "" && r.goWhy != "":
			refused++
		default:
			t.Errorf("row %q is neither resolved nor refused (value %v, why %q)", r.name, r.goValue != "", r.goWhy)
		}
		if r.ansible.kind == "" {
			t.Errorf("row %q has no expectation of Ansible", r.name)
		}
	}
	if resolved < 20 || refused < 25 {
		t.Errorf("%d resolved and %d refused rows: the table lost rows", resolved, refused)
	}
}
