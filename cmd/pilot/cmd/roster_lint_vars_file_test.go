package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `pilot roster lint --vars-file` (issue #165): a roster string that refers to
// a variable the vars file does not define passes a plain lint and then fails
// at apply, inside a no_log task. These tests run the real cobra command and
// check both directions (AGENTS.md §5.12): every reference the vars file lacks
// is reported, every one it has is not, and without --vars-file the command
// prints what it always printed.

// lintRunSentinel is a value generated for one test run: no fixture of the
// repository carries a credential-shaped literal.
func lintRunSentinel(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return "Sn-" + hex.EncodeToString(buf)
}

// lintRefRoster is a current-schema roster that passes lint, with the admin
// password and alice's initial password as the given YAML scalars.
func lintRefRoster(admin, initial string) string {
	return "schema_version: 3\nnetgroups: []\ngrants: []\nfreeipa:\n  admin:\n    principal: admin\n    password: " + admin +
		"\nusers:\n  - name: alice\n    password:\n      initial: " + initial + "\n    ssh_keys: {authoritative: true, values: []}\n"
}

func writeLintFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const lintOK = "ok: schema v3; no issues found\n"

func TestRosterLintVarsFile_ReportsEveryMissingReference(t *testing.T) {
	dir := t.TempDir()
	roster := writeLintFile(t, dir, "roster.yaml", lintRefRoster(`"{{ ipa_admin_password }}"`, `'{{ ipa_default_initial_password }}'`))
	vars := writeLintFile(t, dir, "main.yaml", "unrelated_key: 1\n")

	out, err := execRosterLint(t, "--vars-file", vars, roster)
	want := "[roster-reference] freeipa.admin.password references ipa_admin_password, which " + vars + " does not define\n" +
		"[roster-reference] users[alice].password.initial references ipa_default_initial_password, which " + vars + " does not define\n"
	if out != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if err == nil || err.Error() != "2 issue(s) found" {
		t.Fatalf("error = %v, want the existing %q path", err, "2 issue(s) found")
	}
}

func TestRosterLintVarsFile_ReportsOnlyWhatIsMissing(t *testing.T) {
	dir := t.TempDir()
	roster := writeLintFile(t, dir, "roster.yaml", lintRefRoster(`"{{ ipa_admin_password }}"`, `"{{ initial_pw }}"`))
	for name, tc := range map[string]struct {
		vars string
		want string
		err  string
	}{
		"the admin key only":  {"ipa_admin_password: x\n", "[roster-reference] users[alice].password.initial references initial_pw, which VARS does not define\n", "1 issue(s) found"},
		"the user key only":   {"initial_pw: x\n", "[roster-reference] freeipa.admin.password references ipa_admin_password, which VARS does not define\n", "1 issue(s) found"},
		"both":                {"ipa_admin_password: x\ninitial_pw: x\n", lintOK, ""},
		"both, one null":      {"ipa_admin_password: x\ninitial_pw:\n", lintOK, ""},
		"both by a merge key": {"base: &b {ipa_admin_password: x, initial_pw: y}\n<<: *b\n", lintOK, ""},
	} {
		t.Run(name, func(t *testing.T) {
			vars := writeLintFile(t, dir, "vars-"+strings.ReplaceAll(name, " ", "-")+".yaml", tc.vars)
			out, err := execRosterLint(t, "--vars-file", vars, roster)
			if want := strings.ReplaceAll(tc.want, "VARS", vars); out != want {
				t.Fatalf("stdout = %q, want %q", out, want)
			}
			if got := errText(err); (tc.err == "" && err != nil) || (tc.err != "" && got != tc.err) {
				t.Fatalf("error = %q, want %q", got, tc.err)
			}
		})
	}
}

// A reference finding joins the structural violations of the same lint and
// counts with them.
func TestRosterLintVarsFile_JoinsTheStructuralViolations(t *testing.T) {
	dir := t.TempDir()
	broken := strings.Replace(lintRefRoster(`"`+lintRunSentinel(t)+`"`, `"{{ missing_one }}"`), "name: alice", "name: Alice", 1)
	roster := writeLintFile(t, dir, "roster.yaml", broken)
	vars := writeLintFile(t, dir, "main.yaml", "other: 1\n")
	out, err := execRosterLint(t, "--vars-file", vars, roster)
	if !strings.Contains(out, "[user name]") || !strings.Contains(out, "[roster-reference] users[Alice].password.initial references missing_one") {
		t.Fatalf("stdout = %q, want the structural violation and the reference finding", out)
	}
	if err == nil || err.Error() != "2 issue(s) found" {
		t.Fatalf("error = %v, want 2 issues", err)
	}
}

// Without --vars-file nothing is found on its own and the output is what the
// command printed before the flag existed: a roster that refers to variables
// nobody defines, next to a .vault/main.yaml that lacks them, still lints clean.
func TestRosterLintWithoutVarsFileIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeLintFile(t, filepath.Join(dir, ".vault"), "main.yaml", "unrelated_key: 1\n")
	roster := writeLintFile(t, dir, "roster.yaml", lintRefRoster(`"{{ ipa_admin_password }}"`, `"{{ ipa_default_initial_password }}"`))
	// A password file that does not exist is not read either (no encrypted file).
	for _, args := range [][]string{{roster}, {"--vault-password-file", filepath.Join(dir, "no-such-password-file"), roster}} {
		out, err := execRosterLint(t, args...)
		if out != lintOK || err != nil {
			t.Fatalf("%v: stdout = %q, error = %v, want %q and no error", args, out, err, lintOK)
		}
	}
	// The same roster with a vars file that defines everything prints the same.
	vars := writeLintFile(t, dir, "full.yaml", "ipa_admin_password: x\nipa_default_initial_password: x\n")
	out, err := execRosterLint(t, "--vars-file", vars, roster)
	if out != lintOK || err != nil {
		t.Fatalf("with a complete vars file: stdout = %q, error = %v", out, err)
	}
}

// What cannot be judged is never reported: filters, operators, !unsafe,
// inline !vault, blocks, literals and the names Ansible supplies.
func TestRosterLintVarsFile_DoesNotReportWhatItCannotJudge(t *testing.T) {
	dir := t.TempDir()
	adminLit := `"` + lintRunSentinel(t) + `"`
	vars := writeLintFile(t, dir, "main.yaml", "other: 1\n")
	for name, initial := range map[string]string{
		"default filter": `"{{ nope | default('') }}"`,
		"unsafe":         `!unsafe "{{ nope }}"`,
		"raw block":      `"{% raw %}{{ nope }}{% endraw %}"`,
		"magic variable": `"{{ inventory_hostname }}"`,
		"jinja literal":  `"{{ none }}"`,
		"a literal":      `"` + lintRunSentinel(t) + `"`,
		"empty":          `""`,
		"inline !vault":  "!vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162636465",
		"a call":         `"{{ lookup('env', 'NOPE') }}"`,
		"another scalar": `12345678`,
	} {
		t.Run(name, func(t *testing.T) {
			roster := writeLintFile(t, dir, "r.yaml", lintRefRoster(adminLit, initial))
			out, err := execRosterLint(t, "--vars-file", vars, roster)
			if out != lintOK || err != nil {
				t.Fatalf("stdout = %q, error = %v, want a clean lint", out, err)
			}
		})
	}
}

// An explicit --vars-file is strict: it never falls back to nothing.
func TestRosterLintVarsFile_IsStrict(t *testing.T) {
	dir := t.TempDir()
	roster := writeLintFile(t, dir, "roster.yaml", lintRefRoster(`"{{ a }}"`, `"{{ b }}"`))
	secret := lintRunSentinel(t)

	unreadable := writeLintFile(t, dir, "unreadable.yaml", "a: 1\n")
	if err := os.Chmod(unreadable, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(unreadable, 0o600) })

	cases := []struct {
		name   string
		vars   string
		want   string
		skipIf func() bool
	}{
		{"a missing file", filepath.Join(dir, "no-such-file.yaml"), "no such file or directory", nil},
		{"a directory", dir, "is a directory", nil},
		{"an unreadable file", unreadable, "permission denied", func() bool { return os.Geteuid() == 0 }},
		{"an encrypted file with no password file", writeLintFile(t, dir, "enc.yaml", "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n"), "ansible-vault encrypted", nil},
		{"a file that is not YAML", writeLintFile(t, dir, "bad.yaml", "key: "+secret+"\nother: [1, 2\n"), "not valid YAML", nil},
		{"a file that is not a mapping", writeLintFile(t, dir, "list.yaml", "- "+secret+"\n- two\n"), "not a YAML mapping", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipIf != nil && tc.skipIf() {
				t.Skip("root reads any file")
			}
			out, stderr, err := execRosterLintStreams(t, "--vars-file", tc.vars, roster)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want one containing %q", err, tc.want)
			}
			if strings.Contains(out+stderr+err.Error(), secret) {
				t.Fatalf("the failure shows the file's content:\nstdout %q\nstderr %q\nerr %v", out, stderr, err)
			}
			if out != "" {
				t.Fatalf("stdout = %q, want nothing: a vars file that cannot be read is an error, not a report", out)
			}
		})
	}
}

// A plain vars file never needs the password file, and one that is given but
// not found is not read.
func TestRosterLintVarsFile_PlainFileIgnoresVaultPasswordFile(t *testing.T) {
	dir := t.TempDir()
	roster := writeLintFile(t, dir, "roster.yaml", lintRefRoster(`"{{ a }}"`, `"{{ b }}"`))
	vars := writeLintFile(t, dir, "main.yaml", "a: 1\nb: 2\n")
	out, err := execRosterLint(t, "--vars-file", vars, "--vault-password-file", filepath.Join(dir, "no-such-password-file"), roster)
	if out != lintOK || err != nil {
		t.Fatalf("stdout = %q, error = %v", out, err)
	}
}

// Nothing of the roster's or the vars file's values reaches stdout, stderr or
// an error: not a defined variable's value, not the literal part of a mixed
// value, not a malformed vars file's text.
func TestRosterLintVarsFile_NeverShowsValues(t *testing.T) {
	dir := t.TempDir()
	definedValue, mixedLiteral, adminLiteral := lintRunSentinel(t), lintRunSentinel(t), lintRunSentinel(t)
	roster := writeLintFile(t, dir, "roster.yaml", lintRefRoster(`"`+adminLiteral+`"`, `"`+mixedLiteral+`{{ missing_name }}"`))
	rosterDefined := writeLintFile(t, dir, "roster-defined.yaml", lintRefRoster(`"{{ defined_name }}"`, `"`+mixedLiteral+`{{ defined_name }}"`))
	vars := writeLintFile(t, dir, "main.yaml", "defined_name: "+definedValue+"\n")
	malformed := writeLintFile(t, dir, "malformed.yaml", "defined_name: "+definedValue+"\nbroken: [unclosed "+definedValue+"\n")

	for name, tc := range map[string]struct {
		roster, vars string
	}{
		"a missing reference next to values": {roster, vars},
		"every reference defined":            {rosterDefined, vars},
		"a malformed vars file":              {roster, malformed},
	} {
		t.Run(name, func(t *testing.T) {
			stdout, stderr, err := execRosterLintStreams(t, "--vars-file", tc.vars, tc.roster)
			shown := stdout + "\n" + stderr + "\n" + errText(err)
			for _, secret := range []string{definedValue, mixedLiteral, adminLiteral} {
				if strings.Contains(shown, secret) {
					t.Fatalf("a value was shown:\nstdout %q\nstderr %q\nerr %v", stdout, stderr, err)
				}
			}
		})
	}
}

// Real ansible-vault: an encrypted vars file (and an encrypted roster, with the
// same password) reports exactly what the plaintext files report, a wrong
// password is an error that names none of the content, and no decrypted text
// is left on disk.
func TestRosterLintVarsFile_EncryptedFilesReportLikePlaintext(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	tempDirs := isolateRosterLintTempDirs(t)
	definedValue, mixedLiteral := lintRunSentinel(t), lintRunSentinel(t)
	marker := "marker" + strings.ToLower(lintRunSentinel(t)[3:])
	rosterText := lintRefRoster(`"{{ ipa_admin_password }}"`, `"`+mixedLiteral+`{{ missing_name }}"`)
	varsText := "ipa_admin_password: " + definedValue + "\n" + marker + ": 1\n"

	plainRoster := writeLintFile(t, dir, "plain-roster.yaml", rosterText)
	plainVars := writeLintFile(t, dir, "plain-vars.yaml", varsText)
	wantOut, wantErr := execRosterLint(t, "--vars-file", plainVars, plainRoster)
	if wantErr == nil || !strings.Contains(wantOut, "references missing_name, which") {
		t.Fatalf("plaintext lint: stdout = %q, error = %v, want the missing_name finding", wantOut, wantErr)
	}

	pw := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), lintRunSentinel(t))
	wrong := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass-wrong"), lintRunSentinel(t))
	encVars := writeLintFile(t, dir, "enc-vars.yaml", varsText)
	encryptFileForTest(t, encVars, pw)
	encRoster := writeLintFile(t, dir, "enc-roster.yaml", rosterText)
	encryptFileForTest(t, encRoster, pw)

	// The report names the vars file as it was given, so compare with that name
	// substituted.
	normalize := func(out, varsPath string) string { return strings.ReplaceAll(out, varsPath, "VARS") }
	for name, tc := range map[string]struct{ roster, vars string }{
		"encrypted vars file, plain roster":     {plainRoster, encVars},
		"encrypted vars file, encrypted roster": {encRoster, encVars},
		"plain vars file, encrypted roster":     {encRoster, plainVars},
	} {
		t.Run(name, func(t *testing.T) {
			out, stderr, err := execRosterLintStreams(t, "--vars-file", tc.vars, "--vault-password-file", pw, tc.roster)
			if normalize(out, tc.vars) != normalize(wantOut, plainVars) || errText(err) != errText(wantErr) {
				t.Fatalf("stdout = %q, error = %v\nwant     %q, error = %v", out, err, wantOut, wantErr)
			}
			for _, secret := range []string{definedValue, mixedLiteral, marker} {
				if strings.Contains(out+stderr+errText(err), secret) {
					t.Fatalf("a decrypted value was shown: %q %q %v", out, stderr, err)
				}
			}
		})
	}

	t.Run("an encrypted vars file with no password file", func(t *testing.T) {
		out, err := execRosterLint(t, "--vars-file", encVars, plainRoster)
		if err == nil || !strings.Contains(err.Error(), encVars) || !strings.Contains(err.Error(), "ansible-vault encrypted") || !strings.Contains(err.Error(), "--vault-password-file") || out != "" {
			t.Fatalf("stdout = %q, error = %v, want the strict --vault-password-file error", out, err)
		}
	})
	t.Run("a wrong password", func(t *testing.T) {
		out, stderr, err := execRosterLintStreams(t, "--vars-file", encVars, "--vault-password-file", wrong, plainRoster)
		if err == nil || out != "" {
			t.Fatalf("stdout = %q, error = %v, want a decrypt failure", out, err)
		}
		for _, secret := range []string{definedValue, mixedLiteral, marker} {
			if strings.Contains(out+stderr+err.Error(), secret) {
				t.Fatalf("a decrypt failure shows content: %q %q %v", out, stderr, err)
			}
		}
	})

	for _, secret := range []string{definedValue, mixedLiteral, marker} {
		if hits := filesContaining(t, secret, append([]string{dir}, tempDirs...)...); len(hits) != 0 {
			// The plain files this test wrote are the only allowed holders.
			for _, hit := range hits {
				if hit != plainRoster && hit != plainVars {
					t.Fatalf("decrypted content was left on disk in %s", hit)
				}
			}
		}
	}
	for _, d := range tempDirs {
		if names := dirEntryNames(t, d); len(names) != 0 {
			t.Fatalf("temp directory %s not empty after lint: %v", d, names)
		}
	}
}
