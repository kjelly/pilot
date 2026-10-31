package cmd

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// rosterLintVaultMarker is a user name only the plaintext of the encrypted
// fixtures below contains: finding it in any file after a run means lint
// left decrypted roster content on disk.
const rosterLintVaultMarker = "lintmarker7f3a"

const rosterLintVaultFixtureCurrent = `
schema_version: 3
netgroups: []
grants: []
users:
  - name: ` + rosterLintVaultMarker + `
    ssh_keys: {authoritative: true, values: []}
`

// execRosterLint runs `pilot roster lint <args>` through the real root
// command and returns what it wrote to stdout. lint's flags are package
// state that cobra leaves set after a run, so they are reset before and
// after each run (a missing flag is skipped, so this still compiles and
// runs against a lint without --vault-password-file).
func execRosterLint(t *testing.T, args ...string) (string, error) {
	t.Helper()
	reset := func() {
		for _, name := range []string{"upgrade", "vault-password-file"} {
			if f := rosterLintCmd.Flags().Lookup(name); f != nil {
				_ = f.Value.Set(f.DefValue)
				f.Changed = false
			}
		}
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	}
	reset()
	t.Cleanup(reset)
	var stdout, stderr bytes.Buffer
	rootCmd.SetArgs(append([]string{"roster", "lint"}, args...))
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	err := rootCmd.Execute()
	return stdout.String(), err
}

// isolateRosterLintTempDirs points every temp directory lint or
// ansible-vault could use at fresh test directories and returns them, so a
// test can check afterwards that nothing was left in them.
func isolateRosterLintTempDirs(t *testing.T) []string {
	t.Helper()
	tmp := t.TempDir()
	ansibleTmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("ANSIBLE_LOCAL_TEMP", ansibleTmp)
	return []string{tmp, ansibleTmp}
}

// filesContaining lists every regular file under dirs whose content
// contains needle.
func filesContaining(t *testing.T, needle string, dirs ...string) []string {
	t.Helper()
	var hits []string
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
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
			if bytes.Contains(data, []byte(needle)) {
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

func dirEntryNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func errText(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// TestRosterLintCmd_EncryptedRosterReportsLikePlaintext lints each fixture
// as plaintext, encrypts the same file with ansible-vault, and lints it
// again with --vault-password-file: stdout and the error must be identical
// (the path is the same, so so is the migrate notice), and the encrypted
// file must be left as it was.
func TestRosterLintCmd_EncryptedRosterReportsLikePlaintext(t *testing.T) {
	requireAnsibleVault(t)
	example, err := os.ReadFile(filepath.Join(repoRootForTest(t), "playbooks", "apply", "freeipa-identity.roster.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		roster  string
		wantOut string
		wantErr bool
	}{
		"current schema":          {roster: rosterLintVaultFixtureCurrent, wantOut: "ok: schema v3; no issues found"},
		"older schema notice":     {roster: strings.Replace(rosterLintFixtureValid, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1), wantOut: "notice: current schema is v3"},
		"deprecation warnings":    {roster: rosterLintFixtureTwoAccessGroups, wantOut: `warning: group "access-a" uses deprecated category "access"`},
		"dangling host warning":   {roster: rosterLintFixtureDanglingHostReference, wantOut: `warning: hostgroups[hg1].membership.hosts references "missing.ipa.pilot.internal"`},
		"structural violations":   {roster: rosterLintFixtureBroken, wantOut: "[user name]", wantErr: true},
		"repository example file": {roster: string(example), wantOut: "ok: schema v"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "roster.yaml")
			if err := os.WriteFile(path, []byte(tc.roster), 0o600); err != nil {
				t.Fatal(err)
			}
			plainOut, plainErr := execRosterLint(t, path)
			if (plainErr != nil) != tc.wantErr || !strings.Contains(plainOut, tc.wantOut) {
				t.Fatalf("plaintext lint: err = %v, output = %q, want error %v and %q", plainErr, plainOut, tc.wantErr, tc.wantOut)
			}

			pw := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "lint-test-password")
			encryptFileForTest(t, path, pw)
			encrypted, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			gotOut, gotErr := execRosterLint(t, "--vault-password-file", pw, path)
			if gotOut != plainOut {
				t.Fatalf("encrypted lint stdout differs from plaintext lint:\nencrypted: %q\nplaintext: %q", gotOut, plainOut)
			}
			if errText(gotErr) != errText(plainErr) {
				t.Fatalf("encrypted lint error = %q, plaintext lint error = %q", errText(gotErr), errText(plainErr))
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, encrypted) {
				t.Fatalf("lint without --upgrade changed the encrypted roster (err=%v)", err)
			}
		})
	}
}

func TestRosterLintCmd_EncryptedRosterWithoutFlagSuggestsIt(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintVaultFixtureCurrent), 0o600); err != nil {
		t.Fatal(err)
	}
	encryptFileForTest(t, path, writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "lint-test-password"))

	out, err := execRosterLint(t, path)
	if err == nil || !strings.Contains(err.Error(), "ansible-vault encrypted") || !strings.Contains(err.Error(), "--vault-password-file") {
		t.Fatalf("Execute() error = %v, want an ansible-vault-encrypted message pointing at --vault-password-file", err)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want nothing", out)
	}
}

func TestRosterLintCmd_EncryptedRosterWrongPasswordFails(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintVaultFixtureCurrent), 0o600); err != nil {
		t.Fatal(err)
	}
	encryptFileForTest(t, path, writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "lint-test-password"))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	wrong := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass-wrong"), "not-the-password")

	for _, args := range [][]string{{"--vault-password-file", wrong, path}, {"--upgrade", "--vault-password-file", wrong, path}} {
		out, err := execRosterLint(t, args...)
		if err == nil || !strings.Contains(err.Error(), "decrypt roster "+path) || !strings.Contains(err.Error(), "Decryption failed") {
			t.Fatalf("%v: Execute() error = %v, want a decrypt failure naming the roster", args, err)
		}
		if out != "" || strings.Contains(err.Error(), rosterLintVaultMarker) {
			t.Fatalf("%v: stdout = %q, error = %q: a failed decrypt must report nothing of the roster", args, out, err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("roster changed after a failed decrypt (err=%v)", err)
	}
	if names := dirEntryNames(t, dir); strings.Join(names, ",") != "roster.yaml,vault-pass,vault-pass-wrong" {
		t.Fatalf("roster directory = %v, want only the roster and the password files (no lock, backup or temp file)", names)
	}
}

func TestRosterLintCmd_EncryptedRosterMissingPasswordFileFails(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte(rosterLintVaultFixtureCurrent), 0o600); err != nil {
		t.Fatal(err)
	}
	encryptFileForTest(t, path, writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "lint-test-password"))
	missing := filepath.Join(dir, "no-such-vault-pass")

	out, err := execRosterLint(t, "--vault-password-file", missing, path)
	if err == nil || !strings.Contains(err.Error(), "decrypt roster "+path) || !strings.Contains(err.Error(), missing+" was not found") {
		t.Fatalf("Execute() error = %v, want a decrypt failure saying the password file was not found", err)
	}
	if out != "" {
		t.Fatalf("stdout = %q, want nothing", out)
	}
}

// TestRosterLintCmd_PlaintextRosterIgnoresVaultPasswordFile: the flag is
// accepted and not read for a plaintext roster (as for `pilot roster
// migrate` and `remove-user`), so a script can pass one password file for
// every roster it lints. The password file here does not even exist.
func TestRosterLintCmd_PlaintextRosterIgnoresVaultPasswordFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	v2 := strings.Replace(rosterLintFixtureValid, "schema_version: 1", "schema_version: 2\nnetgroups: []", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	want, wantErr := execRosterLint(t, path)
	got, gotErr := execRosterLint(t, "--vault-password-file", filepath.Join(dir, "no-such-vault-pass"), path)
	if got != want || errText(gotErr) != errText(wantErr) {
		t.Fatalf("with the flag: %q, %v; without: %q, %v", got, gotErr, want, wantErr)
	}
	if !strings.Contains(got, "ok: schema v2 is valid") {
		t.Fatalf("output = %q, want the plaintext roster linted", got)
	}
}

// TestRosterLintCmd_EncryptedRosterLeavesNoPlaintext checks every place a
// decrypted copy could land — the roster's directory, $TMPDIR and
// ansible's local temp directory — for the fixture's plaintext, after a
// clean lint, a failing lint and an unparsable roster.
func TestRosterLintCmd_EncryptedRosterLeavesNoPlaintext(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	tempDirs := isolateRosterLintTempDirs(t)
	pw := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "lint-test-password")
	rosters := map[string]string{
		"clean.yaml":  rosterLintVaultFixtureCurrent,
		"broken.yaml": strings.Replace(rosterLintVaultFixtureCurrent, rosterLintVaultMarker, rosterLintVaultMarker+"-Bad", 1),
		// A YAML scalar, not a mapping: yaml.v3's error would quote it.
		"scalar.yaml": rosterLintVaultMarker + "\n",
	}
	for name, content := range rosters {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		encryptFileForTest(t, path, pw)
	}
	before := dirEntryNames(t, dir)

	out, err := execRosterLint(t, "--vault-password-file", pw, filepath.Join(dir, "clean.yaml"))
	if err != nil || !strings.Contains(out, "ok: schema v3; no issues found") {
		t.Fatalf("clean roster: err = %v, output = %q", err, out)
	}
	out, err = execRosterLint(t, "--vault-password-file", pw, filepath.Join(dir, "broken.yaml"))
	if err == nil || !strings.Contains(out, "[user name]") {
		t.Fatalf("broken roster: err = %v, output = %q, want a user name violation", err, out)
	}
	scalar := filepath.Join(dir, "scalar.yaml")
	out, err = execRosterLint(t, "--vault-password-file", pw, scalar)
	if err == nil || !strings.Contains(err.Error(), "parse roster "+scalar) || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("scalar roster: err = %v, want a parse error naming the roster and line 1", err)
	}
	// yaml.v3 quotes at most the first seven characters of a long value.
	if out != "" || strings.Contains(err.Error(), rosterLintVaultMarker[:7]) {
		t.Fatalf("scalar roster: stdout = %q, error = %q: the error must not quote decrypted text", out, err)
	}

	if hits := filesContaining(t, rosterLintVaultMarker, append([]string{dir}, tempDirs...)...); len(hits) != 0 {
		t.Fatalf("decrypted roster content left on disk in %v", hits)
	}
	if after := dirEntryNames(t, dir); strings.Join(after, ",") != strings.Join(before, ",") {
		t.Fatalf("roster directory changed: before %v, after %v", before, after)
	}
	for _, d := range tempDirs {
		if names := dirEntryNames(t, d); len(names) != 0 {
			t.Fatalf("temp directory %s not empty after lint: %v", d, names)
		}
	}
}

// TestRosterLintCmd_UpgradeEncryptedRosterReencrypts: --upgrade on an
// encrypted roster goes through MigrateRosterFile's encrypted path with the
// same password file, the same as `pilot roster migrate
// --vault-password-file`: the roster and its backup stay encrypted and no
// plaintext is left behind.
func TestRosterLintCmd_UpgradeEncryptedRosterReencrypts(t *testing.T) {
	requireAnsibleVault(t)
	dir := t.TempDir()
	tempDirs := isolateRosterLintTempDirs(t)
	path := filepath.Join(dir, "roster.yaml")
	v2 := strings.Replace(rosterLintVaultFixtureCurrent, "schema_version: 3\nnetgroups: []\ngrants: []", "schema_version: 2\nnetgroups: []", 1)
	if err := os.WriteFile(path, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	pw := writeVaultPasswordFile(t, filepath.Join(dir, "vault-pass"), "lint-test-password")
	encryptFileForTest(t, path, pw)

	out, err := execRosterLint(t, "--upgrade", "--vault-password-file", pw, path)
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Roster migrated successfully") || !strings.Contains(out, "schema:\n  2 -> 3") || !strings.Contains(out, "backup:") {
		t.Fatalf("output = %q, want a v2->v3 migration report", out)
	}
	migrated, err := os.ReadFile(path)
	if err != nil || !strings.HasPrefix(string(migrated), "$ANSIBLE_VAULT") {
		t.Fatalf("upgraded roster is not ansible-vault encrypted (err=%v)", err)
	}
	if !strings.Contains(string(viewFileForTest(t, path, pw)), "schema_version: 3") {
		t.Fatal("decrypted upgraded roster is not schema_version: 3")
	}
	backups, err := filepath.Glob(filepath.Join(dir, "roster.yaml.v2.*.bak"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("backups = %v (err=%v), want exactly one", backups, err)
	}
	if backup, err := os.ReadFile(backups[0]); err != nil || !strings.HasPrefix(string(backup), "$ANSIBLE_VAULT") {
		t.Fatalf("backup %s is not the encrypted original (err=%v)", backups[0], err)
	}
	if hits := filesContaining(t, rosterLintVaultMarker, append([]string{dir}, tempDirs...)...); len(hits) != 0 {
		t.Fatalf("decrypted roster content left on disk in %v", hits)
	}

	// Linting the upgraded roster now reports it current.
	out, err = execRosterLint(t, "--vault-password-file", pw, path)
	if err != nil || !strings.Contains(out, "ok: schema v3; no issues found") {
		t.Fatalf("lint after upgrade: err = %v, output = %q", err, out)
	}
}
