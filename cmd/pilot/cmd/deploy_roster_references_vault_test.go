package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// What the roster reference precheck cannot read, it skips with one line and
// does not fail on; what it can read, in memory only, it judges like plain
// files; and no value of the roster or the vars file reaches its output or its
// error (issue #165).

const skippedMarker = "roster 變數引用檢查已略過"

func TestPrecheckRosterReferencesSkipsWhatItCannotRead(t *testing.T) {
	secret := lintRunSentinel(t)
	roster := rosterRefRoster(true, `"{{ lacking_admin }}"`, `"`+lintRunSentinel(t)+`"`)

	t.Run("--ask-vault-pass: no prompt of its own, no ansible-inventory at all", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, "other: 1\n")
		calls := toolCalls(t)
		out, err := env.call(t, "freeipa-nfs-server", nil, vaultInput{ExtraVarsFile: env.vars, AskVaultPass: true})
		if err != nil || !strings.Contains(out, skippedMarker) || !strings.Contains(out, "--ask-vault-pass") {
			t.Fatalf("err = %v, output = %q, want a skip that names --ask-vault-pass", err, out)
		}
		if got := calls(); len(got) != 0 {
			t.Fatalf("the check started %v with --ask-vault-pass", got)
		}
	})

	t.Run("an inventory ansible-inventory cannot list with the run's vault arguments", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
		out, err := env.call(t, "freeipa-nfs-server", nil, env.vault())
		if err != nil || !strings.Contains(out, skippedMarker) || !strings.Contains(out, "ansible-inventory") {
			t.Fatalf("err = %v, output = %q, want a skip that names ansible-inventory", err, out)
		}
	})

	t.Run("a malformed vars file: skipped, and its text is not repeated", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, "defined_name: "+secret+"\nbroken: [unclosed "+secret+"\n")
		out, err := env.call(t, "freeipa-nfs-server", nil, env.vault())
		if err != nil || !strings.Contains(out, skippedMarker) {
			t.Fatalf("err = %v, output = %q, want a skip", err, out)
		}
		if strings.Contains(out+errText(err), secret) {
			t.Fatalf("the skip shows the vars file's text: %q", out)
		}
	})

	t.Run("a roster that is not YAML: skipped, and its text is not repeated", func(t *testing.T) {
		env := newRosterRefEnv(t, "freeipa: {admin: "+secret+"\nusers: [unclosed\n", "other: 1\n")
		out, err := env.call(t, "freeipa-nfs-server", nil, env.vault())
		if err != nil || !strings.Contains(out, skippedMarker) {
			t.Fatalf("err = %v, output = %q, want a skip", err, out)
		}
		if strings.Contains(out+errText(err), secret) {
			t.Fatalf("the skip shows the roster's text: %q", out)
		}
	})

	t.Run("a roster that is not there", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, "other: 1\n")
		if err := os.Remove(env.roster); err != nil {
			t.Fatal(err)
		}
		out, err := env.call(t, "freeipa-nfs-server", nil, env.vault())
		if err != nil || !strings.Contains(out, skippedMarker) || !strings.Contains(out, "找不到 roster") {
			t.Fatalf("err = %v, output = %q, want a skip that says the roster is missing", err, out)
		}
	})

	t.Run("an encrypted roster and no --vault-password-file", func(t *testing.T) {
		requireAnsibleVault(t)
		env := newRosterRefEnv(t, roster, "other: 1\n")
		pw := writeVaultPasswordFile(t, filepath.Join(env.ws, "vault-pass"), lintRunSentinel(t))
		encryptFileForTest(t, env.roster, pw)
		out, err := env.call(t, "freeipa-nfs-server", nil, env.vault())
		if err != nil || !strings.Contains(out, skippedMarker) || !strings.Contains(out, "--vault-password-file") {
			t.Fatalf("err = %v, output = %q, want a skip that names --vault-password-file", err, out)
		}
	})

	t.Run("each reason is said once", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, "other: 1\n")
		env.rewriteInventory(t, "", withSecondNFSHost)
		if err := os.Remove(env.roster); err != nil {
			t.Fatal(err)
		}
		out, err := env.call(t, "freeipa-nfs-server", nil, env.vault())
		if err != nil || strings.Count(out, skippedMarker) != 1 {
			t.Fatalf("err = %v, output = %q, want the missing roster said once for two hosts", err, out)
		}
	})
}

// Real ansible-vault: an encrypted vars file and an encrypted roster, one
// password, are judged exactly like the plain files, in memory: the refusal and
// the verdict that it goes on are the plain ones, no decrypted text is left on
// disk, and nothing of either file is in the error.
func TestPrecheckRosterReferencesEncryptedFiles(t *testing.T) {
	requireAnsibleVault(t)
	tempDirs := isolateRosterLintTempDirs(t)
	definedValue, rosterLiteral := lintRunSentinel(t), lintRunSentinel(t)
	marker := "marker" + strings.ToLower(lintRunSentinel(t)[3:])
	// alice's password is a literal; nfs-server renders only the admin password.
	rosterText := strings.Replace(rosterRefRoster(true, `"{{ lacking_admin }}"`, `"`+rosterLiteral+`"`), "name: alice", "name: "+marker, 1)

	t.Run("refused with the encrypted files", func(t *testing.T) {
		env := newRosterRefEnv(t, rosterText, "defined_name: "+definedValue+"\n")
		pw := writeVaultPasswordFile(t, filepath.Join(env.ws, "vault-pass"), lintRunSentinel(t))
		encryptFileForTest(t, env.vars, pw)
		encryptFileForTest(t, env.roster, pw)
		vault := vaultInput{ExtraVarsFile: env.vars, VaultPasswordFile: pw}
		out, err := env.call(t, "freeipa-nfs-server", nil, vault)
		if err == nil || !strings.Contains(err.Error(), "freeipa.admin.password references lacking_admin") {
			t.Fatalf("err = %v, output = %q, want the refusal naming lacking_admin", err, out)
		}
		for _, secret := range []string{definedValue, rosterLiteral, marker} {
			if strings.Contains(out+err.Error(), secret) {
				t.Fatalf("a decrypted value was shown: %q / %v", out, err)
			}
		}
		for _, secret := range []string{definedValue, rosterLiteral, marker} {
			if hits := filesContaining(t, secret, append([]string{env.ws}, tempDirs...)...); len(hits) != 0 {
				t.Fatalf("decrypted content was left on disk in %v", hits)
			}
		}
	})

	t.Run("goes on when the encrypted vars file defines it", func(t *testing.T) {
		env := newRosterRefEnv(t, rosterText, "lacking_admin: "+definedValue+"\n")
		pw := writeVaultPasswordFile(t, filepath.Join(env.ws, "vault-pass"), lintRunSentinel(t))
		encryptFileForTest(t, env.vars, pw)
		encryptFileForTest(t, env.roster, pw)
		out, err := env.call(t, "freeipa-nfs-server", nil, vaultInput{ExtraVarsFile: env.vars, VaultPasswordFile: pw})
		if err != nil || out != "" {
			t.Fatalf("err = %v, output = %q, want a run that goes on, with nothing said", err, out)
		}
	})

	t.Run("a wrong password skips and shows nothing", func(t *testing.T) {
		env := newRosterRefEnv(t, rosterText, "defined_name: "+definedValue+"\n")
		pw := writeVaultPasswordFile(t, filepath.Join(env.ws, "vault-pass"), lintRunSentinel(t))
		wrong := writeVaultPasswordFile(t, filepath.Join(env.ws, "vault-pass-wrong"), lintRunSentinel(t))
		encryptFileForTest(t, env.vars, pw)
		encryptFileForTest(t, env.roster, pw)
		out, err := env.call(t, "freeipa-nfs-server", nil, vaultInput{ExtraVarsFile: env.vars, VaultPasswordFile: wrong})
		if err != nil || !strings.Contains(out, skippedMarker) {
			t.Fatalf("err = %v, output = %q, want a skip", err, out)
		}
		for _, secret := range []string{definedValue, rosterLiteral, marker} {
			if strings.Contains(out+errText(err), secret) {
				t.Fatalf("a decrypt failure shows content: %q", out)
			}
		}
	})

	for _, d := range tempDirs {
		if names := dirEntryNames(t, d); len(names) != 0 {
			t.Fatalf("temp directory %s not empty: %v", d, names)
		}
	}
}

// Whatever the precheck says, no value of the roster or the vars file is in it:
// not a defined variable's value, not the literal part of a mixed value, not
// another user's literal password.
func TestPrecheckRosterReferencesNeverShowsValues(t *testing.T) {
	mixed, userLiteral, definedValue := lintRunSentinel(t), lintRunSentinel(t), lintRunSentinel(t)
	roster := rosterRefRoster(true, `"`+mixed+`{{ lacking_admin }}"`, `"`+userLiteral+`"`)
	for name, component := range map[string]string{"nfs-server": "freeipa-nfs-server", "identity": "freeipa-identity"} {
		t.Run(name, func(t *testing.T) {
			env := newRosterRefEnv(t, roster, "defined_name: "+definedValue+"\nipa_admin_password:\n")
			out, err := env.call(t, component, nil, env.vault())
			if err == nil || !strings.Contains(err.Error(), "references lacking_admin") {
				t.Fatalf("err = %v, want the refusal", err)
			}
			for _, secret := range []string{mixed, userLiteral, definedValue} {
				if strings.Contains(out+err.Error(), secret) {
					t.Fatalf("a value was shown:\n%s\n%v", out, err)
				}
			}
		})
	}
	// The funnel's own output on a refusal.
	t.Run("the funnel", func(t *testing.T) {
		env := newRosterRefEnv(t, roster, "defined_name: "+definedValue+"\n")
		out, err := env.funnel(nfsPlaybook, "freeipa-nfs-server", nil, env.vault())
		env.assertRefusedByRosterReferences(err, out, "freeipa.admin.password references lacking_admin")
		for _, secret := range []string{mixed, userLiteral, definedValue} {
			if strings.Contains(out+err.Error(), secret) {
				t.Fatalf("a value was shown:\n%s\n%v", out, err)
			}
		}
	})
}
