package cmd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/identityreconcile"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/rosteroracletest"
)

// A password.initial that is exactly one bare {{ name }} (issue #394) from the cobra command to
// FreeIPA: the variable is resolved through the real `ansible-inventory --list` run with the
// run's own -e @.vault/main.yaml (plain or encrypted with the ambient vault secret), the value
// the server receives is exactly the vault's, and the value is in no output, plan, result,
// journal, log or error. The FreeIPA server and the dialer are the apply tests' fakes; what is
// real is ansible-inventory, ansible and ansible-vault, which these tests need (skipped without
// them; PILOT_REQUIRE_CONTAINER_TESTS=1 makes their absence a failure).

// pwRefSecret is a password made for one run of a test: nothing in the repository holds one.
func pwRefSecret(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 9)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	return "Rf-" + hex.EncodeToString(buf)
}

// pwRefWorkspace is golangWorkspace with a REAL inventory file and no fake ansible tools: the
// inventory, the vault vars file (extraVault is more of its YAML; encrypt makes it an
// ansible-vault file whose secret is the ambient ANSIBLE_VAULT_PASSWORD_FILE) and the roster.
func pwRefWorkspace(t *testing.T, roster, extraVault string, encrypt bool) string {
	t.Helper()
	rosteroracletest.RequireAnsiblePlaybook(t)
	dir := t.TempDir()
	t.Chdir(dir)
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, ".vault"), 0o700))
	vault := map[string]string{}
	for _, key := range inventory.ExpectedVaultKeysForRoles([]string{"freeipa-server"}) {
		vault[key] = "sample-value-for-" + key
	}
	vault["ipa_admin_password"] = golangTestPassword
	vaultYAML, _ := yaml.Marshal(vault)
	vaultPath := filepath.Join(dir, ".vault", "main.yaml")
	must(os.WriteFile(vaultPath, append(vaultYAML, []byte(extraVault)...), 0o600))
	if encrypt {
		pass := filepath.Join(t.TempDir(), "vault-pass")
		must(os.WriteFile(pass, []byte(pwRefSecret(t)+"\n"), 0o600))
		if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", pass, vaultPath).CombinedOutput(); err != nil {
			t.Fatalf("ansible-vault encrypt: %v\n%s", err, out)
		}
		t.Setenv("ANSIBLE_VAULT_PASSWORD_FILE", pass)
	}
	must(os.WriteFile(filepath.Join(dir, ".vault", "ipa-identity.yaml"), []byte(roster), 0o600))
	must(os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte(`all:
  children:
    freeipa-server:
      hosts:
        ipa-1:
          ansible_host: 192.0.2.10
          ansible_user: root
          freeipa_roster_file: .vault/ipa-identity.yaml
`), 0o600))
	return dir
}

// pwRefApplyEnv is newApplyEnvWith over pwRefWorkspace: the entry's ansible-playbook is the apply
// tests' script, and the lock is the in-memory one.
func pwRefApplyEnv(t *testing.T, roster, extraVault string, encrypt bool) *applyEnv {
	t.Helper()
	f := newFakeIPA(t, "p1-self")
	withFakeDialer(t, f)
	dir := pwRefWorkspace(t, roster, extraVault, encrypt)
	e := &applyEnv{t: t, f: f, a: newApplyFake(f), dir: dir, lock: useFakeIdentityLock(t)}
	e.log = filepath.Join(dir, "playbook.log")
	e.events = filepath.Join(dir, "events.log")
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-playbook"), []byte(fakeEntryPlaybook), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("P26_LOG", e.log)
	e.lock.Events = func(s string) { appendEvent(t, e.events, s) }
	return e
}

// pwRefRoster is the capture's roster plus p26-new, new to the server, whose password.initial is
// the YAML scalar given.
func pwRefRoster(initial string) string {
	return strings.Replace(captureRoster, "%s", "/bin/sh", 1) + "  - {name: p26-new, first: P26, last: New, password: {initial: " + initial + "}}\n"
}

// pwRefInventoryTap puts an ansible-inventory first on PATH that logs its arguments and, when the
// listing is asked with a -e @vault, fails with stderr text of the sentinel (the way a vars file
// ansible cannot parse makes it quote file content); every other call is the real one.
func pwRefInventoryTap(t *testing.T, failWith string) (calls func() []string) {
	t.Helper()
	real, err := exec.LookPath("ansible-inventory")
	if err != nil {
		t.Skipf("ansible-inventory is not installed: %v", err)
	}
	bin := t.TempDir()
	log := filepath.Join(bin, "calls")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\n"
	if failWith != "" {
		body += "case \"$*\" in *'-e @'*) echo '" + failWith + "' >&2; exit 1;; esac\n"
	}
	body += "exec '" + real + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "ansible-inventory"), []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return func() []string {
		data, _ := os.ReadFile(log)
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
}

// assertNoValueAnywhere fails when any of values is in the error, the output, the plan or
// result file, the journal (the store) or any file of the pilot data directory (ansible.log
// included).
func assertNoValueAnywhere(t *testing.T, values []string, err error, out string, files ...string) {
	t.Helper()
	if dataDir == "" {
		t.Fatal("the pilot data directory is not the test's: the scan would read nothing")
	}
	texts := map[string]string{"output": out}
	if err != nil {
		texts["error"] = err.Error()
	}
	for _, f := range files {
		if data, rerr := os.ReadFile(f); rerr == nil {
			texts[f] = string(data)
		}
	}
	scanned := 0
	_ = filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, werr error) error {
		if werr == nil && !d.IsDir() {
			if data, rerr := os.ReadFile(p); rerr == nil {
				texts[p] = string(data)
				scanned++
			}
		}
		return nil
	})
	if scanned == 0 {
		t.Fatal("the pilot data directory holds no file: the scan read nothing")
	}
	for where, text := range texts {
		for _, v := range values {
			if v != "" && strings.Contains(text, v) {
				t.Fatalf("a value leaked into %s", where)
			}
		}
	}
}

// R1: a templated new user, the value in the run's vault vars file, plain and encrypted: the plan
// has the password operation, the server receives the vault's value byte for byte, and the exit
// is what a successful apply of a new user is (4: only the authorization cache is owed).
func TestRosterPasswordReferenceIsSentAsTheVaultValue(t *testing.T) {
	hostile := "  Pa ss 0123 密碼🔑`$HOME`%s \\n 'q' \"d\"  "
	for _, tc := range []struct {
		name    string
		encrypt bool
		value   func(t *testing.T) string
	}{
		{"a plain vault file", false, func(t *testing.T) string { return pwRefSecret(t) }},
		{"an encrypted vault file and the ambient secret", true, func(t *testing.T) string { return pwRefSecret(t) }},
		{"a hostile value", false, func(t *testing.T) string { return hostile }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := tc.value(t)
			quoted, _ := json.Marshal(secret) // a JSON string is a YAML double-quoted scalar
			e := pwRefApplyEnv(t, pwRefRoster(`"{{ ipa_default_initial_password }}"`), "ipa_default_initial_password: "+string(quoted)+"\n", tc.encrypt)
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
			if got := processExitCode(err); got != 4 {
				t.Fatalf("exit %d (err %v), want 4 (the run applied; only the authorization cache is owed)\n%s", got, err, out)
			}
			if got := e.a.writeMethods(); !slices.Equal(got, []string{"user_add", "passwd"}) {
				t.Fatalf("the server received writes %v, want a user_add and one passwd", got)
			}
			sent, ok := e.a.passwordSent("p26-new")
			if !ok || sent != secret {
				t.Fatalf("the server received password (equal to the vault's: %v, received: %v)", sent == secret, ok)
			}
			doc := readApplyDoc(t, result)
			if doc.Verdict != "unsettled" {
				t.Fatalf("verdict %s, want unsettled (every operation applied and verified)", doc.Verdict)
			}
			var ops []string
			for _, op := range doc.Plan3.Operations {
				ops = append(ops, op.Kind+" "+op.Object)
			}
			if len(ops) != 0 {
				t.Fatalf("the plan after the writes still has %v: the password operation did not converge", ops)
			}
			raw, _ := json.Marshal(doc)
			assertNoValueAnywhere(t, []string{secret, golangTestPassword, "fake-session-cookie-value"}, err, out+string(raw), result)
		})
	}
}

// The preview of the same roster plans the password operation and says nothing of the value.
func TestRosterPasswordReferencePreviewPlansItAndHoldsNoValue(t *testing.T) {
	secret := pwRefSecret(t)
	e := pwRefApplyEnv(t, pwRefRoster(`"{{ ipa_default_initial_password }}"`), "ipa_default_initial_password: "+secret+"\n", false)
	plan := filepath.Join(e.dir, "plan.json")
	out, err := runGolangPreview(t, "--plan-out", plan)
	if err != nil {
		t.Fatalf("preview: %v\n%s", err, out)
	}
	if !strings.Contains(out, "user.password.initialize") {
		t.Fatalf("the preview does not plan the password operation:\n%s", out)
	}
	if got := e.a.writeMethods(); len(got) != 0 {
		t.Fatalf("a preview wrote %v", got)
	}
	assertNoValueAnywhere(t, []string{secret, golangTestPassword}, err, out, plan)
}

// R2 and the gates that decide it: a variable the run does not define, or defines in a form the
// engine cannot send, is exit 3 with zero writes and no entry; the message names the user, the
// field and (for a bare reference) the variable, and holds no value. Each row is the trigger of
// one gate; R1 is the row that passes.
func TestRosterPasswordReferenceThatCannotBeSentBlocksTheRun(t *testing.T) {
	for _, tc := range []struct {
		name       string
		initial    string
		extraVault func(secret string) string
		want       []string
		notWant    []string
	}{
		{"the variable is not defined", `"{{ ipa_default_initial_password }}"`, func(s string) string { return "some_other_variable: " + s + "\n" },
			[]string{"p26-new", "password.initial", "ipa_default_initial_password", "nothing in the run defines"}, nil},
		{"the variable is empty", `"{{ ipa_default_initial_password }}"`, func(string) string { return "ipa_default_initial_password: \"\"\n" },
			[]string{"p26-new", "ipa_default_initial_password", "empty string"}, nil},
		{"the variable is a number", `"{{ ipa_default_initial_password }}"`, func(string) string { return "ipa_default_initial_password: 12345678\n" },
			[]string{"p26-new", "ipa_default_initial_password", "not a string"}, nil},
		{"the name is one the playbook sets itself", `"{{ identity_admin_password }}"`, func(s string) string { return "identity_admin_password: " + s + "\n" },
			[]string{"p26-new", "identity_admin_password", "defines before the playbook reads the password"}, nil},
		{"a filter", `"{{ ipa_default_initial_password | default('') }}"`, func(s string) string { return "ipa_default_initial_password: " + s + "\n" },
			[]string{"p26-new", "password.initial", "not exactly one bare"}, []string{"default("}},
		{"a lookup", `"{{ lookup('env', 'HOME') }}"`, func(string) string { return "" },
			[]string{"p26-new", "password.initial", "not exactly one bare"}, []string{"lookup("}},
		{"an inline !vault value in the roster", "!vault |\n          $ANSIBLE_VAULT;1.1;AES256\n          6162636465\n", func(string) string { return "" },
			[]string{"p26-new", "password.initial", "inline !vault value"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := pwRefSecret(t)
			roster := pwRefRoster(tc.initial)
			if strings.HasPrefix(tc.initial, "!vault") {
				roster = strings.Replace(captureRoster, "%s", "/bin/sh", 1) + "  - name: p26-new\n    first: P26\n    last: New\n    password:\n      initial: " + tc.initial
			}
			e := pwRefApplyEnv(t, roster, tc.extraVault(secret), false)
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
			if got := processExitCode(err); got != 3 {
				t.Fatalf("exit %d (err %v), want 3 (blocked)\n%s", got, err, out)
			}
			if got := e.a.writeMethods(); len(got) != 0 {
				t.Fatalf("the server received writes %v, want none", got)
			}
			if calls := e.playbookCalls(); len(calls) != 0 {
				t.Fatalf("the entry ran: %v", calls)
			}
			doc := readApplyDoc(t, result)
			if len(doc.Plan1.Blocked) != 1 || doc.Plan1.Blocked[0].Object != "p26-new" || doc.Plan1.Blocked[0].Reason != identityreconcile.BlockedPasswordValue {
				t.Fatalf("blocked = %+v", doc.Plan1.Blocked)
			}
			detail := doc.Plan1.Blocked[0].Detail
			for _, want := range tc.want {
				if !strings.Contains(detail+out, want) {
					t.Errorf("neither the blocked detail nor the output say %q: %s", want, detail)
				}
			}
			for _, not := range tc.notWant {
				if strings.Contains(detail, not) {
					t.Errorf("the detail echoes the roster's template: %q", detail)
				}
			}
			raw, _ := json.Marshal(doc)
			assertNoValueAnywhere(t, []string{secret, golangTestPassword}, err, out+string(raw), result)
		})
	}
}

// The __ansible_unsafe marker (merge-gate finding of #394, F1): ansible-inventory lists a genuine
// !unsafe string and a literal YAML mapping {__ansible_unsafe: x} the same way, and Ansible sends
// them differently (text, and the JSON of a dict). The Go engine cannot tell which a run holds, so
// a reference that reaches either is blocked, whatever the vault file is (plain or encrypted), with
// the real ansible-inventory in the loop and no write, no playbook call and no value anywhere.
func TestRosterPasswordReferenceThroughTheUnsafeMarkerBlocksTheRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vault   func(quotedSecret string) string
		encrypt bool
	}{
		{"a literal mapping in a plain vault file", func(q string) string { return "ipa_default_initial_password: {__ansible_unsafe: " + q + "}\n" }, false},
		{"a literal mapping in an encrypted vault file", func(q string) string { return "ipa_default_initial_password: {__ansible_unsafe: " + q + "}\n" }, true},
		{"a genuine !unsafe string in a plain vault file", func(q string) string { return "ipa_default_initial_password: !unsafe " + q + "\n" }, false},
		{"a genuine !unsafe string in an encrypted vault file", func(q string) string { return "ipa_default_initial_password: !unsafe " + q + "\n" }, true},
		{"a chain that ends in a literal mapping", func(q string) string {
			return "ipa_default_initial_password: \"{{ other_password_var }}\"\nother_password_var: {__ansible_unsafe: " + q + "}\n"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := pwRefSecret(t)
			quoted, _ := json.Marshal(secret) // a JSON string is a YAML double-quoted scalar
			e := pwRefApplyEnv(t, pwRefRoster(`"{{ ipa_default_initial_password }}"`), tc.vault(string(quoted)), tc.encrypt)
			result := filepath.Join(e.dir, "result.json")
			out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
			if got := processExitCode(err); got != 3 {
				t.Fatalf("exit %d (err %v), want 3 (blocked)\n%s", got, err, out)
			}
			if got := e.a.writeMethods(); len(got) != 0 {
				t.Fatalf("the server received writes %v, want none", got)
			}
			if calls := e.playbookCalls(); len(calls) != 0 {
				t.Fatalf("the entry ran: %v", calls)
			}
			doc := readApplyDoc(t, result)
			if len(doc.Plan1.Blocked) != 1 || doc.Plan1.Blocked[0].Object != "p26-new" || doc.Plan1.Blocked[0].Reason != identityreconcile.BlockedPasswordValue {
				t.Fatalf("blocked = %+v", doc.Plan1.Blocked)
			}
			detail := doc.Plan1.Blocked[0].Detail
			for _, want := range []string{"password.initial", "ipa_default_initial_password", "__ansible_unsafe"} {
				if !strings.Contains(detail, want) {
					t.Errorf("the blocked detail does not say %q: %s", want, detail)
				}
			}
			raw, _ := json.Marshal(doc)
			assertNoValueAnywhere(t, []string{secret, golangTestPassword}, err, out+string(raw), result)
		})
	}
}

// G4: ansible-inventory fails when asked for the run's variables (the vault's -e): the text on its
// stderr, which can quote the plaintext of a vars file, is shown nowhere; the templated user is
// refused as "the run's variables were not read" (exit 3, zero writes), and the same failure does
// not block a user whose password needs no change (G8: exit 0).
func TestRosterPasswordReferenceWhenAnsibleInventoryFailsShowsNothingOfItsError(t *testing.T) {
	sentinel := pwRefSecret(t)
	t.Run("a planned password operation is blocked", func(t *testing.T) {
		e := pwRefApplyEnv(t, pwRefRoster(`"{{ ipa_default_initial_password }}"`), "ipa_default_initial_password: "+pwRefSecret(t)+"\n", false)
		calls := pwRefInventoryTap(t, sentinel)
		result := filepath.Join(e.dir, "result.json")
		out, err := runReconcileCLI(t, applyArgs("--result-out", result)...)
		if got := processExitCode(err); got != 3 {
			t.Fatalf("exit %d (err %v), want 3\n%s", got, err, out)
		}
		if got := e.a.writeMethods(); len(got) != 0 {
			t.Fatalf("the server received writes %v, want none", got)
		}
		if !slices.ContainsFunc(calls(), func(c string) bool { return strings.Contains(c, "-e @") }) {
			t.Fatalf("ansible-inventory was never asked for the run's variables: %v", calls())
		}
		doc := readApplyDoc(t, result)
		if len(doc.Plan1.Blocked) != 1 || !strings.Contains(doc.Plan1.Blocked[0].Detail, "the run's variables were not read") || !strings.Contains(doc.Plan1.Blocked[0].Detail, "ipa_default_initial_password") {
			t.Fatalf("blocked = %+v", doc.Plan1.Blocked)
		}
		raw, _ := json.Marshal(doc)
		assertNoValueAnywhere(t, []string{sentinel}, err, out+string(raw), result)
	})
	t.Run("a user whose password needs no change is not blocked (G8)", func(t *testing.T) {
		// p1-self has a password change time in the capture: preserve_existing (the default) leaves it.
		roster := strings.Replace(strings.Replace(captureRoster, "%s", "/bin/sh", 1),
			"{name: p1-self, first: P1, last: Self, display_name: P1 Self, login_shell: /bin/sh}",
			"{name: p1-self, first: P1, last: Self, display_name: P1 Self, login_shell: /bin/sh, password: {initial: \"{{ ipa_default_initial_password }}\"}}", 1)
		if !strings.Contains(roster, "ipa_default_initial_password") {
			t.Fatal("the fixture's user line moved")
		}
		e := pwRefApplyEnv(t, roster, "", false)
		calls := pwRefInventoryTap(t, sentinel)
		out, err := runGolangPreview(t, "--plan-out", filepath.Join(e.dir, "plan.json"))
		if err != nil {
			t.Fatalf("a run with no password work was blocked: %v\n%s", err, out)
		}
		if !slices.ContainsFunc(calls(), func(c string) bool { return strings.Contains(c, "-e @") }) {
			t.Fatalf("the failing listing was never asked for: the row does not exercise the failure: %v", calls())
		}
		assertNoValueAnywhere(t, []string{sentinel}, err, out, filepath.Join(e.dir, "plan.json"))
	})
}

// A roster with no templated password never asks for the run's variables: ansible-inventory is
// listed once, without the vault, as before (literal-only rosters behave exactly as today).
func TestRosterPasswordReferenceIsOnlyResolvedWhenAUserNeedsIt(t *testing.T) {
	for _, tc := range []struct {
		name    string
		roster  string
		listing int // how many listings carry the vault's -e
	}{
		{"a literal", pwRefRoster(`"a-literal-password"`), 0},
		{"a template that is not bare", pwRefRoster(`"x{{ v }}"`), 0},
		{"no password at all", strings.Replace(captureRoster, "%s", "/bin/sh", 1), 0},
		{"a bare reference", pwRefRoster(`"{{ v }}"`), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := pwRefApplyEnv(t, tc.roster, "v: some-value-for-the-test\n", false)
			calls := pwRefInventoryTap(t, "")
			if _, err := runGolangPreview(t, "--plan-out", filepath.Join(e.dir, "plan.json")); err != nil && processExitCode(err) != 3 {
				t.Fatal(err)
			}
			withVault := 0
			for _, c := range calls() {
				if strings.Contains(c, "-e @") {
					withVault++
				}
			}
			if withVault != tc.listing {
				t.Fatalf("%d listings asked for the run's variables, want %d: %v", withVault, tc.listing, calls())
			}
		})
	}
}

// golangRunVars on its own: the pairing with the Ansible engine's vault input, and what it reads.
func TestGolangRunVarsInputIsTheAnsibleEnginesDefaultsVaultInput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vault   string
		missing bool
	}{
		{"a plain vault file", "ipa_admin_password: x\n", false},
		{"an encrypted vault file", "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n", false},
		{"no vault file", "", true},
	} {
		for _, driver := range []struct {
			name   string
			driver promptAutomation
		}{
			{"--force", promptAutomation{useDefaults: true, forceApply: true}},
			{"--preview-only", promptAutomation{useDefaults: true, previewOnly: true}},
		} {
			t.Run(tc.name+" "+driver.name, func(t *testing.T) {
				dir := t.TempDir()
				t.Chdir(dir)
				inv := "inventory.yml"
				if tc.vault != "" {
					if err := os.MkdirAll(".vault", 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(".vault", "main.yaml"), []byte(tc.vault), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				// What the Ansible engine's wizard hands the playbook run under the defaults driver.
				old := activePromptAutomation
				d := driver.driver
				activePromptAutomation = &d
				defer func() { activePromptAutomation = old }()
				ansibleSide, err := promptVault(io.Discard, inv, "")
				if err != nil {
					t.Fatal(err)
				}
				goSide, ok := golangRunVarsInput(inv)
				if ok == tc.missing {
					t.Fatalf("golangRunVarsInput ok = %v for %s", ok, tc.name)
				}
				if tc.missing {
					if ansibleSide != (vaultInput{}) {
						t.Fatalf("the Ansible engine's wizard took a vault file (%+v) where the Go engine has none", ansibleSide)
					}
					return
				}
				abs, err := filepath.Abs(ansibleSide.ExtraVarsFile)
				if err != nil {
					t.Fatal(err)
				}
				want := ansibleSide
				want.ExtraVarsFile = abs
				if goSide != want {
					t.Fatalf("the Go engine reads the run's variables with %+v, the Ansible engine's defaults driver runs with %+v (made absolute: %+v)", goSide, ansibleSide, want)
				}
				if ansibleSide.AskVaultPass || ansibleSide.VaultPasswordFile != "" {
					t.Fatalf("the defaults driver asked for a vault password (%+v): the Go engine reads the ambient one only", ansibleSide)
				}
			})
		}
	}
}

// The listing golangRunVars makes carries exactly the vault input above: the arguments of the real
// ansible-inventory call are `-i <inv> --list -e @<absolute vault file>` and nothing else.
func TestGolangRunVarsListsWithTheDefaultsVaultInput(t *testing.T) {
	rosteroracletest.RequireAnsiblePlaybook(t)
	secret := pwRefSecret(t)
	dir := pwRefWorkspace(t, pwRefRoster(`"{{ v }}"`), "v: "+secret+"\n", false)
	root := t.TempDir()
	t.Setenv("PILOT_ROOT", root)
	calls := pwRefInventoryTap(t, "")
	ctx := withDeployAnsibleRuntime(context.Background(), deployAnsibleRuntime{})
	run := golangRunVars(ctx, "inventory.yml", "ipa-1", []byte(pwRefRoster(`"{{ v }}"`)))
	if run == nil {
		t.Fatal("the run's variables were not read")
	}
	if got, _ := run.UserInitialPassword("{{ v }}"); got != secret {
		t.Fatalf("the vault's value was not resolved (equal: %v)", got == secret)
	}
	want, ok := golangRunVarsInput("inventory.yml")
	if !ok || want.ExtraVarsFile != filepath.Join(dir, ".vault", "main.yaml") {
		t.Fatalf("golangRunVarsInput = %+v, %v", want, ok)
	}
	var listing string
	for _, c := range calls() {
		if strings.Contains(c, "-e @") {
			listing = c
		}
	}
	if wantArgs := strings.Join(append([]string{"-i", "inventory.yml", "--list"}, golangRunVarsArgs(want, root)...), " "); listing != wantArgs {
		t.Fatalf("the listing was %q, want %q", listing, wantArgs)
	}
	// The listing is the vault input and the playbook directory, nothing more.
	if got := golangRunVarsArgs(want, root); !slices.Equal(got, []string{"-e", "@" + want.ExtraVarsFile, "--playbook-dir", filepath.Join(root, "playbooks", "apply")}) {
		t.Fatalf("golangRunVarsArgs = %v", got)
	}
	// Nothing is made of a roster that has no bare reference.
	if r := golangRunVars(ctx, "inventory.yml", "ipa-1", []byte(pwRefRoster(`"literal"`))); r != nil {
		t.Fatal("run variables were read for a roster with no bare reference")
	}
	// And a host the listing does not have is not a run.
	if r := golangRunVars(ctx, "inventory.yml", "no-such-host", []byte(pwRefRoster(`"{{ v }}"`))); r != nil {
		t.Fatal("run variables were taken for a host the inventory does not list")
	}
	// No vault vars file is no run's variables (G4): the command never gets here without one, the
	// completeness check refuses the workspace first, so this is the only place the case is seen.
	if err := os.Remove(filepath.Join(dir, ".vault", "main.yaml")); err != nil {
		t.Fatal(err)
	}
	if r := golangRunVars(ctx, "inventory.yml", "ipa-1", []byte(pwRefRoster(`"{{ v }}"`))); r != nil {
		t.Fatal("run variables were read with no vault vars file")
	}
	if _, ok := golangRunVarsInput("inventory.yml"); ok {
		t.Fatal("a vault input was made for a workspace with no vault vars file")
	}
}

// What golangPrep and the run's variables print: no verb shows a value of either, and the
// struct that holds a prep by value or by pointer is no way around it.
func TestGolangPrepAndRunVarsFormatNoValue(t *testing.T) {
	secret := pwRefSecret(t)
	run := &inventory.RosterRunVars{HostVars: map[string]any{"v": secret}, Consumer: inventory.RosterConsumerFreeIPAIdentity}
	prep := &golangPrep{host: "ipa-1", rosterData: []byte("password: " + secret), password: secret, runVars: run, hostVars: map[string]any{"x": secret}}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for what, arg := range map[string]any{"a pointer to a prep": prep, "a prep": *prep, "the run's variables": run, "the run's variables by value": *run} {
			if got := fmt.Sprintf(verb, arg); strings.Contains(got, secret) {
				t.Errorf("%s of %s shows a value: %s", verb, what, got)
			}
		}
	}
}

// mixedInventoryWith puts an ansible-inventory first on PATH that answers every call with the mixed
// harness's host and these variables more: the script stands for the listing with the vault's variables.
func mixedInventoryWith(t *testing.T, extra map[string]any) {
	t.Helper()
	vars := map[string]any{
		"freeipa_roster_file": ".vault/ipa-identity.yaml", "ansible_host": "192.0.2.10", "ansible_user": "root",
		"ipa_admin_password": golangTestPassword,
	}
	for k, v := range extra {
		vars[k] = v
	}
	inv := map[string]any{"_meta": map[string]any{"hostvars": map[string]any{"ipa-1": vars}}, "freeipa-server": map[string]any{"hosts": []string{"ipa-1"}}}
	invJSON, _ := json.Marshal(inv)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ansible-inventory"), []byte("#!/bin/sh\ncat <<'EOF'\n"+string(invJSON)+"\nEOF\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The mixed run (--scope full) sends a bare reference through the same preflight: its Go phase
// builds its source of the passwords from the run's variables the preflight read, the playbook that
// follows is told to skip users and groups, and the idempotency check (the preflight again, with the
// password set) plans nothing. The listing here is a script that answers every ansible-inventory
// call with a host that has the vault's variable: the real ansible-inventory is the users-groups
// tests' above; this row is the plumbing of the mixed transaction's three preflights.
func TestMixedRunSendsABareReferencePasswordTheGoPhaseResolved(t *testing.T) {
	secret := pwRefSecret(t)
	e := newMixedCLIEnv(t, pwRefRoster(`"{{ ipa_default_initial_password }}"`))
	mixedInventoryWith(t, map[string]any{"ipa_default_initial_password": secret})
	result := filepath.Join(e.dir, "result.json")
	out, err := runReconcileCLI(t, mixedArgs("--result-out", result)...)
	if err != nil || processExitCode(err) != 0 {
		t.Fatalf("exit %d: %v\n%s", processExitCode(err), err, out)
	}
	if sent, ok := e.a.passwordSent("p26-new"); !ok || sent != secret {
		t.Fatalf("the server received the password (equal to the vault's: %v, received: %v)", sent == secret, ok)
	}
	if got := e.a.writeMethods(); !slices.Equal(got, []string{"user_add", "passwd"}) {
		t.Fatalf("the server received writes %v, want a user_add and one passwd", got)
	}
	if args := e.identityArgs("apply"); !hasExtraVar(args, engineArg) {
		t.Fatalf("the identity playbook was not told to skip users and groups: %v", args)
	}
	doc := readApplyDoc(t, result)
	if doc.Verdict != identityreconcile.VerdictOK || doc.ExitCode != 0 {
		t.Fatalf("result file: verdict %q exit %d", doc.Verdict, doc.ExitCode)
	}
	raw, _ := json.Marshal(doc)
	assertNoValueAnywhere(t, []string{secret, golangTestPassword}, err, out+string(raw), result)
}

// The same mixed run for a name the playbook sets itself: the roster-reference precheck of the
// Ansible engine lets it through (the inventory defines it), and the Go plan is what refuses it
// (exit 3), before the identity playbook or any write: the inventory's value is not what the
// playbook would send for it. (A name that nothing defines is the precheck's refusal, exit 1, as for
// the Ansible engine; the users-groups scope has no such precheck and refuses it in the plan.)
func TestMixedRunBlocksAShadowedBareReferenceBeforeTheIdentityPlaybook(t *testing.T) {
	secret := pwRefSecret(t)
	e := newMixedCLIEnv(t, pwRefRoster(`"{{ identity_admin_password }}"`))
	mixedInventoryWith(t, map[string]any{"identity_admin_password": secret})
	out, err := runReconcileCLI(t, mixedArgs()...)
	if got := processExitCode(err); got != 3 {
		t.Fatalf("exit %d (err %v), want 3 (blocked)\n%s", got, err, out)
	}
	if got := e.a.writeMethods(); len(got) != 0 {
		t.Fatalf("the server received writes %v", got)
	}
	if args := e.identityArgs("apply"); args != nil {
		t.Fatalf("the identity playbook ran: %v", args)
	}
	for _, want := range []string{"p26-new", "password.initial", "identity_admin_password"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output does not say %q:\n%s", want, out)
		}
	}
	assertNoValueAnywhere(t, []string{secret, golangTestPassword}, err, out)
}

// The listing is the variables of the playbook run, not of the directory pilot happens to run in:
// group_vars next to the inventory and next to the identity playbook are the run's, and the
// working directory's are not (ansible-playbook does not load them; ansible-inventory does unless
// it is given the playbook directory). A variable that is only in the working directory's
// group_vars is therefore undefined here, as it is for the playbook, and not a password.
func TestGolangRunVarsAreThePlaybookRunsVariablesNotTheWorkingDirectorys(t *testing.T) {
	rosteroracletest.RequireAnsiblePlaybook(t)
	inventoryDir, cwd, root := t.TempDir(), t.TempDir(), t.TempDir()
	value := map[string]string{"from_inventory": pwRefSecret(t), "from_playbook": pwRefSecret(t), "from_cwd": pwRefSecret(t)}
	write := func(path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(inventoryDir, "inventory.yml"), "all:\n  children:\n    freeipa-server:\n      hosts:\n        ipa-1:\n          ansible_connection: local\n")
	write(filepath.Join(inventoryDir, ".vault", "main.yaml"), "ipa_admin_password: x\n")
	write(filepath.Join(inventoryDir, "group_vars", "all.yml"), "from_inventory: "+value["from_inventory"]+"\n")
	write(filepath.Join(root, "playbooks", "apply", "group_vars", "all.yml"), "from_playbook: "+value["from_playbook"]+"\n")
	write(filepath.Join(cwd, "group_vars", "all.yml"), "from_cwd: "+value["from_cwd"]+"\n")
	t.Chdir(cwd)
	t.Setenv("PILOT_ROOT", root)
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = "" })

	roster := "schema_version: 3\nusers:\n"
	for name := range value {
		roster += "  - {name: " + strings.ReplaceAll(name, "_", "-") + ", password: {initial: \"{{ " + name + " }}\"}}\n"
	}
	run := golangRunVars(context.Background(), filepath.Join(inventoryDir, "inventory.yml"), "ipa-1", []byte(roster))
	if run == nil {
		t.Fatal("the run's variables were not read")
	}
	for name, want := range map[string]struct {
		value  string
		reason inventory.PasswordValueReason
	}{
		"from_inventory": {value["from_inventory"], inventory.PasswordValueOK},
		"from_playbook":  {value["from_playbook"], inventory.PasswordValueOK},
		"from_cwd":       {"", inventory.PasswordReasonUndefined},
	} {
		got, reason := run.UserInitialPassword("{{ " + name + " }}")
		if got != want.value || reason != want.reason {
			t.Errorf("%s: (value kept %v, %s), want (value kept %v, %s)", name, got != "", reason, want.value != "", want.reason)
		}
	}
}

// The scan the tests above end with sees a value wherever it can be: in the output, in the error,
// in the plan or result file and in any file of the pilot data directory. Without this the scans
// could pass for a reason of their own.
func TestTheValueScanSeesAValueInEveryPlaceItLooks(t *testing.T) {
	value := pwRefSecret(t)
	for _, where := range []string{"output", "error", "file", "data directory"} {
		t.Run(where, func(t *testing.T) {
			dataDir = t.TempDir()
			t.Cleanup(func() { dataDir = "" })
			if err := os.WriteFile(filepath.Join(dataDir, "history.db"), []byte("rows"), 0o600); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(t.TempDir(), "plan.json")
			if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			var err error
			out := "clean"
			switch where {
			case "output":
				out = "text " + value
			case "error":
				err = errors.New("failed: " + value)
			case "file":
				if werr := os.WriteFile(file, []byte(value), 0o600); werr != nil {
					t.Fatal(werr)
				}
			case "data directory":
				if werr := os.WriteFile(filepath.Join(dataDir, "history.db"), []byte("rows "+value), 0o600); werr != nil {
					t.Fatal(werr)
				}
			}
			fake := &testing.T{}
			done := make(chan struct{})
			go func() {
				defer close(done)
				assertNoValueAnywhere(fake, []string{value}, err, out, file)
			}()
			<-done
			if !fake.Failed() {
				t.Fatalf("a value in the %s was not found", where)
			}
		})
	}
}
