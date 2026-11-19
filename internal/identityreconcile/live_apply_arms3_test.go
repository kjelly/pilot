package identityreconcile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// A23 (issue #394): a password.initial that is exactly one bare {{ name }} is sent as the run's
// value. The arms below are the live half of the restricted template: the value comes from the
// vault vars file the Ansible engine would run with (encrypted, with the ambient vault secret),
// the user's initial password on the real server is that value, and what cannot be proved the
// playbook would send is refused before any write. They run from the acked baseline like the
// others and need nothing new of the lab.
//
// The login oracle is the exit code of kinit and nothing else: an initial password that an admin
// set is expired, so kinit asks for a new one, and given the three answers on stdin (the password,
// the new one twice) it succeeds exactly when the password is the user's and the new one is
// accepted. A wrong password is the control that makes the oracle meaningful: it must fail.
//
// TODO(Root, live capture; AGENTS.md section 5.6): nothing here parses kinit's text, but the oracle
// rests on kinit reading those three answers from a non-terminal stdin when the password is
// expired. The first live run confirms it on the real server (the wrong-password control failing
// and the right one succeeding in the same run is the evidence); if kinit needs a terminal there,
// the oracle must change to a captured exchange, not to a guess at its output.

const a23Var = "ipa_default_initial_password"

// a23Hostile is a password made for the run with every character a shell, a template or a YAML
// loader would treat specially: spaces inside, a leading-zero number, backticks, $HOME, %s, CJK and
// both kinds of quote. Leading and trailing spaces are left out only because kinit's prompt strips
// the line it reads, which says nothing about pilot.
func a23Hostile() string {
	return randomPassword() + " 0123 `$HOME` %s 密碼 'q' \"d\""
}

// yamlText is s as a YAML double-quoted scalar (a JSON string is one).
func yamlText(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// templatedUser is a roster user whose password.initial is the template given, written as it is.
func (d *applyDriver) templatedUser(name, initial string) map[string]any {
	return d.user(name, with("password", map[string]any{"initial": initial}))
}

// vaultWith makes the vault vars file of ws hold what it held and the variables given (raw YAML
// scalars), plaintext or ansible-vault encrypted with the lab's vault password.
func (lv *labEnv) vaultWith(ws string, extra map[string]string, encrypt bool) error {
	path := filepath.Join(ws, ".vault", "main.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(data)
	if strings.HasPrefix(strings.TrimSpace(text), "$ANSIBLE_VAULT") {
		out, err := exec.Command("ansible-vault", "view", "--vault-password-file", lv.vaultPass, path).Output()
		if err != nil {
			return err
		}
		text = string(out)
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	keys := make([]string, 0, len(extra))
	for k := range extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		text += k + ": " + extra[k] + "\n"
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		return err
	}
	if !encrypt {
		return nil
	}
	if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", lv.vaultPass, path).CombinedOutput(); err != nil {
		return fmt.Errorf("ansible-vault encrypt: %w\n%s", err, out)
	}
	return nil
}

// kinitInitial is whether password is the initial password of user, by exit code only (see the
// comment at the top): the answers go in on stdin, never in an argument.
func (lv *labEnv) kinitInitial(user, password, newPassword string) bool {
	const cc = "FILE:/tmp/p26a23.ccache"
	cmd := exec.Command("ssh", append(sshArgs(lv.srv), sshHost(lv.srv),
		"export KRB5CCNAME="+cc+"; kinit "+user+" >/dev/null 2>&1; rc=$?; kdestroy -c "+cc+" >/dev/null 2>&1; exit $rc")...)
	cmd.Stdin = strings.NewReader(password + "\n" + newPassword + "\n" + newPassword + "\n")
	return cmd.Run() == nil
}

// noValue fails the arm when any of values is in what the run printed, its result file or any
// file of the arm's pilot data directory (the history, ansible.log).
func (a *armCtx) noValue(r applyRun, values ...string) {
	texts := map[string]string{"output": r.Out}
	if data, err := os.ReadFile(r.Result); err == nil {
		texts["result file"] = string(data)
	}
	scanned := 0
	_ = filepath.WalkDir(a.data, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if data, rerr := os.ReadFile(p); rerr == nil {
				texts[p] = string(data)
				scanned++
			}
		}
		return nil
	})
	a.ok(scanned > 0, "the pilot data directory holds no file: the scan read nothing")
	for where, text := range texts {
		for _, v := range values {
			a.ok(v == "" || !strings.Contains(text, v), "a password leaked into %s", where)
		}
	}
}

func (d *applyDriver) runA23(base func() rosterDoc) {
	lv := d.lv
	withTemplated := func(name, initial string) rosterDoc {
		return d.mutate(base(), func(r rosterDoc) { d.addUser(r, d.templatedUser(name, initial)) })
	}
	ref := "{{ " + a23Var + " }}"

	// (a) a templated new user: the value comes from the encrypted vault vars file, read with the
	// ambient vault secret. The server received it once (one passwd), and it is the user's initial
	// password; a wrong one is not.
	var ws23, value23 string
	d.arm("A23(a) a bare reference to the encrypted vault's value is the user's initial password", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		value := a23Hostile()
		ws := lv.copyWorkspace(withTemplated("p26-tpl", ref), "", nil)
		if err := lv.vaultWith(ws, map[string]string{a23Var: yamlText(value)}, true); err != nil {
			a.fail("the vault: %v", err)
			return
		}
		r := a.apply(ws)
		a.exit(r, 4)
		a.opsAre(r, "user.create p26-tpl", "user.password.initialize p26-tpl")
		a.writesAre(r, map[string]int{"user_add": 1, "passwd": 1})
		a.verifyClean(r)
		a.noValue(r, value)
		newPW := randomPassword()
		a.ok(!lv.kinitInitial("p26-tpl", value+"x", newPW), "a wrong initial password logged in: the oracle accepts anything")
		a.ok(lv.kinitInitial("p26-tpl", value, newPW), "the vault's value is not the user's initial password")
		a.pending(true)
		ws23, value23 = ws, value
	})

	// (c) continues (a): the Ansible engine's full run afterwards changes nothing in the users and
	// groups sections and the server logs no passwd (H2's oracle): the Go engine left the user
	// as the playbook would have, and the playbook agrees on the value (no reset of the password).
	d.arm("A23(c) the legacy full run after a templated Go run changes nothing in users and groups", func(a *armCtx) {
		if ws23 == "" {
			a.fail("A23(a) did not run")
			return
		}
		logAt, _ := serverLogSize(lv.srv)
		r := lv.runPilot(lv.pilot, a.data, []string{"reconcile", "--dir", ws23, "--component", "freeipa-identity", "--force"})
		a.exit(applyRun{pilotResult: r}, 0)
		names := d.usersGroupsTaskNames()
		changed, seen := changedTasks(r.Out, names)
		a.fact("users_groups_tasks_in_output", seen)
		a.ok(seen >= 30, "only %d of the %d tasks of the users and groups sections are in the output: the parse sees nothing", seen, len(names))
		a.ok(len(changed) == 0, "tasks of the users and groups sections changed in the legacy run after the Go run: %v", changed)
		w, _ := lv.writesSince(logAt)
		a.ok(w["passwd"] == 0 && w["user_add"] == 0, "the legacy run logged writes of the user the Go run made: %v", w)
		a.ok(!strings.Contains(r.Out, value23), "the legacy run printed the password")
		a.pending(false)
	})

	// (b) the oracle's control: the same value written out in the roster is the user's initial
	// password too, so the oracle accepts a right password and the arms above did not pass by
	// accepting every one.
	d.arm("A23(b) control: the same value written out in the roster", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		value := a23Hostile()
		ws := lv.copyWorkspace(withTemplated("p26-tpl", yamlText(value)), "", nil)
		r := a.apply(ws)
		a.exit(r, 4)
		a.opsAre(r, "user.create p26-tpl", "user.password.initialize p26-tpl")
		a.writesAre(r, map[string]int{"user_add": 1, "passwd": 1})
		a.verifyClean(r)
		newPW := randomPassword()
		a.ok(!lv.kinitInitial("p26-tpl", value+"x", newPW), "a wrong initial password logged in")
		a.ok(lv.kinitInitial("p26-tpl", value, newPW), "the roster's literal is not the user's initial password: the oracle cannot tell a right one")
	})

	// (d) the mixed run: the Go phase sends the same value, the playbook (told to skip users and
	// groups) goes on, and the legacy full run after it changes nothing in users and groups.
	d.arm("A23(d) a mixed run sends a bare reference as the vault's value", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		value := a23Hostile()
		ws := lv.copyWorkspace(withTemplated("p26-tpl", ref), "", nil)
		if err := lv.vaultWith(ws, map[string]string{a23Var: yamlText(value)}, true); err != nil {
			a.fail("the vault: %v", err)
			return
		}
		r := a.mixed(ws)
		a.exit(r, 0)
		if r.HasDoc {
			a.ok(r.Doc.Scope == "full" && r.Doc.Verdict == VerdictOK, "the result file: scope %q verdict %q", r.Doc.Scope, r.Doc.Verdict)
		}
		a.ok(r.Writes["passwd"] == 1 && r.Writes["user_add"] == 1, "the server logged writes %v, want one user_add and one passwd", r.Writes)
		a.noValue(r, value)
		newPW := randomPassword()
		a.ok(!lv.kinitInitial("p26-tpl", value+"x", newPW), "a wrong initial password logged in")
		a.ok(lv.kinitInitial("p26-tpl", value, newPW), "the vault's value is not the user's initial password after the mixed run")
		a.pending(false)
		logAt, _ := serverLogSize(lv.srv)
		legacy := lv.runPilot(lv.pilot, a.data, []string{"reconcile", "--dir", ws, "--component", "freeipa-identity", "--force"})
		a.exit(applyRun{pilotResult: legacy}, 0)
		changed, seen := changedTasks(legacy.Out, d.usersGroupsTaskNames())
		a.ok(seen >= 30 && len(changed) == 0, "the legacy run after the mixed run changed tasks of the users and groups sections: %v (saw %d)", changed, seen)
		w, _ := lv.writesSince(logAt)
		a.ok(w["passwd"] == 0, "the legacy run logged a passwd: %v", w)
	})

	// (e) what cannot be proved is refused before any write: exit 3, nothing written, no entry, the
	// plan says which user, which field and (for a bare reference) which variable, and no value. The
	// inline !vault value in the roster and the lookup are A15's rows.
	inlineVault := func(a *armCtx) string {
		out, err := execShell("ANSIBLE_VAULT_PASSWORD_FILE=" + lv.vaultPass + " ansible-vault encrypt_string 'x' 2>/dev/null")
		if err != nil || !strings.Contains(out, "$ANSIBLE_VAULT") {
			a.fail("ansible-vault encrypt_string: %v", err)
			return ""
		}
		var b strings.Builder
		b.WriteString("!vault |\n")
		for _, l := range strings.Split(strings.TrimRight(out, "\n"), "\n")[1:] {
			b.WriteString("  " + strings.TrimSpace(l) + "\n")
		}
		return strings.TrimRight(b.String(), "\n")
	}
	type trigger struct {
		name    string
		initial string
		vars    map[string]string // raw YAML scalars for the vault ("__INLINE_VAULT__" is an inline !vault value)
		want    string
	}
	secretish := a23Hostile()
	for _, tg := range []trigger{
		{"the variable is not defined", ref, nil, "nothing in the run defines"},
		{"the variable is an empty string", ref, map[string]string{a23Var: `""`}, "empty string"},
		{"the variable is an unquoted number", ref, map[string]string{a23Var: "12345678"}, "not a string"},
		{"the variable is an inline !vault value", ref, map[string]string{a23Var: "__INLINE_VAULT__"}, "inline !vault value"},
		{"a filter", "{{ " + a23Var + " | default('') }}", map[string]string{a23Var: yamlText(secretish)}, "not exactly one bare"},
		{"a name the identity playbook sets itself", "{{ identity_admin_password }}", map[string]string{"identity_admin_password": yamlText(secretish)}, "before the playbook reads the password"},
	} {
		tg := tg
		d.arm("A23(e) trigger: "+tg.name, func(a *armCtx) {
			if !a.fresh() {
				return
			}
			vars := map[string]string{}
			for k, v := range tg.vars {
				if v == "__INLINE_VAULT__" {
					if v = inlineVault(a); v == "" {
						return
					}
				}
				vars[k] = v
			}
			ws := lv.copyWorkspace(withTemplated("p26-tpl", tg.initial), "", nil)
			if err := lv.vaultWith(ws, vars, false); err != nil {
				a.fail("the vault: %v", err)
				return
			}
			r := a.apply(ws)
			a.exit(r, 3)
			a.ok(r.HasDoc && !r.Doc.Entry.Ran && r.WriteN == 0, "the run entered or wrote: %v", r.Writes)
			for _, want := range []string{"p26-tpl", "password.initial", tg.want} {
				a.ok(strings.Contains(r.Out, want), "the refusal does not say %q:\n%s", want, tail(r.Out, 900))
			}
			a.noValue(r, secretish)
			a.ok(strings.Contains(a.serverHas("ipa user-show p26-tpl 2>&1"), "not found"), "the blocked user exists on the server")
		})
	}

	// (e) control of the no-op rule: an existing user whose password.initial is a reference nothing
	// defines needs no password operation (preserve_existing), so the run is not blocked on it. (A
	// workspace with no .vault/main.yaml never gets this far: the inventory completeness check refuses
	// it first; golangRunVars with no vault file is a unit row.)
	d.arm("A23(e) control: an existing user with no password operation is not blocked by an undefined reference", func(a *armCtx) {
		if !a.fresh() {
			return
		}
		roster := d.mutate(base(), func(r rosterDoc) {
			find(r, "users", "p26-ann")["password"] = map[string]any{"initial": "{{ a23_never_defined }}"}
		})
		ws := lv.copyWorkspace(roster, "", nil)
		r := a.apply(ws)
		a.exit(r, 0)
		a.ok(r.HasDoc && len(r.Doc.Plan1.Operations) == 0 && len(r.Doc.Plan1.Blocked) == 0 && r.WriteN == 0, "the run planned or wrote something: %v", r.Writes)
	})
}
