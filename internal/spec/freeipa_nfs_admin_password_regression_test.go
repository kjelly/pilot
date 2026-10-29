package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	nfsServerApplyPath        = "../../playbooks/apply/freeipa-nfs-server-apply.yml"
	nfsRosterLoadTask         = "Load canonical roster under a namespace"
	nfsRosterAndStageGate     = "Gate: required roster and stage authorization"
	nfsAdminPasswordDriftGate = "Gate: roster admin password matches the vault's ipa_admin_password"
	nfsStageCrossCheckGate    = "Gate: stage must match this host's inventory environment group"
)

func nfsServerPreTasks(t *testing.T, names ...string) []map[string]any {
	t.Helper()
	doc := loadYAML(t, nfsServerApplyPath).([]any)
	pre, _ := doc[0].(map[string]any)["pre_tasks"].([]any)
	tasks := namedTasks(pre, names)
	if len(tasks) != len(names) {
		t.Fatalf("%s pre_tasks: found %d of %q", nfsServerApplyPath, len(tasks), names)
	}
	return tasks
}

// The credential check is its own gate, outside the no_log one, so a
// rotation that changed only one of the two files is named instead of
// hidden (issue #146). It follows the stage gates (AGENTS.md §4.3), and its
// message gives the fix that works: pilot edit only carries a password
// change forward on the save that makes it, so saving again fixes nothing.
func TestRegression_FreeIPANFSServerAdminPasswordGateIsVisible(t *testing.T) {
	tasks := nfsServerPreTasks(t, nfsRosterAndStageGate, nfsStageCrossCheckGate, nfsAdminPasswordDriftGate)
	gate, drift := tasks[0], tasks[2]
	if tasks[1]["name"] != nfsStageCrossCheckGate {
		t.Errorf("the admin password gate must come after %q", nfsStageCrossCheckGate)
	}
	msg, _ := drift["ansible.builtin.assert"].(map[string]any)["fail_msg"].(string)
	if !strings.Contains(msg, "by hand") || strings.Contains(msg, "updates the roster too") {
		t.Errorf("fail_msg must ask for a hand edit of the roster, not a pilot edit save: %q", msg)
	}
	for _, condition := range gate["ansible.builtin.assert"].(map[string]any)["that"].([]any) {
		if strings.Contains(condition.(string), "ipa_admin_password") {
			t.Errorf("the no_log roster gate still checks the vault password: %q", condition)
		}
	}
	if _, ok := drift["no_log"]; ok {
		t.Error("the admin password gate must not set no_log: its failure is the only diagnosis")
	}
	if tags, _ := drift["tags"].([]any); len(tags) != 1 || tags[0] != "always" {
		t.Errorf("the admin password gate must be tagged always, like the roster load: %v", drift["tags"])
	}
}

// The no_log roster gate's fail_msg says what it requires — the roster's
// schema versions as the assert accepts them, an admin password of at
// least 8 characters, the stage confirmation — and holds no template, so
// it can never print a value. It stays tagged always and first among the
// gates (AGENTS.md §4.3, §4.4). (no_log hides the message on a failure;
// it is for whoever reads the playbook — PR #148 review, P3.)
func TestRegression_FreeIPANFSServerRosterGateNamesItsConditions(t *testing.T) {
	tasks := nfsServerPreTasks(t, nfsRosterAndStageGate, nfsStageCrossCheckGate)
	gate := tasks[0]
	if gate["name"] != nfsRosterAndStageGate {
		t.Fatalf("the roster gate must come before %q", nfsStageCrossCheckGate)
	}
	if tags, _ := gate["tags"].([]any); len(tags) != 1 || tags[0] != "always" {
		t.Errorf("the roster gate must be tagged always: %v", gate["tags"])
	}
	if gate["no_log"] != true {
		t.Error("the roster gate reads the roster's admin password and must keep no_log")
	}
	assert := gate["ansible.builtin.assert"].(map[string]any)
	msg, _ := assert["fail_msg"].(string)
	for _, marker := range []string{"{{", "{%", "{#"} {
		if strings.Contains(msg, marker) {
			t.Errorf("fail_msg must not be templated (it could print a value): %q", msg)
		}
	}
	var versions []string
	for _, condition := range assert["that"].([]any) {
		if c := condition.(string); strings.HasPrefix(c, "freeipa_roster.schema_version | int in [") {
			list := strings.TrimSuffix(strings.TrimPrefix(c, "freeipa_roster.schema_version | int in ["), "]")
			versions = strings.Split(list, ", ")
		}
	}
	if len(versions) < 2 {
		t.Fatalf("no schema_version condition with a version list in the roster gate: %v", assert["that"])
	}
	accepted := strings.Join(versions[:len(versions)-1], ", ") + " or " + versions[len(versions)-1]
	for _, want := range []string{
		"schema_version " + accepted,
		"freeipa.admin.password of at least 8 characters",
		"confirm_staging=true", "confirm_prod=true", "staging_attested_within_hours",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("fail_msg does not say %q: %q", want, msg)
		}
	}
}

// Run from the real playbook: a drifted roster fails naming the field and
// printing neither value; a matching, referencing or vault-less run passes;
// and the recovery the fail_msg and runbook §4.5 give — set the roster's
// password to the vault's by hand — makes a drifted roster pass.
func TestRegression_FreeIPANFSServerAdminPasswordDriftGate(t *testing.T) {
	const vaultPassword, stalePassword = `Vault"pass#2 密碼`, `Stale'pass\1`
	for name, tt := range map[string]struct {
		roster   string
		raw      string // the roster's password scalar as written, unquoted
		vault    bool
		wantFail bool
	}{
		"drifted": {roster: stalePassword, vault: true, wantFail: true},
		// Ansible compares typed values: a number never equals the vault's
		// string, whatever it reads. pilot's preflight and sync judge it the
		// same way (inventory.CompareRosterAdminPassword, RosterAdminNotString).
		"unquoted number": {raw: "12345678", vault: true, wantFail: true},
		"matching":        {roster: vaultPassword, vault: true},
		"reference":       {roster: "{{ ipa_admin_password }}", vault: true},
		"no vault":        {roster: stalePassword},
	} {
		t.Run(name, func(t *testing.T) {
			// Each case runs its own playbook in its own directory.
			t.Parallel()
			dir := t.TempDir()
			roster := filepath.Join(dir, "ipa-identity.yaml")
			scalar := yamlDoubleQuoted(tt.roster)
			if tt.raw != "" {
				scalar = tt.raw
			}
			body := "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n    password: " + scalar + "\n"
			if err := os.WriteFile(roster, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			vars := map[string]any{"freeipa_roster_file": roster}
			if tt.vault {
				vars["ipa_admin_password"] = vaultPassword
				if tt.raw != "" {
					vars["ipa_admin_password"] = tt.raw
				}
			}
			var tasks []any
			for _, task := range nfsServerPreTasks(t, nfsRosterLoadTask, nfsAdminPasswordDriftGate) {
				tasks = append(tasks, task)
			}
			res := runGatewayTasks(t, dir, tasks, vars, nil)
			if (res.rc != 0) != tt.wantFail {
				t.Fatalf("rc=%d, want failure %v; failures=%v\n%s", res.rc, tt.wantFail, res.failures, res.raw)
			}
			if tt.wantFail {
				msg := strings.Join(res.failures, "\n")
				if !strings.Contains(msg, nfsAdminPasswordDriftGate) ||
					!strings.Contains(msg, "freeipa.admin.password in "+roster+" differs from ipa_admin_password") {
					t.Fatalf("drift failure does not name the field and roster: %v", res.failures)
				}
			}
			// The JSON callback escapes quotes, backslashes and non-ASCII, so
			// also look for a fragment of each that it prints verbatim.
			for _, secret := range []string{vaultPassword, stalePassword, "pass#2", "Stale'pass"} {
				if strings.Contains(res.raw, secret) || strings.Contains(res.stderr, secret) {
					t.Fatal("Ansible output leaked an admin password")
				}
			}
		})
	}

	t.Run("drifted, then fixed by hand", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		roster := filepath.Join(dir, "ipa-identity.yaml")
		line := func(password string) string { return "    password: " + yamlDoubleQuoted(password) + "\n" }
		drifted := "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n" + line(stalePassword)
		if err := os.WriteFile(roster, []byte(drifted), 0o600); err != nil {
			t.Fatal(err)
		}
		vars := map[string]any{"freeipa_roster_file": roster, "ipa_admin_password": vaultPassword}
		var tasks []any
		for _, task := range nfsServerPreTasks(t, nfsRosterLoadTask, nfsAdminPasswordDriftGate) {
			tasks = append(tasks, task)
		}
		if res := runGatewayTasks(t, dir, tasks, vars, nil); res.rc == 0 {
			t.Fatalf("a drifted roster passed the gate:\n%s", res.raw)
		}
		// The operator's edit: the password line, and nothing else.
		fixed := strings.Replace(drifted, line(stalePassword), line(vaultPassword), 1)
		if err := os.WriteFile(roster, []byte(fixed), 0o600); err != nil {
			t.Fatal(err)
		}
		if res := runGatewayTasks(t, dir, tasks, vars, nil); res.rc != 0 {
			t.Fatalf("the documented hand fix did not pass the gate: rc=%d failures=%v", res.rc, res.failures)
		}
	})
}

func yamlDoubleQuoted(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// The leak scan above reads what Ansible writes to stderr too: warnings
// and errors go there, not into the JSON callback's stdout. An unmatched
// --limit pattern is one: Ansible prints it in a [WARNING] on stderr.
func TestRegression_GatewayTaskHarnessCapturesStderr(t *testing.T) {
	t.Parallel()
	const marker = "pilot-stderr-marker-7c1f"
	task := map[string]any{"name": "noop", "ansible.builtin.debug": map[string]any{"msg": "ok"}}
	res := runGatewayTasks(t, t.TempDir(), []any{task}, nil, nil, "--limit", "localhost:"+marker)
	if res.rc != 0 {
		t.Fatalf("rc=%d\nstdout:\n%s\nstderr:\n%s", res.rc, res.raw, res.stderr)
	}
	if !strings.Contains(res.stderr, "[WARNING]") || !strings.Contains(res.stderr, marker) {
		t.Fatalf("stderr does not hold the unmatched-pattern warning naming %s:\n%s", marker, res.stderr)
	}
}
