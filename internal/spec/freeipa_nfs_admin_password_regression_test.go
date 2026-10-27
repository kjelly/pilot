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
// hidden (issue #146).
func TestRegression_FreeIPANFSServerAdminPasswordGateIsVisible(t *testing.T) {
	tasks := nfsServerPreTasks(t, nfsRosterAndStageGate, nfsAdminPasswordDriftGate)
	gate, drift := tasks[0], tasks[1]
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

// Run from the real playbook: a drifted roster fails naming the field and
// printing neither value; a matching, referencing or vault-less run passes.
func TestRegression_FreeIPANFSServerAdminPasswordDriftGate(t *testing.T) {
	const vaultPassword, stalePassword = `Vault"pass#2 密碼`, `Stale'pass\1`
	for name, tt := range map[string]struct {
		roster   string
		vault    bool
		wantFail bool
	}{
		"drifted":   {roster: stalePassword, vault: true, wantFail: true},
		"matching":  {roster: vaultPassword, vault: true},
		"reference": {roster: "{{ ipa_admin_password }}", vault: true},
		"no vault":  {roster: stalePassword},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			roster := filepath.Join(dir, "ipa-identity.yaml")
			body := "schema_version: 3\nfreeipa:\n  admin:\n    principal: admin\n    password: " + yamlDoubleQuoted(tt.roster) + "\n"
			if err := os.WriteFile(roster, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			vars := map[string]any{"freeipa_roster_file": roster}
			if tt.vault {
				vars["ipa_admin_password"] = vaultPassword
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
				if strings.Contains(res.raw, secret) {
					t.Fatal("Ansible output leaked an admin password")
				}
			}
		})
	}
}

func yamlDoubleQuoted(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
