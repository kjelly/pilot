package spec

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRegression_LogServerSELinuxRescueKeepsRuntimePermissions runs the entire
// production rescue through Ansible. Only external systemd/SELinux operations
// are replaced, recording whether a permission was revoked while the runtime
// may still use the new root. Real labels and delivery are covered by EL evidence.
func TestRegression_LogServerSELinuxRescueKeepsRuntimePermissions(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	var rescue []map[string]any
	for _, x := range loadFirstPlay(t, "log-server-apply.yml")["tasks"].([]any) {
		if m, ok := x.(map[string]any); ok && m["rescue"] != nil {
			for _, task := range m["rescue"].([]any) {
				rescue = append(rescue, task.(map[string]any))
			}
		}
	}
	for _, c := range []struct {
		name                               string
		syntax, snapshotRC, currentRC      int
		snapshotID, currentID              string
		restartFails, inactive, wantRevoke bool
	}{
		{name: "after restart, rescue restarts", snapshotID: "old", currentID: "new", wantRevoke: true},
		{name: "after restart, invalid restored configuration", syntax: 1, snapshotID: "old", currentID: "new"},
		{name: "before restart, original invocation still active", syntax: 1, snapshotID: "old", currentID: "old", wantRevoke: true},
		{name: "empty successful invocation probes", syntax: 1},
		{name: "failed invocation probes", syntax: 1, snapshotRC: 1, currentRC: 1},
		{name: "failed probes with stale stdout", syntax: 1, snapshotRC: 1, currentRC: 1, snapshotID: "old", currentID: "old"},
		{name: "snapshot probe failed", syntax: 1, snapshotRC: 1, snapshotID: "old", currentID: "old"},
		{name: "current probe failed", syntax: 1, currentRC: 1, snapshotID: "old", currentID: "old"},
		{name: "restart failed after config passed", snapshotID: "old", currentID: "new", restartFails: true},
		{name: "restart failed but original invocation still active", snapshotID: "old", currentID: "old", restartFails: true, wantRevoke: true},
		{name: "successful restart but inactive", snapshotID: "old", currentID: "new", inactive: true},
		{name: "same invocation but inactive", syntax: 1, snapshotID: "old", currentID: "old", inactive: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			tasks := []any{map[string]any{"ansible.builtin.set_fact": map[string]any{
				"log_server_snapshot_rsyslog":    map[string]any{"rc": c.snapshotRC, "stdout": c.snapshotID},
				"rsyslog_selinux_fcontext_added": true, "rsyslog_selinux_fcontext_target": "/srv/new(/.*)?",
				"siem_log_root_real": "/srv/new", "siem_receiver_conf": filepath.Join(dir, "receiver"),
				"revoked": false, "relabelled": false, "writes_old": c.currentID == c.snapshotID && c.currentID != "" && c.snapshotRC == 0 && c.currentRC == 0,
			}}}
			for _, x := range withPath(t, rescue, apparmorLocal, filepath.Join(dir, "absent-local")) {
				m := x.(map[string]any)
				delete(m, "tags")
				switch m["name"] {
				case "ROLLBACK — validate the restored rsyslog configuration":
					m = map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_rescue_syntax": map[string]any{"rc": c.syntax, "stderr_lines": []string{"injected invalid configuration"}}}}
				case "ROLLBACK — restart rsyslog with the restored configuration":
					delete(m, "ansible.builtin.systemd")
					if c.restartFails {
						m["ansible.builtin.set_fact"] = map[string]any{"log_server_rescue_restart": map[string]any{"failed": true, "msg": "injected restart failure"}}
						delete(m, "register")
					} else {
						m["ansible.builtin.set_fact"] = map[string]any{"writes_old": true}
					}
				case "ROLLBACK — which rsyslog process is running now":
					m = map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_rescue_rsyslog": map[string]any{"rc": c.currentRC, "stdout": c.currentID}}}
				case "ROLLBACK — is rsyslog active after recovery":
					rc := 0
					if c.inactive {
						rc = 3
					}
					m = map[string]any{"ansible.builtin.set_fact": map[string]any{"log_server_rescue_active": map[string]any{"rc": rc}}}
				case "ROLLBACK — remove the SELinux file-context rule this apply added":
					delete(m, "community.general.sefcontext")
					m["ansible.builtin.set_fact"] = map[string]any{"revoked": true, "safe_at_revoke": "{{ writes_old }}"}
				case "ROLLBACK — relabel the log root without that rule":
					delete(m, "ansible.builtin.command")
					m["ansible.builtin.set_fact"] = map[string]any{"relabelled": true, "safe_at_relabel": "{{ writes_old }}"}
				case "ROLLBACK — surface the original failure":
					m["ansible.builtin.set_fact"] = map[string]any{"message": m["ansible.builtin.fail"].(map[string]any)["msg"]}
					delete(m, "ansible.builtin.fail")
				}
				tasks = append(tasks, m)
			}
			tasks = append(tasks, showTask([]string{"revoked", "relabelled", "safe_at_revoke", "safe_at_relabel", "message"}))
			got, failed := tryInventoryPlay(t, "log-server", nil, tasks, nil)
			if failed != "" {
				t.Fatal(failed)
			}
			for _, key := range []string{"revoked", "relabelled"} {
				if got[key] != c.wantRevoke {
					t.Errorf("%s=%v, want %v", key, got[key], c.wantRevoke)
				}
			}
			if c.wantRevoke && (got["safe_at_revoke"] != true || got["safe_at_relabel"] != true) {
				t.Error("permissions revoked before runtime returned to the original config")
			}
			msg := fmt.Sprint(got["message"])
			if c.syntax == 0 && (c.restartFails || c.inactive) && strings.Contains(msg, "did not pass (rc=0") {
				t.Errorf("false validation failure: %s", msg)
			}
			if !c.wantRevoke && !strings.Contains(msg, "were kept") {
				t.Errorf("must report retained permissions: %s", msg)
			}
		})
	}
}
