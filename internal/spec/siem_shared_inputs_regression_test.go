package spec

import (
	"os/exec"
	"strings"
	"testing"
)

// siemResolve runs the tasks of playbook that keep selects, on localhost in
// group with groupVars, and returns the values of names.
func siemResolve(t *testing.T, playbook, group string, keep func(string) bool, groupVars map[string]any, names ...string) map[string]any {
	t.Helper()
	play := loadFirstPlay(t, playbook)
	tasks := append(pickTasks(play, keep), showTask(names))
	return runInventoryPlay(t, group, play["vars"], tasks, groupVars)
}

// TestRegression_SIEMSharedInputsResolveTheSameOnEverySide is the AGENTS.md
// §5.7 consistency test for the inputs the SIEM playbooks share on one host:
// log-server writes under siem_log_root and log-shipping's Promtail tails it;
// audit-log-forwarding and wazuh-manager send to siem_forward_port and
// log-server listens on siem_receiver_tcp_port. For the same inventory value
// (unset, "", null or set), each pair must resolve the same directory and
// port. With `default()` alone an empty or null siem_log_root reached
// log-server as "" (rsyslog then wrote /%HOSTNAME%/audit.log) while
// log-shipping tailed /var/log/siem.
func TestRegression_SIEMSharedInputsResolveTheSameOnEverySide(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	cases := []struct {
		name     string
		value    any // siem_log_root; nil with set=false means not set at all
		port     any // siem_forward_port and siem_receiver_tcp_port
		set      bool
		wantRoot string
		wantPort string
	}{
		{"unset", nil, nil, false, "/var/log/siem", "514"},
		{"empty", "", "", true, "/var/log/siem", "514"},
		{"null", nil, nil, true, "/var/log/siem", "514"},
		{"set", "/var/log/siem-site", "2514", true, "/var/log/siem-site", "2514"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gv map[string]any
			if tc.set {
				gv = map[string]any{"siem_log_root": tc.value, "siem_forward_port": tc.port, "siem_receiver_tcp_port": tc.port}
			}
			server := siemResolve(t, "log-server-apply.yml", "log-server", isDefaultsTask, gv, "siem_log_root", "siem_receiver_tcp_port")
			shipping := siemResolve(t, "log-shipping-apply.yml", "log-server", func(name string) bool {
				return strings.HasPrefix(name, "Resolve siem_log_root_effective")
			}, gv, "siem_log_root_effective")
			audit := siemResolve(t, "audit-log-forwarding-apply.yml", "audit-log-forwarding", isDefaultsTask, gv, "siem_forward_port")
			wazuh := siemResolve(t, "wazuh-manager-apply.yml", "wazuh-manager", isDefaultsTask, gv, "siem_forward_port")

			if server["siem_log_root"] != tc.wantRoot || shipping["siem_log_root_effective"] != tc.wantRoot {
				t.Errorf("siem_log_root: log-server writes under %v, log-shipping tails %v; want both %s",
					server["siem_log_root"], shipping["siem_log_root_effective"], tc.wantRoot)
			}
			if server["siem_receiver_tcp_port"] != tc.wantPort || audit["siem_forward_port"] != tc.wantPort || wazuh["siem_forward_port"] != tc.wantPort {
				t.Errorf("ports: log-server listens on %v, audit-log-forwarding sends to %v, wazuh-manager to %v; want all %s",
					server["siem_receiver_tcp_port"], audit["siem_forward_port"], wazuh["siem_forward_port"], tc.wantPort)
			}
		})
	}
}

// TestRegression_LogServerRefusesASharedSiemLogRoot runs log-server's
// defaults and its siem_log_root gate. log-server's Step 2 makes
// siem_log_root owned by the rsyslog user and Step 4 rotates
// siem_log_root/*/*.log, so since siem_log_root comes from inventory a value
// such as /var/log must fail before any mutation.
func TestRegression_LogServerRefusesASharedSiemLogRoot(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	play := loadFirstPlay(t, "log-server-apply.yml")
	tasks := append(pickTasks(play, func(name string) bool {
		return isDefaultsTask(name) || name == "Gate: siem_log_root is a dedicated absolute directory"
	}), showTask([]string{"siem_log_root"}))
	if len(tasks) != 3 {
		t.Fatalf("expected the defaults task, the gate and show; got %d tasks", len(tasks))
	}
	for _, ok := range []string{"/var/log/siem", "/var/log/siem-site", "/srv/siem", "/data/logs/siem_1.x"} {
		got, failed := tryInventoryPlay(t, "log-server", play["vars"], tasks, map[string]any{"siem_log_root": ok})
		if failed != "" || got["siem_log_root"] != ok {
			t.Errorf("siem_log_root=%s: want accepted, got %v (%s)", ok, got, failed)
		}
	}
	for _, bad := range []string{"/var/log", "/var", "/", "/etc", "/srv", "var/log/siem", "/var/log/siem/",
		"/var//log/siem", "/var/log/../siem", "/var/log/./siem", "/var/log/siem dir", "/var/log/$(id)"} {
		_, failed := tryInventoryPlay(t, "log-server", play["vars"], tasks, map[string]any{"siem_log_root": bad})
		if !strings.Contains(failed, "Gate: siem_log_root is a dedicated absolute directory") {
			t.Errorf("siem_log_root=%q: want the gate to fail, got %q", bad, failed)
		}
	}
}
