package spec

import (
	"strings"
	"testing"
)

// logServerReceiverTask is the name log-server-apply.yml gives the task that
// renders /etc/rsyslog.d/10-siem-receiver.conf; wazuh_alert_delivery_regression_test.go
// looks it up by the same name.
const logServerReceiverTask = "Step 3: Render 10-siem-receiver.conf (imtcp + %HOSTNAME% dynaFile routing)"

// logServerReceiverContent returns the unrendered content: of Step 3 (Jinja
// still in place).
func logServerReceiverContent(t *testing.T) string {
	t.Helper()
	task := findNamedTask(t, loadFirstPlay(t, "log-server-apply.yml"), logServerReceiverTask)
	args, ok := task["ansible.builtin.copy"].(map[string]any)
	if !ok {
		t.Fatalf("%q is not an ansible.builtin.copy task", logServerReceiverTask)
	}
	content, ok := args["content"].(string)
	if !ok {
		t.Fatalf("%q has no content:", logServerReceiverTask)
	}
	return content
}

// siemReceiverTemplate returns the template(...) line log-server-apply.yml
// renders for the path template called name (SiemAuditPath, SiemAuthPath or
// SiemWazuhPath) with siem_log_root set to root. Tests that need the receiver
// config's path templates take them from here, so they follow the playbook
// when its %HOSTNAME% spelling changes (AGENTS.md §5.7; issue #363 changed it
// and four copies written out by hand each had to be found and updated).
func siemReceiverTemplate(t *testing.T, name, root string) string {
	t.Helper()
	var found []string
	for _, line := range strings.Split(logServerReceiverContent(t), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, `template(name="`+name+`" `) {
			found = append(found, line)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one template(name=%q ...) line in %q, found %d", name, logServerReceiverTask, len(found))
	}
	const rootVar = "{{ siem_log_root }}"
	if strings.Count(found[0], "{{") != 1 || strings.Count(found[0], rootVar) != 1 || strings.Contains(found[0], "{%") {
		t.Fatalf("%q must use no Jinja but %s, so a test can render it without Ansible: %s", name, rootVar, found[0])
	}
	return strings.Replace(found[0], rootVar, root, 1)
}
