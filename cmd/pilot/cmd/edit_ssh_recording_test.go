package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestSetHostField_SSHRecording(t *testing.T) {
	for _, v := range []string{"inherit", "off", "terminal_output"} {
		step := editAction{Action: "set_host_field", Host: "db-01", Field: "ssh_recording", Value: v}
		if err := validateSetHostField(step); err != nil {
			t.Errorf("value %q rejected: %v", v, err)
		}
	}
	for _, v := range []string{"terminal_io", "", "yes", "true", "output"} {
		step := editAction{Action: "set_host_field", Host: "db-01", Field: "ssh_recording", Value: v}
		if err := validateSetHostField(step); err == nil {
			t.Errorf("value %q accepted, want rejection", v)
		}
	}
}

func TestHostMenu_SSHRecordingChoices(t *testing.T) {
	cases := []struct {
		value inventory.SSHRecording
		label string
	}{
		{"", "inherit（沿用 gateway 預設）"},
		{inventory.SSHRecordingOff, "off"},
		{inventory.SSHRecordingTerminalOutput, "terminal_output"},
	}
	for _, c := range cases {
		if got := sshRecordingLabel(c.value); got != c.label {
			t.Errorf("sshRecordingLabel(%q) = %q, want %q", c.value, got, c.label)
		}
	}
}

// runSSHRecordingScenario drives the real edit TUI through set_host_field
// and returns the host as re-parsed from the saved hosts.yml.
func runSSHRecordingScenario(t *testing.T, dir string, steps []editAction) inventory.Host {
	t.Helper()
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, editScenario{Version: 1, Steps: steps}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("Parse(saved hosts.yml): %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 {
		t.Fatalf("hosts = %+v, want one host", hf.Hosts)
	}
	return hf.Hosts[0]
}

func TestHostMenu_SSHRecordingInheritRemovesField(t *testing.T) {
	dir := t.TempDir()
	h := runSSHRecordingScenario(t, dir, []editAction{
		{Action: "create_host", Host: "db-01"},
		{Action: "set_host_field", Host: "db-01", Field: "ansible_host", Value: "10.0.0.31"},
		{Action: "set_host_field", Host: "db-01", Field: "ssh_recording", Value: "terminal_output"},
		{Action: "save_hosts"},
	})
	if h.SSHRecording != inventory.SSHRecordingTerminalOutput {
		t.Fatalf("after terminal_output: ssh_recording = %q", h.SSHRecording)
	}

	h = runSSHRecordingScenario(t, dir, []editAction{
		{Action: "set_host_field", Host: "db-01", Field: "ssh_recording", Value: "off"},
		{Action: "save_hosts"},
	})
	if h.SSHRecording != inventory.SSHRecordingOff {
		t.Fatalf("after off: ssh_recording = %q", h.SSHRecording)
	}

	h = runSSHRecordingScenario(t, dir, []editAction{
		{Action: "set_host_field", Host: "db-01", Field: "ssh_recording", Value: "inherit"},
		{Action: "save_hosts"},
	})
	if h.SSHRecording != "" {
		t.Fatalf("after inherit: ssh_recording = %q, want field removed", h.SSHRecording)
	}
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "ssh_recording:") {
		t.Fatalf("inherit left an ssh_recording line in hosts.yml:\n%s", data)
	}
}
