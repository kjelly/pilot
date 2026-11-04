package spec

import (
	"os/exec"
	"testing"
)

// The native-command harness has explicit boundaries in its module docstring.
// In particular, real tar recovery is not a substitute for target Docker/agent
// availability, migration or cross-host compatibility evidence.
func TestWazuhVersionTransactionBehavior(t *testing.T) {
	cmd := exec.Command("python3", "testdata/wazuh_transaction_test.py")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Wazuh transaction behavioral controls failed: %v\n%s", err, output)
	}
}

func TestAptExactVersionTaskBehavior(t *testing.T) {
	cmd := exec.Command("python3", "testdata/apt_exact_task_test.py")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real Ansible exact APT task controls failed: %v\n%s", err, output)
	}
}

func TestWazuhWriterTaskGraph(t *testing.T) {
	cmd := exec.Command("python3", "testdata/wazuh_writer_task_test.py")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real Ansible Wazuh writer/delegation graph failed: %v\n%s", err, output)
	}
}

func TestWazuhSelectionTaskGraph(t *testing.T) {
	cmd := exec.Command("python3", "testdata/wazuh_selection_task_test.py")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real Ansible Wazuh selection/failure-authority graph failed: %v\n%s", err, output)
	}
}
