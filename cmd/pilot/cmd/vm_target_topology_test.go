package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestVMTargetTopologyCmdRegistered(t *testing.T) {
	var found bool
	for _, c := range vmTargetCmd.Commands() {
		if c.Name() == "topology" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("topology subcommand not registered on vmTargetCmd")
	}
}

func TestVMTargetTopologySubCommandsAllRegistered(t *testing.T) {
	want := []string{"up", "down", "inventory", "status", "snapshot", "rollback", "reset"}
	var have []string
	for _, c := range vtTopologyCmd.Commands() {
		have = append(have, c.Name())
	}
	for _, w := range want {
		ok := false
		for _, h := range have {
			if h == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("topology subcommand %q missing; have %v", w, have)
		}
	}
}

func TestRunVtTopologyUp_RequiresSpecFlag(t *testing.T) {
	vtTopoSpecPath = ""
	rootCmd.SetArgs([]string{"vm-target", "topology", "up"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "spec") {
		t.Fatalf("want a missing --spec error, got %v", err)
	}
}

func TestRunVtTopologyUp_MissingSpecFileErrors(t *testing.T) {
	vtTopoSpecPath = "/nonexistent/topology.yaml"
	rootCmd.SetArgs([]string{"vm-target", "topology", "up", "--spec", vtTopoSpecPath})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "topology spec") {
		t.Fatalf("want a topology-spec load error, got %v", err)
	}
}

func TestRunVtTopologySnapshot_RequiresTagFlag(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/topo.yaml"
	if err := os.WriteFile(path, []byte("nodes:\n  - name: a\n"), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	rootCmd.SetArgs([]string{"vm-target", "topology", "snapshot", "--spec", path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("want a missing --tag error, got %v", err)
	}
}

func TestRunVtTopologyRollback_RequiresTagFlag(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/topo.yaml"
	if err := os.WriteFile(path, []byte("nodes:\n  - name: a\n"), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	rootCmd.SetArgs([]string{"vm-target", "topology", "rollback", "--spec", path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("want a missing --tag error, got %v", err)
	}
}

func TestRunVtTopologyReset_MissingSpecFileErrors(t *testing.T) {
	vtTopoSpecPath = "/nonexistent/topology.yaml"
	rootCmd.SetArgs([]string{"vm-target", "topology", "reset", "--spec", vtTopoSpecPath})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "topology spec") {
		t.Fatalf("want a topology-spec load error, got %v", err)
	}
}

func TestRunVtTopologyInventory_RequiresGroups(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/no-groups.yaml"
	if err := os.WriteFile(path, []byte("nodes:\n  - name: a\n"), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	vtTopoSpecPath = path
	vtTopoOut = ""
	rootCmd.SetArgs([]string{"vm-target", "topology", "inventory", "--spec", path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "declares no node 'groups:'") {
		t.Fatalf("want a no-groups error, got %v", err)
	}
}
