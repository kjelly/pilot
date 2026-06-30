package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestVMTargetCmdRegistered guards the rootCmd.AddCommand wiring.
func TestVMTargetCmdRegistered(t *testing.T) {
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Name() == "vm-target" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("vm-target subcommand not registered on rootCmd")
	}
}

// TestVMTargetSubCommandsAllRegistered walks the promised subcommands.
func TestVMTargetSubCommandsAllRegistered(t *testing.T) {
	want := []string{"up", "down", "list", "show-inventory", "run", "verify", "exec", "snapshot", "rollback"}
	var have []string
	for _, c := range vmTargetCmd.Commands() {
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
			t.Errorf("subcommand %q missing; have %v", w, have)
		}
	}
}

func TestRunVtUp_RequiresName(t *testing.T) {
	vtName = ""
	vtBaseImage = ""
	rootCmd.SetArgs([]string{"vm-target", "up"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("want --name-required, got %v", err)
	}
}

func TestRunVtUp_RequiresBaseImage(t *testing.T) {
	vtName = ""
	vtBaseImage = ""
	rootCmd.SetArgs([]string{"vm-target", "up", "--name", "x"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "--base-image is required") {
		t.Fatalf("want --base-image-required, got %v", err)
	}
}

func TestResolveVMDir_DefaultAndOverride(t *testing.T) {
	old := vtVMDir
	defer func() { vtVMDir = old }()
	vtVMDir = ""
	if got := resolveVMDir(); got != "/var/lib/libvirt/images/pilot" {
		t.Errorf("default vm dir = %q", got)
	}
	vtVMDir = "/custom/vmdir"
	if got := resolveVMDir(); got != "/custom/vmdir" {
		t.Errorf("override vm dir = %q", got)
	}
}
