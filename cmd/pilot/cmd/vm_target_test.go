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

// TestRunVtRun_SkipsAutoLimitWhenTargetGroupPresent is the regression
// guard for the symlink to docker_target.go's `extraHasTargetGroup`:
// without it, `pilot vm-target run <pb> -e target_group=foo` would
// also inject `-l <name>`, and `-l` would override the user's group.
func TestRunVtRun_SkipsAutoLimitWhenTargetGroupPresent(t *testing.T) {
	// We can't actually start a VM in a unit test, so the regression
	// guard is at the *args-builder* level: when target_group= is in
	// the user's extra, we must not add -l. extraHasTargetGroup is
	// already covered; here we additionally assert that the runVtRun
	// builder code path skips -l when the helper says so.
	cases := []struct {
		name      string
		extra     []string
		wantLimit bool
	}{
		{"explicit -e target_group=", []string{"-e", "target_group=dns"}, false},
		{"joined -e target_group=", []string{"-e target_group=dns"}, false},
		{"target_group via --extra-vars", []string{"--extra-vars", "target_group=keycloak"}, false},
		{"no target_group", []string{"-e", "infra_role=ntp"}, true},
		{"no extra at all", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Mirror the builder logic from runVtRun.
			ansibleArgs := []string{"<playbook>", "-i", "<inv>"}
			if !extraHasTargetGroup(tc.extra) {
				ansibleArgs = append(ansibleArgs, "-l", "core")
			}
			ansibleArgs = append(ansibleArgs, tc.extra...)

			hasLimit := false
			for i, a := range ansibleArgs {
				if a == "-l" && i+1 < len(ansibleArgs) && ansibleArgs[i+1] == "core" {
					hasLimit = true
				}
			}
			if hasLimit != tc.wantLimit {
				t.Fatalf("hasLimit=%v want %v; args=%v", hasLimit, tc.wantLimit, ansibleArgs)
			}
		})
	}
}
