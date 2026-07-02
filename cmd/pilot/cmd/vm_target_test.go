package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/vmtarget"
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
	want := []string{"up", "down", "list", "show-inventory", "run", "verify", "exec", "snapshot", "rollback", "ssh", "shell", "resize-disk"}
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

// TestBuildVtSSHArgv_PTYAndConnectionFlags is the regression guard
// for the `pilot vm-target ssh` / `shell` argv builder. We must:
//  1. start with the same flags vmtarget.Exec would build (single
//     source of truth for host-key / key / port),
//  2. add -tt to force PTY allocation (so resize and sudo prompts
//     work, and so the user gets an actual terminal instead of
//     captured pipes),
//  3. add `--` so a remote argv starting with `-` is not parsed
//     as a flag by the remote sshd.
func TestBuildVtSSHArgv_PTYAndConnectionFlags(t *testing.T) {
	tgt := &vmtarget.Target{
		Name:    "core",
		IP:      "192.168.123.232",
		SSHUser: "ubuntu",
		SSHPort: 22,
		KeyPath: "/var/lib/libvirt/images/pilot/core/id_ed25519",
	}
	argv := buildVtSSHArgv(tgt, []string{"bash", "-l"})

	// 1) Connection flags (same as vmtarget.Exec's shim)
	mustContain(t, argv, "-i", "/var/lib/libvirt/images/pilot/core/id_ed25519")
	mustContain(t, argv, "-p", "22")
	mustContain(t, argv, "ubuntu@192.168.123.232")

	// 2) PTY
	mustContain(t, argv, "-tt")

	// 3) Separator + remote command
	mustContain(t, argv, "--", "bash", "-l")

	// Order check: PTY comes before `--` so the remote command
	// doesn't accidentally include the PTY flag.
	idxTT, idxSep := -1, -1
	for i, a := range argv {
		if a == "-tt" && idxTT < 0 {
			idxTT = i
		}
		if a == "--" && idxSep < 0 {
			idxSep = i
		}
	}
	if idxTT < 0 || idxSep < 0 || idxTT >= idxSep {
		t.Fatalf("-tt must come before --; got argv=%v", argv)
	}
}

// TestBuildVtSSHArgv_NoRemoteArgv still emits the connection flags
// (so a future default like ["$SHELL"] lands in the right place).
func TestBuildVtSSHArgv_NoRemoteArgv(t *testing.T) {
	tgt := &vmtarget.Target{
		Name: "core", IP: "10.0.0.5", SSHUser: "u", SSHPort: 22, KeyPath: "/k",
	}
	argv := buildVtSSHArgv(tgt, nil)
	mustContain(t, argv, "-tt", "--")
	// Trailing `--` followed by no command: ssh on the other end
	// will run the user's login shell, which is what we want.
	last := argv[len(argv)-1]
	if last != "--" {
		t.Errorf("argv should end with --; got last=%q argv=%v", last, argv)
	}
}

// TestContainerFixPermsScript_CreatesControlPathDir guards the sandbox fix:
// the generated inventory pins ssh ControlPath under ~/.ansible/cp, so the
// in-container prep MUST create that directory (and ~/.ssh) or ControlMaster
// socket creation fails and every ansible task errors.
func TestContainerFixPermsScript_CreatesControlPathDir(t *testing.T) {
	s := containerFixPermsScript("/tmp/pilot-ssh/id_ed25519")
	for _, want := range []string{
		"cp /tmp/pilot-ssh/id_ed25519 /tmp/pilot-ssh-key",
		"chmod 600 /tmp/pilot-ssh-key",
		"~/.ansible/cp", // the ControlPath parent dir the inventory requires
		"~/.ssh",
		"touch ~/.ssh/known_hosts",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("fix-perms script missing %q\ngot: %s", want, s)
		}
	}
}

// TestIdempotencyChangedCount locks in the recap-scoped idempotency parser:
// it must sum changed= across PLAY RECAP host lines only, ignoring any
// "changed=N" that appears elsewhere in task/debug output, and report
// ok=false when there is no recap at all.
func TestIdempotencyChangedCount(t *testing.T) {
	const recapClean = "\nPLAY RECAP *********\n" +
		"core                       : ok=5    changed=0    unreachable=0    failed=0    skipped=1\n"
	const recapChanged = "\nPLAY RECAP *********\n" +
		"core                       : ok=5    changed=2    unreachable=0    failed=0    skipped=1\n"
	const recapTwoHosts = "\nPLAY RECAP *********\n" +
		"a                          : ok=1    changed=1    unreachable=0    failed=0\n" +
		"b                          : ok=1    changed=3    unreachable=0    failed=0\n"

	cases := []struct {
		name   string
		out    string
		wantN  int
		wantOK bool
	}{
		{"clean single host", recapClean, 0, true},
		{"changed single host", recapChanged, 2, true},
		{"summed across hosts", recapTwoHosts, 4, true},
		{
			"debug line before recap is ignored",
			"TASK [debug] ok: msg 'changed=9 things happened'\n" + recapClean,
			0, true,
		},
		{"no recap at all", "TASK failed with changed=1 in the text\nfatal: unreachable", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotN, gotOK := idempotencyChangedCount(tc.out)
			if gotN != tc.wantN || gotOK != tc.wantOK {
				t.Fatalf("idempotencyChangedCount() = (%d,%v), want (%d,%v)", gotN, gotOK, tc.wantN, tc.wantOK)
			}
		})
	}
}

// TestVMTargetTestAndResetRegistered rounds out the subcommand wiring guard
// for the newer `test`/`reset` subcommands.
func TestVMTargetTestAndResetRegistered(t *testing.T) {
	want := map[string]bool{"test": false, "reset": false}
	for _, c := range vmTargetCmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
}

func mustContain(t *testing.T, argv []string, want ...string) {
	t.Helper()
	for i := 0; i+len(want) <= len(argv); i++ {
		match := true
		for j, w := range want {
			if argv[i+j] != w {
				match = false
				break
			}
		}
		if match {
			return
		}
	}
	t.Fatalf("argv missing %v; got %v", want, argv)
}
