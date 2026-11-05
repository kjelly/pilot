package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain doubles as the pilot-mcp CLI, so a test can signal a real CLI
// process.
func TestMain(m *testing.M) {
	if os.Getenv("PILOT_MCP_CLI_CHILD") == "1" {
		os.Exit(run())
	}
	os.Exit(m.Run())
}

// cliEnv prepares an isolated environment for one CLI run: a profile, a
// bare config repository, and an ssh stand-in on PATH that serves Git over
// ssh from the bare repository and, for the pilot-mcp command, runs
// behaviour (shell, with $PID_FILE set) to play a remote that never ends.
func cliEnv(t *testing.T, mode, behaviour string) ([]string, string) {
	t.Helper()
	root := t.TempDir()
	work := filepath.Join(root, "work")
	bare := filepath.Join(root, "config.git")
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	if err := os.MkdirAll(filepath.Join(work, "prod"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "prod", "hosts.yml"), []byte("hosts: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(work, "init", "--quiet")
	git(work, "add", "-A")
	git(work, "commit", "--quiet", "-m", "config")
	git(root, "clone", "--quiet", "--bare", work, bare)

	bin := filepath.Join(root, "bin")
	pidFile := filepath.Join(root, "remote.pid")
	ssh := "#!/bin/sh\ncase \"$*\" in *git-upload-pack*) exec git-upload-pack " + bare + " ;; esac\nPID_FILE=" + pidFile + "\n" + behaviour + "\n"
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(ssh), 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "config")
	if err := os.MkdirAll(filepath.Join(config, "pilot-mcp"), 0o700); err != nil {
		t.Fatal(err)
	}
	profile := "version: 1\nprofiles:\n  p:\n    source:\n      url: ssh://git@git.example.invalid/org/config.git\n      ref: main\n      subdir: prod\n" +
		"    target:\n      ssh_host: deploy\n      env: prod\n      env_root: /srv/env\n      image: pilot-cli:test\n    mode: " + mode + "\n"
	if err := os.WriteFile(filepath.Join(config, "pilot-mcp", "profiles.yaml"), []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "GIT_") || k == "PATH" || k == "HOME" || strings.HasPrefix(k, "XDG_") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, "PILOT_MCP_CLI_CHILD=1", "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+root, "XDG_CONFIG_HOME="+config, "XDG_CACHE_HOME="+filepath.Join(root, "cache"), "XDG_STATE_HOME="+filepath.Join(root, "state"),
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1")
	return env, pidFile
}

// SIGTERM or SIGINT ends a CLI waiting on the deploy node, within a few
// seconds and with 143/130, and the ssh process and its helpers are gone:
// during `changes` output and during doctor's remote-version step, with a
// remote that never ends and with a helper that keeps stdout open after
// ssh ends.
func TestCLISignalEndsAWaitOnTheDeployNode(t *testing.T) {
	behaviours := map[string]string{
		"remote hangs":        "echo $$ > \"$PID_FILE\"\nexec sleep 60",
		"helper keeps stdout": "sleep 60 &\necho $! > \"$PID_FILE\"\nexit 0",
	}
	commands := map[string]struct {
		mode string
		args []string
	}{
		"changes":        {"edit", []string{"changes", "--profile", "p", "--session", strings.Repeat("d", 32), "--into", "."}},
		"doctor version": {"observe", []string{"doctor", "--profile", "p"}},
	}
	signals := map[string]struct {
		sig  syscall.Signal
		exit int
	}{"SIGTERM": {syscall.SIGTERM, 143}, "SIGINT": {syscall.SIGINT, 130}}
	for cname, c := range commands {
		for bname, behaviour := range behaviours {
			for sname, s := range signals {
				t.Run(cname+"/"+bname+"/"+sname, func(t *testing.T) {
					env, pidFile := cliEnv(t, c.mode, behaviour)
					cmd := exec.Command(os.Args[0], c.args...)
					cmd.Env = env
					cmd.Dir = t.TempDir()
					if err := cmd.Start(); err != nil {
						t.Fatal(err)
					}
					defer func() { _ = cmd.Process.Kill() }()
					pid := waitForPID(t, pidFile)
					t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })

					sent := time.Now()
					if err := cmd.Process.Signal(s.sig); err != nil {
						t.Fatal(err)
					}
					exited := make(chan error, 1)
					go func() { exited <- cmd.Wait() }()
					select {
					case err := <-exited:
						var exitErr *exec.ExitError
						if !errors.As(err, &exitErr) || exitErr.ExitCode() != s.exit {
							t.Fatalf("exit = %v, want %d", err, s.exit)
						}
						if d := time.Since(sent); d > 5*time.Second {
							t.Fatalf("exited %v after the signal", d)
						}
					case <-time.After(15 * time.Second):
						t.Fatal("pilot-mcp did not exit after the signal")
					}
					for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
						if gone(pid) {
							break
						}
						if time.Now().After(deadline) {
							t.Fatalf("the remote stand-in %d is still running", pid)
						}
					}
				})
			}
		}
	}
}

func waitForPID(t *testing.T, path string) int {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		data, err := os.ReadFile(path)
		if err != nil || !strings.HasSuffix(string(data), "\n") {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil {
			return pid
		}
	}
	t.Fatalf("%s never got a pid", path)
	return 0
}

// gone reports whether pid has exited (gone, or a zombie waiting to be
// reaped by its new parent).
func gone(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return syscall.Kill(pid, 0) != nil
	}
	fields := strings.Fields(string(data[strings.LastIndexByte(string(data), ')')+1:]))
	return len(fields) > 0 && fields[0] == "Z"
}
