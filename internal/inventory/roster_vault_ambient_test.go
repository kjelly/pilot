package inventory

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

// fakeVaultPrompt stands in for ansible-vault with no vault secret: like
// Python's getpass it prompts on the controlling terminal when it has one
// and waits for an answer there, and otherwise reads closed stdin and ends
// with EOFError (the stderr of the real tool in that case is in
// testdata/ansible-vault-view-no-secret.stderr).
const fakeVaultPrompt = `if ( : </dev/tty ) 2>/dev/null; then
  printf 'Vault password: ' >/dev/tty
  read -r pw </dev/tty
  exit 3
fi
echo "[ERROR]: EOFError (ctrl-d) on prompt for (default)" >&2
exit 1
`

// fakeVaultBin returns a directory holding an ansible-vault that runs
// body, and an ansible-vault-looking vars file for it to be asked about.
func fakeVaultBin(t *testing.T, body string) (bin, vault string) {
	t.Helper()
	dir := t.TempDir()
	bin = filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "ansible-vault"), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	vault = filepath.Join(dir, "vars.yml")
	if err := os.WriteFile(vault, []byte("$ANSIBLE_VAULT;1.1;AES256\n3132\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return bin, vault
}

func withVaultPath(t *testing.T, bin string) {
	t.Helper()
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// processAlive reports whether pid is a running process; a zombie, which
// nobody has reaped yet, is not.
func processAlive(pid int) bool {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return false
	}
	// The state is the field after the command name, which is in parentheses.
	rest := string(data[strings.LastIndexByte(string(data), ')')+1:])
	fields := strings.Fields(rest)
	return len(fields) > 0 && fields[0] != "Z" && fields[0] != "X"
}

func TestViewVaultFileAmbientReturnsTheViewAndPassesTheEnvironment(t *testing.T) {
	bin, vault := fakeVaultBin(t, `printf '%s|%s|%s' "$1" "$2" "$ANSIBLE_VAULT_PASSWORD_FILE"`)
	withVaultPath(t, bin)
	out, err := ViewVaultFileAmbient(context.Background(), vault, []string{"ANSIBLE_VAULT_PASSWORD_FILE=/run/secret"})
	if err != nil || string(out) != "view|"+vault+"|/run/secret" {
		t.Fatalf("got %q, %v", out, err)
	}
}

func TestViewVaultFileAmbientStartsNothingWithAnEndedContext(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	bin, vault := fakeVaultBin(t, "touch '"+marker+"'")
	withVaultPath(t, bin)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ViewVaultFileAmbient(ctx, vault, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("ansible-vault ran under a context that had ended")
	}
}

// unsetenv removes key from the test process's environment until the test
// ends.
func unsetenv(t *testing.T, key string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, old)
		}
	})
}

// The real ansible-vault (ansible-core) under ViewVaultFileAmbient's new
// session: a secret named by the environment decrypts the file, another
// secret and no secret are the two classified failures. Skipped where
// ansible-vault is not installed.
func TestViewVaultFileAmbientRealAnsibleVault(t *testing.T) {
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skipf("ansible-vault not installed: %v", err)
	}
	dir := t.TempDir()
	password := filepath.Join(dir, "pw")
	other := filepath.Join(dir, "other-pw")
	vars := filepath.Join(dir, "vars.yml")
	noConfig := filepath.Join(dir, "ansible.cfg")
	const content = "ipa_admin_password: not-a-real-secret\n"
	for path, data := range map[string]string{password: "lab-only-vault-password\n", other: "another-lab-only-password\n", vars: content, noConfig: ""} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", password, vars).CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt (test setup): %v: %s", err, out)
	}
	t.Setenv("ANSIBLE_CONFIG", noConfig)
	for _, key := range []string{"ANSIBLE_VAULT_PASSWORD_FILE", "ANSIBLE_VAULT_IDENTITY_LIST", "ANSIBLE_VAULT_ID_MATCH", "ANSIBLE_ASK_VAULT_PASS"} {
		unsetenv(t, key)
	}
	for _, tc := range []struct {
		name string
		env  []string
		want error
	}{
		{name: "secret from the environment", env: []string{"ANSIBLE_VAULT_PASSWORD_FILE=" + password}},
		{name: "another secret", env: []string{"ANSIBLE_VAULT_PASSWORD_FILE=" + other}, want: ErrVaultDecryptFailed},
		{name: "no secret", want: ErrNoVaultSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			got, err := ViewVaultFileAmbient(ctx, vars, tc.env)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil || string(got) != content {
				t.Fatalf("got %q, %v; want the decrypted file", got, err)
			}
		})
	}
}

// ptyChild runs the named test in a child of this test binary whose
// controlling terminal is a pty nobody answers on, and returns what the
// child wrote to the terminal. The child recognizes itself by ptyChildEnv.
func ptyChild(t *testing.T, name string, env []string) (output string, err error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^"+name+"$", "-test.v", "-test.count=1")
	cmd.Env = append(env, ptyChildEnv+"=1")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	defer ptmx.Close()
	var out bytes.Buffer
	copied := make(chan struct{})
	go func() { _, _ = io.Copy(&out, ptmx); close(copied) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		err = errors.New("the child hung")
	}
	_ = ptmx.Close()
	<-copied
	return out.String(), err
}

// ptyChildEnv, set to 1 in a ptyChild's environment, makes the test run its
// body (the part that needs a controlling terminal) instead of starting one.
const ptyChildEnv = "PILOT_TEST_VAULT_TTY_CHILD"

// Run from a terminal with no vault secret, the Go preview must fail with
// ErrNoVaultSecret instead of prompting there (spec §3, D6): the child test
// has a pty as its controlling terminal, and the fake ansible-vault prompts
// on /dev/tty whenever it can open it.
func TestViewVaultFileAmbientNeverPromptsOnATerminal(t *testing.T) {
	if os.Getenv(ptyChildEnv) == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := ViewVaultFileAmbient(ctx, os.Getenv("PILOT_TEST_VAULT_FILE"), nil); !errors.Is(err, ErrNoVaultSecret) {
			t.Fatalf("err = %v, want ErrNoVaultSecret", err)
		}
		return
	}
	bin, vault := fakeVaultBin(t, fakeVaultPrompt)
	out, err := ptyChild(t, "TestViewVaultFileAmbientNeverPromptsOnATerminal", append(os.Environ(),
		"PILOT_TEST_VAULT_FILE="+vault, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH")))
	if err != nil || !strings.Contains(out, "--- PASS") {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if strings.Contains(out, "Vault password") {
		t.Fatalf("a prompt reached the terminal:\n%s", out)
	}
}

// The same with the real ansible-vault (ansible-core): this is the tool
// whose getpass opened /dev/tty and waited when the preview ran on a
// terminal. Skipped where ansible-vault is not installed.
func TestViewVaultFileAmbientNeverPromptsOnATerminalRealAnsibleVault(t *testing.T) {
	if os.Getenv(ptyChildEnv) == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, err := ViewVaultFileAmbient(ctx, os.Getenv("PILOT_TEST_VAULT_FILE"), nil); !errors.Is(err, ErrNoVaultSecret) {
			t.Fatalf("err = %v, want ErrNoVaultSecret", err)
		}
		return
	}
	if _, err := exec.LookPath("ansible-vault"); err != nil {
		t.Skipf("ansible-vault not installed: %v", err)
	}
	dir := t.TempDir()
	password := filepath.Join(dir, "pw")
	vars := filepath.Join(dir, "vars.yml")
	noConfig := filepath.Join(dir, "ansible.cfg")
	for path, content := range map[string]string{password: "lab-only-vault-password\n", vars: "ipa_admin_password: not-a-real-secret\n", noConfig: ""} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("ansible-vault", "encrypt", "--vault-password-file", password, vars).CombinedOutput(); err != nil {
		t.Fatalf("ansible-vault encrypt (test setup): %v: %s", err, out)
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "ANSIBLE_VAULT_") && !strings.HasPrefix(kv, "ANSIBLE_CONFIG=") {
			env = append(env, kv)
		}
	}
	out, err := ptyChild(t, "TestViewVaultFileAmbientNeverPromptsOnATerminalRealAnsibleVault", append(env,
		"PILOT_TEST_VAULT_FILE="+vars, "ANSIBLE_CONFIG="+noConfig))
	if err != nil || !strings.Contains(out, "--- PASS") {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if strings.Contains(out, "Vault password") {
		t.Fatalf("a prompt reached the terminal:\n%s", out)
	}
}

// --timeout bounds the whole Go preview (spec §2.1), the vault read too.
// These run in a child process so that a regression that stops bounding the
// read fails one test after its own timeout instead of hanging the package.
func TestViewVaultFileAmbientStopsAtTheDeadline(t *testing.T) {
	runIsolated(t, 15*time.Second, func(t *testing.T) {
		bin, vault := fakeVaultBin(t, "exec sleep 60\n")
		withVaultPath(t, bin)
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := ViewVaultFileAmbient(ctx, vault, nil)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
			t.Fatalf("err = %v after %s, want the deadline", err, time.Since(start))
		}
	})
}

// A helper ansible-vault started (a vault password client script) dies with
// it: the whole process group is killed, not only the direct child.
func TestViewVaultFileAmbientKillsTheProcessGroup(t *testing.T) {
	runIsolated(t, 15*time.Second, func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "helper.pid")
		bin, vault := fakeVaultBin(t, "sleep 60 &\necho $! > '"+pidFile+"'\nwait\n")
		withVaultPath(t, bin)
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if _, err := ViewVaultFileAmbient(ctx, vault, nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want the deadline", err)
		}
		data, err := os.ReadFile(pidFile)
		if err != nil {
			t.Fatalf("the helper never started: %v", err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
		for deadline := time.Now().Add(3 * time.Second); processAlive(pid); {
			if time.Now().After(deadline) {
				t.Fatalf("the helper (pid %d) outlived ansible-vault", pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	})
}

// A helper that left the process group and still holds ansible-vault's
// pipes cannot hold the read past the deadline: Wait stops waiting for the
// pipes after a short delay.
func TestViewVaultFileAmbientDoesNotWaitForAnEscapedHelper(t *testing.T) {
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skipf("setsid not installed: %v", err)
	}
	runIsolated(t, 15*time.Second, func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "helper.pid")
		// setsid leaves the group; the helper keeps the inherited stdout.
		bin, vault := fakeVaultBin(t, "setsid sleep 60 &\necho $! > '"+pidFile+"'\nexec sleep 60\n")
		withVaultPath(t, bin)
		t.Cleanup(func() {
			if data, err := os.ReadFile(pidFile); err == nil {
				if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
					_ = syscall.Kill(pid, syscall.SIGKILL)
				}
			}
		})
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := ViewVaultFileAmbient(ctx, vault, nil)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 6*time.Second {
			t.Fatalf("err = %v after %s, want the deadline soon after the wait delay", err, time.Since(start))
		}
	})
}
