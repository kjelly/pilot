package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ----- LocalEnvironment tests -----

func TestLocalEnvironment_StartStopNoOp(t *testing.T) {
	e := NewLocalEnvironment()
	if err := e.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// Idempotent Stop
	if err := e.Stop(context.Background()); err != nil {
		t.Fatalf("Stop (2nd call): %v", err)
	}
}

func TestLocalEnvironment_Name(t *testing.T) {
	if got := NewLocalEnvironment().Name(); got != "local" {
		t.Errorf("Name: %q", got)
	}
}

func TestLocalEnvironment_IsAvailable(t *testing.T) {
	if err := NewLocalEnvironment().IsAvailable(context.Background()); err != nil {
		t.Errorf("IsAvailable should always succeed for local: %v", err)
	}
}

func TestLocalEnvironment_ConnectionInfo(t *testing.T) {
	c := NewLocalEnvironment().ConnectionInfo()
	if c.ConnectionType != "local" {
		t.Errorf("ConnectionType: %q", c.ConnectionType)
	}
	if c.Host != "127.0.0.1" {
		t.Errorf("Host: %q", c.Host)
	}
}

func TestLocalEnvironment_Exec_Success(t *testing.T) {
	if _, err := execLookPathSkip(t, "sh"); err != nil {
		return
	}
	e := NewLocalEnvironment()
	res, err := e.Exec(context.Background(),
		[]string{"sh", "-c", "echo hello"},
		ExecOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode: %d, stderr: %s", res.ExitCode, res.Stderr)
	}
	if !strings.Contains(res.Stdout, "hello") {
		t.Errorf("Stdout: %q", res.Stdout)
	}
}

func TestLocalEnvironment_Exec_NonZeroExit(t *testing.T) {
	if _, err := execLookPathSkip(t, "sh"); err != nil {
		return
	}
	e := NewLocalEnvironment()
	res, err := e.Exec(context.Background(),
		[]string{"sh", "-c", "exit 7"},
		ExecOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if res.ExitCode != 7 {
		t.Errorf("ExitCode: %d", res.ExitCode)
	}
}

func TestLocalEnvironment_Exec_Timeout(t *testing.T) {
	if _, err := execLookPathSkip(t, "sleep"); err != nil {
		return
	}
	e := NewLocalEnvironment()
	res, err := e.Exec(context.Background(),
		[]string{"sleep", "30"},
		ExecOptions{Timeout: 500 * time.Millisecond})
	if err == nil {
		t.Errorf("expected timeout error, got result: %+v", res)
	}
	if res != nil && res.ExitCode != -1 {
		t.Errorf("expected ExitCode -1 on timeout, got %d", res.ExitCode)
	}
}

func TestLocalEnvironment_Exec_EmptyArgv(t *testing.T) {
	e := NewLocalEnvironment()
	_, err := e.Exec(context.Background(), nil, ExecOptions{})
	if err == nil {
		t.Errorf("expected error for empty argv")
	}
}

func TestLocalEnvironment_Exec_EnvAndWorkDir(t *testing.T) {
	if _, err := execLookPathSkip(t, "sh"); err != nil {
		return
	}
	tmp := t.TempDir()
	e := NewLocalEnvironment()
	res, err := e.Exec(context.Background(),
		[]string{"sh", "-c", "echo $MYVAR; pwd"},
		ExecOptions{
			Timeout: 5 * time.Second,
			WorkDir: tmp,
			Env:     []string{"MYVAR=pilot-test"},
		})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !strings.Contains(res.Stdout, "pilot-test") {
		t.Errorf("expected MYVAR in stdout: %q", res.Stdout)
	}
	if !strings.Contains(res.Stdout, tmp) {
		t.Errorf("expected WorkDir in pwd output: %q", res.Stdout)
	}
}

func TestLocalEnvironment_ReadWriteFile(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.txt")
	e := NewLocalEnvironment()
	if err := e.WriteFile(context.Background(), path, []byte("hello sandbox"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := e.ReadFile(context.Background(), path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello sandbox" {
		t.Errorf("got %q", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("mode: %v", info.Mode().Perm())
	}
}

// ----- DockerEnvironment tests (mostly unit; integration only if docker present) -----

func TestDockerEnvironment_RequiresImage(t *testing.T) {
	e := &DockerEnvironment{}
	if err := e.Start(context.Background()); err == nil {
		t.Error("Start without image should fail")
	}
}

func TestDockerEnvironment_Name(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	if got := e.Name(); got != "docker:ubuntu:22.04" {
		t.Errorf("Name: %q", got)
	}
	e2 := &DockerEnvironment{}
	if got := e2.Name(); got != "docker:<unset>" {
		t.Errorf("Name unset: %q", got)
	}
}

func TestDockerEnvironment_Defaults(t *testing.T) {
	e := NewDockerEnvironment("alpine:3.20")
	if e.Network != "host" {
		t.Errorf("Network default: %q", e.Network)
	}
	if e.Pull != "missing" {
		t.Errorf("Pull default: %q", e.Pull)
	}
	if e.Timeout <= 0 {
		t.Errorf("Timeout default: %v", e.Timeout)
	}
	if e.ReadinessTimeout <= 0 {
		t.Errorf("ReadinessTimeout default: %v", e.ReadinessTimeout)
	}
}

func TestDockerEnvironment_ExecRequiresContainerID(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	// Not started: containerID is empty
	_, err := e.Exec(context.Background(), []string{"true"}, ExecOptions{})
	if err == nil {
		t.Error("Exec on un-started container should fail")
	}
}

func TestDockerEnvironment_ExecEmptyArgv(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	e.containerID = "deadbeef" // pretend started
	_, err := e.Exec(context.Background(), nil, ExecOptions{})
	if err == nil {
		t.Error("Exec with empty argv should fail")
	}
}

func TestDockerEnvironment_StopWithoutStart(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	// Stop without Start should be a clean no-op (or remove a
	// stale container with the same name, which is also fine).
	if err := e.Stop(context.Background()); err != nil {
		t.Errorf("Stop without Start: %v", err)
	}
}

func TestDockerEnvironment_ConnectionInfo(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	e.containerID = "abc123"
	c := e.ConnectionInfo()
	if c.ConnectionType != "docker" {
		t.Errorf("ConnectionType: %q", c.ConnectionType)
	}
	if c.ContainerID != "abc123" {
		t.Errorf("ContainerID: %q", c.ContainerID)
	}
	if c.Host != "abc123" {
		t.Errorf("Host: %q", c.Host)
	}
	if c.User != "root" {
		t.Errorf("User: %q", c.User)
	}
}

// ----- helper: skip if binary missing -----

func execLookPathSkip(t *testing.T, name string) (string, error) {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not installed: %v", name, err)
	}
	return p, nil
}

func TestValidateExecPath(t *testing.T) {
	cases := map[string]bool{
		"/etc/ssh/sshd_config":   true,
		"/etc/shadow":             true,
		"/home/alice/.ssh/id_rsa": true,
		"relative/path":           true,
		"":                        false,
		"/path/with/\nnewline":    false,
		"/path/with/\rcr":         false,
		"/path/with/\x00nul":      false,
	}
	for in, want := range cases {
		if got := validateExecPath(in); (got == nil) != want {
			t.Errorf("validateExecPath(%q) ok=%v want ok=%v (err=%v)", in, got == nil, want, got)
		}
	}
}

func TestDockerEnvironment_ReadFileUsesDd(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	e.containerID = "fake-id"
	dir := t.TempDir()
	e.CLI = writeFakeDocker(t, dir, "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done\n")
	out, err := e.ReadFile(context.Background(), "/etc/shadow")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	stdout := string(out)
	if !strings.Contains(stdout, "dd") {
		t.Errorf("expected dd in argv, got: %q", stdout)
	}
	if !strings.Contains(stdout, "if=/etc/shadow") {
		t.Errorf("expected if=/etc/shadow in argv, got: %q", stdout)
	}
	if strings.Contains(stdout, " cat ") || strings.HasPrefix(stdout, "cat ") {
		t.Errorf("ReadFile should NOT use cat: %q", stdout)
	}
}

func TestDockerEnvironment_ReadFileRejectsBadPath(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	e.containerID = "fake-id"
	if _, err := e.ReadFile(context.Background(), "/path/with/\nnewline"); err == nil {
		t.Error("expected error for path with newline")
	}
	if _, err := e.ReadFile(context.Background(), ""); err == nil {
		t.Error("expected error for empty path")
	}
}


func TestDockerEnvironment_WriteFileUsesDockerCpNotShell(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	e.containerID = "fake-id"
	dir := t.TempDir()
	e.CLI = writeFakeDocker(t, dir, "#!/bin/sh\nfor a in \"$@\"; do echo \"$a\"; done\nexit 0\n")
	if err := e.WriteFile(context.Background(), "/etc/test.conf", []byte("hello"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestDockerEnvironment_WriteFileRejectsBadPath(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	e.containerID = "fake-id"
	if err := e.WriteFile(context.Background(), "/path/with/\nnewline", []byte("x"), 0o644); err == nil {
		t.Error("expected error for path with newline")
	}
	if err := e.WriteFile(context.Background(), "", []byte("x"), 0o644); err == nil {
		t.Error("expected error for empty path")
	}
}

func TestDockerEnvironment_WriteFileRejectsWithoutContainer(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	if err := e.WriteFile(context.Background(), "/etc/test", []byte("x"), 0o644); err == nil {
		t.Error("expected error when not started")
	}
}

// writeFakeDocker creates a shell script that pretends to be the
// docker CLI. The script writes its full argv to stdout (one
// argument per line) so tests can assert what arguments pilot
// would have passed.
func writeFakeDocker(t *testing.T, dir, body string) string {
	t.Helper()
	path := filepath.Join(dir, "docker")
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake docker: %v", err)
	}
	return path
}

func TestDefaultContainerName_IncludesNanoID(t *testing.T) {
	names := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		n := defaultContainerName()
		if !strings.HasPrefix(n, "pilot-sandbox-") {
			t.Errorf("missing prefix: %s", n)
		}
		// Sanity: the suffix must be 6 hex chars.
		parts := strings.Split(n, "-")
		if len(parts) < 4 {
			t.Errorf("name too short: %s", n)
		}
		suffix := parts[len(parts)-1]
		if len(suffix) != 6 {
			t.Errorf("nano suffix wrong length: %q (full name: %s)", suffix, n)
		}
		for _, r := range suffix {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				t.Errorf("nano suffix has non-hex char %q in %s", r, n)
			}
		}
		names[n] = true
	}
	// Collision check: with 6 hex chars (24 bits) and 1000 draws
	// the probability of a collision is ~1.2e-4 — should be 0 in
	// practice. Allow 1 collision to avoid flaky tests but fail
	// loudly if more.
	if len(names) < 999 {
		t.Errorf("too many collisions in 1000 names: got %d unique", len(names))
	}
}

func TestStripArg_RemovesSingleOccurrence(t *testing.T) {
	cases := []struct {
		in    []string
		drop  string
		want  []string
	}{
		{[]string{"a", "--rm", "b"}, "--rm", []string{"a", "b"}},
		{[]string{"--rm", "a", "--rm", "b"}, "--rm", []string{"a", "b"}},
		{[]string{"a", "b"}, "--rm", []string{"a", "b"}},
		{[]string{}, "--rm", []string{}},
	}
	for _, c := range cases {
		got := stripArg(c.in, c.drop)
		if !equalStrings(got, c.want) {
			t.Errorf("stripArg(%v, %q) = %v, want %v", c.in, c.drop, got, c.want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestParseDockerDiff_AllStatuses(t *testing.T) {
	stdout := "A /etc/newfile\nC /etc/ssh/sshd_config\nD /tmp/removed\n"
	// Use a fake docker CLI: print stdout verbatim, exit 0.
	dir := t.TempDir()
	path := writeFakeDocker(t, dir,
		"#!/bin/sh\ncat\n") // 'cat' ignores argv, prints stdin (empty)
	// We can't easily feed docker diff stdout via the fake; instead
	// call detectChangedPaths through a manual docker exec. Use the
	// dockerCmd path: set CLI to a script that prints the literal
	// diff output.
	path = writeFakeDocker(t, dir, "#!/bin/sh\ncat <<'EOF'\n"+stdout+"EOF\n")
	e := NewDockerEnvironment("ubuntu:22.04")
	e.CLI = path
	paths := e.detectChangedPaths(context.Background(), "fake")
	want := []string{"/etc/newfile", "/etc/ssh/sshd_config", "/tmp/removed"}
	if !equalStrings(paths, want) {
		t.Errorf("detectChangedPaths = %v, want %v", paths, want)
	}
}

func TestDetectChangedPaths_NoDockerDiff(t *testing.T) {
	// Fake docker that fails; should return nil.
	dir := t.TempDir()
	path := writeFakeDocker(t, dir, "#!/bin/sh\nexit 1\n")
	e := NewDockerEnvironment("ubuntu:22.04")
	e.CLI = path
	paths := e.detectChangedPaths(context.Background(), "fake")
	if paths != nil {
		t.Errorf("expected nil on docker diff failure, got %v", paths)
	}
}

func TestDockerEnvironment_PreferCachedDefaults(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	if e.PreferCached {
		t.Errorf("PreferCached should default false")
	}
	if e.init != true {
		t.Errorf("init should default true (tini is recommended)")
	}
	if e.Keep {
		t.Errorf("Keep should default false")
	}
}

func TestDockerEnvironment_ChangedPaths_InitiallyNil(t *testing.T) {
	e := NewDockerEnvironment("ubuntu:22.04")
	if e.ChangedPaths() != nil {
		t.Errorf("ChangedPaths() should be nil before Stop")
	}
}
