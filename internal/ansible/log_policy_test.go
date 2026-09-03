package ansible

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRedactSecrets(t *testing.T) {
	raw := `password: hunter2 token=abc123 api_key: "key value" --secret cli-secret`
	got := RedactSecrets(raw)
	for _, secret := range []string{"hunter2", "abc123", "key value", "cli-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("RedactSecrets leaked %q: %q", secret, got)
		}
	}
	if !strings.Contains(got, "password: [REDACTED]") || !strings.Contains(got, "token= [REDACTED]") {
		t.Fatalf("RedactSecrets did not preserve the key and redact its value: %q", got)
	}
}

func TestMaintainLogRedactsRotatesAndRestrictsPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	if err := os.WriteFile(path, []byte("password: first-secret\nordinary line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	policy := LogPolicy{MaxBytes: 10, MaxFiles: 2}
	if err := MaintainLogWithPolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("active log mode = %o, want 600", info.Mode().Perm())
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rotated), "first-secret") {
		t.Fatalf("rotated log leaked secret: %q", rotated)
	}
	if info, err := os.Stat(path + ".1"); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rotated log mode = %v, want 600", info)
	}
}

// TestRedactFile_LeavesNoTempFileOnSuccess locks the happy path: a
// successful redact must rename its temp file away, not merely rely on
// its own defer os.Remove (which never runs if the process is killed
// before returning — the exact scenario that leaked 436 orphaned
// .ansible-log-redacted-* files / 76 GB in production before this fix).
func TestRedactFile_LeavesNoTempFileOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	if err := os.WriteFile(path, []byte("password: secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := redactFile(path); err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, logRedactedTempPrefix+"-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("redactFile left temp files behind: %v", matches)
	}
}

// TestSweepStaleLogTemp_RemovesOnlyDeadPIDOrphans is the regression lock
// for the leak itself: a temp file named after a PID that has since
// exited (the SIGKILL-orphan case) must be swept, but one named after a
// still-live PID (a peer's legitimate in-flight write, or this process's
// own) must never be touched — the whole reason the old scheme used a
// random suffix instead of something sweepable was that nothing could
// tell those two cases apart. Naming by PID plus a liveness check is what
// makes safe, unattended cleanup possible.
func TestSweepStaleLogTemp_RemovesOnlyDeadPIDOrphans(t *testing.T) {
	dir := t.TempDir()

	dead := deadPIDForTest(t)
	orphan := filepath.Join(dir, logRedactedTempPrefix+"-"+strconv.Itoa(dead))
	if err := os.WriteFile(orphan, []byte("leaked"), 0o600); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(dir, logRedactedTempPrefix+"-"+strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(live, []byte("in-flight"), 0o600); err != nil {
		t.Fatal(err)
	}

	sweepStaleLogTemp(dir, logRedactedTempPrefix)

	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Fatalf("orphan from dead pid %d was not swept: stat err=%v", dead, err)
	}
	if _, err := os.Stat(live); err != nil {
		t.Fatalf("live (self) pid's temp file was incorrectly removed: %v", err)
	}
}

func deadPIDForTest(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run throwaway process: %v", err)
	}
	return cmd.Process.Pid
}

func TestMaintainLogFromEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	if err := os.WriteFile(path, []byte("secret: value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogFromEnv([]string{"ANSIBLE_LOG_PATH=" + path}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "value") {
		t.Fatalf("log still contains secret: %q", data)
	}
}
