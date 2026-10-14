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

// Redacting twice must not change an already-redacted line. It did: the
// value pattern stops before "]", so "password: [REDACTED]" became
// "password: [REDACTED]]", and because the whole log was redacted after
// every Ansible run, masked values in the controller log grew by one
// bracket per run (issue #70).
func TestRedactSecretsIsIdempotent(t *testing.T) {
	for _, raw := range []string{
		"password: hunter2",
		"token=abc123",
		`"api_key": "key value"`,
		`{"vault_password": 'x', "other": 1}`,
		"--secret cli-secret --password=p",
		"ordinary line",
	} {
		once := RedactSecrets(raw)
		if twice := RedactSecrets(once); twice != once {
			t.Errorf("RedactSecrets(%q): once %q, twice %q", raw, once, twice)
		}
	}
	// Values that earlier versions grew by one bracket per pass are left
	// as they are, not rewritten.
	for _, masked := range []string{"password: [REDACTED]", "token= [REDACTED]]", `"secret": [REDACTED]]]], "other": 1`} {
		if got := RedactSecrets(masked); got != masked {
			t.Errorf("RedactSecrets(%q) = %q, want it unchanged", masked, got)
		}
	}
	// A full pass over an already-redacted log leaves it unchanged.
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("password: hunter2\ntoken=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := redactFile(path); err != nil {
		t.Fatal(err)
	}
	first := readLog(t, path)
	if err := redactFile(path); err != nil {
		t.Fatal(err)
	}
	if second := readLog(t, path); second != first {
		t.Fatalf("second pass changed the log: %q -> %q", first, second)
	}
}

// Only the marker itself counts as already masked. A value that merely
// starts like it is a value, and is masked (PR #71 review).
func TestRedactSecretsMasksMarkerLookalikes(t *testing.T) {
	for raw, want := range map[string]string{
		"password: [REDACTED-synthetic-marker-secret": "password: [REDACTED]",
		"token=[REDACTEDsynthetic":                    "token= [REDACTED]",
		"api_key: [REDACTED]synthetic-glued":          "api_key: [REDACTED]",
		"secret: [REDACTED]]]synthetic-after-legacy":  "secret: [REDACTED]",
		"password: [redacted]":                        "password: [REDACTED]",
	} {
		if got := RedactSecrets(raw); got != want {
			t.Errorf("RedactSecrets(%q) = %q, want %q", raw, got, want)
		}
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

func appendLog(t *testing.T, path, text string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func readLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func sameInode(t *testing.T, a os.FileInfo, path string) bool {
	t.Helper()
	b, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return os.SameFile(a, b)
}

// Issue #70: maintenance after each Ansible run must cost what was appended,
// not the size of the whole log. A run that finds nothing to mask leaves the
// file alone, and content before the recorded offset is never scanned again:
// a "secret" planted there after maintenance (same inode, same size) stays,
// which shows the old part was not reread.
func TestMaintainLogScansOnlyAppendedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	policy := DefaultLogPolicy()
	old := strings.Repeat("ordinary line from an earlier run\n", 2000)
	if err := os.WriteFile(path, []byte(old+"password: early-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); strings.Contains(got, "early-secret") || !strings.HasPrefix(got, old) {
		t.Fatal("first maintenance must redact the whole file and keep the rest")
	}

	// Nothing new to mask: the file is not rewritten.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	appendLog(t, path, "another ordinary line\n")
	if err := MaintainLogWithPolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	if !sameInode(t, before, path) {
		t.Fatal("maintenance rewrote the log although nothing new needed masking")
	}

	// Plant a secret inside the already-redacted part, then append a clean
	// line: the planted text is not reread.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("token=planted"), 0); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	appendLog(t, path, "a clean line\n")
	if err := MaintainLogWithPolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(readLog(t, path), "token=planted") {
		t.Fatal("maintenance rescanned content before the recorded offset")
	}

	// Should trigger: a secret appended later is still masked, and the
	// planted prefix is copied unchanged when the file is rewritten.
	appendLog(t, path, "api_key: late-secret\n")
	if err := MaintainLogWithPolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	got := readLog(t, path)
	if strings.Contains(got, "late-secret") || !strings.Contains(got, "api_key: [REDACTED]") {
		t.Fatalf("appended secret not redacted: %q", got[len(got)-80:])
	}
	if !strings.HasPrefix(got, "token=planted") {
		t.Fatal("rewrite changed the already-redacted prefix")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("log mode after rewrite = %v, %v", info, err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, logRedactedTempPrefix+"-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temp files left behind: %v %v", matches, err)
	}
	if info, err := os.Stat(redactionStatePath(path)); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("redaction state = %v, %v; want a 0600 file", info, err)
	}
}

// A line still being written (no newline yet) is judged only once it is
// complete, so a secret split across two writes is masked.
func TestMaintainLogWaitsForCompleteLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("ordinary\npass"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	appendLog(t, path, "word: split-secret\n")
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); got != "ordinary\npassword: [REDACTED]\n" {
		t.Fatalf("log = %q", got)
	}
}

// maintainTwice runs maintenance twice and requires the second run to leave
// the log as the first one did.
func maintainTwice(t *testing.T, path string) string {
	t.Helper()
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	first := readLog(t, path)
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	if second := readLog(t, path); second != first {
		t.Fatalf("second maintenance changed the log: %q -> %q", first, second)
	}
	return first
}

// Maintenance runs after Ansible exits, so a final line without its newline
// may never be completed. It is masked now, and stays masked; if a writer
// does complete it later, the line is judged whole again, so the rest of a
// secret split across the two writes is masked too (PR #71 review).
func TestMaintainLogMasksAFinalLineWithoutNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("ordinary\npassword: synthetic-eof-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := maintainTwice(t, path); got != "ordinary\npassword: [REDACTED]" {
		t.Fatalf("log = %q", got)
	}
	appendLog(t, path, "-synthetic-continued\nnext line\n")
	if got := maintainTwice(t, path); got != "ordinary\npassword: [REDACTED]\nnext line\n" {
		t.Fatalf("log = %q", got)
	}
}

// The same for a private key whose last line has no newline.
func TestMaintainLogMasksAFinalPrivateKeyLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsynthetic-first\nAAAAsynthetic-eof"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := maintainTwice(t, path); strings.Contains(got, "AAAA") {
		t.Fatalf("log = %q", got)
	}
	appendLog(t, path, "-rest\nAAAAsynthetic-more\n-----END OPENSSH PRIVATE KEY-----\nafter the key\n")
	got := maintainTwice(t, path)
	if strings.Contains(got, "AAAA") || strings.Contains(got, "-rest") || !strings.HasSuffix(got, "]\nafter the key\n") {
		t.Fatalf("log = %q", got)
	}
}

// A key logged on one line (a JSON string with escaped newlines) that is cut
// after its BEGIN marker: the rest of the key, written later, is masked.
func TestMaintainLogMasksTheRestOfACutOneLineKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(`{"key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEsynthetic-first`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := maintainTwice(t, path); strings.Contains(got, "MIIE") {
		t.Fatalf("log = %q", got)
	}
	appendLog(t, path, `MIIEsynthetic-second\n-----END RSA PRIVATE KEY-----\n"}`+"\nafter the key\n")
	if got := maintainTwice(t, path); got != "[REDACTED PRIVATE KEY]\nafter the key\n" {
		t.Fatalf("log = %q", got)
	}
}

// A key's END marker cut before its newline is not secret and is left as
// is: masking it would hide the marker and every later line would be read
// as key material.
func TestMaintainLogKeepsAHalfWrittenEndMarker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsynthetic\n-----END OPENSSH PRIV"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := maintainTwice(t, path); strings.Contains(got, "AAAA") || !strings.HasSuffix(got, "\n-----END OPENSSH PRIV") {
		t.Fatalf("log = %q", got)
	}
	appendLog(t, path, "ATE KEY-----\nafter the key\n")
	if got := maintainTwice(t, path); strings.Contains(got, "AAAA") || !strings.HasSuffix(got, "]\nafter the key\n") {
		t.Fatalf("log = %q", got)
	}
}

// A private key block that spans two maintenance runs is masked to its end.
func TestMaintainLogKeepsPrivateKeyStateAcrossRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAfirst\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	appendLog(t, path, "AAAAsecond\n-----END OPENSSH PRIVATE KEY-----\nafter the key\n")
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	got := readLog(t, path)
	if strings.Contains(got, "AAAA") || !strings.HasSuffix(got, "after the key\n") {
		t.Fatalf("log = %q", got)
	}
}

// A replaced log (rotation, trimming, an operator's copy) does not match the
// recorded file identity, so it is redacted in full; so is a log whose
// record says it is longer than it is.
func TestMaintainLogRedactsAReplacedLogInFull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	replacement := path + ".new"
	if err := os.WriteFile(replacement, []byte("ordinary\nsecret: replaced-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); strings.Contains(got, "replaced-file") {
		t.Fatalf("replaced log not redacted: %q", got)
	}

	// Truncated in place below the recorded offset.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendLog(t, path, "token: after-truncate\n")
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); strings.Contains(got, "after-truncate") {
		t.Fatalf("truncated log not redacted: %q", got)
	}
}

// Rotation, trimming and truncation start a new active log, so the record
// is dropped. Today trimFileToTail replaces the inode before truncateLog
// runs, which already invalidates the record; dropping it keeps the result
// right even if truncateLog (same inode) ran alone, where a log that grew
// past the old offset would otherwise have its start skipped.
func TestMaintainLogResetsStateWhenItTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary\n", 4)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, LogPolicy{MaxBytes: 10, MaxFiles: 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(redactionStatePath(path)); !os.IsNotExist(err) {
		t.Fatalf("redaction state kept after truncation: %v", err)
	}
	// The secret sits where the old offset would have skipped it.
	appendLog(t, path, "password: after-truncation\n"+strings.Repeat("ordinary\n", 10))
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	if got := readLog(t, path); strings.Contains(got, "after-truncation") {
		t.Fatalf("log not redacted after truncation: %q", got)
	}
}
