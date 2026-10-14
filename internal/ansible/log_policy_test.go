package ansible

import (
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
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
		"password=abc]def",
		"password:[REDACTED]--password p",
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
// starts like it is a value, and is masked (PR #71 review). Text after the
// marker's closing bracket is not part of the value and is judged by the
// other rules, as on main: a flag glued to it is still masked.
func TestRedactSecretsMasksMarkerLookalikes(t *testing.T) {
	for raw, want := range map[string]string{
		"password: [REDACTED-synthetic-marker-secret":         "password: [REDACTED]",
		"token=[REDACTEDsynthetic":                            "token= [REDACTED]",
		"password: [redacted]":                                "password: [REDACTED]]",
		"password:[REDACTED]--password synthetic-flag-secret": "password:[REDACTED]--password [REDACTED]",
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

// scanStarts returns where maintenance started scanning during f.
func scanStarts(t *testing.T, f func()) []int64 {
	t.Helper()
	var starts []int64
	redactRangeStarts = func(offset int64) { starts = append(starts, offset) }
	defer func() { redactRangeStarts = nil }()
	f()
	return starts
}

func maintain(t *testing.T, path string) {
	t.Helper()
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

// Issue #70: maintenance after each Ansible run must cost what was appended,
// not the size of the whole log. A run that finds nothing to mask leaves the
// file alone, and the regex scan starts where the previous run stopped; the
// part before it is only hashed and copied.
func TestMaintainLogScansOnlyAppendedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	old := strings.Repeat("ordinary line from an earlier run\n", 2000)
	if err := os.WriteFile(path, []byte(old+"password: early-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if starts := scanStarts(t, func() { maintain(t, path) }); len(starts) == 0 || starts[0] != 0 {
		t.Fatalf("first maintenance scan starts = %v, want the whole file", starts)
	}
	if got := readLog(t, path); strings.Contains(got, "early-secret") || !strings.HasPrefix(got, old) {
		t.Fatal("first maintenance must redact the whole file and keep the rest")
	}

	// Nothing new to mask: only the appended line is scanned, and the file
	// is not rewritten.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	appendLog(t, path, "another ordinary line\n")
	if starts := scanStarts(t, func() { maintain(t, path) }); len(starts) != 1 || starts[0] != before.Size() {
		t.Fatalf("scan starts = %v, want [%d]", starts, before.Size())
	}
	if !sameInode(t, before, path) {
		t.Fatal("maintenance rewrote the log although nothing new needed masking")
	}

	// Should trigger: a secret appended later is masked, again scanning
	// only from the end of the previous run, and the rest is kept.
	cleanEnd := fileSize(t, path)
	appendLog(t, path, "api_key: late-secret\n")
	for _, start := range scanStarts(t, func() { maintain(t, path) }) {
		if start != cleanEnd {
			t.Fatalf("scan started at %d, want %d", start, cleanEnd)
		}
	}
	got := readLog(t, path)
	if strings.Contains(got, "late-secret") || !strings.HasSuffix(got, "another ordinary line\napi_key: [REDACTED]\n") {
		t.Fatalf("appended secret not redacted: %q", got[len(got)-80:])
	}
	if !strings.HasPrefix(got, old) {
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

	// Nothing appended: nothing is scanned.
	if starts := scanStarts(t, func() { maintain(t, path) }); len(starts) != 0 {
		t.Fatalf("scan starts = %v with nothing appended", starts)
	}
}

// rewriteInPlace replaces the log's content through O_TRUNC, keeping the
// inode, as "> file" or logrotate's copytruncate do.
func rewriteInPlace(t *testing.T, path, content string) {
	t.Helper()
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if !sameInode(t, before, path) {
		t.Fatal("test setup: the rewrite replaced the inode")
	}
}

// The record must not outlive the content it describes (PR #71 review). A
// log truncated in place keeps its device and inode; once it has grown back
// past the recorded offset, only the bytes it holds show that its start is
// new and was never scanned.
func TestMaintainLogRedactsALogTruncatedAndRegrown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line before the truncation\n", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	oldSize := fileSize(t, path)
	rewriteInPlace(t, path, "password: synthetic-regrown-secret\n"+strings.Repeat("ordinary line after the truncation\n", 64))
	if fileSize(t, path) <= oldSize {
		t.Fatal("test setup: the regrown log must be longer than the old one")
	}
	if got := maintainTwice(t, path); strings.Contains(got, "synthetic-regrown-secret") {
		t.Fatalf("regrown log not redacted: %q", got[:80])
	}
}

// Grown back to exactly the old size, the log takes the "nothing appended"
// path, which must check the content too.
func TestMaintainLogRedactsALogRegrownToItsOldSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	original := strings.Repeat("ordinary line before the truncation\n", 32)
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	regrown := "password: synthetic-same-size-secret\n"
	regrown += strings.Repeat("x", len(original)-len(regrown)-1) + "\n"
	rewriteInPlace(t, path, regrown)
	if fileSize(t, path) != int64(len(original)) {
		t.Fatal("test setup: the regrown log must have the old size")
	}
	if got := maintainTwice(t, path); strings.Contains(got, "synthetic-same-size-secret") {
		t.Fatalf("regrown log not redacted: %q", got[:80])
	}
}

// A log deleted and recreated whose new inode gets the old number. The
// filesystem decides whether a number is reused, so the record is pointed
// at the new file instead, which is what such a reuse looks like.
func TestMaintainLogRedactsARecreatedLogWithTheOldInodeNumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line in the first file\n", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("token=synthetic-recreated-secret\n"+strings.Repeat("ordinary line in the second file\n", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	state := loadRedactionState(path)
	if state.Offset == 0 {
		t.Fatal("test setup: no record from the first file")
	}
	state.Device, state.Inode, _ = fileIdentity(info)
	if err := saveRedactionState(path, state); err != nil {
		t.Fatal(err)
	}
	if got := maintainTwice(t, path); strings.Contains(got, "synthetic-recreated-secret") {
		t.Fatalf("recreated log not redacted: %q", got[:80])
	}
}

// Bytes before the recorded offset overwritten in place, without a change of
// size, then a clean line appended; and the same with nothing appended.
func TestMaintainLogRedactsAPrefixOverwrittenInPlace(t *testing.T) {
	for _, appended := range []string{"a clean line\n", ""} {
		path := filepath.Join(t.TempDir(), "ansible.log")
		if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line from an earlier run\n", 32)), 0o600); err != nil {
			t.Fatal(err)
		}
		maintain(t, path)
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt([]byte("token=synthetic-planted"), 34); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if appended != "" {
			appendLog(t, path, appended)
		}
		if got := maintainTwice(t, path); strings.Contains(got, "synthetic-planted") {
			t.Fatalf("appended %q: overwritten prefix not redacted: %q", appended, got[:120])
		}
	}
}

// A record written before the prefix hash existed is not trusted: the next
// run redacts the whole file once, then works from the new record.
func TestMaintainLogRedactsInFullOnceForARecordWithoutAHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary\n", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	state := loadRedactionState(path)
	state.PrefixSHA256 = ""
	if err := saveRedactionState(path, state); err != nil {
		t.Fatal(err)
	}
	appendLog(t, path, "ordinary\n")
	if starts := scanStarts(t, func() { maintain(t, path) }); len(starts) != 1 || starts[0] != 0 {
		t.Fatalf("scan starts = %v, want one full pass", starts)
	}
	size := fileSize(t, path)
	appendLog(t, path, "ordinary\n")
	if starts := scanStarts(t, func() { maintain(t, path) }); len(starts) != 1 || starts[0] != size {
		t.Fatalf("scan starts = %v, want [%d]", starts, size)
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
// may never be completed. It is masked now, and stays masked (PR #71
// review). When something is appended later, for example the next run's
// first record, the line is judged again as a whole, as a full pass would
// judge it.
func TestMaintainLogMasksAFinalLineWithoutNewline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("ordinary\npassword: synthetic-eof-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := maintainTwice(t, path); got != "ordinary\npassword: [REDACTED]" {
		t.Fatalf("log = %q", got)
	}
	appendLog(t, path, testRecord("PLAY [next run]")+"\n")
	if got, want := maintainTwice(t, path), "ordinary\npassword: [REDACTED]"+testRecord("PLAY [next run]")+"\n"; got != want {
		t.Fatalf("log = %q, want %q", got, want)
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

// testRecordPrefix is the record prefix ansible-core 2.19.2 writes, taken
// from a real controller log line (pid and user changed).
const testRecordPrefix = "2026-09-15 09:50:37,791 p=4242 u=pilot n=ansible INFO| "

func testRecord(message string) string {
	return testRecordPrefix + message
}

// A key whose END marker never comes must not mask the rest of the log
// (PR #71 review): it used to mask every later line, in that run and every
// later one. Key material never starts with an Ansible record prefix, so the
// next record ends it.
func TestMaintainLogEndsAnUnfinishedKeyAtTheNextRecord(t *testing.T) {
	for name, tc := range map[string]struct{ log, completion string }{
		"BEGIN marker quoted in a command": {
			log: testRecord(`changed: [h] => {"cmd": "grep -q -- '-----BEGIN RSA PRIVATE KEY-----' /etc/x"}`) + "\n",
		},
		"run killed mid-key": {
			log: testRecord("ok: [h] => ") + "\n-----BEGIN OPENSSH PRIVATE KEY-----\nsynthkeyline\nsynthkeyl",
		},
		"one-line key cut inside its END marker": {
			log:        testRecord(`ok: [h] => {"key": "-----BEGIN RSA PRIVATE KEY-----\nsynthkeyline\n-----END RSA PRIV`),
			completion: `ATE KEY-----\n"}` + "\n",
		},
		"indented key cut inside its END marker": {
			log:        testRecord("ok: [h] => ") + "\n    -----BEGIN RSA PRIVATE KEY-----\n    synthkeyline\n    -----END RSA PRIV",
			completion: "ATE KEY-----\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ansible.log")
			if err := os.WriteFile(path, []byte(tc.log), 0o600); err != nil {
				t.Fatal(err)
			}
			maintainTwice(t, path)
			if tc.completion != "" {
				appendLog(t, path, tc.completion)
				maintainTwice(t, path)
			}
			appendLog(t, path, testRecord("ok: [h] => synthetic-visible-after")+"\n"+testRecord("PLAY RECAP")+"\n")
			got := maintainTwice(t, path)
			if strings.Contains(got, "synthkey") || !strings.Contains(got, "synthetic-visible-after") || !strings.Contains(got, "PLAY RECAP") {
				t.Fatalf("log = %q", got)
			}
		})
	}
}

// A key logged one line per record keeps the key state: a record whose
// whole message could be key material does not end it.
func TestMaintainLogMasksAKeyLoggedOneRecordPerLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	log := testRecord("-----BEGIN RSA PRIVATE KEY-----") + "\n" +
		testRecord("MIIEsyntheticPerRecordKeyLine0123456789abcdef") + "\n" +
		testRecord("Hw==") + "\n" +
		testRecord("-----END RSA PRIVATE KEY-----") + "\n" +
		testRecord("ok: [h] => synthetic-visible-after") + "\n"
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	got := maintainTwice(t, path)
	if strings.Contains(got, "MIIEsynthetic") || strings.Contains(got, "Hw==") || !strings.Contains(got, "synthetic-visible-after") {
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

// logFiles returns the active log and every retained log next to it.
func logFiles(t *testing.T, path string) map[string]string {
	t.Helper()
	files := map[string]string{}
	for _, name := range []string{path, path + ".1", path + ".2", path + ".3"} {
		data, err := os.ReadFile(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(data)
	}
	return files
}

// Rotation must not copy a byte it did not scan (PR #71 review). Ansible
// keeps its log open for the whole run; when maintenance did not rewrite the
// log, such a writer was still attached, and what it appended after the
// scan was copied into path.1 as it was, where nothing scans it again.
func TestMaintainLogRotationKeepsNoBytesItDidNotScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line before the rotation\n", 250)), 0o600); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	// Every scan is preceded by a write through the open file.
	writes := 0
	redactRangeStarts = func(int64) {
		writes++
		if _, err := fmt.Fprintf(writer, "password: synthetic-window-secret-%d\n", writes); err != nil {
			t.Error(err)
		}
	}
	defer func() { redactRangeStarts = nil }()
	policy := LogPolicy{MaxBytes: 4096, MaxFiles: 2}
	for run := 0; run < 2; run++ {
		if err := MaintainLogWithPolicy(path, policy); err != nil {
			t.Fatal(err)
		}
	}
	if writes == 0 {
		t.Fatal("test setup: nothing was written during maintenance")
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("test setup: no rotation: %v", err)
	}
	for name, content := range logFiles(t, path) {
		if strings.Contains(content, "synthetic-window-secret") {
			t.Errorf("%s keeps a secret written during maintenance", filepath.Base(name))
		}
	}
}

// The same with a writer that starts appending a secret every 200 µs, as
// maintenance starts to scan, through a file it opened before, while a
// 512 KiB log rotates. After that maintenance no retained log may hold one, and
// after the writer stops and one more maintenance, no file at all.
func TestMaintainLogRotationUnderAConcurrentWriter(t *testing.T) {
	defer func() { redactRangeStarts = nil }()
	for round := 0; round < 3; round++ {
		path := filepath.Join(t.TempDir(), "ansible.log")
		if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line before the rotation, padded to 64 bytes.........\n", 512<<10/64)), 0o600); err != nil {
			t.Fatal(err)
		}
		writer, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		stop, done := make(chan struct{}), make(chan struct{})
		write := func() {
			defer close(done)
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = fmt.Fprintf(writer, "password: synthetic-live-%d\n", n)
				time.Sleep(200 * time.Microsecond)
			}
		}
		started := false
		redactRangeStarts = func(int64) {
			if !started {
				started = true
				go write()
			}
		}
		if err := MaintainLogWithPolicy(path, LogPolicy{MaxBytes: 256 << 10, MaxFiles: 2}); err != nil {
			t.Fatal(err)
		}
		redactRangeStarts = nil
		for name, content := range logFiles(t, path) {
			if name != path && strings.Contains(content, "synthetic-live-") {
				t.Errorf("round %d: %s keeps %d secrets the writer appended", round, filepath.Base(name), strings.Count(content, "synthetic-live-"))
			}
		}
		if !started {
			t.Fatal("test setup: the writer never started")
		}
		close(stop)
		<-done
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		maintain(t, path)
		for name, content := range logFiles(t, path) {
			if strings.Contains(content, "synthetic-live-") {
				t.Errorf("round %d: %s keeps a secret after the final maintenance", round, filepath.Base(name))
			}
		}
	}
}

// Rotation itself redacts what it keeps: bytes a still-attached writer
// appended after the last scan are masked in path.1, and what the writer
// appends after the rotation reaches no file that is kept.
func TestRotateRedactedRedactsBytesAppendedAfterTheScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line before the rotation\n", 250)), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	writer, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.WriteString("password: synthetic-after-scan\n"); err != nil {
		t.Fatal(err)
	}
	if err := rotateRedacted(path, LogPolicy{MaxBytes: 4096, MaxFiles: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString("password: synthetic-after-rotation\n"); err != nil {
		t.Fatal(err)
	}
	files := logFiles(t, path)
	if !strings.HasSuffix(files[path+".1"], "password: [REDACTED]\n") {
		t.Fatalf("path.1 = ...%q", files[path+".1"][max(0, len(files[path+".1"])-80):])
	}
	for name, content := range files {
		if strings.Contains(content, "synthetic-after") {
			t.Errorf("%s keeps a secret", filepath.Base(name))
		}
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 || info.Mode().Perm() != 0o600 {
		t.Fatalf("active log after rotation = %v, %v; want an empty 0600 file", info, err)
	}
}

// A record made under other rules is not trusted (PR #71 review): after an
// upgrade that masks one more key name, that value must be masked in what
// earlier runs already passed.
func TestMaintainLogRedactsAgainWhenTheRulesChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("cookie: synthetic-cookie-value\n"+strings.Repeat("ordinary\n", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	if !strings.Contains(readLog(t, path), "synthetic-cookie-value") {
		t.Fatal("test setup: the current rules mask cookies")
	}
	current := sensitiveAssignment
	t.Cleanup(func() { sensitiveAssignment = current })
	sensitiveAssignment = regexp.MustCompile(strings.Replace(current.String(), "|authorization)", "|authorization|cookie)", 1))
	if sensitiveAssignment.String() == current.String() {
		t.Fatal("test setup: the rule was not changed")
	}
	appendLog(t, path, "ordinary\n")
	if got := maintainTwice(t, path); strings.Contains(got, "synthetic-cookie-value") {
		t.Fatalf("value the new rules mask kept: %q", got[:60])
	}
}

// A symlinked log is replaced by the redacted file on the first maintenance,
// as a full pass always did, so later writes, including secrets, go to a
// file that maintenance redacts (PR #71 review). Before, a run with nothing
// to mask kept the link, and Ansible kept writing through it into the
// target, which maintenance never redacts.
func TestMaintainLogReplacesASymlinkedLog(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "central", "pilot-ansible.log")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(strings.Repeat("ordinary\n", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ansible.log")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("log after maintenance = %v, %v; want a regular file", info, err)
	}
	appendLog(t, path, "password: synthetic-link-secret\n")
	maintain(t, path)
	for _, name := range []string{path, target} {
		if strings.Contains(readLog(t, name), "synthetic-link-secret") {
			t.Errorf("%s keeps the secret", name)
		}
	}
}

// A record whose offset and tail length overflow when added is not used.
func TestMaintainLogIgnoresARecordThatOverflows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte("password: synthetic-overflow-secret\n"+strings.Repeat("ordinary\n", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	device, inode, _ := fileIdentity(info)
	if err := saveRedactionState(path, redactionState{Device: device, Inode: inode, Offset: math.MaxInt64 - 4, TailLength: 8, Rules: redactionRules()}); err != nil {
		t.Fatal(err)
	}
	if got := maintainTwice(t, path); strings.Contains(got, "synthetic-overflow-secret") {
		t.Fatalf("log = %q", got[:60])
	}
}

// The record's and rotation's per-PID temp files are swept like the others
// once their process is gone, on any maintenance: the rotation's holds a
// log that may not have been scanned.
func TestMaintainLogSweepsStaleRecordAndRotationTempFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line\n", 400)), 0o600); err != nil {
		t.Fatal(err)
	}
	dead := strconv.Itoa(deadPIDForTest(t))
	stale := []string{
		redactionStatePath(path) + "-" + dead,
		filepath.Join(filepath.Dir(path), logRotatingTempPrefix+"-"+dead),
	}
	for _, name := range stale {
		if err := os.WriteFile(name, []byte("password: synthetic-stale\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	maintain(t, path)
	for _, name := range stale {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Errorf("%s not swept: %v", filepath.Base(name), err)
		}
	}
}
