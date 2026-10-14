package ansible

import (
	"context"
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
		" --password\t\"\"]",
		"--password=[REDACTED]--password\rp",
		"ordinary line",
	} {
		once := RedactSecrets(raw)
		if twice := RedactSecrets(once); twice != once {
			t.Errorf("RedactSecrets(%q): once %q, twice %q", raw, once, twice)
		}
	}
	// A masked value is left as it is, with the brackets after it: they may
	// be the text's own ("[password=abc]"), or grown by earlier versions,
	// which cannot be told apart and hide nothing. Masking never adds one
	// (PR #90 review: folding them dropped a real bracket).
	for masked, want := range map[string]string{
		"password: [REDACTED]":                `password: [REDACTED]`,
		"token= [REDACTED]]":                  "token= [REDACTED]]",
		`"secret": [REDACTED]]]], "other": 1`: `"secret": [REDACTED]]]], "other": 1`,
		`{"list": [password=abc]}`:            `{"list": [password= [REDACTED]]}`,
		`[--token=abc]`:                       `[--token= [REDACTED]]`,
		`[--token abc]`:                       `[--token [REDACTED]`,
	} {
		if got := RedactSecrets(masked); got != want {
			t.Errorf("RedactSecrets(%q) = %q, want %q", masked, got, want)
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

// A value that merely starts like the marker is masked (PR #71 review), and
// text glued after a marker is judged by the other rules, as on main: a
// flag glued to it is still masked, also when its value follows a carriage
// return (PR #71 follow-up review).
func TestRedactSecretsMasksMarkerLookalikes(t *testing.T) {
	for raw, want := range map[string]string{
		"password: [REDACTED-synthetic-marker-secret":            "password: [REDACTED]",
		"token=[REDACTEDsynthetic":                               "token= [REDACTED]",
		"password: [redacted]":                                   "password: [REDACTED]",
		"password:[REDACTED]--password synthetic-flag-secret":    "password: [REDACTED]--password [REDACTED]",
		"--password=[REDACTED]--password\rsynthetic-flag-secret": "--password= [REDACTED]--password\r[REDACTED]",
		" --password\t\"\"]":                                     " --password\t[REDACTED]]",
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

// testOtherRecord is a record of another Ansible process, such as the
// next run's.
func testOtherRecord(message string) string {
	return "2026-09-15 09:51:02,114 p=4343 u=pilot n=ansible INFO| " + message
}

// A key whose END marker never comes must not mask the rest of the log
// (PR #71 review). Within the scan that finds it, the rest is masked, as
// main masked it. Carried into a later scan, it goes on only through the
// lines of the process it belongs to: a record of another process, such as
// the next run's, ends it, and so does that process's PLAY RECAP.
func TestMaintainLogBoundsAnUnfinishedKeyToItsProcess(t *testing.T) {
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
		t.Run(name+", next run", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ansible.log")
			if err := os.WriteFile(path, []byte(tc.log), 0o600); err != nil {
				t.Fatal(err)
			}
			maintainTwice(t, path)
			if tc.completion != "" {
				appendLog(t, path, tc.completion)
				maintainTwice(t, path)
			}
			appendLog(t, path, testOtherRecord("ok: [h] => synthetic-visible-after")+"\n"+testOtherRecord("PLAY RECAP")+"\n")
			got := maintainTwice(t, path)
			if strings.Contains(got, "synthkey") || !strings.Contains(got, "synthetic-visible-after") || !strings.Contains(got, "PLAY RECAP") {
				t.Fatalf("log = %q", got)
			}
		})
		t.Run(name+", same process", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ansible.log")
			if err := os.WriteFile(path, []byte(tc.log), 0o600); err != nil {
				t.Fatal(err)
			}
			maintainTwice(t, path)
			if tc.completion != "" {
				appendLog(t, path, tc.completion)
				maintainTwice(t, path)
			}
			appendLog(t, path, testRecord("ok: [h] => synthkey-more")+"\n"+testRecord("PLAY RECAP *****")+"\n"+testRecord("ok: [h] => synthetic-visible-after")+"\n")
			got := maintainTwice(t, path)
			if strings.Contains(got, "synthkey") || !strings.Contains(got, "PLAY RECAP") || !strings.Contains(got, "synthetic-visible-after") {
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

// Rotation, trimming and dropping the log at retention 0 start a new active
// log, so the record is dropped. Each of them replaces the inode, which
// already invalidates the record; dropping it keeps the result right even
// if one of them kept the inode, where a log that grew past the old offset
// would otherwise have its start skipped.
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

// A loop over a key's lines (with_lines: cat key.pem, or a loop over
// splitlines()) logs the key across many records. The shapes are copied
// from a capture with ansible-core 2.19.2 (host, paths and key changed):
// one record per item, a labeled loop, an include_tasks loop and the
// included task run per item. The key is masked through all of them, and an
// error report between them, up to the END marker (PR #71 and #90 reviews).
func TestMaintainLogMasksAKeyLoggedOneLoopItemPerLine(t *testing.T) {
	body := []string{"MIIEsyntheticloopkeybodyone", "syntheticloopkeybodytwo=="}
	for name, log := range map[string]string{
		"command loop": testRecord("TASK [loop over key lines] ***") + "\n" +
			testRecord("changed: [h] => (item=-----BEGIN RSA PRIVATE KEY-----)") + "\n" +
			testRecord("changed: [h] => (item="+body[0]+")") + "\n" +
			testRecord("changed: [h] => (item="+body[1]+")") + "\n" +
			testRecord("changed: [h] => (item=-----END RSA PRIVATE KEY-----)") + "\n",
		"debug loop": testRecord("ok: [h] => (item=-----BEGIN RSA PRIVATE KEY-----) => {") + "\n" +
			"    \"msg\": \"-----BEGIN RSA PRIVATE KEY-----\"\n}\n" +
			testRecord("ok: [h] => (item="+body[0]+") => {") + "\n" +
			"    \"msg\": \"" + body[0] + "\"\n}\n" +
			testRecord("ok: [h] => (item="+body[1]+") => {") + "\n" +
			"    \"msg\": \"" + body[1] + "\"\n}\n" +
			testRecord("ok: [h] => (item=-----END RSA PRIVATE KEY-----) => {") + "\n" +
			"    \"msg\": \"-----END RSA PRIVATE KEY-----\"\n}\n",
		// loop_control.label hides the item; the BEGIN marker is only in the
		// first item's result body.
		"labeled debug loop": testRecord("ok: [h] => (item=1) => {") + "\n" +
			"    \"msg\": \"-----BEGIN RSA PRIVATE KEY-----\"\n}\n" +
			testRecord("ok: [h] => (item=2) => {") + "\n" +
			"    \"msg\": \"" + body[0] + "\"\n}\n" +
			testRecord("ok: [h] => (item=3) => {") + "\n" +
			"    \"msg\": \"" + body[1] + "\"\n}\n" +
			testRecord("ok: [h] => (item=4) => {") + "\n" +
			"    \"msg\": \"-----END RSA PRIVATE KEY-----\"\n}\n",
		"include_tasks loop": testRecord("TASK [include loop] ***") + "\n" +
			testRecord("included: /x/write_line.yml for h => (item=-----BEGIN RSA PRIVATE KEY-----)") + "\n" +
			testRecord("included: /x/write_line.yml for h => (item="+body[0]+")") + "\n" +
			testRecord("included: /x/write_line.yml for h => (item="+body[1]+")") + "\n" +
			testRecord("included: /x/write_line.yml for h => (item=-----END RSA PRIVATE KEY-----)") + "\n",
		// The included task then runs once per item, each under its own banner.
		"included task per item": testRecord("TASK [inner] ***") + "\n" + testRecord("ok: [h] => {") + "\n" +
			"    \"msg\": \"-----BEGIN RSA PRIVATE KEY-----\"\n}\n" +
			testRecord("TASK [inner] ***") + "\n" + testRecord("ok: [h] => {") + "\n" +
			"    \"msg\": \"" + body[0] + "\"\n}\n" +
			testRecord("TASK [inner] ***") + "\n" + testRecord("ok: [h] => {") + "\n" +
			"    \"msg\": \"" + body[1] + "\"\n}\n" +
			testRecord("TASK [inner] ***") + "\n" + testRecord("ok: [h] => {") + "\n" +
			"    \"msg\": \"-----END RSA PRIVATE KEY-----\"\n}\n",
		"failed items with an error report between them": testRecord("changed: [h] => (item=-----BEGIN RSA PRIVATE KEY-----)") + "\n" +
			"2026-09-15 09:50:37,791 p=4242 u=pilot n=ansible ERROR| [ERROR]: Task failed: Module failed: non-zero return code\nOrigin: /x/play.yml:20:7\n\n" +
			testRecord(`failed: [h] (item=`+body[0]+`) => {"ansible_loop_var": "item", "changed": true, "cmd": ["false", "`+body[0]+`"], "item": "`+body[0]+`", "rc": 1}`) + "\n" +
			testRecord(`failed: [h] (item=`+body[1]+`) => {"ansible_loop_var": "item", "item": "`+body[1]+`", "rc": 1}`) + "\n" +
			testRecord("changed: [h] => (item=-----END RSA PRIVATE KEY-----)") + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ansible.log")
			if err := os.WriteFile(path, []byte(log+testRecord("TASK [next] ***")+"\n"+testRecord("ok: [h] => synthetic-visible-after")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			got := maintainTwice(t, path)
			for _, line := range body {
				if strings.Contains(got, line) {
					t.Errorf("key line %q left: %q", line, got)
				}
			}
			if !strings.Contains(got, "synthetic-visible-after") {
				t.Errorf("the record after the loop was masked: %q", got)
			}
		})
	}
}

// A loop whose END item never comes (a loop that only quotes a BEGIN
// marker) masks the rest of the scan that finds it, as main did, and not
// the next run's lines.
func TestMaintainLogBoundsAKeyLoopWithoutAnEndItem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	log := testRecord("changed: [h] => (item=-----BEGIN RSA PRIVATE KEY-----)") + "\n" +
		testRecord("changed: [h] => (item=MIIEsyntheticloopkeybodyone)") + "\n" +
		testRecord("TASK [next] ***") + "\n" +
		testRecord("changed: [h] => (item=synthetic-masked-item)") + "\n"
	if err := os.WriteFile(path, []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	got := maintainTwice(t, path)
	if strings.Contains(got, "MIIEsynthetic") || strings.Contains(got, "synthetic-masked-item") {
		t.Fatalf("log = %q", got)
	}
	appendLog(t, path, testOtherRecord("changed: [h] => (item=synthetic-visible-item)")+"\n")
	if got := maintainTwice(t, path); !strings.Contains(got, "synthetic-visible-item") {
		t.Fatalf("the next run's record was masked: %q", got)
	}
}

// numberedLines returns n lines that each say their number, and countLines
// how many different ones of them the files under dir hold.
func numberedLines(n int, extra string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "ordinary line number %04d\n", i)
		if i == n/2 {
			b.WriteString(extra)
		}
	}
	return b.String()
}

func countNumberedLines(t *testing.T, dir string) (int, string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var all strings.Builder
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		all.Write(data)
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "ordinary line number ") {
				seen[line] = true
			}
		}
	}
	return len(seen), all.String()
}

// A rotation that fails after renaming the log aside must not lose the
// log (PR #71 follow-up review): main kept every line when its redaction
// failed. The renamed file stays, and the next maintenance finishes the
// rotation. A directory in the way of the redaction's temp file stands in
// for ENOSPC or EIO.
func TestMaintainLogKeepsTheLogWhenRotationFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	if err := os.WriteFile(path, []byte(numberedLines(200, "password: synthetic-rotation-secret\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	blocker := filepath.Join(dir, fmt.Sprintf("%s-%d", logRedactedTempPrefix, os.Getpid()))
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := LogPolicy{MaxBytes: 4096, MaxFiles: 2}
	if err := MaintainLogWithPolicy(path, policy); err == nil {
		t.Fatal("test setup: the rotation did not fail")
	}
	if n, _ := countNumberedLines(t, dir); n != 200 {
		t.Fatalf("after the failed rotation %d of 200 lines are left", n)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, policy); err != nil {
		t.Fatal(err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, logRotatingTempPrefix+"-*")); len(leftovers) != 0 {
		t.Fatalf("rotation leftovers: %v", leftovers)
	}
	rotated := readLog(t, path+".1")
	if !strings.HasSuffix(rotated, "ordinary line number 0199\n") || len(rotated) > 4096 {
		t.Fatalf("path.1 = ...%q (%d bytes)", rotated[max(0, len(rotated)-60):], len(rotated))
	}
	if _, all := countNumberedLines(t, dir); strings.Contains(all, "synthetic-rotation-secret") {
		t.Fatal("a file keeps the secret")
	}
}

// A rotation killed after renaming the log aside is finished by the next
// maintenance: the renamed log is redacted and kept as path.1, not deleted.
func TestMaintainLogFinishesAKilledRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	aside := filepath.Join(dir, logRotatingTempPrefix+"-"+strconv.Itoa(deadPIDForTest(t)))
	if err := os.WriteFile(aside, []byte(numberedLines(300, "password: synthetic-killed-secret\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ordinary line in the new log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	if _, err := os.Stat(aside); !os.IsNotExist(err) {
		t.Fatalf("the renamed log is still there: %v", err)
	}
	rotated := readLog(t, path+".1")
	if n, all := countNumberedLines(t, dir); n != 300 || strings.Contains(all, "synthetic-killed-secret") || !strings.Contains(rotated, "password: [REDACTED]") {
		t.Fatalf("%d of 300 lines kept; path.1 = %q...", n, rotated[:min(len(rotated), 80)])
	}
}

// A process of another user is alive: signal 0 to it fails with EPERM. Its
// rotation in progress is left alone, unless its file is so old that the
// PID must have been reused (PR #71 follow-up review).
func TestMaintainLogLeavesAnotherUsersRotationAlone(t *testing.T) {
	if !processAlive(1) {
		t.Fatal("PID 1 is reported dead")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	aside := filepath.Join(dir, logRotatingTempPrefix+"-1")
	if err := os.WriteFile(aside, []byte(numberedLines(10, "password: synthetic-other-user\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	if _, err := os.Stat(aside); err != nil {
		t.Fatalf("a recent rotation of a live process was touched: %v", err)
	}
	old := time.Now().Add(-2 * rotationLeftoverAge)
	if err := os.Chtimes(aside, old, old); err != nil {
		t.Fatal(err)
	}
	maintain(t, path)
	if _, err := os.Stat(aside); !os.IsNotExist(err) {
		t.Fatalf("an old leftover was not finished: %v", err)
	}
	if n, all := countNumberedLines(t, dir); n != 10 || strings.Contains(all, "synthetic-other-user") {
		t.Fatalf("%d of 10 lines kept, or the secret was kept", n)
	}
}

// A writer outside this process that appends faster than the scan reads
// would keep maintenance, and every Ansible run waiting for it, going. The
// scan stops scanCatchUp past the size seen at open; the next maintenance
// scans the rest.
func TestMaintainLogBoundsTheScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ansible.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("ordinary line before the scan\n", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	start := fileSize(t, path)
	burst := strings.Repeat("ordinary line appended during the scan\n", 2*scanCatchUp/38) + "password: synthetic-beyond-the-bound\n"
	appended := false
	redactRangeStarts = func(int64) {
		if !appended {
			appended = true
			appendLog(t, path, burst)
		}
	}
	defer func() { redactRangeStarts = nil }()
	maintain(t, path)
	if state := loadRedactionState(path); state.Offset > start+scanCatchUp {
		t.Fatalf("scanned to %d, past %d + %d", state.Offset, start, scanCatchUp)
	}
	if got := maintainTwice(t, path); strings.Contains(got, "synthetic-beyond-the-bound") {
		t.Fatal("the rest was not scanned by the next maintenance")
	}
}

// Waiting for a maintenance in progress stops when the caller's context
// ends, so a step or probe timeout still bounds it.
func TestHoldLogUseContextStopsWaitingWhenTheContextEnds(t *testing.T) {
	logUseMu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := HoldLogUseContext(ctx, "/x/ansible.log")
	logUseMu.Unlock()
	if err == nil || time.Since(started) > 5*time.Second {
		t.Fatalf("HoldLogUseContext = %v after %v; want the context's error", err, time.Since(started))
	}
	release, err := HoldLogUseContext(context.Background(), "/x/ansible.log")
	if err != nil {
		t.Fatal(err)
	}
	release()
}

// rotationLeftoverName names a renamed-aside log as rotateRedacted does.
func rotationLeftoverName(dir string, pid int, started time.Time) string {
	return filepath.Join(dir, fmt.Sprintf("%s-%d-%d", logRotatingTempPrefix, pid, started.UnixNano()))
}

// A leftover of an interrupted rotation that this user may not read (a
// killed sudo pilot's) must not stop the redaction of the active log,
// which goes on being written (PR #90 review). It is left in place, with a
// warning, and maintenance does not fail.
func TestMaintainLogRedactsTheActiveLogPastAnUnreadableLeftover(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads a mode 000 file")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	leftover := rotationLeftoverName(dir, 999999, time.Now().Add(-time.Minute))
	if err := os.WriteFile(leftover, []byte("ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(leftover, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(leftover, 0o600) })
	if err := os.WriteFile(path, []byte("password: synthetic-blocked-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatalf("maintenance failed: %v", err)
	}
	if got := readLog(t, path); strings.Contains(got, "synthetic-blocked-secret") {
		t.Fatalf("active log = %q", got)
	}
	if _, err := os.Stat(leftover); err != nil {
		t.Fatalf("the leftover is gone: %v", err)
	}
}

// When a leftover cannot be finished for another reason, the active log is
// still redacted, the error is reported, and the leftover keeps its content
// for the next maintenance.
func TestMaintainLogRedactsTheActiveLogWhenRecoveryFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	leftover := rotationLeftoverName(dir, 999999, time.Now().Add(-time.Minute))
	if err := os.WriteFile(leftover, []byte("ordinary leftover line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// path.1 is a directory with something in it: moving the leftover there
	// fails.
	if err := os.MkdirAll(filepath.Join(path+".1", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("password: synthetic-active-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := MaintainLogWithPolicy(path, DefaultLogPolicy())
	if err == nil || !strings.Contains(err.Error(), "interrupted rotation") {
		t.Fatalf("err = %v, want the failed recovery", err)
	}
	if got := readLog(t, path); strings.Contains(got, "synthetic-active-secret") {
		t.Fatalf("active log = %q", got)
	}
	if got := readLog(t, leftover); !strings.Contains(got, "ordinary leftover line") {
		t.Fatalf("leftover = %q", got)
	}
}

// A rotation's age is the time it started, recorded in the leftover's
// name, not the renamed log's last write (PR #90 review): a live rotation
// of a log that was idle for hours is left alone, and a rotation of a live
// PID that started hours ago (the PID was reused) is finished.
func TestMaintainLogAgesRotationsByTheirStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ansible.log")
	live := os.Getppid() // alive, and not this process
	idle := rotationLeftoverName(dir, live, time.Now())
	stale := rotationLeftoverName(dir, live, time.Now().Add(-2*time.Hour))
	for name, line := range map[string]string{idle: "idle log in rotation\n", stale: "stale leftover line\n"} {
		if err := os.WriteFile(name, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		old := time.Now().Add(-3 * time.Hour)
		if err := os.Chtimes(name, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := MaintainLogWithPolicy(path, DefaultLogPolicy()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(idle); err != nil {
		t.Fatalf("a rotation in progress was taken over: %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("a stale leftover was not finished: %v", err)
	}
	if got := readLog(t, path+".1"); !strings.Contains(got, "stale leftover line") {
		t.Fatalf("%s.1 = %q", path, got)
	}
}

// A temp file named after a live PID is a peer's write in progress, unless
// it was last written over rotationLeftoverAge ago: these files live for
// one write, so the PID was reused, possibly by another user's process,
// which processAlive counts as alive (PR #90 review).
func TestSweepStaleLogTempBoundsALivePID(t *testing.T) {
	dir := t.TempDir()
	live := os.Getppid()
	recent := filepath.Join(dir, fmt.Sprintf("%s-%d", logRedactedTempPrefix, live))
	old := filepath.Join(dir, fmt.Sprintf("%s-%d", logTrimmedTempPrefix, live))
	for _, name := range []string{recent, old} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(old, past, past); err != nil {
		t.Fatal(err)
	}
	sweepStaleLogTemp(dir, logRedactedTempPrefix)
	sweepStaleLogTemp(dir, logTrimmedTempPrefix)
	if _, err := os.Stat(recent); err != nil {
		t.Fatalf("a live write was swept: %v", err)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("a stale temp of a reused PID was kept: %v", err)
	}
}

// At retention 0 the log is dropped by renaming an empty file over it, which
// detaches a writer that still holds it, as main's rename did. Truncating it
// in place kept the writer attached: the rest of a BEGIN marker it was
// writing then started the log, and the key after it was left as text
// (PR #90 fuzzing; this is what FuzzMaintainLogMasksWhatMainMasks found).
func TestMaintainLogRetentionZeroDetachesAWriterMidKey(t *testing.T) {
	checkKeepsNothingMainWouldMask(t, []logStep{
		{data: testRecord("ok: [h] => ") + "\n    -----BEGIN OPENSS", attached: true},
		{maintain: true, policy: LogPolicy{MaxBytes: 1, MaxFiles: 0}},
		{data: "H PRIVATE KEY-----\n    XLZLMMLZMZMUJLLMQQZUXUZJ\n    -----END OPENSSH PRIVATE KEY-----\n", attached: true},
		{maintain: true, policy: DefaultLogPolicy()},
	})
}
