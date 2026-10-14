package ansible

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	// DefaultLogMaxBytes bounds the active Ansible log. A rotated log is
	// already redacted before it is retained.
	DefaultLogMaxBytes  int64 = 100 * 1024 * 1024
	DefaultLogRetention       = 3
)

// LogPolicy controls the controller-side Ansible log. The log is diagnostic
// only; it is not a source of Pilot configuration or delivery evidence.
type LogPolicy struct {
	MaxBytes int64
	MaxFiles int
}

var logUseMu sync.RWMutex

// HoldLogUse prevents log maintenance from replacing a file while an
// Ansible process is still writing it. Different Ansible invocations may
// continue concurrently; only the short maintenance window is exclusive.
func HoldLogUse(path string) func() {
	if path == "" {
		return func() {}
	}
	logUseMu.RLock()
	return logUseMu.RUnlock
}

func DefaultLogPolicy() LogPolicy {
	return LogPolicy{MaxBytes: DefaultLogMaxBytes, MaxFiles: DefaultLogRetention}
}

// LogPolicyFromEnv returns the safe defaults unless an explicitly valid
// override is supplied. Invalid values intentionally fall back rather than
// disabling retention or redaction by accident.
func LogPolicyFromEnv() LogPolicy {
	policy := DefaultLogPolicy()
	if value, err := strconv.ParseInt(os.Getenv("PILOT_ANSIBLE_LOG_MAX_BYTES"), 10, 64); err == nil && value > 0 {
		policy.MaxBytes = value
	}
	if value, err := strconv.Atoi(os.Getenv("PILOT_ANSIBLE_LOG_RETENTION")); err == nil && value >= 0 {
		policy.MaxFiles = value
	}
	return policy
}

// MaintainLog redacts the current log and rotates it when it exceeds the
// configured bound. It is safe to call when the file does not exist yet.
func MaintainLog(path string) error {
	return MaintainLogWithPolicy(path, LogPolicyFromEnv())
}

func MaintainLogWithPolicy(path string, policy LogPolicy) error {
	if path == "" {
		return nil
	}
	logUseMu.Lock()
	defer logUseMu.Unlock()

	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("the Ansible log is not a regular file: %s", path)
	}

	// The old implementation created this file with mode 0644 on the
	// deployment host. Fix that before doing anything else.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict Ansible log permissions: %w", err)
	}
	if err := redactNewLines(path); err != nil {
		return fmt.Errorf("redact Ansible log: %w", err)
	}

	info, err = os.Stat(path)
	if err != nil {
		return err
	}
	if policy.MaxBytes <= 0 || info.Size() <= policy.MaxBytes {
		return nil
	}
	for n := 1; n <= policy.MaxFiles; n++ {
		if err := redactIfPresent(fmt.Sprintf("%s.%d", path, n)); err != nil {
			return fmt.Errorf("redact rotated Ansible log: %w", err)
		}
	}

	// Rotation, trimming and truncation below all start a new active log,
	// sometimes in the same inode (truncateLog); drop the record so the next
	// run redacts it from the start.
	if err := os.Remove(redactionStatePath(path)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reset Ansible log redaction state: %w", err)
	}

	// Keep the newest part of an unexpectedly oversized existing file before
	// rotating it. This prevents one historical 900 MiB log from defeating
	// the retention bound on the first run after an upgrade.
	if err := trimFileToTail(path, policy.MaxBytes); err != nil {
		return fmt.Errorf("trim oversized Ansible log: %w", err)
	}
	if policy.MaxFiles == 0 {
		return truncateLog(path)
	}
	return rotateLog(path, policy.MaxFiles)
}

// LogPathFromEnv extracts the path used by Ansible's log_path setting from a
// process environment assembled by Pilot.
func LogPathFromEnv(env []string) string {
	for _, entry := range env {
		if strings.HasPrefix(entry, "ANSIBLE_LOG_PATH=") {
			return strings.TrimPrefix(entry, "ANSIBLE_LOG_PATH=")
		}
	}
	return ""
}

func MaintainLogFromEnv(env []string) error {
	return MaintainLog(LogPathFromEnv(env))
}

var (
	// The value alternative "\[REDACTED\]+[^\s,}\]]*" reads a masked value
	// and anything glued to it as one value, so RedactSecrets can tell the
	// marker alone from the marker followed by more text.
	sensitiveAssignment = regexp.MustCompile(`(?i)((?:["']?[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|vault[_-]?password|authorization)[A-Za-z0-9_.-]*["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|\[REDACTED\]+[^\s,}\]]*|[^\s,}\]]+))`)
	sensitiveFlag       = regexp.MustCompile(`(?i)(--(?:password|passwd|passphrase|secret|token|api[-_]key|access[-_]key|private[-_]key|vault[-_]password)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)`)
	// maskedValue is a value RedactSecrets already masked: "[REDACTED]", or
	// the "[REDACTED]]…" that earlier versions grew by one bracket per pass.
	maskedValue     = regexp.MustCompile(`^\[REDACTED\]+$`)
	privateKeyBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	privateKeyEnd   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	// privateKeyMarkerPart is the start of a "-----END … PRIVATE KEY-----"
	// line that is still being written. Key material is base64 and never
	// starts with "-", so such a line is not secret.
	privateKeyMarkerPart = regexp.MustCompile(`^-[-A-Z0-9 ]*\r?$`)
)

const privateKeyPlaceholder = "[REDACTED PRIVATE KEY]"

// RedactSecrets masks common structured secret values in one line. It is a
// defense-in-depth filter, not a replacement for Ansible no_log.
func RedactSecrets(line string) string {
	line = sensitiveAssignment.ReplaceAllStringFunc(line, func(match string) string {
		separator := strings.IndexAny(match, ":=")
		if separator < 0 {
			return "[REDACTED]"
		}
		// An already-masked value: the value pattern used to stop before
		// "]", so replacing it again turned "[REDACTED]" into
		// "[REDACTED]]", one more bracket on every pass over the log
		// (issue #70). Only the marker itself counts: a value that merely
		// starts like it, such as "[REDACTED-x" or "[REDACTED]x", is masked.
		if maskedValue.MatchString(strings.TrimSpace(match[separator+1:])) {
			return match
		}
		return match[:separator+1] + " [REDACTED]"
	})
	return sensitiveFlag.ReplaceAllString(line, "$1[REDACTED]")
}

type streamRedactor struct {
	inPrivateKey bool
}

func (r *streamRedactor) redact(line string) string {
	if r.inPrivateKey {
		if privateKeyEnd.MatchString(line) {
			r.inPrivateKey = false
		}
		return preserveLineEnding(line, privateKeyPlaceholder)
	}
	if privateKeyBegin.MatchString(line) {
		r.inPrivateKey = !privateKeyEnd.MatchString(line)
		return preserveLineEnding(line, privateKeyPlaceholder)
	}
	return RedactSecrets(line)
}

// redactContinuation judges a line whose first maskedLen bytes are a final
// line that an earlier maintenance masked before its writer finished it.
// The original text of that part is gone, so tailInPrivateKey, the
// private-key state after it, decides how the rest is read.
func (r *streamRedactor) redactContinuation(line string, maskedLen int64, tailInPrivateKey bool) string {
	if tailInPrivateKey {
		r.inPrivateKey = !privateKeyEnd.MatchString(line[maskedLen:])
		return preserveLineEnding(line, privateKeyPlaceholder)
	}
	r.inPrivateKey = false
	return r.redact(line)
}

func preserveLineEnding(line, replacement string) string {
	if strings.HasSuffix(line, "\r\n") {
		return replacement + "\r\n"
	}
	if strings.HasSuffix(line, "\n") {
		return replacement + "\n"
	}
	return replacement
}

// logTempPrefix names below are per-PID and deterministic, not
// os.CreateTemp's random suffix, so a caller killed mid-write (SIGKILL —
// e.g. a context.WithTimeout expiry, which skips every defer) always
// leaves behind an orphan identifiable by the PID that made it. Nothing
// could tell a random-named orphan apart from a still-running peer's own
// in-flight temp file, so the old scheme could never safely self-clean;
// this one lets sweepStaleLogTemp remove only orphans whose owning PID has
// verifiably exited, without racing a live peer's write. This is what
// found (and, going forward, prevents re-accumulating) 436 leaked
// .ansible-log-redacted-* files / 76 GB under
// ~/.local/share/pilot/ansible/ from repeated SIGKILL'd `pilot mcp serve`
// subprocesses.
const (
	logRedactedTempPrefix = ".ansible-log-redacted"
	logTrimmedTempPrefix  = ".ansible-log-trimmed"
)

// sweepStaleLogTemp removes dir's <prefix>-<pid> temp files left by a
// process that no longer exists. A file named after a still-live PID
// (including this process's own) is left alone — it may be a peer's
// legitimate in-flight write.
func sweepStaleLogTemp(dir, prefix string) {
	matches, err := filepath.Glob(filepath.Join(dir, prefix+"-*"))
	if err != nil {
		return
	}
	self := os.Getpid()
	for _, m := range matches {
		pid, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(m), prefix+"-"))
		if err != nil || pid == self || processAlive(pid) {
			continue
		}
		_ = os.Remove(m)
	}
}

// processAlive reports whether pid names a live process, via a signal-0
// probe (delivers nothing, only checks existence/permission).
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

// redactionState records how much of the active log is already redacted.
// Maintenance runs after every Pilot Ansible invocation, including every
// pilot_diagnose_* step, and rescanning the whole log each time cost about
// 11 s of CPU per call on a 74 MB log (issue #70). With this record each
// run only scans what was appended since the previous one.
//
// The record is trusted only while the file still holds the bytes
// maintenance left: PrefixSHA256 is the SHA-256 of the first
// Offset+TailLength bytes, and every run checks it before using Offset.
// Device, inode and size alone do not show that: a log truncated in place
// (O_TRUNC, "> file", logrotate copytruncate) and written again past the old
// offset, or deleted and recreated under a reused inode number, matches all
// three, and its new start would never be scanned. When the hash differs,
// or the record has none (written by an earlier version), the whole file is
// redacted again. Hashing the prefix costs tens of milliseconds on a 74 MB
// log; the regex pass it replaces cost about 11 s.
//
// A final line without its newline is masked in place when it needs it,
// because maintenance runs after Ansible exits and that line may never be
// completed. Offset still stops at its start, so the line is judged again
// once a writer completes it and a secret split across two writes is
// masked whole. TailLength and TailInPrivateKey describe the masked part.
type redactionState struct {
	Device           uint64 `json:"device"`
	Inode            uint64 `json:"inode"`
	Offset           int64  `json:"offset"`
	InPrivateKey     bool   `json:"in_private_key"`
	TailLength       int64  `json:"tail_length,omitempty"`
	TailInPrivateKey bool   `json:"tail_in_private_key,omitempty"`
	PrefixSHA256     string `json:"prefix_sha256,omitempty"`
}

func redactionStatePath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".redaction-state")
}

func fileIdentity(info os.FileInfo) (device, inode uint64, ok bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), uint64(st.Ino), true // Dev is int32 on darwin
}

// loadRedactionState returns the saved record, or a zero record (redact
// from the start) when there is none or it cannot be read.
func loadRedactionState(path string) redactionState {
	var state redactionState
	data, err := os.ReadFile(redactionStatePath(path))
	if err != nil || json.Unmarshal(data, &state) != nil {
		return redactionState{}
	}
	return state
}

func saveRedactionState(path string, state redactionState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	statePath := redactionStatePath(path)
	tmpPath := fmt.Sprintf("%s-%d", statePath, os.Getpid())
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, statePath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

// verifyPrefix hashes the part of input that state covers and reports
// whether it still matches state.PrefixSHA256. It returns the hash after
// the first state.Offset bytes, for the caller to continue.
func verifyPrefix(input io.ReaderAt, state redactionState) (hash.Hash, bool, error) {
	digest := sha256.New()
	if _, err := io.Copy(digest, io.NewSectionReader(input, 0, state.Offset)); err != nil {
		return nil, false, err
	}
	covered := digest
	if state.TailLength > 0 {
		var err error
		if covered, err = cloneDigest(digest, input, state.Offset); err != nil {
			return nil, false, err
		}
		if _, err := io.Copy(covered, io.NewSectionReader(input, state.Offset, state.TailLength)); err != nil {
			return nil, false, err
		}
	}
	return digest, state.PrefixSHA256 != "" && hex.EncodeToString(covered.Sum(nil)) == state.PrefixSHA256, nil
}

// cloneDigest copies digest, the SHA-256 of input's first n bytes. Hashes
// in the standard library can be cloned except in FIPS 140 v1.0.0 mode;
// then the bytes are hashed again.
func cloneDigest(digest hash.Hash, input io.ReaderAt, n int64) (hash.Hash, error) {
	if cloner, ok := digest.(hash.Cloner); ok {
		if clone, err := cloner.Clone(); err == nil {
			return clone, nil
		}
	}
	clone := sha256.New()
	_, err := io.Copy(clone, io.NewSectionReader(input, 0, n))
	return clone, err
}

// redactRangeStarts, when set by a test, sees where each scan starts.
var redactRangeStarts func(offset int64)

// redactRange redacts input from state.Offset to to, writing the result to
// w when w is not nil and adding the part the returned record covers to
// digest when digest is not nil. It returns the record for that result,
// which starts at the same offset, and whether any line changed. The
// returned Offset is just after the last complete line; a final line
// without a newline is written masked (see redactionState) but stays after
// Offset, so the next run judges it again once it is complete.
func redactRange(input io.ReaderAt, state redactionState, to int64, w io.Writer, digest hash.Hash) (redactionState, bool, error) {
	if redactRangeStarts != nil {
		redactRangeStarts(state.Offset)
	}
	reader := bufio.NewReaderSize(io.NewSectionReader(input, state.Offset, to-state.Offset), 128*1024)
	redactor := streamRedactor{inPrivateKey: state.InPrivateKey}
	next := redactionState{Device: state.Device, Inode: state.Inode, Offset: state.Offset, InPrivateKey: state.InPrivateKey}
	maskedTail, changed := state.TailLength, false
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return next, changed, err
		}
		if line == "" {
			return next, changed, nil
		}
		complete := err == nil
		continued := maskedTail > 0 && int64(len(line)) >= maskedTail
		maskedTail = 0
		var redacted string
		switch {
		case continued:
			redacted = redactor.redactContinuation(line, state.TailLength, state.TailInPrivateKey)
		case !complete && redactor.inPrivateKey && privateKeyMarkerPart.MatchString(line):
			// Masking a half-written END marker would hide it, and every
			// later line would be read as key material.
			redacted = line
		default:
			redacted = redactor.redact(line)
		}
		if redacted != line {
			changed = true
		}
		if w != nil {
			if _, err := io.WriteString(w, redacted); err != nil {
				return next, changed, err
			}
		}
		covered := complete || continued || redacted != line
		if covered && digest != nil {
			_, _ = io.WriteString(digest, redacted) // hash.Hash writes never fail
		}
		if !complete {
			if covered {
				next.TailLength = int64(len(redacted))
				next.TailInPrivateKey = redactor.inPrivateKey
			}
			return next, changed, nil
		}
		next.Offset += int64(len(redacted))
		next.InPrivateKey = redactor.inPrivateKey
	}
}

// redactNewLines redacts what was appended to path since the previous
// maintenance. When none of it needs masking the file is left untouched;
// otherwise the file is rewritten through a temp file and a rename, as
// redactFile does, but the already-redacted prefix is only copied and
// hashed, not scanned again.
func redactNewLines(path string) error {
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	// Identity and size of the file actually read, not of whatever the
	// path names later.
	info, err := input.Stat()
	if err != nil {
		return err
	}
	device, inode, known := fileIdentity(info)
	size := info.Size()
	fresh := redactionState{Device: device, Inode: inode}
	state := loadRedactionState(path)
	if !known || state.Device != device || state.Inode != inode || state.Offset < 0 || state.TailLength < 0 || state.Offset+state.TailLength > size {
		state = fresh
	}
	digest, trusted, err := verifyPrefix(input, state)
	if err != nil {
		return err
	}
	if !trusted {
		state, digest = fresh, sha256.New()
	} else if state.Offset+state.TailLength == size {
		return nil
	}

	next, changed, err := redactRange(input, state, size, nil, nil)
	if err != nil {
		return err
	}
	if !changed {
		if !known {
			return nil
		}
		if _, err := io.Copy(digest, io.NewSectionReader(input, state.Offset, next.Offset+next.TailLength-state.Offset)); err != nil {
			return err
		}
		next.PrefixSHA256 = hex.EncodeToString(digest.Sum(nil))
		return saveRedactionState(path, next)
	}

	dir := filepath.Dir(path)
	sweepStaleLogTemp(dir, logRedactedTempPrefix)
	tmpPath := filepath.Join(dir, fmt.Sprintf("%s-%d", logRedactedTempPrefix, os.Getpid()))
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	writer := bufio.NewWriterSize(tmp, 128*1024)
	if _, err := io.Copy(writer, io.NewSectionReader(input, 0, state.Offset)); err != nil {
		_ = tmp.Close()
		return err
	}
	// digest already holds the copied prefix, as verified above.
	next, _, err = redactRange(input, state, size, writer, digest)
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	rewritten, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	device, inode, known = fileIdentity(rewritten)
	if !known {
		return nil
	}
	next.Device, next.Inode = device, inode
	next.PrefixSHA256 = hex.EncodeToString(digest.Sum(nil))
	return saveRedactionState(path, next)
}

func redactFile(path string) error {
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()

	dir := filepath.Dir(path)
	sweepStaleLogTemp(dir, logRedactedTempPrefix)
	tmpPath := filepath.Join(dir, fmt.Sprintf("%s-%d", logRedactedTempPrefix, os.Getpid()))
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}

	reader := bufio.NewReaderSize(input, 128*1024)
	writer := bufio.NewWriterSize(tmp, 128*1024)
	redactor := streamRedactor{}
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 0 {
			if _, err := writer.WriteString(redactor.redact(line)); err != nil {
				_ = tmp.Close()
				return err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			_ = tmp.Close()
			return readErr
		}
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func redactIfPresent(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return redactFile(path)
}

func trimFileToTail(path string, maxBytes int64) error {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= maxBytes {
		return err
	}
	input, err := os.Open(path)
	if err != nil {
		return err
	}
	defer input.Close()
	if _, err := input.Seek(info.Size()-maxBytes, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReader(input)
	if _, err := reader.ReadString('\n'); err != nil && err != io.EOF {
		return err
	}

	dir := filepath.Dir(path)
	sweepStaleLogTemp(dir, logTrimmedTempPrefix)
	tmpPath := filepath.Join(dir, fmt.Sprintf("%s-%d", logTrimmedTempPrefix, os.Getpid()))
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := io.Copy(tmp, reader); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func truncateLog(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}

func rotateLog(path string, maxFiles int) error {
	for n := maxFiles; n >= 1; n-- {
		destination := fmt.Sprintf("%s.%d", path, n)
		if n == maxFiles {
			if err := os.Remove(destination); err != nil && !os.IsNotExist(err) {
				return err
			}
			continue
		}
		source := fmt.Sprintf("%s.%d", path, n)
		if err := os.Rename(source, destination); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	return file.Close()
}
