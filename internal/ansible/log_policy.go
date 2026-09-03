package ansible

import (
	"bufio"
	"fmt"
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
		return fmt.Errorf("Ansible log is not a regular file: %s", path)
	}

	// The old implementation created this file with mode 0644 on the
	// deployment host. Fix that before doing anything else.
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restrict Ansible log permissions: %w", err)
	}
	if err := redactFile(path); err != nil {
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
	sensitiveAssignment = regexp.MustCompile(`(?i)((?:["']?[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|vault[_-]?password|authorization)[A-Za-z0-9_.-]*["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}\]]+))`)
	sensitiveFlag       = regexp.MustCompile(`(?i)(--(?:password|passwd|passphrase|secret|token|api[-_]key|access[-_]key|private[-_]key|vault[-_]password)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)`)
	privateKeyBegin     = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	privateKeyEnd       = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

// RedactSecrets masks common structured secret values in one line. It is a
// defense-in-depth filter, not a replacement for Ansible no_log.
func RedactSecrets(line string) string {
	line = sensitiveAssignment.ReplaceAllStringFunc(line, func(match string) string {
		separator := strings.IndexAny(match, ":=")
		if separator < 0 {
			return "[REDACTED]"
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
		return preserveLineEnding(line, "[REDACTED PRIVATE KEY]")
	}
	if privateKeyBegin.MatchString(line) {
		r.inPrivateKey = !privateKeyEnd.MatchString(line)
		return preserveLineEnding(line, "[REDACTED PRIVATE KEY]")
	}
	return RedactSecrets(line)
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
