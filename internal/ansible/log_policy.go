package ansible

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
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

// HoldLogUseContext is HoldLogUse that stops waiting when ctx ends:
// maintenance holds the log exclusively while it runs, and the caller's
// deadline (a step or probe timeout) must still bound the wait.
func HoldLogUseContext(ctx context.Context, path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	for !logUseMu.TryRLock() {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for Ansible log maintenance: %w", ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	return logUseMu.RUnlock, nil
}

// HoldCommandLog holds the Ansible log that command writes, the
// ANSIBLE_LOG_PATH of its environment (command.Env, or this process's when
// that is nil), until the returned release is called. Run the command in
// between, so that maintenance does not rewrite or rotate the log under it.
func HoldCommandLog(ctx context.Context, command *exec.Cmd) (func(), error) {
	env := command.Env
	if env == nil {
		env = os.Environ()
	}
	return HoldLogUseContext(ctx, LogPathFromEnv(env))
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

	if err := recoverRotations(path, policy); err != nil {
		return err
	}
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
	link, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if link.Mode()&os.ModeSymlink != 0 {
		// A symlinked log gets what every log got before the record existed:
		// one full pass, whose rename replaces the link with the redacted
		// file. Later writes then go to that file, which is maintained
		// incrementally. Maintenance does not rewrite the link's target, a
		// file outside the log path; it keeps what was written to it.
		if err := redactFile(path); err != nil {
			return fmt.Errorf("redact Ansible log: %w", err)
		}
		if err := removeRedactionState(path); err != nil {
			return err
		}
	} else if err := redactNewLines(path); err != nil {
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
	if policy.MaxFiles == 0 {
		// Nothing is retained. The record described the old content.
		if err := removeRedactionState(path); err != nil {
			return err
		}
		return truncateLog(path)
	}
	if err := rotateRedacted(path, policy); err != nil {
		return fmt.Errorf("rotate Ansible log: %w", err)
	}
	return nil
}

// LogPathFromEnv extracts the path used by Ansible's log_path setting from a
// process environment assembled by Pilot. As for exec.Cmd, the last entry
// wins.
func LogPathFromEnv(env []string) string {
	path := ""
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "ANSIBLE_LOG_PATH="); ok {
			path = value
		}
	}
	return path
}

func MaintainLogFromEnv(env []string) error {
	return MaintainLog(LogPathFromEnv(env))
}

var (
	sensitiveAssignment = regexp.MustCompile(`(?i)((?:["']?[A-Za-z0-9_.-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|vault[_-]?password|authorization)[A-Za-z0-9_.-]*["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,}\]]+))`)
	sensitiveFlag       = regexp.MustCompile(`(?i)(--(?:password|passwd|passphrase|secret|token|api[-_]key|access[-_]key|private[-_]key|vault[-_]password)(?:=|\s+))(?:"[^"]*"|'[^']*'|[^\s]+)`)
	// grownMarker is the marker followed by the extra brackets that each
	// pass used to add (see RedactSecrets).
	grownMarker     = regexp.MustCompile(`\[REDACTED\]\]+`)
	privateKeyBegin = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)
	privateKeyEnd   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	// ansibleRecord is the start of an Ansible log record: ansible-core
	// 2.19 writes "%(asctime)s p=%(process)d u=%(user)s n=%(name)s
	// %(levelname)s| %(message)s" (lib/ansible/utils/display.py), for
	// example "2026-09-15 09:50:37,791 p=1234 u=pilot n=ansible INFO| ";
	// earlier versions wrote "%(asctime)s p=%(user)s u=%(process)d | ".
	// Lines of a multi-line record do not carry it.
	ansibleRecord = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} p=\S+ u=\S+ (?:n=\S+ )?(?:[A-Z]+)?\| `)
	// ansibleKeyRecord is a record whose whole message could be a line of
	// key material, as when each line of a key is logged on its own.
	ansibleKeyRecord = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} p=\S+ u=\S+ (?:n=\S+ )?(?:[A-Z]+)?\| [A-Za-z0-9+/=]+\r?\n?$`)
	// ansibleItemRecord is the result of one loop item, which the default
	// callback labels with the item itself, as captured from ansible-core
	// 2.19.2: "changed: [h] => (item=<line>)", "ok: [h] => (item=<line>) =>
	// {" followed by lines such as "    \"msg\": \"<line>\"", and
	// "failed: [h] (item=<line>) => {...}". A loop over a key's lines (for
	// example with_lines: cat key.pem) logs one such record per line.
	ansibleItemRecord = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} p=\S+ u=\S+ (?:n=\S+ )?(?:[A-Z]+)?\| [a-z]+: \[[^\]]*\](?: =>)? \(item=`)
	// recordLevelPart is a start of the level and bar that end the record
	// prefix ("INFO|", or "|" in the older format).
	recordLevelPart = regexp.MustCompile(`^[A-Z]*\|?$`)
	// ansibleBanner starts a play, a task or the recap; a loop does not go
	// on past it.
	ansibleBanner = regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} p=\S+ u=\S+ (?:n=\S+ )?(?:[A-Z]+)?\| (?:PLAY \[|TASK \[|RUNNING HANDLER \[|PLAY RECAP)`)
)

const (
	redactedMarker        = "[REDACTED]"
	privateKeyPlaceholder = "[REDACTED PRIVATE KEY]"
	// redactionFormat names the redaction behaviour that the regexes do not
	// show. Change it whenever that behaviour changes, so that records
	// written under the old behaviour are not trusted (see redactionRules).
	// TestRedactionGolden fails when the behaviour changes and this does
	// not.
	redactionFormat = "pilot-ansible-log-redaction/3"
)

// RedactSecrets masks common structured secret values in one line. It is a
// defense-in-depth filter, not a replacement for Ansible no_log.
//
// One pass masks what main always masked, the same way, and then folds
// "[REDACTED]]..." back into "[REDACTED]": the value pattern stops before
// "]", so masking an already-masked value turned "[REDACTED]" into
// "[REDACTED]]", one more bracket on every pass over the log (issue #70).
// Folding only removes brackets. A masked flag value can still read
// differently to the next pass ("--token=[REDACTED]" becomes "--token=
// [REDACTED]"), so passes repeat until the line no longer changes; a line
// with nothing to mask takes one. The result masks at least what main's
// repeated passes did, and redacting it again changes nothing.
func RedactSecrets(line string) string {
	for range 4 {
		next := redactSecretsOnce(line)
		if next == line {
			break
		}
		line = next
	}
	return line
}

func redactSecretsOnce(line string) string {
	line = sensitiveAssignment.ReplaceAllStringFunc(line, func(match string) string {
		separator := strings.IndexAny(match, ":=")
		if separator < 0 {
			return redactedMarker
		}
		return match[:separator+1] + " " + redactedMarker
	})
	line = sensitiveFlag.ReplaceAllString(line, "${1}"+redactedMarker)
	return grownMarker.ReplaceAllString(line, redactedMarker)
}

// redactionRules fingerprints the redaction rules. A record made under
// other rules does not say what these rules would mask, so it is not
// trusted (AGENTS.md §5.9): after an upgrade that, say, adds a key name, the
// whole log is redacted again once.
func redactionRules() string {
	digest := sha256.New()
	for _, part := range []string{
		redactionFormat,
		sensitiveAssignment.String(),
		sensitiveFlag.String(),
		grownMarker.String(),
		privateKeyBegin.String(),
		privateKeyEnd.String(),
		ansibleRecord.String(),
		ansibleKeyRecord.String(),
		ansibleItemRecord.String(),
		ansibleBanner.String(),
		redactedMarker,
		privateKeyPlaceholder,
	} {
		_, _ = io.WriteString(digest, part) // hash.Hash writes never fail
		_, _ = digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// keyState is where a stream of log lines stands with private keys.
type keyState uint8

const (
	// inKey: inside a key's lines, up to its END marker.
	inKey keyState = 1 << iota
	// inKeyLoop: inside a loop over a key's lines (ansibleItemRecord). Each
	// item's record, and the lines that belong to it, are key material, up
	// to the item with the END marker or the next banner. Other records in
	// between, such as an error report, are judged as usual.
	inKeyLoop
	// inKeyItem: the lines that follow belong to an item's record in such
	// a loop.
	inKeyItem
)

type streamRedactor struct {
	state keyState
}

func (r *streamRedactor) redact(line string) string {
	if ansibleRecord.MatchString(line) {
		r.state &^= inKeyItem
		if r.state&inKeyLoop != 0 {
			if ansibleItemRecord.MatchString(line) {
				if privateKeyEnd.MatchString(line) {
					r.state &^= inKeyLoop
				} else {
					r.state |= inKeyItem
				}
				return preserveLineEnding(line, privateKeyPlaceholder)
			}
			if ansibleBanner.MatchString(line) {
				r.state &^= inKeyLoop
			}
		}
		// A key whose END marker never came (a cut log, or a BEGIN marker
		// quoted in a command) would otherwise mask every later line, in
		// this run and every later one. Key material never starts with
		// Ansible's record prefix, so a new record ends it, unless its whole
		// message could be a line of key material.
		if r.state&inKey != 0 && !ansibleKeyRecord.MatchString(line) {
			r.state &^= inKey
		}
	} else if r.state&inKeyItem != 0 {
		return preserveLineEnding(line, privateKeyPlaceholder)
	}
	if r.state&inKey != 0 {
		if privateKeyEnd.MatchString(line) {
			r.state &^= inKey
		}
		return preserveLineEnding(line, privateKeyPlaceholder)
	}
	if privateKeyBegin.MatchString(line) {
		if !privateKeyEnd.MatchString(line) {
			switch {
			case ansibleItemRecord.MatchString(line):
				r.state |= inKeyLoop | inKeyItem
			case strings.Contains(line, "(item="):
				// An item's record glued to the end of a line its writer
				// never finished (a killed run, then the next one): it
				// cannot be told from a key that starts in that line, so
				// both are assumed.
				r.state |= inKey | inKeyLoop | inKeyItem
			default:
				r.state |= inKey
			}
		}
		return preserveLineEnding(line, privateKeyPlaceholder)
	}
	return RedactSecrets(line)
}

// redactContinuation judges a line whose first maskedLen bytes are a final
// line that an earlier maintenance masked before its writer finished it.
// The original text of that part is gone; tail is the state after it. When
// that part was key material, the rest of the line is too, up to an END
// marker, unless the rest starts a new Ansible record. Otherwise the masked
// part and the rest are judged together, as a full pass over the log would.
func (r *streamRedactor) redactContinuation(line string, maskedLen int64, tail keyState) string {
	r.state = tail
	if tail&(inKey|inKeyItem) == 0 {
		return r.redact(line)
	}
	rest := line[maskedLen:]
	if ansibleRecord.MatchString(rest) {
		return privateKeyPlaceholder + r.redact(rest)
	}
	// The masked part is gone, so the line may have been a line of the key,
	// or a record (an item of a loop over a key, say) cut early in its
	// message. Keep every state either reading leads to: masking more is
	// the safe side, and a record or banner bounds it.
	if begin := privateKeyBegin.FindStringIndex(rest); begin != nil && !privateKeyEnd.MatchString(rest[begin[1]:]) {
		r.state |= inKey | inKeyLoop | inKeyItem
	} else if privateKeyEnd.MatchString(rest) {
		r.state &^= inKey
	}
	return preserveLineEnding(line, privateKeyPlaceholder)
}

// mayStartRecord reports whether line, a final line without its newline,
// could be an Ansible record cut before the end of its prefix (see
// ansibleRecord): "2026-09-15 09:50:37,791 p=4242 u=pilot n=ansible INFO| "
// or "2026-09-15 09:50:37,791 p=pilot u=4242 | ", up to any point.
func mayStartRecord(line string) bool {
	line = strings.TrimSuffix(line, "\r")
	const stamp = "0000-00-00 00:00:00,000"
	for i := 0; i < len(line) && i < len(stamp); i++ {
		digit := line[i] >= '0' && line[i] <= '9'
		if stamp[i] == '0' && !digit || stamp[i] != '0' && line[i] != stamp[i] {
			return false
		}
	}
	if len(line) <= len(stamp) {
		return true
	}
	tokens := strings.Split(line[len(stamp):], " ")
	if tokens[0] != "" {
		return false
	}
	tokens = tokens[1:]
	// field reports whether tokens[i] is "name=value", or, as the last
	// token, a start of one.
	field := func(i int, name string) bool {
		tok := tokens[i]
		if i == len(tokens)-1 && strings.HasPrefix(name+"=", tok) {
			return true
		}
		return strings.HasPrefix(tok, name+"=") && len(tok) > len(name)+1
	}
	i := 0
	for _, name := range []string{"p", "u"} {
		if i == len(tokens) {
			return true
		}
		if !field(i, name) {
			return false
		}
		i++
	}
	if i < len(tokens) && field(i, "n") {
		i++
	}
	if i == len(tokens) {
		return true
	}
	if i == len(tokens)-1 {
		return recordLevelPart.MatchString(tokens[i])
	}
	return false
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
	// logRotatingTempPrefix names the active log while rotation redacts it
	// (rotateRedacted).
	logRotatingTempPrefix = ".ansible-log-rotating"
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
	// EPERM: the process exists but belongs to another user, for example a
	// sudo pilot, or a container's PID 1, sharing the data directory.
	err = proc.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

// redactionState records how much of the active log is already redacted.
// Maintenance runs after every Pilot Ansible invocation, including every
// pilot_diagnose_* step, and rescanning the whole log each time cost about
// 11 s of CPU per call on a 74 MB log (issue #70). With this record each
// run only scans what was appended since the previous one.
//
// The record is trusted only while the file still holds the bytes
// maintenance left, under the same rules. PrefixSHA256 is the SHA-256 of the
// first Offset+TailLength bytes, and every run checks it before using
// Offset. Device, inode and size alone do not show that: a log truncated in
// place (O_TRUNC, "> file", logrotate copytruncate) and written again past
// the old offset, or deleted and recreated under a reused inode number,
// matches all three, and its new start would never be scanned. Rules is
// redactionRules() when the record was written. When either differs, or the
// record has neither (written by an earlier build), the whole file is
// redacted again. Hashing the prefix costs about 46 ms on a 74 MB log with
// the CPU's SHA extensions and about 160 ms without; the regex pass it
// replaces cost about 11 s.
//
// A final line without its newline is masked in place when it needs it,
// because maintenance runs after Ansible exits and that line may never be
// completed. Offset still stops at its start, so when a writer completes
// it the line is judged again, from the masked part and the rest, as a full
// pass would judge it. TailLength and TailKeyState describe the masked
// part.
type redactionState struct {
	Device       uint64   `json:"device"`
	Inode        uint64   `json:"inode"`
	Offset       int64    `json:"offset"`
	KeyState     keyState `json:"key_state"`
	TailLength   int64    `json:"tail_length,omitempty"`
	TailKeyState keyState `json:"tail_key_state,omitempty"`
	PrefixSHA256 string   `json:"prefix_sha256,omitempty"`
	Rules        string   `json:"rules_sha256,omitempty"`
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
	sweepStaleLogTemp(filepath.Dir(statePath), filepath.Base(statePath))
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

func removeRedactionState(path string) error {
	if err := os.Remove(redactionStatePath(path)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reset Ansible log redaction state: %w", err)
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

// scanCatchUp bounds how far past the size seen at open a scan reads. A
// writer outside this process may still append while maintenance holds
// the log; reading until it stops would keep maintenance, and every Ansible
// run waiting for it, going for as long as the writer is faster than the
// scan. What it appends past the bound is scanned by the next maintenance,
// or, when this one renames a new file over the log, never kept (as the
// rename of a full pass always did).
const scanCatchUp = 1 << 20

// redactRangeStarts, when set by a test, sees where each scan starts.
var redactRangeStarts func(offset int64)

// redactRange redacts input from state.Offset up to limit, or to its end
// at the time of reading if that comes first, writing the result to w when
// w is not nil and adding the part the returned record covers to digest. It returns the record for that
// result, which starts at the same offset, and whether any line changed.
// The returned Offset is just after the last complete line; a final line
// without a newline is written masked (see redactionState) but stays after
// Offset, so the next run judges it again once it is complete.
func redactRange(input io.ReaderAt, state redactionState, limit int64, w io.Writer, digest hash.Hash) (redactionState, bool, error) {
	if redactRangeStarts != nil {
		redactRangeStarts(state.Offset)
	}
	// Read past the size seen at open, up to limit (see scanCatchUp): a
	// writer that still holds the file may have appended since.
	reader := bufio.NewReaderSize(io.NewSectionReader(input, state.Offset, limit-state.Offset), 128*1024)
	redactor := streamRedactor{state: state.KeyState}
	next := redactionState{Device: state.Device, Inode: state.Inode, Offset: state.Offset, KeyState: state.KeyState, Rules: state.Rules}
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
			redacted = redactor.redactContinuation(line, state.TailLength, state.TailKeyState)
		case !complete && redactor.state&(inKey|inKeyItem) != 0 && !ansibleRecord.MatchString(line) && mayStartRecord(line):
			// The start of a record, cut before the end of its prefix. Key
			// material never looks like that (it has no "-" after digits, no
			// spaces), so it is left as it is: masking it would hide where
			// the record, and so the key's end, starts once it is complete.
			// Only up to four digits, a cut year, could also start a line
			// of key material.
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
		if covered {
			_, _ = io.WriteString(digest, redacted) // hash.Hash writes never fail
		}
		if !complete {
			if covered {
				next.TailLength = int64(len(redacted))
				next.TailKeyState = redactor.state
			}
			return next, changed, nil
		}
		next.Offset += int64(len(redacted))
		next.KeyState = redactor.state
	}
}

// redactNewLines redacts what was appended to path since the previous
// maintenance and saves the record for the result.
func redactNewLines(path string) error {
	next, save, err := redactLog(path, loadRedactionState(path), false)
	if err != nil || !save {
		return err
	}
	return saveRedactionState(path, next)
}

// redactLog redacts path, starting where state says the redacted part ends
// when the file still matches it (see redactionState), and returns the
// record for the result and whether to save it. When none of what it scans
// needs masking the file is left untouched, unless rewrite is set;
// otherwise the file is rewritten through a temp file and a rename, as
// redactFile does, but the redacted prefix is only copied, not scanned
// again. The rename also detaches any writer that still holds the old file:
// what it writes from then on reaches no file that is kept.
func redactLog(path string, state redactionState, rewrite bool) (redactionState, bool, error) {
	input, err := os.Open(path)
	if err != nil {
		return redactionState{}, false, err
	}
	defer input.Close()
	// Identity and size of the file actually read, not of whatever the
	// path names later.
	info, err := input.Stat()
	if err != nil {
		return redactionState{}, false, err
	}
	device, inode, known := fileIdentity(info)
	size := info.Size()
	limit := size + scanCatchUp
	rules := redactionRules()
	fresh := redactionState{Device: device, Inode: inode, Rules: rules}
	if !known || state.Device != device || state.Inode != inode || state.Rules != rules ||
		state.Offset < 0 || state.TailLength < 0 || state.Offset > size || state.TailLength > size-state.Offset {
		state = fresh
	}
	digest, trusted, err := verifyPrefix(input, state)
	if err != nil {
		return redactionState{}, false, err
	}
	if !trusted {
		state, digest = fresh, sha256.New()
	} else if !rewrite && state.Offset+state.TailLength == size {
		return state, false, nil
	}
	// The write pass, if one is needed, hashes from the same point.
	again, err := cloneDigest(digest, input, state.Offset)
	if err != nil {
		return redactionState{}, false, err
	}

	if !rewrite {
		next, changed, err := redactRange(input, state, limit, nil, digest)
		if err != nil {
			return redactionState{}, false, err
		}
		if !changed {
			next.PrefixSHA256 = hex.EncodeToString(digest.Sum(nil))
			return next, known, nil
		}
	}

	dir := filepath.Dir(path)
	sweepStaleLogTemp(dir, logRedactedTempPrefix)
	tmpPath := filepath.Join(dir, fmt.Sprintf("%s-%d", logRedactedTempPrefix, os.Getpid()))
	tmp, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return redactionState{}, false, err
	}
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return redactionState{}, false, err
	}
	writer := bufio.NewWriterSize(tmp, 128*1024)
	// The prefix verified above; again already holds its hash.
	if _, err := io.Copy(writer, io.NewSectionReader(input, 0, state.Offset)); err != nil {
		_ = tmp.Close()
		return redactionState{}, false, err
	}
	next, _, err := redactRange(input, state, limit, writer, again)
	if err != nil {
		_ = tmp.Close()
		return redactionState{}, false, err
	}
	if err := writer.Flush(); err != nil {
		_ = tmp.Close()
		return redactionState{}, false, err
	}
	rewritten, err := tmp.Stat()
	if err != nil {
		_ = tmp.Close()
		return redactionState{}, false, err
	}
	if err := tmp.Close(); err != nil {
		return redactionState{}, false, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return redactionState{}, false, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return redactionState{}, false, err
	}
	device, inode, known = fileIdentity(rewritten)
	next.Device, next.Inode = device, inode
	next.PrefixSHA256 = hex.EncodeToString(again.Sum(nil))
	return next, known, nil
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

// rotateRedacted moves the active log to path.1 without copying a byte that
// was not redacted. Copying it as it is would not do: an Ansible process
// that still holds the log open (Ansible keeps its log file open for the
// whole run) may have appended after the scan, and those bytes would land
// in path.1, which nothing scans again. So the log is first renamed aside
// and a new, empty active log takes its place; finishRotation then redacts
// the renamed file into path.1. If that fails, or the process is killed,
// the renamed file stays, and the next maintenance finishes the rotation
// (recoverRotations): a failure never loses the log.
func rotateRedacted(path string, policy LogPolicy) error {
	aside := filepath.Join(filepath.Dir(path), fmt.Sprintf("%s-%d", logRotatingTempPrefix, os.Getpid()))
	// The record describes the file being renamed, which keeps its inode.
	state := loadRedactionState(path)
	if err := os.Rename(path, aside); err != nil {
		return err
	}
	if err := removeRedactionState(path); err != nil {
		return err
	}
	active, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := active.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return finishRotation(path, aside, state, policy)
}

// finishRotation redacts aside, the former active log, to its end into a
// new file, whether or not anything needs masking, so a writer that still
// holds it is detached from what is kept; trims it to the newest MaxBytes;
// and moves it to path.1. state is the record for aside, if any.
func finishRotation(path, aside string, state redactionState, policy LogPolicy) error {
	if policy.MaxFiles == 0 {
		// Rotated logs are not kept at all.
		return os.Remove(aside)
	}
	if _, _, err := redactLog(aside, state, true); err != nil {
		return err
	}
	// Keep the newest part of an unexpectedly oversized existing file. This
	// prevents one historical 900 MiB log from defeating the retention bound
	// on the first run after an upgrade.
	if err := trimFileToTail(aside, policy.MaxBytes); err != nil {
		return fmt.Errorf("trim oversized Ansible log: %w", err)
	}
	return retainRotated(path, aside, policy.MaxFiles)
}

// rotationLeftoverAge is how old a renamed-aside log must be before it is
// recovered although a live process has the PID in its name: no rotation
// takes that long, so the PID was reused.
const rotationLeftoverAge = time.Hour

// recoverRotations finishes rotations that failed, or were killed, after
// renaming the log aside (rotateRedacted). Such a file holds the old log,
// possibly with lines that were never scanned; it is redacted in full and
// kept as path.1, as the rotation would have kept it, never removed with
// its content lost. A recent file whose process is still running belongs to
// a rotation in progress and is left alone.
func recoverRotations(path string, policy LogPolicy) error {
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(path), logRotatingTempPrefix+"-*"))
	if err != nil || len(matches) == 0 {
		return nil
	}
	type leftover struct {
		name    string
		modTime time.Time
	}
	var leftovers []leftover
	self := os.Getpid()
	for _, name := range matches {
		pid, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(name), logRotatingTempPrefix+"-"))
		if err != nil {
			continue
		}
		info, err := os.Stat(name)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		// This process holds logUseMu, so a file of its own is not in
		// progress: an earlier call failed.
		if pid != self && processAlive(pid) && time.Since(info.ModTime()) < rotationLeftoverAge {
			continue
		}
		leftovers = append(leftovers, leftover{name, info.ModTime()})
	}
	// Oldest first, so the newest ends up as path.1.
	sort.Slice(leftovers, func(i, j int) bool { return leftovers[i].modTime.Before(leftovers[j].modTime) })
	for _, l := range leftovers {
		if err := finishRotation(path, l.name, redactionState{}, policy); err != nil {
			return fmt.Errorf("finish an interrupted rotation of the Ansible log (%s): %w", filepath.Base(l.name), err)
		}
	}
	return nil
}

func trimFileToTail(path string, maxBytes int64) error {
	info, err := os.Stat(path)
	if err != nil || maxBytes <= 0 || info.Size() <= maxBytes {
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

// retainRotated moves rotated, the redacted former active log, to path.1.
// The loop before it is meant to shift the retained logs first, but renames
// each one to its own name, so only path.1 is ever kept (issue #82).
func retainRotated(path, rotated string, maxFiles int) error {
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
	return os.Rename(rotated, path+".1")
}
