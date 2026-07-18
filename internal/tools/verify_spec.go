package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/spec"
)

// VerifySpecTool replaces the standalone `scripts/spec-runner.py`.
// It walks a parsed Spec, runs each row's `command` against the
// inventory (via `ansible <host> -m command -a …`), and emits one
// NDJSON line per row.
//
// Why ansible ad-hoc instead of running commands directly?
//
//   - We get the user's SSH credentials / become settings / inventory
//     for free — same connection as the playbook they just applied.
//   - Multi-host invocations are handled by ansible's -l / -i
//     pipeline; the spec author writes one command per row, and
//     pilot fans it out across the inventory.
//   - For localhost / no-inventory, it falls back to running the
//     command locally, matching what spec-runner.py used to do.
type VerifySpecTool struct {
	Runner *ansible.Runner
	// Inventory, when non-empty, is forwarded to ansible ad-hoc.
	Inventory string
	// Limit, when non-empty, narrows the inventory pattern.
	Limit string
	// LocalOnly, when true, runs every command on the control node
	// without touching ansible. Useful for spec rows that test the
	// host that pilot itself is running on (the smoke-test case).
	LocalOnly bool
	// Host, when non-empty, overrides the default target for
	// ansible ad-hoc (default: "all").
	Host string
}

// Spec describes the tool for its caller (`pilot verify`).
func (t *VerifySpecTool) Spec() *Spec {
	return &Spec{
		Name:        "verify_spec",
		Description: "Verify a spec by running each row's command and emitting one NDJSON object per row.",
		RiskLevel:   "low",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  verifySpecArgs,
	}
}

var verifySpecArgs = json.RawMessage(`{
	"type": "object",
	"properties": {
		"spec_path": {"type": "string", "description": "Absolute path to the spec markdown file"},
		"host": {"type": "string", "description": "Override target host (default: all in inventory)"},
		"timeout_sec": {"type": "integer", "description": "Per-row command timeout in seconds (default 15)"}
	},
	"required": ["spec_path"]
}`)

type verifySpecArgsStruct struct {
	SpecPath   string `json:"spec_path"`
	Host       string `json:"host"`
	TimeoutSec int    `json:"timeout_sec"`
}

// VerifyRow is one NDJSON object emitted by VerifySpecTool.Execute.
// Mirrors what the (removed 2026-07-17) scripts/spec-runner.py
// produced, so old reports stay diffable against new ones.
type VerifyRow struct {
	ID       string `json:"id"`
	Status   string `json:"status"` // pass | fail | skip
	Detail   string `json:"detail"`
	Host     string `json:"host,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// stageVerifyEnv writes /etc/pilot-verify.env on every host reachable
// from the inventory when KEYCLOAK_ISSUER is set in our env. The spec
// rows that need to reference the issuer can `source /etc/pilot-verify.env`
// (ansible ad-hoc does NOT propagate env vars across SSH to the target,
// so we drop a file). Best-effort: spec rows fall back to the in-spec
// default if this fails.
func stageVerifyEnv(invPath string) {
	val := os.Getenv("KEYCLOAK_ISSUER")
	if val == "" || invPath == "" {
		return
	}
	content := "KEYCLOAK_ISSUER=" + val + "\n"
	args := []string{
		"all", "-i", invPath, "-m", "copy",
		"-a", fmt.Sprintf("dest=/etc/pilot-verify.env content=%s mode=0644", strconv.Quote(content)),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "ansible", args...).Run()
}

// Execute runs every row in the spec and returns the joined NDJSON
// stream as the tool Result.
func (t *VerifySpecTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a verifySpecArgsStruct
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("verify_spec: invalid args: %w", err)
	}
	if a.SpecPath == "" {
		return nil, fmt.Errorf("verify_spec: spec_path required")
	}
	parsed, err := spec.Parse(a.SpecPath)
	if err != nil {
		return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
	}
	// NOTE: spec.Lint(parsed) may report errors here; we intentionally run
	// the verifier anyway (lint issues are surfaced by `pilot spec --lint`,
	// not by the verify tool).

	timeoutSec := a.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 15
	}
	host := a.Host
	if host == "" {
		host = t.Host
	}
	stageVerifyEnv(t.Inventory)
	// Warm the SSH master ONCE before the per-row loop (ad-hoc mode only).
	// Otherwise the first row pays the full cold TCP+SSH+auth handshake
	// inside its own per-row timeout and intermittently trips the 15s
	// deadline, reporting a spurious rc=-1 on an otherwise-healthy target.
	if !t.LocalOnly && t.Inventory != "" {
		t.warmConnection(ctx, host)
	}
	rows := make([]VerifyRow, 0, len(parsed.Rows))
	for _, r := range parsed.Rows {
		vr := t.runRow(ctx, r, host, timeoutSec)
		rows = append(rows, vr)
	}

	var sb strings.Builder
	for _, r := range rows {
		b, _ := json.Marshal(r)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return &Result{Content: sb.String()}, nil
}

// runRow runs one spec row against either ansible ad-hoc or a local
// shell, depending on t.LocalOnly / inventory presence.
func (t *VerifySpecTool) runRow(ctx context.Context, r spec.Row, host string, timeoutSec int) VerifyRow {
	if r.Command == "" {
		return VerifyRow{ID: r.ID, Status: "skip", Detail: "no command"}
	}
	if t.LocalOnly || t.Inventory == "" {
		return t.runLocal(ctx, r, timeoutSec)
	}
	return t.runAnsibleAdHoc(ctx, r, host, timeoutSec)
}

func (t *VerifySpecTool) runLocal(ctx context.Context, r spec.Row, timeoutSec int) VerifyRow {
	timeout := time.Duration(timeoutSec) * time.Second
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "sh", "-c", r.Command)
	out, err := cmd.CombinedOutput()
	rawOut := strings.TrimSpace(string(out))
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		}
	}
	detail := fmt.Sprintf("(rc=%d) %s", rc, rawOut)
	ok, mismatch := matchExpected(r.Expected, detail, rc)
	status := "pass"
	if !ok {
		status = "fail"
	}
	return VerifyRow{ID: r.ID, Status: status, Detail: mismatch, ExitCode: rc}
}

func (t *VerifySpecTool) runAnsibleAdHoc(ctx context.Context, r spec.Row, host string, timeoutSec int) VerifyRow {
	// ansible <host|all> -i <inv> -m command -a "<row.Command>" --one-line
	target := host
	if target == "" {
		target = "all"
	}
	module := adHocModule(r.Command)
	// Decide privilege the SAME way the apply path does: spec.NeedsBecome
	// is the single source of truth. If the row touches root-owned state
	// (a privileged path, systemctl, the docker socket, pg_isready, …),
	// apply generated the task with `become: true`, so verify must run it
	// with `-b` too — otherwise verify reports false-negatives on
	// operations that apply already performed as root.
	become := spec.NeedsBecome(r)
	slog.Debug("verify ad-hoc", "module", module, "cmd", r.Command, "become", become)
	args := []string{target, "-i", t.Inventory, "-m", module, "-a", r.Command, "--one-line"}
	if t.Limit != "" {
		args = append(args, "-l", t.Limit)
	}
	if become {
		args = append(args, "-b")
	}
	rc, rawOut := t.execAnsible(ctx, args, timeoutSec)

	// Reactive safety net: if the heuristic missed it and the command
	// failed with what looks like a privilege error, retry once with
	// become. The vm-target's ubuntu user has NOPASSWD sudo, so this
	// never prompts; the extra round-trip only hits rows that already
	// failed. Skip when we already escalated (become == true) — a second
	// identical run would just fail the same way.
	if !become && rc != 0 && looksLikePermissionError(rawOut) {
		retryArgs := append(append([]string{}, args...), "-b") // copy: args may have spare cap from -l
		rc, rawOut = t.execAnsible(ctx, retryArgs, timeoutSec)
		rawOut = "[escalated] " + rawOut // mark in the report for traceability
	}

	detail := fmt.Sprintf("(rc=%d) %s", rc, rawOut)
	ok, mismatch := matchExpected(r.Expected, detail, rc)
	status := "pass"
	if !ok {
		status = "fail"
	}
	return VerifyRow{ID: r.ID, Status: status, Detail: mismatch, ExitCode: rc}
}

// adHocModule picks the ansible module for a spec command: `shell` when the
// command uses shell features (pipes, redirects, sequencing, expansion),
// otherwise `command`. Kept as a package function so both the row runner and
// the --probe path decide identically.
func adHocModule(command string) string {
	for _, c := range command {
		if c == '|' || c == '>' || c == '<' || c == ';' || c == '$' || c == '`' {
			return "shell"
		}
	}
	if strings.Contains(command, "&&") || strings.Contains(command, "||") {
		return "shell"
	}
	return "command"
}

// warmConnection opens (and, via the inventory's ControlPersist, leaves open)
// the SSH master connection once before the per-row loop. Best-effort: any
// failure here is ignored — a real connectivity problem still surfaces on the
// row itself. Uses a generous fixed budget so a cold connect completes
// regardless of the (possibly tight) per-row timeout, and the `raw` module so
// it needs no remote Python.
func (t *VerifySpecTool) warmConnection(ctx context.Context, host string) {
	target := host
	if target == "" {
		target = "all"
	}
	args := []string{target, "-i", t.Inventory, "-m", "raw", "-a", "true", "--one-line"}
	if t.Limit != "" {
		args = append(args, "-l", t.Limit)
	}
	_, _ = t.execAnsible(ctx, args, 60)
}

// execAnsible runs one `ansible` ad-hoc invocation and returns its exit
// code and trimmed combined output. We piggy-back on the same ansible
// binary that drives run_ansible; ansible.Runner.Run is hardcoded to
// ansible-playbook, so we shell out to `ansible` directly here to keep
// the dependency surface small and avoid refactoring Runner.Run.
func (t *VerifySpecTool) execAnsible(ctx context.Context, args []string, timeoutSec int) (int, string) {
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ansible", args...).CombinedOutput()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	}
	return rc, strings.TrimSpace(string(out))
}

// permissionErrorRe matches the stderr signatures a command emits when
// it fails purely for lack of privilege. Kept narrow enough that a
// non-permission failure that merely mentions "denied" in unrelated
// output won't trip it — and it only ever runs on already-failed rows,
// so a rare false positive costs one extra become round-trip, nothing more.
var permissionErrorRe = regexp.MustCompile(`(?i)permission denied` +
	`|operation not permitted` +
	`|must be root|are you root|need(s)? to be root|requires root` +
	`|(has|have) to be run (as|under)[^.]*root` + // ansible: "run under the root user"
	`|to be run as root|run as the root` +
	`|connect: permission denied` + // docker: dial unix /var/run/docker.sock
	`|docker daemon socket` +
	`|eacces|access is denied|insufficient priv`)

// looksLikePermissionError reports whether ad-hoc output reads like a
// privilege failure, gating the verify-path reactive become retry.
func looksLikePermissionError(out string) bool {
	return permissionErrorRe.MatchString(out)
}

// matchExpected decides whether captured stdout (or, for rc-equality,
// the captured rc) satisfies the spec row's Expected value. The
// previous implementation only checked exit code, which made rows
// like C1 in pam-oidc-sshd report pass when the command explicitly
// printed `1` (the rc-echo trick). The matrix this implements:
//
//	expected == ""          → rc == 0
//	expected starts with "^" → anchored regex on stripped stdout
//	expected is a pure int   → rc (taken from stdout `(rc=N)` first)
//	expected == "present"    → rc == 0
//	otherwise                → exact equality after trim
//
// The second case is what unblocks the verify-passes-when-it-shouldn't
// regression in the pam-oidc-sshd spec.
func matchExpected(expected, detail string, rc int) (bool, string) {

	expected = strings.TrimSpace(expected)
	clean := stripRunnerPrefix(detail)
	rcOnly := extractRC(detail)

	switch {
	case expected == "":
		return rc == 0, "expected: rc=0 (default)"
	case strings.HasPrefix(expected, "^"):
		re, err := regexp.Compile(expected)
		if err != nil {
			return false, fmt.Sprintf("invalid regex %q: %v", expected, err)
		}
		if re.MatchString(clean) {
			return true, fmt.Sprintf("regex %q matched %q", expected, truncate(clean, 80))
		}
		return false, fmt.Sprintf("regex %q did not match stdout %q", expected, truncate(clean, 80))
	case isInt(expected):
		want := atoi(expected)
		if rcOnly >= 0 {
			if rcOnly == want {
				return true, fmt.Sprintf("rc-from-stdout=%d matches expected %d", rcOnly, want)
			}
			return false, fmt.Sprintf("rc-from-stdout=%d, expected %d", rcOnly, want)
		}
		if rc == want {
			return true, fmt.Sprintf("rc=%d matches expected %d", rc, want)
		}
		return false, fmt.Sprintf("rc=%d, expected %d (detail: %q)", rc, want, truncate(detail, 80))
	case expected == "present":
		return rc == 0, "expected: present (rc=0)"
	case strings.HasPrefix(expected, "~"):
		want := strings.TrimPrefix(expected, "~")
		if strings.Contains(clean, want) {
			return true, fmt.Sprintf("stdout contains %q", want)
		}
		return false, fmt.Sprintf("stdout=%q, expected substring ~%q", truncate(clean, 80), want)
	default:
		if clean == expected {
			return true, fmt.Sprintf("stdout matched %q", expected)
		}
		return false, fmt.Sprintf("stdout=%q, expected %q", truncate(clean, 80), expected)
	}
}

// stripRunnerPrefix removes a leading rc-only or "(rc=N)" marker from
// the captured detail so comparison focuses on the semantic content.
// Pure rc echo (e.g. `sh -c 'cmd; echo $?'`) becomes "" so rc-equality
// expected values compare cleanly.
func stripRunnerPrefix(s string) string {
	if isInt(s) {
		return ""
	}
	if rcOnlyPattern.MatchString(s) {
		return ""
	}
	if loc := rcPrefixPattern.FindStringIndex(s); loc != nil {
		return unwrapAdhocOneline(strings.TrimSpace(s[loc[1]:]))
	}
	return unwrapAdhocOneline(s)
}

// extractRC pulls a recovered rc from the runner-prefixed detail.
// Returns -1 when no rc is present.
func extractRC(s string) int {
	// 1) Pure rc echo: the whole string is an integer (e.g. `sh -c 'cmd; echo $?'`).
	if isInt(s) {
		return atoi(s)
	}
	// 2) Runner-prepended "(rc=N) ...": skip that prefix and look at the rest.
	stripped := s
	if loc := rcPrefixPattern.FindStringIndex(s); loc != nil {
		stripped = strings.TrimSpace(s[loc[1]:])
	}
	// 3) If the remaining stdout is itself an integer, that's the rc-echo.
	if isInt(stripped) {
		return atoi(stripped)
	}
	// 4) Ansible ad-hoc (`-i inventory`) wraps the real stdout in its
	// "--one-line" callback format ("<host> | CHANGED | rc=0 | (stdout) N"),
	// possibly behind [WARNING]/[DEPRECATION WARNING] lines. Unwrap it and
	// retry — without this, every ad-hoc-verified numeric check using the
	// `cmd; echo $?` / `cmd && echo 0 || echo 1` idiom (the very idiom this
	// repo's spec template recommends to avoid trap 1) would silently
	// always resolve to the ansible process's own exit code instead — which
	// is always 0 for that idiom, since the trailing echo always succeeds.
	if unwrapped := unwrapAdhocOneline(stripped); unwrapped != stripped && isInt(unwrapped) {
		return atoi(unwrapped)
	}
	return -1
}

func isInt(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '-' && i == 0 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

var (
	rcOnlyPattern   = regexp.MustCompile(`^\(rc=\d+\)$`)
	rcPrefixPattern = regexp.MustCompile(`^\(rc=\d+\)\s+`)

	// adhocResultLineRe locates the "| rc=N" segment of ansible's
	// `--one-line` ad-hoc callback output, e.g.
	// "myhost | CHANGED | rc=0 | (stdout) 2". When the command also wrote
	// to stderr, ansible appends " (stderr) <text>" right after the
	// "(stdout) <text>" segment on the SAME line with no separator — that
	// tail must be cut off, not folded into the captured stdout.
	adhocResultLineRe = regexp.MustCompile(`\|\s*rc=-?\d+\b`)
)

// unwrapAdhocOneline extracts the real remote command output from
// ansible's `--one-line` ad-hoc callback line
// ("<host> | STATUS | rc=N | (stdout) <text> [(stderr) <text>]"), scanning
// from the last line backwards so any "[WARNING]"/"[DEPRECATION WARNING]"
// lines ansible prints ahead of the result line don't interfere. Commands
// captured outside ad-hoc mode (no such wrapper line present, e.g. --local
// runs) are returned unchanged — this is a no-op there, not a hazard.
func unwrapAdhocOneline(s string) string {
	const stdoutMarker = "(stdout)"
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		loc := adhocResultLineRe.FindStringIndex(line)
		if loc == nil {
			continue
		}
		rest := line[loc[1]:]
		idx := strings.Index(rest, stdoutMarker)
		if idx < 0 {
			// Recognized ad-hoc result line, but no stdout was captured
			// (empty stdout, or a stderr-only failure).
			return ""
		}
		out := strings.TrimSpace(rest[idx+len(stdoutMarker):])
		if j := strings.Index(out, " (stderr)"); j >= 0 {
			out = strings.TrimSpace(out[:j])
		}
		return out
	}
	return s
}

// ProbeResult is the outcome of VerifySpecTool.Probe: one candidate command
// run through the exact verify pipeline, with every intermediate value the
// matcher sees exposed so a spec author can pick the right Expected grammar
// (rc vs ~contains vs ^regex) without guessing.
type ProbeResult struct {
	Command  string `json:"command"`
	Expected string `json:"expected"`
	Module   string `json:"module"` // command | shell | local
	Become   bool   `json:"become"`
	RC       int    `json:"rc"`
	Raw      string `json:"raw"`   // trimmed combined output as the matcher receives it
	Clean    string `json:"clean"` // Raw with the "(rc=N)" runner prefix stripped
	Pass     bool   `json:"pass"`  // only meaningful when Expected != ""
	Verdict  string `json:"verdict"`
}

// Probe runs a single command through the same module/become/ad-hoc (or local)
// path as a real spec row and returns the raw + cleaned output plus the match
// verdict for the given expected value. It writes no NDJSON, no report and no
// store rows — it exists purely to make authoring Expected values a
// see-what-verify-sees exercise. When expected is "", Pass/Verdict reflect the
// default rc==0 rule.
func (t *VerifySpecTool) Probe(ctx context.Context, command, expected, host string, timeoutSec int) ProbeResult {
	if timeoutSec <= 0 {
		timeoutSec = 15
	}
	r := spec.Row{ID: "probe", Command: command, Expected: expected}
	var (
		rc     int
		rawOut string
		module string
		become bool
	)
	if t.LocalOnly || t.Inventory == "" {
		module = "local"
		cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
		out, err := exec.CommandContext(cctx, "sh", "-c", command).CombinedOutput()
		cancel()
		rawOut = strings.TrimSpace(string(out))
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		}
	} else {
		target := host
		if target == "" {
			target = t.Host
		}
		if target == "" {
			target = "all"
		}
		module = adHocModule(command)
		become = spec.NeedsBecome(r)
		t.warmConnection(ctx, target)
		args := []string{target, "-i", t.Inventory, "-m", module, "-a", command, "--one-line"}
		if t.Limit != "" {
			args = append(args, "-l", t.Limit)
		}
		if become {
			args = append(args, "-b")
		}
		rc, rawOut = t.execAnsible(ctx, args, timeoutSec)
	}
	detail := fmt.Sprintf("(rc=%d) %s", rc, rawOut)
	pass, verdict := matchExpected(expected, detail, rc)
	return ProbeResult{
		Command:  command,
		Expected: expected,
		Module:   module,
		Become:   become,
		RC:       rc,
		Raw:      rawOut,
		Clean:    stripRunnerPrefix(detail),
		Pass:     pass,
		Verdict:  verdict,
	}
}

// ReadNDJSON is a helper for the CLI to parse the Result.Content
// back into VerifyRow slices.
func ReadNDJSON(content string) ([]VerifyRow, error) {
	var out []VerifyRow
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var vr VerifyRow
		if err := json.Unmarshal([]byte(line), &vr); err != nil {
			return nil, fmt.Errorf("verify_spec: malformed NDJSON line %q: %w", line, err)
		}
		out = append(out, vr)
	}
	return out, scanner.Err()
}
