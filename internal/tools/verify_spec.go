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
	"github.com/anomalyco/pilot/internal/store"
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
	// ansible ad-hoc. With an inventory, no implicit remote "all" scope
	// exists: a spec target table or an explicit --host/--limit is required.
	Host string
	// PerHostWorkers bounds concurrent isolated host×row invocations. Zero
	// selects the production default (8); larger values are capped at 8.
	PerHostWorkers int
	// EvidenceWriter, when present, receives one immutable observation for
	// every host×row result before Execute returns.
	EvidenceWriter *store.RunWriter

	// Test seams: production uses Ansible for both operations. Kept private so
	// callers cannot accidentally replace the evidence path.
	listHosts ansibleHostLister
	runJSON   ansibleJSONRunner
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
	ID          string `json:"id"`
	Status      string `json:"status"` // pass | fail | skip
	Detail      string `json:"detail"`
	Host        string `json:"host,omitempty"`
	ExitCode    int    `json:"exit_code,omitempty"`
	ProbeStatus string `json:"probe_status,omitempty"`
	Stdout      string `json:"stdout,omitempty"`
	Stderr      string `json:"stderr,omitempty"`
	Message     string `json:"message,omitempty"`
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
	var remoteHosts []string
	if !t.LocalOnly && t.Inventory != "" {
		resolution, err := t.resolveRemoteHosts(ctx, parsed, host)
		if err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: resolve verification hosts: %v", err), IsError: true}, nil
		}
		remoteHosts = resolution.Hosts
		for _, finding := range resolution.Findings {
			slog.Warn("verify host-scope finding", "finding", finding)
		}
	}
	rows := make([]VerifyRow, 0, len(parsed.Rows)*max(1, len(remoteHosts)))
	for _, r := range parsed.Rows {
		if !t.LocalOnly && t.Inventory != "" {
			if r.Command == "" {
				for _, remoteHost := range remoteHosts {
					rows = append(rows, VerifyRow{ID: r.ID, Status: "skip", Detail: "no command", Host: remoteHost})
				}
				continue
			}
			rows = append(rows, t.runAnsiblePerHost(ctx, r, remoteHosts, timeoutSec)...)
			continue
		}
		rows = append(rows, t.runRow(ctx, r, host, timeoutSec))
	}
	if t.EvidenceWriter != nil {
		if err := t.appendEvidence(ctx, parsed, rows); err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: append verification evidence: %v", err), IsError: true}, nil
		}
	}

	var sb strings.Builder
	for _, r := range rows {
		b, _ := json.Marshal(r)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return &Result{Content: sb.String()}, nil
}

func (t *VerifySpecTool) appendEvidence(ctx context.Context, parsed *spec.Spec, rows []VerifyRow) error {
	byID := make(map[string]spec.Row, len(parsed.Rows))
	for _, row := range parsed.Rows {
		byID[row.ID] = row
	}
	evidence := make([]store.VerifyEvidence, 0, len(rows))
	for i, result := range rows {
		if result.Status == "skip" {
			continue
		}
		row, ok := byID[result.ID]
		if !ok {
			return fmt.Errorf("result references unknown spec row %q", result.ID)
		}
		host := result.Host
		if host == "" {
			host = "localhost"
		}
		verdict := result.Status
		evidence = append(evidence, store.VerifyEvidence{
			SpecPath:    parsed.Path,
			RowID:       result.ID,
			Host:        host,
			Attempt:     1,
			OperationID: fmt.Sprintf("verify:%s:%s:%s:%d", parsed.Path, result.ID, host, i),
			Command:     row.Command,
			Expected:    row.Expected,
			Stdout:      result.Stdout,
			Stderr:      result.Stderr,
			ExitCode:    result.ExitCode,
			ProbeStatus: firstNonEmpty(result.ProbeStatus, "local"),
			Verdict:     verdict,
		})
	}
	return t.EvidenceWriter.AppendEvidence(ctx, evidence)
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
	ok, mismatch := evaluateV1Expected(r.Expected, detail, rc)
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
	ok, mismatch := evaluateV1Expected(r.Expected, detail, rc)
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

// evaluateV1Expected is the v1 compatibility boundary. It adapts historical
// detail output to a normalized ProbeResult, then delegates all comparison to
// spec.Expect.Eval. New formats must construct ProbeResult directly instead.
func evaluateV1Expected(expected, detail string, rc int) (bool, string) {
	matcher, err := spec.CompileV1Expected(expected)
	if err != nil {
		return false, err.Error()
	}
	clean := stripRunnerPrefix(detail)
	var legacyRC *int
	if recovered := extractRC(detail); recovered >= 0 {
		legacyRC = &recovered
	}
	verdict := matcher.Eval(spec.ProbeResult{Stdout: clean, ExitCode: rc, LegacyExitCode: legacyRC})
	return verdict.Pass, verdict.Detail
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
	pass, verdict := evaluateV1Expected(expected, detail, rc)
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
