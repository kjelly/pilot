package tools

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/spec"
)

// VerifySpecTool replaces the standalone `scripts/spec-runner.py`.
// It walks a parsed Spec, runs each row's `command` against the
// inventory (via `ansible <host> -m command -a …`), and emits one
// NDJSON line per row. Results are also written to
// proposal_results when a ProposalID is provided (linking verify
// output back to the spec → apply lifecycle).
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
	// ProposalID, when non-empty, records each NDJSON result into
	// proposal_results (joined on ProposalID + row ID) so the
	// store can answer "did requirement C2.5.1 pass on proposal P?".
	ProposalID string
	// Host, when non-empty, overrides the default target for
	// ansible ad-hoc (default: "all").
	Host string
}

// Spec is the tool spec exposed to the LLM agent loop.
func (t *VerifySpecTool) Spec() *Spec {
	return &Spec{
		Name:        "verify_spec",
		Description: "Verify a spec by running each row's command and emitting one NDJSON object per row. Use after a `pilot spec --apply` to close the loop.",
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
// Mirrors what scripts/spec-runner.py produced, so downstream
// tooling (render-report.py, dashboards) keeps working.
type VerifyRow struct {
	ID       string `json:"id"`
	Status   string `json:"status"`   // pass | fail | skip
	Detail   string `json:"detail"`
	Host     string `json:"host,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
}

// Execute runs every row in the spec and returns the joined NDJSON
// stream as the tool Result. It does NOT touch proposal_results —
// callers that need that should call RecordVerifyResults separately
// (the cmd/pilot/cmd/verify.go path does this).
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
	if findings := spec.Lint(parsed); spec.HasErrors(findings) {
		// Run anyway but warn — verifier might be the first time
		// an author sees the lint issues.
	}

	timeoutSec := a.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 15
	}
	host := a.Host
	if host == "" {
		host = t.Host
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
	vr := VerifyRow{ID: r.ID, Detail: strings.TrimSpace(string(out))}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			vr.ExitCode = ee.ExitCode()
		}
		vr.Status = "fail"
		return vr
	}
	vr.Status = "pass"
	return vr
}

func (t *VerifySpecTool) runAnsibleAdHoc(ctx context.Context, r spec.Row, host string, timeoutSec int) VerifyRow {
	// ansible <host|all> -i <inv> -m command -a "<row.Command>" --one-line
	target := host
	if target == "" {
		target = "all"
	}
	args := []string{target, "-i", t.Inventory, "-m", "command", "-a", r.Command, "--one-line"}
	if t.Limit != "" {
		args = append(args, "-l", t.Limit)
	}
	// We piggy-back on the same ansible.Runner that drives run_ansible.
	// Runner.Run is hardcoded to ansible-playbook, so we shell out to
	// `ansible` directly here. This keeps the dependency surface small
	// and avoids refactoring Runner.Run's signature.
	cctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()
	out, err := exec.CommandContext(cctx, "ansible", args...).CombinedOutput()
	vr := VerifyRow{ID: r.ID, Detail: strings.TrimSpace(string(out))}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			vr.ExitCode = ee.ExitCode()
		}
		vr.Status = "fail"
		return vr
	}
	vr.Status = "pass"
	return vr
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
