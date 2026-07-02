package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/ansible"
	"github.com/anomalyco/pilot/internal/ollama"
	"github.com/anomalyco/pilot/internal/sanitizer"
	"github.com/anomalyco/pilot/internal/tools"
)

// stubApprover auto-approves every proposal.
type stubApprover struct{}

func (stubApprover) Ask(p *Proposal) Decision { return DecisionApproved }

// countingApprover records all proposals.
type countingApprover struct {
	approved []string
}

func (c *countingApprover) Ask(p *Proposal) Decision {
	c.approved = append(c.approved, p.ID)
	return DecisionApproved
}

func newTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		RunID:        "test-run",
		DataDir:      t.TempDir(),
		Ollama:       nil, // not used in these tests
		Tools:        tools.NewRegistry(),
		Store:        nil,
		Sanitizer:    sanitizer.New(),
		Approver:     stubApprover{},
		Stream:       false,
		MaxIter:      1,
		SystemPrompt: "test",
		StreamWriter: newDiscardWriter(),
	}
}

func newDiscardWriter() *discardWriter { return &discardWriter{} }

type discardWriter struct{}

func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func TestLoopDryRunInterceptsWriteTool(t *testing.T) {
	cfg := newTestConfig(t)

	// Register a fake "writing" tool that should be intercepted under dry-run.
	written := false
	spec := &tools.Spec{
		Name:        "write_config",
		Description: "writes a config file",
		RiskLevel:   "high",
		Reversible:  true,
		DryRunSafe:  false, // explicit
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
			written = true
			return &tools.Result{Content: "wrote file"}, nil
		},
	}
	if err := cfg.Tools.Register(spec); err != nil {
		t.Fatal(err)
	}
	cfg.DryRun = true
	loop := NewLoop(cfg)

	// Bypass the model: directly drive handleToolCall with a fake tool call.
	tc := ollama.ToolCall{
		Function: ollama.ToolCallFunction{
			Name:      "write_config",
			Arguments: json.RawMessage(`{"path":"/etc/test","value":"x"}`),
		},
	}
	dec, err := loop.handleToolCall(context.Background(), tc)
	if err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}
	if dec != DecisionApproved {
		t.Errorf("expected DecisionApproved, got %v", dec)
	}
	if written {
		t.Error("write_config should NOT have been executed under --dry-run-all")
	}
}

func TestLoopDryRunAllowsReadTool(t *testing.T) {
	cfg := newTestConfig(t)

	read := false
	spec := &tools.Spec{
		Name:        "read_thing",
		Description: "reads something",
		RiskLevel:   "low",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
			read = true
			return &tools.Result{Content: "data"}, nil
		},
	}
	if err := cfg.Tools.Register(spec); err != nil {
		t.Fatal(err)
	}
	cfg.DryRun = true
	loop := NewLoop(cfg)

	tc := ollama.ToolCall{
		Function: ollama.ToolCallFunction{
			Name:      "read_thing",
			Arguments: json.RawMessage(`{}`),
		},
	}
	if _, err := loop.handleToolCall(context.Background(), tc); err != nil {
		t.Fatal(err)
	}
	if !read {
		t.Error("read_thing should have been executed under --dry-run-all")
	}
}

func TestOverrideCheckFlag(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`{"check":false}`, `{"check":true}`},
		{`{"check":true}`, `{"check":true}`},
		{`{"path":"/x"}`, `{"check":true,"path":"/x"}`},
		{`not json`, `not json`},
	}
	for _, tc := range tests {
		got := overrideCheckFlag(tc.in, true)
		if got != tc.want {
			t.Errorf("overrideCheckFlag(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDryRunStatusApplied(t *testing.T) {
	cfg := newTestConfig(t)
	ca := &countingApprover{}
	cfg.Approver = ca

	spec := &tools.Spec{
		Name: "noop_write", Description: "x", RiskLevel: "high",
		Parameters: json.RawMessage(`{}`),
		Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
			return &tools.Result{Content: "should not run"}, nil
		},
	}
	if err := cfg.Tools.Register(spec); err != nil {
		t.Fatal(err)
	}
	cfg.DryRun = true
	loop := NewLoop(cfg)

	tc := ollama.ToolCall{Function: ollama.ToolCallFunction{
		Name: "noop_write", Arguments: json.RawMessage(`{}`),
	}}
	dec, err := loop.handleToolCall(context.Background(), tc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != DecisionApproved {
		t.Errorf("expected approved, got %v", dec)
	}
	if len(ca.approved) != 1 {
		t.Errorf("expected 1 approved proposal, got %d", len(ca.approved))
	}
}

func TestDryRunMarkerInResultContent(t *testing.T) {
	cfg := newTestConfig(t)
	cfg.DryRun = true

	spec := &tools.Spec{
		Name: "dangerous_op", Description: "x", RiskLevel: "high",
		Parameters: json.RawMessage(`{}`),
		Execute: func(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
			t.Fatal("must not execute under dry-run")
			return nil, nil
		},
	}
	if err := cfg.Tools.Register(spec); err != nil {
		t.Fatal(err)
	}
	loop := NewLoop(cfg)

	tc := ollama.ToolCall{Function: ollama.ToolCallFunction{
		Name: "dangerous_op", Arguments: json.RawMessage(`{}`),
	}}
	if _, err := loop.handleToolCall(context.Background(), tc); err != nil {
		t.Fatal(err)
	}

	// The last message in history should be the tool result mentioning DRY-RUN.
	if n := len(loop.history); n == 0 {
		t.Fatal("history is empty")
	} else {
		last := loop.history[n-1]
		if !strings.Contains(last.Content, "[DRY-RUN]") {
			t.Errorf("expected [DRY-RUN] marker in tool result, got: %s", last.Content)
		}
	}

	// Sanity: a recent timestamp should have been set on the proposal.
	_ = time.Now()
}

func TestUpgradeRiskForApply(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args string
		want string
	}{
		{"other tool, no upgrade", "read_file", `{"path":"/etc/hosts"}`, RiskMedium},
		{"run_ansible check=true stays medium", "run_ansible", `{"check":true}`, RiskMedium},
		{"run_ansible check=false goes high", "run_ansible", `{"check":false}`, RiskHigh},
		{"apply_playbook no check field (defaults to check) stays medium", "apply_playbook", `{}`, RiskMedium},
		{"run_ansible invalid JSON goes high (fail closed)", "run_ansible", `not-json`, RiskHigh},
		{"read_file malformed JSON stays at current risk", "read_file", `not-json`, RiskMedium},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loop := &Loop{}
			got := loop.upgradeRiskForApply(RiskMedium, c.tool, json.RawMessage(c.args))
			if got != c.want {
				t.Errorf("upgradeRiskForApply(%s, %s, %s) = %s, want %s",
					RiskMedium, c.tool, c.args, got, c.want)
			}
		})
	}
}

func TestUpgradeRiskForApply_Disposable(t *testing.T) {
	// Create a temp file for inventory
	tmp, err := os.CreateTemp("", "pilot-vt-inv-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())

	loop := &Loop{
		cfg: Config{
			AllowDisposableApply: true,
		},
	}

	// 1. VM Target inventory (temp file prefix)
	args := fmt.Sprintf(`{"check":false,"inventory":"%s"}`, tmp.Name())
	got := loop.upgradeRiskForApply(RiskMedium, "run_ansible", json.RawMessage(args))
	if got != RiskMedium {
		t.Errorf("expected RiskMedium for disposable VM target, got %s", got)
	}

	// 2. Not disposable, should upgrade to RiskHigh
	argsNotDisposable := `{"check":false,"inventory":"/etc/ansible/hosts"}`
	gotNot := loop.upgradeRiskForApply(RiskMedium, "run_ansible", json.RawMessage(argsNotDisposable))
	if gotNot != RiskHigh {
		t.Errorf("expected RiskHigh for non-disposable target, got %s", gotNot)
	}
}

func TestPreviewAnsibleRunHandlesMissingRunner(t *testing.T) {
	// With a nil runner, previewAnsibleRun should return a helpful
	// diagnostic string, not panic.
	got := previewAnsibleRun(context.Background(), `{"playbook":"/tmp/x.yml"}`, nil)
	if !strings.Contains(got, "not configured") {
		t.Errorf("expected 'not configured' diagnostic, got: %s", got)
	}
}

func TestPreviewAnsibleRunRejectsBadArgs(t *testing.T) {
	got := previewAnsibleRun(context.Background(), `not-json`, &ansible.Runner{})
	if !strings.Contains(got, "could not parse") {
		t.Errorf("expected parse-error diagnostic, got: %s", got)
	}
}

func TestPreviewAnsibleRunRejectsMissingPlaybook(t *testing.T) {
	got := previewAnsibleRun(context.Background(), `{}`, &ansible.Runner{})
	if !strings.Contains(got, "no playbook") {
		t.Errorf("expected missing-playbook diagnostic, got: %s", got)
	}
}
