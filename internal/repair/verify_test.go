package repair

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kjelly/pilot/internal/tools"
)

type fakeVerifyExecutor struct {
	result  *tools.Result
	err     error
	gotArgs json.RawMessage
}

func (f *fakeVerifyExecutor) Execute(ctx context.Context, args json.RawMessage) (*tools.Result, error) {
	f.gotArgs = args
	return f.result, f.err
}

func ndjson(rows ...tools.VerifyRow) string {
	var out string
	for _, r := range rows {
		b, _ := json.Marshal(r)
		out += string(b) + "\n"
	}
	return out
}

func TestVerifyAfterExecution_AllPass(t *testing.T) {
	fake := &fakeVerifyExecutor{result: &tools.Result{Content: ndjson(
		tools.VerifyRow{ID: "C1", Status: "pass"},
		tools.VerifyRow{ID: "C2", Status: "skip"},
	)}}
	out, err := VerifyAfterExecution(context.Background(), fake, "docs/verification/prometheus.md", "web-1", 30)
	if err != nil {
		t.Fatalf("VerifyAfterExecution: %v", err)
	}
	if !out.Passed {
		t.Fatalf("Passed = false, want true; rows=%+v", out.Rows)
	}
	if len(out.Rows) != 2 {
		t.Fatalf("rows = %+v, want 2", out.Rows)
	}
}

func TestVerifyAfterExecution_AnyFailFailsWholeOutcome(t *testing.T) {
	fake := &fakeVerifyExecutor{result: &tools.Result{Content: ndjson(
		tools.VerifyRow{ID: "C1", Status: "pass"},
		tools.VerifyRow{ID: "C2", Status: "fail", Detail: "readiness endpoint returned 503"},
	)}}
	out, err := VerifyAfterExecution(context.Background(), fake, "docs/verification/prometheus.md", "web-1", 30)
	if err != nil {
		t.Fatalf("VerifyAfterExecution: %v", err)
	}
	if out.Passed {
		t.Fatal("Passed = true, want false — a resolved alert with failed verification is still remediation failure")
	}
}

func TestVerifyAfterExecution_ScopesToExactHost(t *testing.T) {
	fake := &fakeVerifyExecutor{result: &tools.Result{Content: ndjson(tools.VerifyRow{ID: "C1", Status: "pass"})}}
	if _, err := VerifyAfterExecution(context.Background(), fake, "docs/verification/prometheus.md", "web-1", 30); err != nil {
		t.Fatalf("VerifyAfterExecution: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(fake.gotArgs, &got); err != nil {
		t.Fatalf("unmarshal args: %v", err)
	}
	if got["host"] != "web-1" {
		t.Errorf("host arg = %v, want web-1", got["host"])
	}
	if got["spec_path"] != "docs/verification/prometheus.md" {
		t.Errorf("spec_path arg = %v", got["spec_path"])
	}
}

func TestVerifyAfterExecution_ToolErrorSurfaces(t *testing.T) {
	fake := &fakeVerifyExecutor{result: &tools.Result{IsError: true, Content: "spec not found"}}
	if _, err := VerifyAfterExecution(context.Background(), fake, "docs/verification/missing.md", "web-1", 30); err == nil {
		t.Fatal("expected an error when the verify tool itself errors")
	}
}
