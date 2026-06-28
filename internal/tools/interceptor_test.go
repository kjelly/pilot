package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestInterceptorShortCircuits verifies that returning a non-nil Result
// from an Interceptor prevents Execute from being called.
func TestInterceptorShortCircuits(t *testing.T) {
	var executed bool
	r := NewRegistry()
	mustReg(t, r, &Spec{
		Name:    "preview_tool",
		Execute: func(ctx context.Context, args json.RawMessage) (*Result, error) { executed = true; return &Result{Content: "real"}, nil },
		Interceptor: func(ctx context.Context, args json.RawMessage) (*Result, error) {
			return &Result{Content: "synthetic preview"}, nil
		},
	})
	spec, _ := r.Get("preview_tool")
	res, err := spec.Interceptor(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if res == nil || !strings.Contains(res.Content, "synthetic") {
		t.Fatalf("interceptor should have returned a result, got: %+v", res)
	}
	if executed {
		t.Fatal("Execute should not have been called when Interceptor returned a result")
	}
}

// TestInterceptorProceedsWhenNil verifies that returning (nil, nil)
// from an Interceptor signals "no interception".
func TestInterceptorProceedsWhenNil(t *testing.T) {
	r := NewRegistry()
	mustReg(t, r, &Spec{
		Name: "pass_through",
		Execute: func(ctx context.Context, args json.RawMessage) (*Result, error) {
			return &Result{Content: "real"}, nil
		},
		Interceptor: func(ctx context.Context, args json.RawMessage) (*Result, error) {
			return nil, nil
		},
	})
	spec, _ := r.Get("pass_through")
	res, err := spec.Interceptor(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if res != nil {
		t.Fatalf("interceptor should have returned nil result, got: %+v", res)
	}
}

// TestRunPlaybookInterceptorDryRunRewrite checks that under dry-run,
// run_ansible Interceptor + OverrideCheckFlag rewrite check=false to
// check=true.
func TestRunPlaybookInterceptorDryRunRewrite(t *testing.T) {
	tp := &RunPlaybookTool{}
	spec := tp.Spec()

	// Without dry-run, interceptor is a no-op.
	DryRun = false
	if res, _ := spec.Interceptor(context.Background(), json.RawMessage(`{"check":false}`)); res != nil {
		t.Errorf("interceptor should be no-op outside dry-run, got: %+v", res)
	}

	// With dry-run, the agent loop's handleToolCall will call
	// OverrideCheckFlag. Verify it does the rewrite correctly.
	DryRun = true
	out, err := OverrideCheckFlag(json.RawMessage(`{"check":false,"playbook":"x.yml"}`))
	if err != nil {
		t.Fatalf("OverrideCheckFlag: %v", err)
	}
	if !strings.Contains(string(out), `"check":true`) {
		t.Errorf("expected check:true after override, got: %s", out)
	}
	// check:true stays check:true (idempotent).
	out, err = OverrideCheckFlag(json.RawMessage(`{"check":true,"playbook":"x.yml"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"check":true`) {
		t.Errorf("idempotent override failed: %s", out)
	}

	// Non-object args → error.
	_, err = OverrideCheckFlag(json.RawMessage(`not-an-object`))
	if err == nil {
		t.Error("expected error overriding non-object args")
	}
}

// TestOverrideCheckFlag_NonObject — explicit, in case the test above
// didn't trigger the branch.
func TestOverrideCheckFlag_NonObject(t *testing.T) {
	_, err := OverrideCheckFlag(json.RawMessage(`"string"`))
	if err == nil {
		t.Fatal("expected error for scalar input")
	}
}

func mustReg(t *testing.T, r *Registry, s *Spec) {
	t.Helper()
	if err := r.Register(s); err != nil {
		t.Fatalf("register: %v", err)
	}
}
