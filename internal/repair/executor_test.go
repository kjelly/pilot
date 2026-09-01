package repair

import (
	"context"
	"encoding/json"
	"testing"
)

func TestExecutorStep_KnownKinds(t *testing.T) {
	cases := []struct {
		kind, target, wantCommand string
	}{
		{"docker_restart", "pilot-prometheus", "docker restart pilot-prometheus"},
		{"systemd_restart", "pilot-detection-engine.service", "systemctl restart pilot-detection-engine.service"},
		{"systemd_reload", "pilot-detection-engine.service", "systemctl reload pilot-detection-engine.service"},
	}
	for _, tc := range cases {
		step, err := ExecutorStep(tc.kind, tc.target)
		if err != nil {
			t.Fatalf("ExecutorStep(%q): %v", tc.kind, err)
		}
		if step.Module != "command" {
			t.Errorf("%s: module = %q, want command (never shell)", tc.kind, step.Module)
		}
		if step.Command != tc.wantCommand {
			t.Errorf("%s: command = %q, want %q", tc.kind, step.Command, tc.wantCommand)
		}
	}
}

func TestExecutorStep_UnknownKindRejected(t *testing.T) {
	if _, err := ExecutorStep("rm_rf", "anything"); err == nil {
		t.Fatal("expected an error for an unknown/unsupported executor kind")
	}
}

func TestExecute_RunsExactlyOneHostOneStep(t *testing.T) {
	var gotHost, gotInventory string
	var gotArgs []string
	fake := func(ctx context.Context, args []string, timeoutSeconds int) (string, int, error) {
		gotArgs = args
		gotHost = args[0]
		gotInventory = args[2]
		doc := map[string]any{"plays": []any{map[string]any{"tasks": []any{map[string]any{"hosts": map[string]any{
			"web-1": map[string]any{"stdout": "", "rc": 0, "failed": false, "unreachable": false},
		}}}}}}
		b, _ := json.Marshal(doc)
		return string(b), 0, nil
	}
	p := Plan{Host: "web-1", ExecutorKind: "docker_restart", ExecutorTarget: "pilot-prometheus"}
	result, err := Execute(context.Background(), fake, "/tmp/inv.yml", p, 5)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if gotHost != "web-1" {
		t.Errorf("ansible host arg = %q, want web-1", gotHost)
	}
	if gotInventory != "/tmp/inv.yml" {
		t.Errorf("ansible inventory arg = %q, want /tmp/inv.yml", gotInventory)
	}
	if result.Result.RunErr != nil {
		t.Errorf("result.RunErr = %v, want nil", result.Result.RunErr)
	}
	for _, a := range gotArgs {
		if a == "shell" {
			t.Fatal("executor must never use the shell module")
		}
	}
}
