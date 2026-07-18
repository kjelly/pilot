package tools

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anomalyco/pilot/internal/spec"
)

const verifyV2Fixture = `---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent: {summary: v2-verify, source: test, maintainer: sre}
targets: {roles: [test]}
inputs: []
traceability: {components: [test]}
defaults:
  become: false
  action: {mode: readOnly}
---
# Verification Spec — v2 verify

## Checks
` + "```yaml" + `
- id: C1
  category: output
  check: exactly one trailing newline is ignored
  probe: "printf ' x  \\n\\n'"
  expect: {stdout: {equals: " x  \n"}}
- id: C2
  category: aggregate
  check: controller only
  probe: "printf controller"
  scope: aggregate
  expect: {stdout: {equals: controller}}
` + "```" + `
`

func TestVerifySpecV2LocalAndAggregate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.md")
	if err := writeFile(path, verifyV2Fixture); err != nil {
		t.Fatal(err)
	}
	res, err := (&VerifySpecTool{LocalOnly: true}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || res.IsError {
		t.Fatalf("Execute err=%v result=%+v", err, res)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Status != "pass" || rows[1].Host != "controller" || rows[1].Status != "pass" {
		t.Fatalf("rows=%+v", rows)
	}
}

func TestVerifySpecV2SelectedRowsFailClosedAndNarrowExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v2.md")
	if err := writeFile(path, verifyV2Fixture); err != nil {
		t.Fatal(err)
	}
	tool := &VerifySpecTool{LocalOnly: true, SelectedRowIDs: map[string]bool{"C1": true}}
	res, err := tool.Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || res.IsError {
		t.Fatalf("Execute err=%v result=%+v", err, res)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil || len(rows) != 1 || rows[0].ID != "C1" {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	res, err = (&VerifySpecTool{LocalOnly: true, SelectedRowIDs: map[string]bool{"missing": true}}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || !res.IsError || !strings.Contains(res.Content, "does not exist") {
		t.Fatalf("err=%v result=%+v", err, res)
	}
}

func TestVerifySpecV2RejectsNeedsReviewAndSecretRef(t *testing.T) {
	for name, replacement := range map[string]struct{ replace, want string }{
		"needs review": {"  expect: {stdout: {equals: controller}}", "  needsReview: [action-unknown]\n  expect: {stdout: {equals: controller}}"},
		"secret ref":   {"inputs: []", "inputs: [{name: token, required: true, secretRef: {provider: ansibleVar, name: token}}]"},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "v2.md")
			raw := strings.Replace(verifyV2Fixture, replacement.replace, replacement.want, 1)
			if err := writeFile(path, raw); err != nil {
				t.Fatal(err)
			}
			res, err := (&VerifySpecTool{LocalOnly: true}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
			if err != nil || !res.IsError {
				t.Fatalf("err=%v result=%+v", err, res)
			}
		})
	}
}

func TestVerifySpecV2InputAndApplicability(t *testing.T) {
	raw := strings.Replace(verifyV2Fixture, "inputs: []", "inputs: [{name: feature, required: true, validation: '^on|off$'}]", 1)
	raw = strings.Replace(raw, "- id: C1", "- id: C0\n  category: input\n  check: conditional row\n  probe: test \"$PILOT_VAR_FEATURE\" = on\n  appliesWhen: {all: [{input: {name: feature, operator: equals, value: on}}]}\n  expect: {exitCode: 0}\n- id: C1", 1)
	path := filepath.Join(t.TempDir(), "inputs.md")
	if err := writeFile(path, raw); err != nil {
		t.Fatal(err)
	}
	res, err := (&VerifySpecTool{LocalOnly: true, Inputs: map[string]string{"feature": "off"}}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != "not_applicable" || rows[0].ProbeStatus != "not_applicable" {
		t.Fatalf("row=%+v", rows[0])
	}
	res, err = (&VerifySpecTool{LocalOnly: true, Inputs: map[string]string{"feature": "on"}}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || res.IsError {
		t.Fatalf("on err=%v res=%+v", err, res)
	}
	rows, _ = ReadNDJSON(res.Content)
	if rows[0].Status != "pass" {
		t.Fatalf("on row=%+v", rows[0])
	}
}

func TestVerifySpecV2SeparatesStderr(t *testing.T) {
	raw := strings.Replace(verifyV2Fixture, "expect: {stdout: {equals: controller}}", "expect: {stderr: {equals: warning}}", 1)
	raw = strings.Replace(raw, "probe: \"printf controller\"", "probe: \"printf warning >&2\"", 1)
	path := filepath.Join(t.TempDir(), "stderr.md")
	if err := writeFile(path, raw); err != nil {
		t.Fatal(err)
	}
	res, err := (&VerifySpecTool{LocalOnly: true}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if rows[1].Status != "pass" || rows[1].Stdout != "" || rows[1].Stderr != "warning" {
		t.Fatalf("row=%+v", rows[1])
	}
}

func TestVerifySpecV2AuthorizedIsolatedMutationAlwaysCleansUp(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "marker")
	raw := strings.Replace(verifyV2Fixture, "probe: \"printf ' x  \\\\n\\\\n'\"", "probe: \"touch "+marker+" && printf ' x  \\\\n\\\\n'\"", 1)
	raw = strings.Replace(raw, "  expect: {stdout: {equals: \" x  \\n\"}}", "  action:\n    mode: isolatedMutation\n    authorization: explicit\n    residualRisk: temporary test marker\n    cleanup:\n      required: true\n      probe: \"rm -f "+marker+"\"\n      expect: {exitCode: 0}\n  expect: {stdout: {equals: \" x  \\n\"}}", 1)
	path := filepath.Join(t.TempDir(), "isolated.md")
	if err := writeFile(path, raw); err != nil {
		t.Fatal(err)
	}
	res, err := (&VerifySpecTool{LocalOnly: true}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || !res.IsError {
		t.Fatalf("unauthorized err=%v result=%+v", err, res)
	}
	res, err = (&VerifySpecTool{LocalOnly: true, AllowIsolatedMutation: true}).Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || res.IsError {
		t.Fatalf("authorized err=%v result=%+v", err, res)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("cleanup did not remove marker: %v", err)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil || len(rows) == 0 || rows[0].CleanupStatus != "pass" {
		t.Fatalf("cleanup result was not recorded: rows=%+v err=%v", rows, err)
	}
}

func TestVerifySpecV2ApplicabilityUsesPerHostInventoryInputs(t *testing.T) {
	raw := strings.Replace(verifyV2Fixture, "inputs: []", "inputs: [{name: feature, required: false}]", 1)
	raw = strings.Replace(raw, "  expect: {stdout: {equals: \" x  \\n\"}}", "  appliesWhen: {all: [{input: {name: feature, operator: equals, value: on}}]}\n  expect: {stdout: {equals: \" x  \\n\"}}", 1)
	path := filepath.Join(t.TempDir(), "remote-inputs.md")
	if err := writeFile(path, raw); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var invoked []string
	tool := &VerifySpecTool{
		Inventory: "inventory.yml",
		listHosts: func(_ context.Context, pattern, _ string) ([]string, error) {
			switch pattern {
			case "all", "test":
				return []string{"host-a", "host-b"}, nil
			default:
				t.Fatalf("unexpected pattern %q", pattern)
				return nil, nil
			}
		},
		hostInputs: func(_ context.Context, host string) (map[string]string, error) {
			if host == "host-a" {
				return map[string]string{"feature": "on"}, nil
			}
			return map[string]string{"feature": "off"}, nil
		},
		runJSON: func(_ context.Context, args []string, _ int) ansibleJSONInvocation {
			host := args[0]
			mu.Lock()
			invoked = append(invoked, host)
			mu.Unlock()
			return ansibleJSONInvocation{Stdout: `{"plays":[{"tasks":[{"hosts":{"` + host + `":{"stdout":" x  \n\n","rc":0}}}]}]}`}
		},
	}
	res, err := tool.Execute(context.Background(), mustJSON(t, map[string]any{"spec_path": path}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v res=%+v", err, res)
	}
	rows, err := ReadNDJSON(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows=%+v", rows)
	}
	if rows[0].Host != "host-b" || rows[0].Status != "not_applicable" {
		t.Fatalf("not-applicable row=%+v", rows[0])
	}
	mu.Lock()
	defer mu.Unlock()
	for _, host := range invoked {
		if host == "host-b" {
			t.Fatalf("inapplicable host executed: %v", invoked)
		}
	}
}

func TestNormalizeV2TextContract(t *testing.T) {
	got := normalizeV2Text("a\r\n\n" + string([]byte{0xff}))
	if got != "a\n\n\uFFFD" {
		t.Fatalf("normalized=%q", got)
	}
	if got := normalizeV2Text("a\n\n"); got != "a\n" {
		t.Fatalf("exactly one trailing newline must be removed, got %q", got)
	}
}

func TestEffectiveTimeoutRoundsPositiveDurationUp(t *testing.T) {
	if got := effectiveTimeout(spec.Row{Timeout: 500 * time.Millisecond}, 15); got != 1 {
		t.Fatalf("timeout=%d want=1", got)
	}
}
