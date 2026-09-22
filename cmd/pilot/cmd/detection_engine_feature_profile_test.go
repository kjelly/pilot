package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// detectionFeatureProfileCLITestYAML mirrors monitoring/detection/feature-
// profiles/linux-host-v1.yaml's shape closely enough to exercise the CLI
// without needing the real (large) fixture.
const detectionFeatureProfileCLITestYAML = `id: cli-test-v1
version: 1
notify:
  warning: dashboard
  critical: teams
  runbookURL: docs/runbooks/detection-engine.md
features:
  - name: cpu_utilization
    required: true
    category: cpu
    scaleFloor: 0.1
    validMin: 0
    validMax: 1
    promql: x
  - name: rootfs_used_ratio
    required: true
    category: storage
    scaleFloor: 0.1
    validMin: 0
    validMax: 1
    promql: x
`

// detectionFeatureProfileCLIRun mirrors iepCLIRun (internal_endpoint_cli_test.go):
// note this drives the shared package-level rootCmd, so — per the
// cobra/pflag Changed()-persists-across-Execute() hazard — this file
// intentionally keeps only ONE set-notify invocation across all its tests;
// the partial-update ("only touch the flags actually passed") semantics
// are covered exhaustively at the pure-function level in
// internal/detection/featureprofile_edit_test.go instead.
func detectionFeatureProfileCLIRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	return out.String(), err
}

func TestDetectionFeatureProfileShowCmd_ListsCategories(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, []byte(detectionFeatureProfileCLITestYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := detectionFeatureProfileCLIRun(t, "detection-engine", "feature-profile", "show", path)
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, "cpu") || !strings.Contains(out, "storage") {
		t.Fatalf("output = %q, want both cpu and storage categories listed", out)
	}
	if !strings.Contains(out, "docs/runbooks/detection-engine.md") {
		t.Fatalf("output = %q, want the profile-wide default runbook URL", out)
	}
}

func TestDetectionFeatureProfileSetNotifyCmd_SetsCategoryOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(path, []byte(detectionFeatureProfileCLITestYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := detectionFeatureProfileCLIRun(t, "detection-engine", "feature-profile", "set-notify", path,
		"--category", "storage",
		"--runbook-url", "docs/runbooks/storage-alerts.md",
		"--recommended-action", "check disk saturation dashboard first",
	)
	if err != nil {
		t.Fatalf("Execute() error = %v, output: %s", err, out)
	}
	if !strings.Contains(out, "docs/runbooks/storage-alerts.md") {
		t.Fatalf("output = %q, want the new runbook URL echoed back", out)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read edited file: %v", err)
	}
	if !strings.Contains(string(data), "notifyByCategory") || !strings.Contains(string(data), "storage-alerts.md") {
		t.Fatalf("edited file did not persist the override:\n%s", data)
	}
	// The untouched category (cpu) must be unaffected.
	showOut, err := detectionFeatureProfileCLIRun(t, "detection-engine", "feature-profile", "show", path)
	if err != nil {
		t.Fatalf("show after edit: %v, output: %s", err, showOut)
	}
	for _, line := range strings.Split(showOut, "\n") {
		if strings.HasPrefix(line, "cpu\t") && strings.Contains(line, "storage-alerts.md") {
			t.Fatalf("cpu row leaked the storage override: %q", line)
		}
	}
}
