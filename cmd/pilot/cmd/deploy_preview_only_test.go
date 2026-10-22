package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
)

// TestDeployPreviewOnlyRunsWithoutTTY mirrors TestDeployForceRunsWithoutTTY:
// --preview-only installs its defaults driver before the TTY gate.
func TestDeployPreviewOnlyRunsWithoutTTY(t *testing.T) {
	prevTTY, prevPreview, prevTimeout, prevPrompt := deployStdinIsTerminal, deployPreviewOnlyFlag, deployTimeoutFlag, activePromptAutomation
	t.Cleanup(func() {
		deployStdinIsTerminal, deployPreviewOnlyFlag, deployTimeoutFlag, activePromptAutomation = prevTTY, prevPreview, prevTimeout, prevPrompt
	})
	deployStdinIsTerminal = func() bool { return false }
	activePromptAutomation = nil
	// --timeout is parsed right after the TTY gate, so an invalid value stops
	// the run there, before it touches a data dir or an inventory.
	deployTimeoutFlag = "not-a-duration"

	deployPreviewOnlyFlag = false
	err := runDeployInteractive(&cobra.Command{}, nil)
	if err == nil || !strings.Contains(err.Error(), "--preview-only") {
		t.Fatalf("plain deploy without a TTY: error = %v, want the TTY error that names --preview-only", err)
	}

	deployPreviewOnlyFlag = true
	err = runDeployInteractive(&cobra.Command{}, nil)
	if err == nil || strings.Contains(err.Error(), "TTY") || !strings.Contains(err.Error(), "--timeout") {
		t.Fatalf("deploy --preview-only without a TTY: error = %v, want to pass the TTY gate and stop at --timeout", err)
	}
	if activePromptAutomation != nil {
		t.Fatal("the --preview-only automation driver outlived runDeployInteractive")
	}
}

func TestDeployPreviewOnlyRejectsForceAndActions(t *testing.T) {
	prevForce, prevPreview, prevActions := deployForceFlag, deployPreviewOnlyFlag, deployActionsPath
	t.Cleanup(func() {
		deployForceFlag, deployPreviewOnlyFlag, deployActionsPath = prevForce, prevPreview, prevActions
	})
	deployPreviewOnlyFlag = true

	deployForceFlag, deployActionsPath = true, ""
	if err := runDeploy(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "--force 不能與 --preview-only") {
		t.Fatalf("--force --preview-only: error = %v", err)
	}
	deployForceFlag, deployActionsPath = false, filepath.Join(t.TempDir(), "scenario.json")
	if err := runDeploy(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), "--preview-only 不能與 --actions") {
		t.Fatalf("--preview-only --actions: error = %v", err)
	}
}

// TestDeployPreviewOnlyDriverStopsAfterPreview drives the real transaction
// with the --preview-only driver: the preview runs, the apply never does, and
// only a passing preview counts as success.
func TestDeployPreviewOnlyDriverStopsAfterPreview(t *testing.T) {
	for _, tt := range []struct {
		name          string
		exitCode      int
		wantPassed    bool
		wantResultErr string
	}{
		{name: "preview passes", exitCode: 0, wantPassed: true},
		{name: "preview fails", exitCode: 2, wantResultErr: "預覽失敗(結束碼 2)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			prevPrompt := activePromptAutomation
			t.Cleanup(func() { activePromptAutomation = prevPrompt })
			driver := &promptAutomation{useDefaults: true}
			activePromptAutomation = driver

			argsLog := filepath.Join(t.TempDir(), "args.log")
			runner := ansible.NewRunner()
			runner.Binary = writeArgsLoggingFixture(t, argsLog, tt.exitCode)
			runner.Timeout = 5 * time.Second

			err := executeDeployment(context.Background(), runner, &bytes.Buffer{},
				"playbooks/apply/docker-apply.yml", "inventory.yml", "", "", nil, vaultInput{})
			if tt.wantPassed && !errors.Is(err, errDeployAborted) {
				t.Fatalf("executeDeployment() error = %v, want errDeployAborted from declining the apply", err)
			}
			if driver.previewPassed != tt.wantPassed {
				t.Fatalf("previewPassed = %v, want %v", driver.previewPassed, tt.wantPassed)
			}

			data, readErr := os.ReadFile(argsLog)
			if readErr != nil {
				t.Fatal(readErr)
			}
			calls := strings.Split(strings.TrimSpace(string(data)), "\n")
			if len(calls) != 1 || !strings.HasPrefix(calls[0], "--check --diff ") {
				t.Fatalf("ansible-playbook calls = %q, want exactly one --check --diff preview", calls)
			}

			var out bytes.Buffer
			resultErr := previewOnlyResult(&out, err, driver.previewPassed)
			if tt.wantResultErr == "" {
				if resultErr != nil || !strings.Contains(out.String(), "預覽通過") {
					t.Fatalf("previewOnlyResult() = %v, output %q; want success", resultErr, out.String())
				}
			} else if resultErr == nil || !strings.Contains(resultErr.Error(), tt.wantResultErr) {
				t.Fatalf("previewOnlyResult() = %v, want %q", resultErr, tt.wantResultErr)
			}
		})
	}
}

func TestPreviewOnlyResultRejectsCancelBeforePreview(t *testing.T) {
	err := previewOnlyResult(&bytes.Buffer{}, errDeployAborted, false)
	if err == nil || !strings.Contains(err.Error(), "預覽通過之前就停止") {
		t.Fatalf("previewOnlyResult() = %v, want a failure for a run that never previewed", err)
	}
}

// writeArgsLoggingFixture is writeExitFixture plus one argv line per call.
func writeArgsLoggingFixture(t *testing.T, argsLog string, exitCode int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ansible-playbook")
	script := "#!/bin/sh\necho \"$*\" >> " + strconv.Quote(argsLog) + "\n" + fakePlayRecapScript + "exit " + strconv.Itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write ansible fixture: %v", err)
	}
	return path
}
