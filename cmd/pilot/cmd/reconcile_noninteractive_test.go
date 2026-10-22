package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
)

func TestReconcileRejectsFlagMisuse(t *testing.T) {
	prevForce, prevPreview, prevActions, prevComponents, prevStage, prevHours := reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileActionsPath, reconcileComponentFlags, stageFlag, stagingAttestedHoursFlag
	t.Cleanup(func() {
		reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileActionsPath, reconcileComponentFlags, stageFlag, stagingAttestedHoursFlag = prevForce, prevPreview, prevActions, prevComponents, prevStage, prevHours
	})
	scenario := filepath.Join(t.TempDir(), "scenario.json")
	for _, tt := range []struct {
		name           string
		force, preview bool
		actions        string
		components     []string
		stage, hours   string
		wantErr        string
	}{
		{name: "force and preview-only", force: true, preview: true, components: []string{"freeipa-identity"}, wantErr: "--force 不能與 --preview-only"},
		{name: "actions with component", actions: scenario, components: []string{"freeipa-identity"}, wantErr: "--actions 不能與"},
		{name: "actions with stage", actions: scenario, stage: "staging", wantErr: "--actions 不能與"},
		{name: "preview-only without component", preview: true, wantErr: "需要用 --component"},
		{name: "force without component", force: true, wantErr: "需要用 --component"},
		{name: "prod without attestation", preview: true, components: []string{"freeipa-identity"}, stage: "prod", wantErr: "--staging-attested-within-hours"},
	} {
		reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileActionsPath = tt.force, tt.preview, tt.actions
		reconcileComponentFlags, stageFlag, stagingAttestedHoursFlag = tt.components, tt.stage, tt.hours
		if err := runReconcile(&cobra.Command{}, nil); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
			t.Errorf("%s: error = %v, want %q", tt.name, err, tt.wantErr)
		}
	}
}

// TestReconcileNonInteractiveRunsWithoutTTY mirrors the deploy test: both
// non-interactive modes install their driver before the TTY gate.
func TestReconcileNonInteractiveRunsWithoutTTY(t *testing.T) {
	prevTTY, prevForce, prevPreview, prevTimeout, prevPrompt := reconcileStdinIsTerminal, reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileTimeoutFlag, activePromptAutomation
	t.Cleanup(func() {
		reconcileStdinIsTerminal, reconcileForceFlag, reconcilePreviewOnlyFlag, reconcileTimeoutFlag, activePromptAutomation = prevTTY, prevForce, prevPreview, prevTimeout, prevPrompt
	})
	reconcileStdinIsTerminal = func() bool { return false }
	activePromptAutomation = nil
	// --timeout is parsed right after the TTY gate.
	reconcileTimeoutFlag = "not-a-duration"

	reconcileForceFlag, reconcilePreviewOnlyFlag = false, false
	if err := runReconcileInteractive(&cobra.Command{}); err == nil || !strings.Contains(err.Error(), "--preview-only") {
		t.Fatalf("plain reconcile without a TTY: error = %v, want the TTY error naming --preview-only", err)
	}
	for _, mode := range []struct{ force, preview bool }{{force: true}, {preview: true}} {
		reconcileForceFlag, reconcilePreviewOnlyFlag = mode.force, mode.preview
		err := runReconcileInteractive(&cobra.Command{})
		if err == nil || strings.Contains(err.Error(), "TTY") || !strings.Contains(err.Error(), "--timeout") {
			t.Fatalf("force=%v preview-only=%v without a TTY: error = %v, want to pass the TTY gate and stop at --timeout", mode.force, mode.preview, err)
		}
		if activePromptAutomation != nil {
			t.Fatal("the automation driver outlived runReconcileInteractive")
		}
	}
}

func TestReconcileComponentIndexes(t *testing.T) {
	entries := []deployPlaybook{{Key: "freeipa-identity"}, {Key: "freeipa-dns-client"}, {Key: "pilot-gateway-scope"}}
	got, err := reconcileComponentIndexes(entries, []string{"pilot-gateway-scope", "freeipa-identity", "pilot-gateway-scope"})
	if err != nil || !reflect.DeepEqual(got, []int{0, 2}) {
		t.Fatalf("reconcileComponentIndexes() = %v, %v; want [0 2] in menu order", got, err)
	}
	_, err = reconcileComponentIndexes(entries, []string{"freeipa-identity", "freeipa-server"})
	if err == nil || !strings.Contains(err.Error(), `"freeipa-server"`) || !strings.Contains(err.Error(), "freeipa-dns-client") {
		t.Fatalf("unknown key: error = %v, want it named along with the available keys", err)
	}
}

// TestExecuteCatalogReconcileBatch_PreviewOnly runs the real reconcile batch
// (two requests, each with a sameHosts dependency) under the --preview-only
// driver: every playbook in the plan is previewed, none is applied, and a
// failing preview stops the plan.
func TestExecuteCatalogReconcileBatch_PreviewOnly(t *testing.T) {
	for _, tt := range []struct {
		name          string
		previewExit   string
		wantRuns      int
		wantErr       bool
		wantSummaryIn string
	}{
		{name: "previews pass", previewExit: "0", wantRuns: 4, wantSummaryIn: "4 支 playbook 的預覽都通過"},
		{name: "first preview fails", previewExit: "2", wantRuns: 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := writeSameHostsCascadeFixture(t)
			t.Chdir(root)
			dataDir = t.TempDir()
			t.Cleanup(func() { dataDir = "" })

			binDir := t.TempDir()
			invJSON := `{"_meta":{"hostvars":{"host-a":{}}},"leaf":{"hosts":["host-a"]},"consumer":{"hosts":["host-a"]}}`
			if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte("#!/bin/sh\nprintf '%s\\n' '"+invJSON+"'\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			ansibleFixture := `#!/bin/sh
case "$*" in
  *--list-hosts*) printf '%s\n' '  hosts (1):' '    host-a'; exit 0 ;;
  *) printf '{"plays":[{"tasks":[{"hosts":{"host-a":{"stdout":"unknown","rc":0}}}]}]}\n' ;;
esac
`
			if err := os.WriteFile(filepath.Join(binDir, "ansible"), []byte(ansibleFixture), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			inv := filepath.Join(t.TempDir(), "inventory.yml")
			if err := os.WriteFile(inv, []byte("all:\n  hosts:\n    host-a: {}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			argsPath := filepath.Join(t.TempDir(), "ansible-playbook-args")
			playbook := filepath.Join(t.TempDir(), "ansible-playbook")
			script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + argsPath + "\n" + fakePlayRecapScript +
				"case \"$1\" in --check) exit " + tt.previewExit + " ;; esac\n"
			if err := os.WriteFile(playbook, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}
			runner := ansible.NewRunner()
			runner.Binary = playbook
			runner.Timeout = 5 * time.Second

			oldPrompt := activePromptAutomation
			activePromptAutomation = &promptAutomation{useDefaults: true, previewOnly: true}
			t.Cleanup(func() { activePromptAutomation = oldPrompt })
			stubDeploymentAvailabilityAllReachable(t)

			var out bytes.Buffer
			request := catalogDeploymentRequest{
				playbook:       "consumer-apply.yml",
				inv:            inv,
				extraVars:      []string{"stage=sandbox"},
				stage:          "sandbox",
				componentHints: []string{"consumer"},
			}
			err := executeCatalogReconcileBatch(context.Background(), runner, &out, []catalogDeploymentRequest{request, request})
			if tt.wantErr {
				if err == nil || errors.Is(err, errPreviewOnlyStop) || errors.Is(err, errDeployAborted) {
					t.Fatalf("executeCatalogReconcileBatch() error = %v, want the preview failure", err)
				}
			} else if err != nil {
				t.Fatalf("executeCatalogReconcileBatch() error = %v\n%s", err, out.String())
			}

			data, readErr := os.ReadFile(argsPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			// The defaults choose the full preflight, which runs before each preview.
			var runs []string
			for _, run := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if !strings.HasPrefix(run, "playbooks/preflight.yml ") {
					runs = append(runs, run)
				}
			}
			if len(runs) != tt.wantRuns {
				t.Fatalf("ansible-playbook runs = %q, want %d", runs, tt.wantRuns)
			}
			order := []string{"leaf-apply.yml", "consumer-apply.yml", "leaf-apply.yml", "consumer-apply.yml"}
			for i, run := range runs {
				if !strings.HasPrefix(run, "--check --diff ") || !strings.Contains(run, order[i]) {
					t.Fatalf("run %d = %q, want a --check --diff preview of %s and no apply", i, run, order[i])
				}
			}
			if tt.wantSummaryIn != "" && !strings.Contains(out.String(), tt.wantSummaryIn) {
				t.Fatalf("output lacks %q:\n%s", tt.wantSummaryIn, out.String())
			}
		})
	}
}
