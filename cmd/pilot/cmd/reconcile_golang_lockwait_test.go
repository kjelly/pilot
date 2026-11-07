package cmd

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// The entry gates of --lock-wait (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md
// §4.3, §8.1). Each row makes its own gate fire (the gate field; the ledger of
// reconcile_golang_ledger_test.go checks every gate of runReconcile has a row
// or an exemption) and names what must be in the error, so a refusal that came
// from another check proves nothing.
const passedLockWait = "--actions 不能與"

func TestReconcileLockWaitFlag(t *testing.T) {
	prevWait, prevPreview, prevForce, prevComponents, prevEngine := reconcileLockWaitFlag, reconcilePreviewOnlyFlag, reconcileForceFlag, reconcileComponentFlags, reconcileEngineFlag
	prevActions, prevStage, prevHours, prevPlanOut := reconcileActionsPath, stageFlag, stagingAttestedHoursFlag, reconcilePlanOutFlag
	t.Cleanup(func() {
		reconcileLockWaitFlag, reconcilePreviewOnlyFlag, reconcileForceFlag, reconcileComponentFlags, reconcileEngineFlag = prevWait, prevPreview, prevForce, prevComponents, prevEngine
		reconcileActionsPath, stageFlag, stagingAttestedHoursFlag, reconcilePlanOutFlag = prevActions, prevStage, prevHours, prevPlanOut
	})
	for _, tc := range []struct {
		name    string
		wait    string
		preview bool
		engine  string
		gate    string
		want    string // in the error; "" when the flags must pass these two gates
	}{
		{name: "not a duration", wait: "soon", gate: "entry-lock-wait-value", want: `--lock-wait "soon"`},
		{name: "negative", wait: "-5m", gate: "entry-lock-wait-value", want: `--lock-wait "-5m"`},
		{name: "under a second rounds to something nobody asked for", wait: "500ms", gate: "entry-lock-wait-value", want: `--lock-wait "500ms"`},
		{name: "a wait with --preview-only", wait: "5m", preview: true, gate: "entry-lock-wait-preview-only", want: "--preview-only 不持鎖"},
		{name: "a zero wait with --preview-only", wait: "0", preview: true, gate: "entry-lock-wait-preview-only", want: "--preview-only 不持鎖"},
		{name: "a wait with the Go engine's preview", wait: "1m", preview: true, engine: "golang", gate: "entry-lock-wait-preview-only", want: "--preview-only 不持鎖"},
		// A valid value passes both gates and is refused further down, by the
		// --actions check that follows them: that message is the proof it got past.
		{name: "unset passes with --preview-only", preview: true, want: passedLockWait},
		{name: "0 passes (fail at once)", wait: "0", want: passedLockWait},
		{name: "30m passes", wait: "30m", want: passedLockWait},
		{name: "1s passes", wait: "1s", want: passedLockWait},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("gate: %q", tc.gate)
			reconcileLockWaitFlag, reconcilePreviewOnlyFlag, reconcileForceFlag = tc.wait, tc.preview, false
			reconcileEngineFlag = tc.engine
			if reconcileEngineFlag == "" {
				reconcileEngineFlag = reconcileEngineAnsible
			}
			reconcileComponentFlags, stageFlag, stagingAttestedHoursFlag, reconcilePlanOutFlag = []string{"freeipa-identity"}, "", "", ""
			reconcileActionsPath = ""
			if tc.want == passedLockWait {
				reconcileActionsPath = "/nonexistent/scenario.json" // refused below the lock-wait gates, before anything runs
			}
			err := runReconcile(&cobra.Command{}, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.want == passedLockWait && strings.Contains(err.Error(), "--lock-wait") {
				t.Fatalf("a valid --lock-wait was refused: %v", err)
			}
		})
	}
}

// What runReconcileInteractive hands the funnels: the wait of the flag (30 minutes
// when unset, 0 meaning fail at once), and stderr for the progress lines.
func TestReconcileLockContextCarriesTheFlag(t *testing.T) {
	prev := reconcileLockWaitFlag
	t.Cleanup(func() { reconcileLockWaitFlag = prev })
	for flag, want := range map[string]time.Duration{"": identityLockWaitDefault, "0": 0, "45s": 45 * time.Second, "2h": 2 * time.Hour} {
		reconcileLockWaitFlag = flag
		ctx, err := reconcileLockContext(context.Background(), &cobra.Command{})
		if err != nil {
			t.Fatalf("--lock-wait %q: %v", flag, err)
		}
		if got := identityLockWaitFrom(ctx); got != want {
			t.Errorf("--lock-wait %q: the funnels wait %v, want %v", flag, got, want)
		}
		if identityLockProgressFrom(ctx) == nil {
			t.Errorf("--lock-wait %q: no progress writer", flag)
		}
	}
	reconcileLockWaitFlag = "soon"
	if _, err := reconcileLockContext(context.Background(), &cobra.Command{}); err == nil {
		t.Error("an invalid --lock-wait was accepted by the context builder")
	}
	// A context nobody set a wait on gets the default: pilot deploy has no flag.
	if got := identityLockWaitFrom(context.Background()); got != identityLockWaitDefault {
		t.Errorf("default wait = %v", got)
	}
}
