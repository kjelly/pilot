package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/outbound"
	"github.com/kjelly/pilot/internal/sshdial"
)

// What a refusal of the lock precheck does to the outbound webhook, per funnel
// (docs/superpowers/specs/2026-11-06-freeipa-go-reconcile-phase2-spec.md §4.2).
// The precheck refuses before the funnel starts a workflow, and no funnel leaves
// an approval behind, but whether the operator's configured webhook hears of it
// depends on where the funnel publishes: the funnels that publish only after
// they have started their workflow (batch deploy and reconcile, `pilot access`,
// breakglass) say nothing; the interactive single-component `pilot deploy`
// (no --component) publishes after its deployment call returns, whatever the
// call returned, so it sends one failure event for the refusal. The spec says
// exactly this; the test is what keeps the sentence true.
func TestPrecheckRefusalOutboundEventsByFunnel(t *testing.T) {
	refusal := "不能對 ipa-1 取 FreeIPA 的 /etc/ipa 鎖：ProxyCommand"
	identity := "freeipa-identity"

	t.Run("the interactive single-component deploy sends one failure event", func(t *testing.T) {
		env := newOutboundWorkflowEnv(t, map[string][]string{identity: {"host-a"}}, eventsYAMLFor(outbound.OperationDeploy, outbound.ResultFailure), 0)
		env.lock.PrecheckErr = errors.New(refusal)
		catalog := loadOutboundWorkflowCatalog(t)
		var out bytes.Buffer
		err := runCatalogPlaybookDeployEntry(context.Background(), newRunnerWithExitCode(t, 0), &out, env.inv, "apply", catalog,
			deployPlaybookEntry(identity, "freeipa-identity-apply.yml"), nil, deployInventorySnapshot{}, false, nil)
		if err == nil || !strings.Contains(err.Error(), "取鎖前檢查沒有通過") || !strings.Contains(err.Error(), "ProxyCommand") {
			t.Fatalf("err = %v, want the precheck's refusal", err)
		}
		if got := env.capture.count(); got != 1 {
			t.Fatalf("webhook deliveries = %d, want 1: this funnel publishes after its deployment call returns, whatever it returned\n%s", got, out.String())
		}
		var body map[string]any
		if err := json.Unmarshal(env.capture.last(), &body); err != nil {
			t.Fatal(err)
		}
		op, _ := body["operation"].(map[string]any)
		failure, _ := body["failure"].(map[string]any)
		if op["result"] != "failure" || failure["class"] != "apply_failed" {
			t.Fatalf("event: operation.result = %v, failure = %v, want failure / apply_failed", op["result"], body["failure"])
		}
		if got := env.lock.Requests(); len(got) != 0 || env.lock.Acquired() != 0 {
			t.Fatalf("a lock was built (%+v) or taken (%d) although the precheck refused", got, env.lock.Acquired())
		}
	})

	for name, operation := range map[string]outbound.OperationKind{
		"pilot reconcile (batch)":        outbound.OperationReconcile,
		"pilot deploy --component batch": outbound.OperationDeploy,
	} {
		t.Run(name+" sends no event", func(t *testing.T) {
			env := newOutboundWorkflowEnv(t, map[string][]string{identity: {"host-a"}}, eventsYAMLFor(operation, outbound.ResultFailure), 0)
			env.lock.PrecheckErr = errors.New(refusal)
			requests := []catalogDeploymentRequest{reconcileRequest(identity, "freeipa-identity-apply.yml")}
			requests[0].inv = env.inv
			requests[0].workspaceDir = env.workspace
			var out bytes.Buffer
			err := executeCatalogBatch(context.Background(), newRunnerWithExitCode(t, 0), &out, requests, operation)
			if err == nil || !strings.Contains(err.Error(), "取鎖前檢查沒有通過") {
				t.Fatalf("err = %v, want the precheck's refusal", err)
			}
			if got := env.capture.count(); got != 0 {
				t.Fatalf("webhook deliveries = %d, want 0: the batch refuses before it starts its workflow", got)
			}
			if strings.Contains(out.String(), "batch execution plan") {
				t.Fatalf("the plan was shown before the refusal:\n%s", out.String())
			}
			// The control: the same batch, past the precheck, with a playbook
			// that fails, does send its failure event, so "0" above is the
			// refusal's and not a subscription that never matches.
			env.lock.PrecheckErr = nil
			if err := executeCatalogBatch(context.Background(), newRunnerWithExitCode(t, 2), &bytes.Buffer{}, requests, operation); err == nil {
				t.Fatal("the control batch with a failing playbook succeeded")
			}
			if got := env.capture.count(); got != 1 {
				t.Fatalf("control: webhook deliveries = %d, want 1 for a batch that failed after the precheck", got)
			}
		})
	}

	for name, args := range map[string]func(roster, inv string) []string{
		"pilot access reconcile --once": func(roster, inv string) []string {
			return []string{"access", "reconcile", roster, "--once", "--inventory", inv}
		},
		"pilot access breakglass activate": func(roster, inv string) []string {
			return []string{"access", "breakglass", "activate", roster, "infra-emergency", "--duration", "30m", "--reason", "t", "--ticket", "T-1", "--inventory", inv}
		},
		"pilot access breakglass deactivate": func(roster, inv string) []string {
			return []string{"access", "breakglass", "deactivate", roster, "infra-emergency", "--inventory", inv}
		},
	} {
		t.Run(name+" sends no event", func(t *testing.T) {
			env := newOutboundWorkflowEnv(t, map[string][]string{"host-a": {"host-a"}},
				reconcileEventsYAMLEffectsAny(outbound.ResultFailure, "access.hbac", "access.grants"), 0)
			env.lock.PrecheckErr = errors.New(refusal)
			fixture := accessBreakglassCLIFixtureRoster
			if strings.HasSuffix(name, "reconcile --once") {
				fixture = accessCLIFixtureRoster
			}
			roster := writeAccessCLIFixture(t, fixture)
			out, err := runCLI(t, args(roster, env.inv)...)
			if err == nil || !strings.Contains(err.Error(), "取鎖前檢查沒有通過") {
				t.Fatalf("err = %v, want the precheck's refusal\n%s", err, out)
			}
			if got := env.capture.count(); got != 0 {
				t.Fatalf("webhook deliveries = %d, want 0: the command refuses before it starts its workflow", got)
			}
			// The control: a lock another run holds is refused after the
			// workflow started, and that does send its failure event.
			env.lock.PrecheckErr = nil
			env.lock.Err = &sshdial.TunnelError{Kind: sshdial.ErrLockBusy, ExitCode: 75}
			if out, err := runCLI(t, args(roster, env.inv)...); err == nil {
				t.Fatalf("the control command with a busy lock succeeded\n%s", out)
			}
			if got := env.capture.count(); got != 1 {
				t.Fatalf("control: webhook deliveries = %d, want 1 for a lock refused after the workflow started", got)
			}
		})
	}
}
