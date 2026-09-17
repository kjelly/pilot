// gateway_scope.go implements `pilot gateway-scope plan/reconcile`
// (spec.md §9.6/§57, Phase 6): management-plane publication of one
// pilot-access-gateway scope's desired target host set into FreeIPA
// hostgroup pilot-target-<scope>. This is NOT part of
// pilot-access-gateway's own runtime (internal/freeipaaccess/
// internal/accessportal/internal/gatewayapi) — it is ordinary Ansible-
// orchestrated management-plane tooling, consistent with spec.md §3.1
// ("management plane 可以使用 roster、inventory、vault、Ansible").
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/outbound"
)

// gatewayScopeEffects is design spec §1's fixed routing effect set for
// every `pilot gateway-scope reconcile/enable-auto/disable-auto` call —
// never derived from the pilot-gateway-scope contract dynamically,
// since these dedicated frontends are a fixed §1 mapping, not a
// contract-effects lookup.
var gatewayScopeEffects = []string{"identity.hostgroups", "access.hbac"}

const gatewayScopeApplyPlaybook = "playbooks/apply/gateway-scope-apply.yml"

const (
	gatewayScopeAllHostsKeyword = "all"
	gatewayScopeAllHostsGroup   = "freeipa-client"
	gatewayScopeAllExcludeGroup = "pilot-access-gateway"
)

var (
	gatewayScopeDirFlag     string
	gatewayScopeFlag        string
	gatewayScopeHostsFlag   []string
	gatewayScopeInventory   string
	gatewayScopeTargetGroup string
	gatewayScopeVaultFile   string
	gatewayScopeTimeout     time.Duration
)

var gatewayScopeCmd = &cobra.Command{
	Use:   "gateway-scope",
	Short: "Publish a pilot-access-gateway target scope into FreeIPA (spec.md §9.6/§57)",
}

var gatewayScopePlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Show add/remove/keep for pilot-target-<scope> without changing FreeIPA",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayScope(cmd, true)
	},
}

var gatewayScopeReconcileCmd = &cobra.Command{
	Use:   "reconcile",
	Short: "Apply add/remove for pilot-target-<scope> in FreeIPA",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayScope(cmd, false)
	},
}

// gatewayScopeEnableAutoCmd/gatewayScopeDisableAutoCmd (2026-09-15) close
// the gap "all" left even after its 2026-09-15 gateway-exclusion fix: a
// one-shot `--hosts all` reconcile is still a snapshot — a freeipa-client
// host enrolled the next day never joins pilot-target-<scope> until someone
// remembers to rerun it. enable-auto backfills right now (same "all"
// expansion as reconcile, so gateways are still excluded) AND installs a
// FreeIPA automember rule so every FUTURE enrollment joins automatically,
// with zero further pilot involvement. See gateway-scope-apply.yml's own
// header comment for why this is safe despite automember being unable to
// exclude gateways at enrollment time (pilot-access-gateway-apply.yml's
// Step 3b is the complementary half of this design).
var gatewayScopeEnableAutoCmd = &cobra.Command{
	Use:   "enable-auto",
	Short: "Backfill pilot-target-<scope> with all freeipa-client hosts now, then keep it in sync automatically via a FreeIPA automember rule",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayScopeAutomember(cmd, true)
	},
}

var gatewayScopeDisableAutoCmd = &cobra.Command{
	Use:   "disable-auto",
	Short: "Remove the FreeIPA automember rule for pilot-target-<scope> (existing membership is left untouched)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGatewayScopeAutomember(cmd, false)
	},
}

func init() {
	for _, sub := range []*cobra.Command{gatewayScopePlanCmd, gatewayScopeReconcileCmd} {
		sub.Flags().StringVar(&gatewayScopeDirFlag, "dir", ".", "workspace directory containing inventory.yml and .vault/main.yaml (matches `pilot deploy --dir`)")
		sub.Flags().StringVar(&gatewayScopeFlag, "scope", "", "gateway scope name, e.g. gpu (required)")
		sub.Flags().StringSliceVar(&gatewayScopeHostsFlag, "hosts", nil, "desired FQDNs for pilot-target-<scope> (comma-separated), or 'all' to use the inventory freeipa-client group (required)")
		sub.Flags().StringVarP(&gatewayScopeInventory, "inventory", "i", "inventory.yml", "inventory path (relative to --dir unless absolute)")
		sub.Flags().StringVar(&gatewayScopeTargetGroup, "target-group", "freeipa-server", "inventory group/host the playbook runs against")
		sub.Flags().StringVar(&gatewayScopeVaultFile, "vault-file", "", "vars file defining ipa_admin_password (default: <dir>/.vault/main.yaml if it exists)")
		sub.Flags().DurationVar(&gatewayScopeTimeout, "timeout", 5*time.Minute, "ansible-playbook timeout")
		sub.MarkFlagRequired("scope")
		sub.MarkFlagRequired("hosts")
	}
	for _, sub := range []*cobra.Command{gatewayScopeEnableAutoCmd, gatewayScopeDisableAutoCmd} {
		sub.Flags().StringVar(&gatewayScopeDirFlag, "dir", ".", "workspace directory containing inventory.yml and .vault/main.yaml (matches `pilot deploy --dir`)")
		sub.Flags().StringVar(&gatewayScopeFlag, "scope", "", "gateway scope name, e.g. gpu (required)")
		sub.Flags().StringVarP(&gatewayScopeInventory, "inventory", "i", "inventory.yml", "inventory path (relative to --dir unless absolute)")
		sub.Flags().StringVar(&gatewayScopeTargetGroup, "target-group", "freeipa-server", "inventory group/host the playbook runs against")
		sub.Flags().StringVar(&gatewayScopeVaultFile, "vault-file", "", "vars file defining ipa_admin_password (default: <dir>/.vault/main.yaml if it exists)")
		sub.Flags().DurationVar(&gatewayScopeTimeout, "timeout", 5*time.Minute, "ansible-playbook timeout")
		sub.MarkFlagRequired("scope")
	}
	gatewayScopeCmd.AddCommand(gatewayScopePlanCmd, gatewayScopeReconcileCmd, gatewayScopeEnableAutoCmd, gatewayScopeDisableAutoCmd)
	rootCmd.AddCommand(gatewayScopeCmd)
}

// resolveGatewayScopeInventoryAndVault applies the same --dir convention
// `pilot deploy`/`pilot edit` already use (workspacePath/defaultVaultFile,
// internal_endpoint_cli.go / deploy.go): --inventory joins with --dir unless
// it's already absolute, and an unset --vault-file auto-detects
// <inventory-dir>/.vault/main.yaml. Fails fast with a clear message instead
// of letting the playbook's own "ipa_admin_password is defined" assert be
// the first place a missing vault file surfaces.
func resolveGatewayScopeInventoryAndVault(cmd *cobra.Command, dir, inventory, vaultFile string) (string, string, error) {
	inv := workspacePath(dir, inventory)
	if vaultFile != "" {
		return inv, vaultFile, nil
	}
	auto := defaultVaultFile(inv)
	if auto == "" {
		return "", "", fmt.Errorf("no --vault-file given and no .vault/main.yaml found next to %s; pass --vault-file explicitly", inv)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "using auto-detected vault file: %s\n", auto)
	return inv, auto, nil
}

// buildGatewayScopeArgs is a pure function so its exact ansible-playbook
// argv can be unit-tested without a real ansible-playbook binary — in
// particular that gateway_scope_hosts is always passed as one JSON-object
// -e value, never the "-e key=[...]" form, which a live vm-target test
// found Ansible's own -e parser does NOT reliably parse as a list (it can
// arrive as a plain string, iterated character-by-character by Jinja
// filters expecting a list — see
// docs/evidence/pilot-access-gateway/2026-09-14-phase6-gateway-scope.md).
func buildGatewayScopeArgs(scope string, hosts []string, inventory, targetGroup, vaultFile string, planOnly bool) ([]string, error) {
	if strings.TrimSpace(scope) == "" {
		return nil, fmt.Errorf("scope is required")
	}
	hosts, err := validateExpandedGatewayScopeHosts(hosts)
	if err != nil {
		return nil, err
	}
	hostsJSON, err := json.Marshal(map[string]any{"gateway_scope_hosts": hosts})
	if err != nil {
		return nil, fmt.Errorf("encode gateway_scope_hosts: %w", err)
	}
	args := []string{
		gatewayScopeApplyPlaybook,
		"-i", inventory,
		"-e", "target_group=" + targetGroup,
		"-e", "gateway_scope=" + scope,
		"-e", string(hostsJSON),
		"-e", "@" + vaultFile,
	}
	if planOnly {
		args = append(args, "-e", "gateway_scope_plan_only=true")
	}
	return args, nil
}

// normalizeGatewayScopeHostRequest validates the user-facing --hosts value.
// The literal "all" is deliberately an explicit, exclusive keyword rather
// than the empty value: omitting a value must never widen an access boundary.
func normalizeGatewayScopeHostRequest(requested []string) ([]string, bool, error) {
	if len(requested) == 0 {
		return nil, false, fmt.Errorf("hosts is required (pass explicit hosts or the literal %q)", gatewayScopeAllHostsKeyword)
	}

	hosts := make([]string, 0, len(requested))
	for _, raw := range requested {
		host := strings.TrimSpace(raw)
		if host == "" {
			return nil, false, fmt.Errorf("hosts must not contain an empty value; use %q explicitly for the inventory group", gatewayScopeAllHostsKeyword)
		}
		if host == gatewayScopeAllHostsKeyword {
			if len(requested) != 1 {
				return nil, false, fmt.Errorf("%q must be used by itself; do not mix it with explicit hosts", gatewayScopeAllHostsKeyword)
			}
			return []string{host}, true, nil
		}
		hosts = append(hosts, host)
	}
	return hosts, false, nil
}

// validateExpandedGatewayScopeHosts is intentionally stricter than the
// user-facing request parser: buildGatewayScopeArgs must only ever receive
// the concrete host list that will be sent to Ansible. Keeping the keyword
// out of this function prevents a future caller from accidentally publishing
// a host literally named "all" instead of resolving the inventory group.
func validateExpandedGatewayScopeHosts(hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, fmt.Errorf("hosts is required")
	}
	normalized := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			return nil, fmt.Errorf("expanded hosts must not contain an empty value")
		}
		if host == gatewayScopeAllHostsKeyword {
			return nil, fmt.Errorf("%q must be expanded from the inventory before invoking the gateway-scope playbook", gatewayScopeAllHostsKeyword)
		}
		normalized = append(normalized, host)
	}
	return normalized, nil
}

// resolveGatewayScopeHosts expands the explicit all keyword from the
// supplied inventory's resolved freeipa-client group. It deliberately uses
// Ansible's resolved group view so child groups and inventory aliases are
// handled exactly as the subsequent playbook invocation sees them.
//
// Every pilot-access-gateway host is excluded from the expansion: contracts/
// pilot-access-gateway.yaml declares freeipa-client as a required sameHosts
// dependency, so a gateway is ALWAYS also a freeipa-client host — without
// this exclusion "all" silently published every gateway (itself included)
// as one of its own SSH targets. Found live 2026-09-15: a real `--hosts all`
// reconcile against a disposable vm-target actually added ag-gw01/ag-gw02 as
// members of the target hostgroup (see
// docs/evidence/pilot-gateway-scope/2026-09-15-all-keyword.md), which also
// means any sudo/HBAC rule later scoped to that hostgroup (the established
// pilot-grant-sudo-<scope>/pilot-grant-login-<scope> convention) would
// silently apply to the gateway hosts themselves too — the opposite of
// spec.md/docs/verification/pilot-access-gateway.md §5's explicit design
// that a gateway's own login authorization lives in the separate
// pilot-access-gateways hostgroup, never pilot-target-<scope>.
//
// The returned bool tells the caller whether to print the expansion for the
// operator/audit trail.
func resolveGatewayScopeHosts(ctx context.Context, inventory string, requested []string) ([]string, bool, error) {
	normalized, expandAll, err := normalizeGatewayScopeHostRequest(requested)
	if err != nil {
		return nil, false, err
	}
	if !expandAll {
		return normalized, false, nil
	}

	groups, err := resolveInventoryGroups(ctx, inventory)
	if err != nil {
		return nil, false, fmt.Errorf("resolve %q from inventory: %w", gatewayScopeAllHostsKeyword, err)
	}
	hosts := groups[gatewayScopeAllHostsGroup]
	if len(hosts) == 0 {
		return nil, false, fmt.Errorf("resolve %q from inventory: group %q is missing or empty", gatewayScopeAllHostsKeyword, gatewayScopeAllHostsGroup)
	}
	gateways := make(map[string]bool, len(groups[gatewayScopeAllExcludeGroup]))
	for _, h := range groups[gatewayScopeAllExcludeGroup] {
		gateways[h] = true
	}
	filtered := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if !gateways[h] {
			filtered = append(filtered, h)
		}
	}
	if len(filtered) == 0 {
		return nil, false, fmt.Errorf("resolve %q from inventory group %q: every member is also a %q host (nothing left to publish as a target)", gatewayScopeAllHostsKeyword, gatewayScopeAllHostsGroup, gatewayScopeAllExcludeGroup)
	}
	expandedHosts, err := validateExpandedGatewayScopeHosts(filtered)
	if err != nil {
		return nil, false, fmt.Errorf("resolve %q from inventory group %q: %w", gatewayScopeAllHostsKeyword, gatewayScopeAllHostsGroup, err)
	}
	return expandedHosts, true, nil
}

func runGatewayScope(cmd *cobra.Command, planOnly bool) error {
	// `plan` is read-only (design spec §1: "不形成 terminal mutation
	// event") — no readiness check, no publication, ever.
	if !planOnly {
		if _, err := webhookReadiness(gatewayScopeDirFlag); err != nil {
			return err
		}
	}
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return fmt.Errorf("prepare ansible runtime for gateway scope: %w", err)
	}
	ctx := withDeployAnsibleRuntime(cmd.Context(), runtime)
	inventory, vaultFile, err := resolveGatewayScopeInventoryAndVault(cmd, gatewayScopeDirFlag, gatewayScopeInventory, gatewayScopeVaultFile)
	if err != nil {
		return err
	}
	hosts, expanded, err := resolveGatewayScopeHosts(ctx, inventory, gatewayScopeHostsFlag)
	if err != nil {
		return err
	}
	if expanded {
		fmt.Fprintf(cmd.OutOrStdout(), "`--hosts all` expanded from inventory group %q (excluding %q hosts): %s\n", gatewayScopeAllHostsGroup, gatewayScopeAllExcludeGroup, strings.Join(hosts, ", "))
	}
	args, err := buildGatewayScopeArgs(gatewayScopeFlag, hosts, inventory, gatewayScopeTargetGroup, vaultFile, planOnly)
	if err != nil {
		return err
	}
	runner := ansible.NewRunner()
	runner.Timeout = gatewayScopeTimeout
	runner.Env = runtime.Env
	runner.LogPath = runtime.LogPath
	runner.StdoutWriter = cmd.OutOrStdout()
	runner.StderrWriter = cmd.ErrOrStderr()

	if planOnly {
		res, err := runner.Run(ctx, args...)
		if err == nil && res.ExitCode != 0 {
			return fmt.Errorf("gateway-scope plan failed (exit=%d)", res.ExitCode)
		}
		return err
	}

	workflowID := newWorkflowID()
	startedAt := time.Now()
	// ansible.Runner.Run reports a genuine playbook failure (non-zero
	// exit) through res.ExitCode, not err — err alone is nil in that
	// case, so checking only err here would silently publish
	// result:"success" for a real ansible failure.
	res, runErr := runner.Run(ctx, args...)
	if runErr == nil && res.ExitCode != 0 {
		runErr = fmt.Errorf("gateway-scope reconcile failed (exit=%d)", res.ExitCode)
	}
	publishGatewayScopeWorkflow(ctx, cmd.OutOrStdout(), inventory, vaultFile, workflowID, startedAt, runErr)
	return runErr
}

// publishGatewayScopeWorkflow is the shared terminal-publication step
// for every gateway-scope dedicated frontend (reconcile/enable-auto/
// disable-auto — design spec §1's table): requested/executed components
// are both ["pilot-gateway-scope"], effects are the fixed
// gatewayScopeEffects set, and delivery_runs is empty since none of
// these frontends use internal/delivery.Transaction.
func publishGatewayScopeWorkflow(ctx context.Context, out io.Writer, inventory, vaultFile, workflowID string, startedAt time.Time, runErr error) {
	result := outbound.ResultSuccess
	consistency := "confirmed_for_effects"
	var failure *outbound.FailureInfo
	if runErr != nil {
		result = outbound.ResultFailure
		consistency = "partial_or_unknown"
		failure = &outbound.FailureInfo{Class: "apply_failed", Component: "pilot-gateway-scope"}
	}
	confirmedEffects := []string(nil)
	if runErr == nil {
		confirmedEffects = gatewayScopeEffects
	}
	publishTerminalWorkflow(ctx, out, PublishTerminalWorkflowInput{
		WorkspaceDir:           gatewayScopeDirFlag,
		Inventory:              inventory,
		Vault:                  vaultInput{VaultPasswordFile: vaultFile},
		Operation:              outbound.OperationReconcile,
		WorkflowID:             workflowID,
		RequestedComponents:    []string{"pilot-gateway-scope"},
		ExecutedComponents:     []string{"pilot-gateway-scope"},
		CompletedComponents:    completedComponentsIf(runErr == nil, "pilot-gateway-scope"),
		Effects:                gatewayScopeEffects,
		ConfirmedEffects:       confirmedEffects,
		Result:                 result,
		ApplicationConsistency: consistency,
		Failure:                failure,
		StartedAt:              startedAt,
		FinishedAt:             time.Now(),
	})
}

func completedComponentsIf(ok bool, id string) []string {
	if ok {
		return []string{id}
	}
	return nil
}

// gatewayScopeAutomemberAction values match gateway-scope-apply.yml's
// gateway_scope_automember_action var exactly.
const (
	gatewayScopeAutomemberEnable  = "enable"
	gatewayScopeAutomemberDisable = "disable"
)

// buildGatewayScopeAutomemberArgs builds the ansible-playbook invocation for
// enable-auto/disable-auto. hosts must be empty for disable (it never
// touches membership, only the automember rule) and the already-expanded,
// gateway-excluded "all" list for enable (it also backfills membership right
// now — see runGatewayScopeAutomember).
func buildGatewayScopeAutomemberArgs(scope string, hosts []string, action, inventory, targetGroup, vaultFile string) ([]string, error) {
	if strings.TrimSpace(scope) == "" {
		return nil, fmt.Errorf("scope is required")
	}
	if action != gatewayScopeAutomemberEnable && action != gatewayScopeAutomemberDisable {
		return nil, fmt.Errorf("invalid automember action %q", action)
	}
	if action == gatewayScopeAutomemberDisable && len(hosts) != 0 {
		return nil, fmt.Errorf("disable-auto must not be given hosts (it never touches hostgroup membership)")
	}
	args := []string{
		gatewayScopeApplyPlaybook,
		"-i", inventory,
		"-e", "target_group=" + targetGroup,
		"-e", "gateway_scope=" + scope,
		"-e", "gateway_scope_automember_action=" + action,
	}
	if len(hosts) > 0 {
		expanded, err := validateExpandedGatewayScopeHosts(hosts)
		if err != nil {
			return nil, err
		}
		hostsJSON, err := json.Marshal(map[string]any{"gateway_scope_hosts": expanded})
		if err != nil {
			return nil, fmt.Errorf("encode gateway_scope_hosts: %w", err)
		}
		args = append(args, "-e", string(hostsJSON))
	}
	args = append(args, "-e", "@"+vaultFile)
	return args, nil
}

func runGatewayScopeAutomember(cmd *cobra.Command, enable bool) error {
	// Outbound webhook readiness (INV-3), before any mutation.
	if _, err := webhookReadiness(gatewayScopeDirFlag); err != nil {
		return err
	}
	runtime, err := prepareDeployAnsibleRuntime(resolvePilotDataDir())
	if err != nil {
		return fmt.Errorf("prepare ansible runtime for gateway scope: %w", err)
	}
	ctx := withDeployAnsibleRuntime(cmd.Context(), runtime)
	inventory, vaultFile, err := resolveGatewayScopeInventoryAndVault(cmd, gatewayScopeDirFlag, gatewayScopeInventory, gatewayScopeVaultFile)
	if err != nil {
		return err
	}

	action := gatewayScopeAutomemberDisable
	var hosts []string
	if enable {
		action = gatewayScopeAutomemberEnable
		var expanded bool
		hosts, expanded, err = resolveGatewayScopeHosts(ctx, inventory, []string{gatewayScopeAllHostsKeyword})
		if err != nil {
			return err
		}
		if expanded {
			fmt.Fprintf(cmd.OutOrStdout(), "`enable-auto` backfilling from inventory group %q (excluding %q hosts): %s\n", gatewayScopeAllHostsGroup, gatewayScopeAllExcludeGroup, strings.Join(hosts, ", "))
		}
	}

	args, err := buildGatewayScopeAutomemberArgs(gatewayScopeFlag, hosts, action, inventory, gatewayScopeTargetGroup, vaultFile)
	if err != nil {
		return err
	}
	runner := ansible.NewRunner()
	runner.Timeout = gatewayScopeTimeout
	runner.Env = runtime.Env
	runner.LogPath = runtime.LogPath
	runner.StdoutWriter = cmd.OutOrStdout()
	runner.StderrWriter = cmd.ErrOrStderr()

	workflowID := newWorkflowID()
	startedAt := time.Now()
	// See runGatewayScope's identical comment: a real playbook failure
	// surfaces as res.ExitCode != 0 with err == nil.
	res, runErr := runner.Run(ctx, args...)
	if runErr == nil && res.ExitCode != 0 {
		runErr = fmt.Errorf("gateway-scope %s-auto failed (exit=%d)", action, res.ExitCode)
	}
	publishGatewayScopeWorkflow(ctx, cmd.OutOrStdout(), inventory, vaultFile, workflowID, startedAt, runErr)
	return runErr
}
