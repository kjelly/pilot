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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/spf13/cobra"
)

const gatewayScopeApplyPlaybook = "playbooks/apply/gateway-scope-apply.yml"

var (
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

func init() {
	for _, sub := range []*cobra.Command{gatewayScopePlanCmd, gatewayScopeReconcileCmd} {
		sub.Flags().StringVar(&gatewayScopeFlag, "scope", "", "gateway scope name, e.g. gpu (required)")
		sub.Flags().StringSliceVar(&gatewayScopeHostsFlag, "hosts", nil, "desired FQDNs for pilot-target-<scope> (comma-separated, required)")
		sub.Flags().StringVarP(&gatewayScopeInventory, "inventory", "i", "", "Ansible inventory targeting the FreeIPA server (required)")
		sub.Flags().StringVar(&gatewayScopeTargetGroup, "target-group", "freeipa-server", "inventory group/host the playbook runs against")
		sub.Flags().StringVar(&gatewayScopeVaultFile, "vault-file", "", "vars file defining ipa_admin_password, passed as -e @<file> (required)")
		sub.Flags().DurationVar(&gatewayScopeTimeout, "timeout", 5*time.Minute, "ansible-playbook timeout")
		sub.MarkFlagRequired("scope")
		sub.MarkFlagRequired("hosts")
		sub.MarkFlagRequired("inventory")
		sub.MarkFlagRequired("vault-file")
	}
	gatewayScopeCmd.AddCommand(gatewayScopePlanCmd, gatewayScopeReconcileCmd)
	rootCmd.AddCommand(gatewayScopeCmd)
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
	if len(hosts) == 0 {
		return nil, fmt.Errorf("hosts is required")
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

func runGatewayScope(cmd *cobra.Command, planOnly bool) error {
	args, err := buildGatewayScopeArgs(gatewayScopeFlag, gatewayScopeHostsFlag, gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile, planOnly)
	if err != nil {
		return err
	}
	runner := ansible.NewRunner()
	runner.Timeout = gatewayScopeTimeout
	runner.StdoutWriter = cmd.OutOrStdout()
	runner.StderrWriter = cmd.ErrOrStderr()
	_, err = runner.Run(cmd.Context(), args...)
	return err
}
