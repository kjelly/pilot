package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/spf13/cobra"
)

// Inventory groups whose hosts a decommission changes besides the retired
// host. buildHostDecommissionProviders wires them into the providers'
// stage arguments and hostDecommissionStageTargets checks them up front,
// so both read these names.
const (
	stageRoleFreeIPAServer = "freeipa-server" // freeipa-identity-apply.yml's default hosts
	stageRoleWazuhManager  = "wazuh-manager"  // wazuh-manager-agent-deregister.yml's default hosts
)

// hostDecommissionStageFlags holds the stage confirmation flags that apply
// and resume take for hosts in staging or prod.
type hostDecommissionStageFlags struct {
	confirmStaging bool
	confirmProd    bool
	attestedHours  int
}

var (
	hostDecommissionApplyStage  hostDecommissionStageFlags
	hostDecommissionResumeStage hostDecommissionStageFlags
)

func addHostDecommissionStageFlags(cmd *cobra.Command, f *hostDecommissionStageFlags) {
	cmd.Flags().BoolVar(&f.confirmStaging, "confirm-staging", false, "confirm changes to hosts in the staging environment; required when the decommissioned host, or a FreeIPA server or Wazuh manager the run changes, is in staging")
	cmd.Flags().BoolVar(&f.confirmProd, "confirm-prod", false, "confirm changes to hosts in the prod environment; required, with --staging-attested-within-hours, when any host the run changes is in prod")
	cmd.Flags().IntVar(&f.attestedHours, "staging-attested-within-hours", -1, "hours since staging was last verified (0-168); required with --confirm-prod")
}

// authorization validates the flags and returns them as a
// decommission.StageAuthorization.
func (f hostDecommissionStageFlags) authorization() (decommission.StageAuthorization, error) {
	if f.attestedHours != -1 && (f.attestedHours < 0 || f.attestedHours > 168) {
		return decommission.StageAuthorization{}, fmt.Errorf("--staging-attested-within-hours must be 0 to 168, got %d", f.attestedHours)
	}
	return decommission.StageAuthorization{
		ConfirmStaging:             f.confirmStaging,
		ConfirmProd:                f.confirmProd,
		StagingAttestedWithinHours: f.attestedHours,
	}, nil
}

// noStageAuthorization is the authorization for `plan`, which runs no
// playbook.
func noStageAuthorization() decommission.StageAuthorization {
	return decommission.StageAuthorization{StagingAttestedWithinHours: -1}
}

// loadHostDecommissionStageScope builds the stage scope from the
// workspace's hosts.yml.
func loadHostDecommissionStageScope(dir string, auth decommission.StageAuthorization) (*decommission.StageScope, error) {
	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		return nil, fmt.Errorf("read hosts.yml for stage check: %w", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("parse hosts.yml for stage check: %w", err)
	}
	return decommission.NewStageScope(hf.Hosts, auth), nil
}

// hostDecommissionStageTarget is one set of hosts that some playbook run
// of the plan targets.
type hostDecommissionStageTarget struct {
	Label string
	Hosts []string
}

// hostDecommissionStageTargets lists the host sets the plan's playbook runs
// target: the retired host for every local step, and for components with
// central steps the hosts those playbooks run on.
func hostDecommissionStageTargets(plan *decommission.Plan, scope *decommission.StageScope) []hostDecommissionStageTarget {
	targets := []hostDecommissionStageTarget{{Label: "local cleanup on " + plan.Host.Name, Hosts: []string{plan.Host.Name}}}
	for _, c := range plan.Components {
		switch c.ComponentID {
		case providers.FreeIPAClientProviderID:
			targets = append(targets, hostDecommissionStageTarget{Label: "FreeIPA identity reconcile on the " + stageRoleFreeIPAServer + " hosts", Hosts: scope.RoleHosts(stageRoleFreeIPAServer)})
		case providers.WazuhAgentProviderID:
			targets = append(targets, hostDecommissionStageTarget{Label: "Wazuh agent deregistration on the " + stageRoleWazuhManager + " hosts", Hosts: scope.RoleHosts(stageRoleWazuhManager)})
		case providers.InternalEndpointProviderID:
			for _, s := range c.Steps {
				if s.Action == providers.ActionInternalEndpointApplyConverge {
					targets = append(targets, hostDecommissionStageTarget{Label: "internal-endpoint apply-converge, whose baseline play targets every host", Hosts: scope.AllHosts()})
					break
				}
			}
		}
	}
	return targets
}

// checkHostDecommissionStage refuses to start an apply or resume whose
// playbook runs would fail their stage gates: a host set that spans
// stages, or a staging/prod host set without the operator's confirmation.
// It runs before any step, so a missing flag never leaves a decommission
// half done.
func checkHostDecommissionStage(dir string, plan *decommission.Plan, auth decommission.StageAuthorization) error {
	scope, err := loadHostDecommissionStageScope(dir, auth)
	if err != nil {
		return err
	}
	var problems []string
	for _, t := range hostDecommissionStageTargets(plan, scope) {
		if _, err := scope.Args(t.Hosts); err != nil {
			problems = append(problems, fmt.Sprintf("  - %s: %v", t.Label, err))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("host decommission %s was not started; the stage gates of its playbook runs would refuse it:\n%s", plan.ID, strings.Join(problems, "\n"))
}

// printHostDecommissionStageNeeds tells the operator, after `plan`, which
// stage confirmation apply/resume will need.
func printHostDecommissionStageNeeds(out io.Writer, dir string, plan *decommission.Plan) {
	scope, err := loadHostDecommissionStageScope(dir, noStageAuthorization())
	if err != nil {
		return
	}
	var lines []string
	for _, t := range hostDecommissionStageTargets(plan, scope) {
		stage, err := scope.Stage(t.Hosts)
		switch {
		case err != nil:
			lines = append(lines, fmt.Sprintf("  %s: cannot run — %v", t.Label, err))
		case stage == "staging":
			lines = append(lines, fmt.Sprintf("  %s: staging — pass --confirm-staging", t.Label))
		case stage == "prod":
			lines = append(lines, fmt.Sprintf("  %s: prod — pass --confirm-prod --staging-attested-within-hours <0-168>", t.Label))
		}
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintln(out, "  stage confirmation for apply/resume:")
	for _, l := range lines {
		fmt.Fprintln(out, l)
	}
}
