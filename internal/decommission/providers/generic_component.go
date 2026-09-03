// generic_component.go implements Phase 5's generic contract-driven
// decommission provider (docs/superpowers/specs/2026-09-02-host-
// decommission-spec.md §15, §37 Phase 5). Unlike the bespoke providers
// (FreeIPA client, Wazuh agent, internal-endpoint — each hand-written for
// a component with real external/central state), this ONE Go type
// handles EVERY component that simply declares
// contracts/<component>.yaml's playbooks.decommission: it runs that
// playbook against the retiring host, restricted to its own "inspect" tag
// convention for read-only checks, full/untagged for the real mutation —
// exactly the same local-cleanup shape freeipa_client.go's
// freeipaUninstallStep already established, generalized to any component.
//
// This provider intentionally has NO central-cleanup step and NO
// knowledge of any component-specific external state — a component that
// needs central cleanup (a manager registration, a DNS record, a service
// principal, ...) needs its own bespoke provider (see
// cmd/pilot/cmd/host_decommission.go's buildHostDecommissionProviders and
// internal/contract/lint.go's componentsWithBespokeDecommissionProvider
// list), not this one. Every "initial stateless component decommission
// playbook" (spec.md §15) is therefore local-only by construction here.
//
// Every generic decommission playbook (spec.md §15's required shape)
// MUST print a single standardized marker under --tags inspect:
//
//	PILOT_COMPONENT_DECOMMISSIONED=true|false
//
// mirroring freeipa-client-decommission.yml's IPA_CLIENT_ENROLLED / wazuh-
// agent-decommission.yml's WAZUH_AGENT_ENROLLED convention, but with one
// FIXED marker name (never a component-specific one) — this is precisely
// what lets one Go provider type serve every stateless component's
// decommission playbook without per-component parsing logic.
package providers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/kjelly/pilot/internal/ansible"
)

// Step actions this provider's Plan returns (providers.Step.Action).
const ActionGenericComponentUninstall = "generic_component_uninstall"

var genericComponentDecommissionedPattern = regexp.MustCompile(`(?i)PILOT_COMPONENT_DECOMMISSIONED=true`)

// GenericComponentProviderConfig configures one GenericComponentProvider
// instance — one per component ID, built by the caller from that
// component's own resolved contract.Playbooks.Decommission (never a
// caller-supplied path per INV-5).
type GenericComponentProviderConfig struct {
	Executor ansibleExecutor

	// ComponentID is this provider's Provider.ID() — must exactly match
	// the contract ID it was resolved from (planner.go's planComponent
	// looks providers up by matched.ID).
	ComponentID string

	// Inventory targets the retiring host.
	Inventory string

	// DecommissionPlaybook is the component contract's own
	// playbooks.decommission path.
	DecommissionPlaybook string

	// ExtraArgs is appended verbatim to every ansible-playbook invocation.
	ExtraArgs []string
}

// GenericComponentProvider implements providers.Provider for any
// component whose only decommission need is "run this one playbook
// against the retiring host" (spec.md §15, Phase 5).
type GenericComponentProvider struct {
	cfg GenericComponentProviderConfig
}

// NewGenericComponentProvider builds a GenericComponentProvider from cfg.
func NewGenericComponentProvider(cfg GenericComponentProviderConfig) *GenericComponentProvider {
	return &GenericComponentProvider{cfg: cfg}
}

// ID implements Provider.
func (p *GenericComponentProvider) ID() string { return p.cfg.ComponentID }

// Inspect runs the component's decommission playbook restricted to
// --tags inspect (read-only by the spec.md §15 convention every generic
// decommission playbook must follow) and parses the standardized
// PILOT_COMPONENT_DECOMMISSIONED marker.
func (p *GenericComponentProvider) Inspect(ctx context.Context, in InspectInput) (Inspection, error) {
	hostName := in.HostName
	args := []string{p.cfg.DecommissionPlaybook}
	if p.cfg.Inventory != "" {
		args = append(args, "-i", p.cfg.Inventory)
	}
	if hostName != "" {
		args = append(args, "--limit", hostName)
	}
	args = append(args, "--tags", "inspect")
	args = append(args, p.cfg.ExtraArgs...)

	res, err := p.exec(ctx, args)
	if err != nil {
		return Inspection{}, fmt.Errorf("%s inspect %s: %w", p.cfg.ComponentID, hostName, err)
	}
	if res.ExitCode != 0 {
		return Inspection{}, fmt.Errorf("%s inspect %s: ansible-playbook exited %d: %s", p.cfg.ComponentID, hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	decommissioned := genericComponentDecommissionedPattern.MatchString(res.Stdout)
	detail := fmt.Sprintf("%s not yet decommissioned (PILOT_COMPONENT_DECOMMISSIONED=false or marker absent)", p.cfg.ComponentID)
	if decommissioned {
		detail = fmt.Sprintf("%s already decommissioned (PILOT_COMPONENT_DECOMMISSIONED=true)", p.cfg.ComponentID)
	}
	// Found=true means "still needs cleanup" (mirrors
	// FreeIPAClientProvider/WazuhAgentProvider's own Found=enrolled/
	// registered convention) — i.e. Found is the INVERSE of decommissioned.
	return Inspection{Provider: p.cfg.ComponentID, Detail: detail, Found: !decommissioned}, nil
}

// Plan returns the single local-cleanup step this provider ever produces.
func (p *GenericComponentProvider) Plan(ctx context.Context, in PlanInput) ([]Step, error) {
	return []Step{
		{Provider: p.cfg.ComponentID, Phase: "local_cleanup", Action: ActionGenericComponentUninstall, TargetIdentity: in.HostName},
	}, nil
}

// ExecutorForStep implements providers.StepRunner.
func (p *GenericComponentProvider) ExecutorForStep(step Step) (StepExecutor, error) {
	if step.Action != ActionGenericComponentUninstall {
		return nil, fmt.Errorf("%s: unknown planned step action %q — programming/version-skew error, not a normal runtime condition", p.cfg.ComponentID, step.Action)
	}
	return &genericComponentUninstallStep{provider: p, hostName: step.TargetIdentity}, nil
}

type genericComponentUninstallStep struct {
	provider *GenericComponentProvider
	hostName string
}

// Inspect reuses Provider.Inspect's own marker check — converged means
// already decommissioned (e.g. a resume after this step already ran).
func (e *genericComponentUninstallStep) Inspect(ctx context.Context) (bool, error) {
	insp, err := e.provider.Inspect(ctx, InspectInput{HostName: e.hostName})
	if err != nil {
		return false, err
	}
	return !insp.Found, nil
}

// Execute runs the real decommission playbook (no --tags inspect this
// time — the mutating tasks are what we want).
func (e *genericComponentUninstallStep) Execute(ctx context.Context) error {
	args := []string{e.provider.cfg.DecommissionPlaybook}
	if e.provider.cfg.Inventory != "" {
		args = append(args, "-i", e.provider.cfg.Inventory)
	}
	if e.hostName != "" {
		args = append(args, "--limit", e.hostName)
	}
	args = append(args, e.provider.cfg.ExtraArgs...)
	res, err := e.provider.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("%s uninstall %s: %w", e.provider.cfg.ComponentID, e.hostName, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s uninstall %s: ansible-playbook exited %d: %s", e.provider.cfg.ComponentID, e.hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// Verify independently re-runs Inspect — this provider has no central
// state to check, so local re-inspection IS the whole verification
// surface for a generic stateless component (spec.md §15 scope).
func (p *GenericComponentProvider) Verify(ctx context.Context, in VerifyInput) ([]Verification, error) {
	insp, err := p.Inspect(ctx, InspectInput{HostName: firstNonEmpty(in.HostName, in.FQDN)})
	if err != nil {
		return nil, fmt.Errorf("%s verify %s: %w", p.cfg.ComponentID, in.HostName, err)
	}
	return []Verification{{
		Provider: p.cfg.ComponentID, Kind: "local_uninstall", Identity: in.HostName,
		Status: statusForAbsence(!insp.Found), Active: insp.Found,
		Detail: insp.Detail,
	}}, nil
}

func (p *GenericComponentProvider) exec(ctx context.Context, args []string) (*ansible.Result, error) {
	if p.cfg.Executor == nil {
		return nil, fmt.Errorf("%s provider: no ansible executor configured", p.cfg.ComponentID)
	}
	return p.cfg.Executor.Run(ctx, args...)
}
