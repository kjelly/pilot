// wazuh_agent.go implements Phase 4's Wazuh agent decommission provider
// (docs/superpowers/specs/2026-09-02-host-decommission-spec.md §37 Phase
// 4, HD14). Mirrors freeipa_client.go's local/central split exactly:
//   - AgentInventory/AgentDecommissionPlaybook: the retiring host itself,
//     running playbooks/decommission/wazuh-agent-decommission.yml (stop the
//     local agent, remove its enrollment key).
//   - ServerInventory/ManagerDeregisterPlaybook: the Wazuh manager host,
//     running playbooks/decommission/wazuh-manager-agent-deregister.yml
//     (list registered agents, find the retiring host by an EXACT Name
//     match, deregister by its numeric ID).
//
// HD14's own wording ("removed by stable recorded identity only, never by
// hostname substring") is why wazuh-fim-apply.yml's Step 9 now pins
// `agent-auth -A {{ inventory_hostname }}` — this provider's manager-side
// lookup is always an EXACT string comparison against that same
// inventory hostname (findWazuhAgentID below), never a substring/fuzzy
// match; a host whose agent was registered before that pin existed (a
// bare `hostname` name Pilot cannot reliably reconstruct) is simply not
// found and treated as already-absent rather than guessed at (spec.md
// §5.6: "a name similarity or hostname substring alone is NOT ownership
// evidence").
//
// Every live query/mutation goes through the same ansibleExecutor seam
// freeipa_client.go defines (same package, reused directly) — every test
// here substitutes an in-package fake; no live host or real
// ansible-playbook binary is touched by `go test` (code + fixture tests
// only; actual disposable-target evidence is a separate follow-up pass).
package providers

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
)

// WazuhAgentProviderID is this provider's stable ID — matches the
// wazuh-fim component/role name (Provider.ID()).
const WazuhAgentProviderID = "wazuh-fim"

// Step actions this provider's Plan returns (providers.Step.Action).
const (
	ActionWazuhAgentUninstall  = "wazuh_agent_uninstall"
	ActionWazuhAgentDeregister = "wazuh_agent_deregister"
)

// WazuhAgentProviderConfig configures one WazuhAgentProvider instance.
// Every path here is resolved by the CALLER (never accepted from an
// Agent/MCP path per INV-5).
type WazuhAgentProviderConfig struct {
	Executor ansibleExecutor

	AgentInventory  string // targets the retiring host for local cleanup
	ServerInventory string // targets the Wazuh manager for central deregistration

	AgentDecommissionPlaybook string // playbooks/decommission/wazuh-agent-decommission.yml
	ManagerDeregisterPlaybook string // playbooks/decommission/wazuh-manager-agent-deregister.yml

	// ExtraArgs is appended verbatim to every ansible-playbook invocation
	// this provider issues — non-secret plumbing only.
	ExtraArgs []string
}

// WazuhAgentProvider implements providers.Provider for the wazuh-fim
// component (spec.md §37 Phase 4).
type WazuhAgentProvider struct {
	cfg WazuhAgentProviderConfig
}

// NewWazuhAgentProvider builds a WazuhAgentProvider from cfg.
func NewWazuhAgentProvider(cfg WazuhAgentProviderConfig) *WazuhAgentProvider {
	return &WazuhAgentProvider{cfg: cfg}
}

// ID implements Provider.
func (p *WazuhAgentProvider) ID() string { return WazuhAgentProviderID }

// ---- Inspect ---------------------------------------------------------

var wazuhAgentEnrolledPattern = regexp.MustCompile(`(?i)WAZUH_AGENT_ENROLLED=true`)

// Inspect reports whether the target host currently looks like an
// enrolled Wazuh agent — best-effort, read-only. Runs
// playbooks/decommission/wazuh-agent-decommission.yml restricted to its
// "inspect" tag (a stat + debug pair, no mutating task carries that tag).
func (p *WazuhAgentProvider) Inspect(ctx context.Context, in InspectInput) (Inspection, error) {
	hostName := in.HostName
	args := []string{p.cfg.AgentDecommissionPlaybook}
	if p.cfg.AgentInventory != "" {
		args = append(args, "-i", p.cfg.AgentInventory)
	}
	if hostName != "" {
		args = append(args, "--limit", hostName)
	}
	args = append(args, "--tags", "inspect")
	args = append(args, p.cfg.ExtraArgs...)

	res, err := p.exec(ctx, args)
	if err != nil {
		return Inspection{}, fmt.Errorf("wazuh-fim inspect %s: %w", hostName, err)
	}
	if res.ExitCode != 0 {
		return Inspection{}, fmt.Errorf("wazuh-fim inspect %s: ansible-playbook exited %d: %s", hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	enrolled := wazuhAgentEnrolledPattern.MatchString(res.Stdout)
	detail := "Wazuh agent enrollment not detected (WAZUH_AGENT_ENROLLED=false or marker absent)"
	if enrolled {
		detail = "Wazuh agent is currently enrolled (WAZUH_AGENT_ENROLLED=true)"
	}
	return Inspection{Provider: WazuhAgentProviderID, Detail: detail, Found: enrolled}, nil
}

// ---- Plan --------------------------------------------------------------

// Plan returns the two ordered steps this provider would execute: local
// agent stop/key-removal, then manager-side deregistration by exact
// recorded identity. Performs no live discovery itself — each step's own
// Inspect (called by internal/decommission's executor before Execute)
// independently re-queries live state to decide whether it is already
// converged, exactly like FreeIPAClientProvider's steps.
func (p *WazuhAgentProvider) Plan(ctx context.Context, in PlanInput) ([]Step, error) {
	hostName := in.HostName
	return []Step{
		{Provider: WazuhAgentProviderID, Phase: "local_cleanup", Action: ActionWazuhAgentUninstall, TargetIdentity: hostName},
		{Provider: WazuhAgentProviderID, Phase: "central_cleanup", Action: ActionWazuhAgentDeregister, TargetIdentity: hostName},
	}, nil
}

// ---- Execute (StepRunner) -------------------------------------------------

// ExecutorForStep implements providers.StepRunner.
func (p *WazuhAgentProvider) ExecutorForStep(step Step) (StepExecutor, error) {
	switch step.Action {
	case ActionWazuhAgentUninstall:
		return &wazuhAgentUninstallStep{provider: p, hostName: step.TargetIdentity}, nil
	case ActionWazuhAgentDeregister:
		return &wazuhAgentDeregisterStep{provider: p, hostName: step.TargetIdentity}, nil
	default:
		return nil, fmt.Errorf("wazuh-fim: unknown planned step action %q — programming/version-skew error, not a normal runtime condition", step.Action)
	}
}

// ---- step: local agent stop/key-removal (playbooks/decommission/wazuh-agent-decommission.yml) ----

type wazuhAgentUninstallStep struct {
	provider *WazuhAgentProvider
	hostName string
}

// Inspect reuses Provider.Inspect's own enrollment marker check.
func (e *wazuhAgentUninstallStep) Inspect(ctx context.Context) (bool, error) {
	insp, err := e.provider.Inspect(ctx, InspectInput{HostName: e.hostName})
	if err != nil {
		return false, err
	}
	return !insp.Found, nil
}

// Execute runs the real local decommission playbook (no --tags inspect
// this time — the mutating tasks are what we want).
func (e *wazuhAgentUninstallStep) Execute(ctx context.Context) error {
	args := []string{e.provider.cfg.AgentDecommissionPlaybook}
	if e.provider.cfg.AgentInventory != "" {
		args = append(args, "-i", e.provider.cfg.AgentInventory)
	}
	if e.hostName != "" {
		args = append(args, "--limit", e.hostName)
	}
	args = append(args, e.provider.cfg.ExtraArgs...)
	res, err := e.provider.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("wazuh-fim uninstall %s: %w", e.hostName, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("wazuh-fim uninstall %s: ansible-playbook exited %d: %s", e.hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// ---- step: central manager deregistration (playbooks/decommission/wazuh-manager-agent-deregister.yml) ----

type wazuhAgentDeregisterStep struct {
	provider *WazuhAgentProvider
	hostName string
}

// Inspect reuses the same live agent-list query Verify uses: converged
// means no agent with this host's EXACT name is currently registered
// (e.g. a resume after this step's deregister already ran, or the agent
// was never registered with -A inventory_hostname to begin with).
func (e *wazuhAgentDeregisterStep) Inspect(ctx context.Context) (bool, error) {
	_, found, err := e.provider.findAgentID(ctx, e.hostName)
	if err != nil {
		return false, err
	}
	return !found, nil
}

// Execute re-resolves the agent's exact numeric ID (never trusts a
// previously-cached value — INV-9 resume-safety) and, only if still
// found, deregisters by that ID.
func (e *wazuhAgentDeregisterStep) Execute(ctx context.Context) error {
	id, found, err := e.provider.findAgentID(ctx, e.hostName)
	if err != nil {
		return fmt.Errorf("wazuh-fim deregister %s: %w", e.hostName, err)
	}
	if !found {
		return nil // already gone -- nothing to do
	}
	args := []string{e.provider.cfg.ManagerDeregisterPlaybook}
	if e.provider.cfg.ServerInventory != "" {
		args = append(args, "-i", e.provider.cfg.ServerInventory)
	}
	args = append(args, "--tags", "agent_deregister")
	args = append(args, "-e", "pilot_decommission_action=deregister")
	args = append(args, "-e", "pilot_decommission_target_agent_id="+id)
	args = append(args, e.provider.cfg.ExtraArgs...)
	res, err := e.provider.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("wazuh-fim deregister %s: %w", e.hostName, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("wazuh-fim deregister %s: ansible-playbook exited %d: %s", e.hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// ---- Verify --------------------------------------------------------------

// Verify independently re-queries the manager's live agent list and
// reports whether this host's EXACT-name agent registration is still
// active (INV-10) — never trusts a prior step's exit code alone.
func (p *WazuhAgentProvider) Verify(ctx context.Context, in VerifyInput) ([]Verification, error) {
	hostName := firstNonEmpty(in.HostName, in.FQDN)
	_, found, err := p.findAgentID(ctx, hostName)
	if err != nil {
		return nil, fmt.Errorf("wazuh-fim verify %s: %w", hostName, err)
	}
	return []Verification{{
		Provider: WazuhAgentProviderID, Kind: "manager_agent_registration", Identity: hostName,
		Status: statusForAbsence(!found), Active: found,
		Detail: "manage_agents -l exact Name match for " + hostName,
	}}, nil
}

// ---- shared live-query plumbing -------------------------------------------

// wazuhAgentListEntryPattern extracts each "ID: <n>, Name: <name>," entry
// from manage_agents -l output. Deliberately NOT anchored to a line
// boundary (no ^/$, no (?m)) — every entry's ID/Name/IP fields live on
// what is conceptually one line regardless of whether the separator
// between entries survives as a real newline or (per freeipa_client.go's
// fieldPattern doc comment) gets flattened to literal "\n" text by
// ansible.builtin.debug's console rendering; a plain, non-anchored search
// finds every entry correctly either way.
var wazuhAgentListEntryPattern = regexp.MustCompile(`ID:\s*(\d+),\s*Name:\s*([^,]+),`)

// findAgentID looks up hostName's registered agent by an EXACT Name
// match (never Contains/substring — spec.md §5.6, HD14) against the
// manager's live agent list, returning its numeric ID.
func (p *WazuhAgentProvider) findAgentID(ctx context.Context, hostName string) (id string, found bool, err error) {
	args := []string{p.cfg.ManagerDeregisterPlaybook}
	if p.cfg.ServerInventory != "" {
		args = append(args, "-i", p.cfg.ServerInventory)
	}
	args = append(args, "--tags", "agent_query")
	args = append(args, "-e", "pilot_decommission_query=agent_list")
	args = append(args, "-e", "pilot_decommission_target_hostname="+hostName)
	args = append(args, p.cfg.ExtraArgs...)
	res, err := p.exec(ctx, args)
	if err != nil {
		return "", false, err
	}
	if res.ExitCode != 0 {
		return "", false, fmt.Errorf("wazuh-fim agent_list query for %s: ansible-playbook exited %d: %s", hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	for _, m := range wazuhAgentListEntryPattern.FindAllStringSubmatch(res.Stdout, -1) {
		if strings.TrimSpace(m[2]) == hostName {
			return strings.TrimSpace(m[1]), true, nil
		}
	}
	return "", false, nil
}

func (p *WazuhAgentProvider) exec(ctx context.Context, args []string) (*ansible.Result, error) {
	if p.cfg.Executor == nil {
		return nil, fmt.Errorf("wazuh-fim provider: no ansible executor configured")
	}
	return p.cfg.Executor.Run(ctx, args...)
}
