// freeipa_nfs_server.go implements Phase 6's freeipa-nfs-server
// decommission provider (docs/superpowers/specs/2026-09-02-host-
// decommission-spec.md §20.2, §37 Phase 6). This is the feature's one
// stateful/retention-gated component with a real bespoke provider — the
// retention gate itself (class=stateful, retention=required) already
// blocks planning at the generic planComponent level (Phase 1, INV-8)
// until an operator supplies a disposition; once satisfied, THIS provider
// removes only the FreeIPA-side service identity and this host's own
// local exports fragment, never any actual NFS share/export DATA
// (spec.md §20.2/§20.3 — explicitly out of scope regardless of which
// disposition was recorded, see playbooks/decommission/
// freeipa-nfs-server-decommission.yml's own doc comment).
//
// Unlike freeipa_client.go's local/central split across two playbooks,
// this provider's single ansible playbook does both (the NFS server
// authenticates as the roster admin directly, see that playbook's doc
// comment) — but the roster-side convergence (nfs.servers[] -> state:
// absent) is still its own separate, pure-Go step, mirroring
// freeipaRosterAbsentStep exactly.
package providers

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

// FreeIPANFSServerProviderID is this provider's stable ID — matches the
// freeipa-nfs-server component/role name (Provider.ID()).
const FreeIPANFSServerProviderID = "freeipa-nfs-server"

// Step actions this provider's Plan returns (providers.Step.Action).
const (
	ActionFreeIPANFSRosterAbsent = "freeipa_nfs_roster_absent"
	ActionFreeIPANFSDecommission = "freeipa_nfs_decommission"
)

var nfsServerDecommissionedPattern = regexp.MustCompile(`(?i)NFS_SERVER_DECOMMISSIONED=true`)

// FreeIPANFSServerProviderConfig configures one FreeIPANFSServerProvider
// instance. Every path here is resolved by the CALLER (never accepted
// from an Agent/MCP path per INV-5).
type FreeIPANFSServerProviderConfig struct {
	Executor ansibleExecutor

	Inventory string // targets the retiring NFS server host

	DecommissionPlaybook string // playbooks/decommission/freeipa-nfs-server-decommission.yml

	// ExtraArgs is appended verbatim to every ansible-playbook invocation
	// (must include "-e freeipa_roster_file=<path>" — this provider does
	// not resolve that itself, matching FreeIPAClientProvider's own
	// caller-resolves-the-roster-path convention).
	ExtraArgs []string
}

// FreeIPANFSServerProvider implements providers.Provider for the
// freeipa-nfs-server component (spec.md §37 Phase 6).
type FreeIPANFSServerProvider struct {
	cfg FreeIPANFSServerProviderConfig
}

// NewFreeIPANFSServerProvider builds a FreeIPANFSServerProvider from cfg.
func NewFreeIPANFSServerProvider(cfg FreeIPANFSServerProviderConfig) *FreeIPANFSServerProvider {
	return &FreeIPANFSServerProvider{cfg: cfg}
}

// ID implements Provider.
func (p *FreeIPANFSServerProvider) ID() string { return FreeIPANFSServerProviderID }

// ---- Inspect ---------------------------------------------------------

// Inspect reports whether the target host still looks like an active
// FreeIPA NFS server (service principal and/or local exports fragment
// still present) — best-effort, read-only.
func (p *FreeIPANFSServerProvider) Inspect(ctx context.Context, in InspectInput) (Inspection, error) {
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
		return Inspection{}, fmt.Errorf("freeipa-nfs-server inspect %s: %w", hostName, err)
	}
	if res.ExitCode != 0 {
		return Inspection{}, fmt.Errorf("freeipa-nfs-server inspect %s: ansible-playbook exited %d: %s", hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	decommissioned := nfsServerDecommissionedPattern.MatchString(res.Stdout)
	detail := "NFS server not yet decommissioned (service principal and/or exports fragment still present)"
	if decommissioned {
		detail = "NFS server already decommissioned (NFS_SERVER_DECOMMISSIONED=true)"
	}
	return Inspection{Provider: FreeIPANFSServerProviderID, Detail: detail, Found: !decommissioned}, nil
}

// ---- Plan --------------------------------------------------------------

// Plan returns the two ordered steps this provider would execute: roster
// nfs.servers[] convergence to state: absent, then the real service-
// principal/exports-fragment removal. Performs only read-only local
// simulation itself (a dry-run roster check, never mutates) — matching
// FreeIPAClientProvider's own posture.
func (p *FreeIPANFSServerProvider) Plan(ctx context.Context, in PlanInput) ([]Step, error) {
	hostName := in.HostName
	fqdn := firstNonEmpty(in.FQDN, hostName)

	if p.RosterPathSet(in) {
		violations, found, err := inventory.SimulateRemoveRosterNFSServer(in.RosterPath, fqdn)
		if err != nil {
			return nil, fmt.Errorf("freeipa-nfs-server plan %s: roster mutation would be invalid: %w", hostName, err)
		}
		if found && len(violations) > 0 {
			return nil, fmt.Errorf("freeipa-nfs-server plan %s: roster would be invalid after converging this nfs server to absent: %v", hostName, violations)
		}
	}

	rosterStepParams := map[string]string(nil)
	if p.RosterPathSet(in) {
		rosterStepParams = map[string]string{"roster_path": in.RosterPath}
	}

	return []Step{
		{Provider: FreeIPANFSServerProviderID, Phase: "central_cleanup", Action: ActionFreeIPANFSRosterAbsent, TargetIdentity: hostName, Params: rosterStepParams},
		{Provider: FreeIPANFSServerProviderID, Phase: "central_cleanup", Action: ActionFreeIPANFSDecommission, TargetIdentity: fqdn},
	}, nil
}

// RosterPathSet reports whether in carries a roster path — see
// FreeIPAClientProvider's identically-named method.
func (p *FreeIPANFSServerProvider) RosterPathSet(in PlanInput) bool {
	return strings.TrimSpace(in.RosterPath) != ""
}

// ---- Execute (StepRunner) -------------------------------------------------

// ExecutorForStep implements providers.StepRunner.
func (p *FreeIPANFSServerProvider) ExecutorForStep(step Step) (StepExecutor, error) {
	switch step.Action {
	case ActionFreeIPANFSRosterAbsent:
		return &freeipaNFSRosterAbsentStep{fqdn: step.TargetIdentity, rosterPath: step.Params["roster_path"]}, nil
	case ActionFreeIPANFSDecommission:
		return &freeipaNFSDecommissionStep{provider: p, fqdn: step.TargetIdentity}, nil
	default:
		return nil, fmt.Errorf("freeipa-nfs-server: unknown planned step action %q — programming/version-skew error, not a normal runtime condition", step.Action)
	}
}

// ---- step: roster nfs.servers[] convergence (pure Go, no ansible) --------

type freeipaNFSRosterAbsentStep struct {
	fqdn       string
	rosterPath string
}

func (e *freeipaNFSRosterAbsentStep) Inspect(ctx context.Context) (bool, error) {
	if strings.TrimSpace(e.rosterPath) == "" {
		return true, nil
	}
	return inventory.RosterNFSServerAbsent(e.rosterPath, e.fqdn)
}

func (e *freeipaNFSRosterAbsentStep) Execute(ctx context.Context) error {
	if strings.TrimSpace(e.rosterPath) == "" {
		return nil
	}
	if err := inventory.SetRosterNFSServerAbsent(e.rosterPath, e.fqdn); err != nil {
		return fmt.Errorf("freeipa-nfs-server roster-absent %s: %w", e.fqdn, err)
	}
	return nil
}

// ---- step: real service-principal + exports removal (playbooks/decommission/freeipa-nfs-server-decommission.yml) ----

type freeipaNFSDecommissionStep struct {
	provider *FreeIPANFSServerProvider
	fqdn     string
}

// Inspect reuses Provider.Inspect's own marker check.
func (e *freeipaNFSDecommissionStep) Inspect(ctx context.Context) (bool, error) {
	insp, err := e.provider.Inspect(ctx, InspectInput{HostName: e.fqdn})
	if err != nil {
		return false, err
	}
	return !insp.Found, nil
}

// Execute runs the real decommission playbook (no --tags inspect this
// time — the mutating tasks are what we want).
func (e *freeipaNFSDecommissionStep) Execute(ctx context.Context) error {
	args := []string{e.provider.cfg.DecommissionPlaybook}
	if e.provider.cfg.Inventory != "" {
		args = append(args, "-i", e.provider.cfg.Inventory)
	}
	if e.fqdn != "" {
		args = append(args, "--limit", e.fqdn)
	}
	args = append(args, e.provider.cfg.ExtraArgs...)
	res, err := e.provider.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("freeipa-nfs-server decommission %s: %w", e.fqdn, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("freeipa-nfs-server decommission %s: ansible-playbook exited %d: %s", e.fqdn, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// ---- Verify --------------------------------------------------------------

// Verify independently re-runs Inspect's own live query (INV-10) — this
// provider's whole external-state surface is the nfs/<fqdn> service
// principal and this host's own exports fragment, both of which
// Inspect's marker already covers together; splitting them into two
// separate Verification entries isn't needed since both are checked in
// the SAME live ansible run this calls (unlike internal-endpoint's
// multi-identity case, there is exactly one identity here: this host).
func (p *FreeIPANFSServerProvider) Verify(ctx context.Context, in VerifyInput) ([]Verification, error) {
	fqdn := firstNonEmpty(in.FQDN, in.HostName)
	insp, err := p.Inspect(ctx, InspectInput{HostName: fqdn})
	if err != nil {
		return nil, fmt.Errorf("freeipa-nfs-server verify %s: %w", fqdn, err)
	}
	return []Verification{{
		Provider: FreeIPANFSServerProviderID, Kind: "nfs_service_principal_and_exports", Identity: fqdn,
		Status: statusForAbsence(!insp.Found), Active: insp.Found,
		Detail: insp.Detail,
	}}, nil
}

func (p *FreeIPANFSServerProvider) exec(ctx context.Context, args []string) (*ansible.Result, error) {
	if p.cfg.Executor == nil {
		return nil, fmt.Errorf("freeipa-nfs-server provider: no ansible executor configured")
	}
	return p.cfg.Executor.Run(ctx, args...)
}
