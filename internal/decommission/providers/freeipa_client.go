// freeipa_client.go implements Phase 3a's FreeIPA client decommission
// provider (docs/superpowers/specs/2026-09-02-host-decommission-spec.md
// §16, §37 Phase 3). It is the first real Provider (provider.go) to
// register — until now every component was unconditionally classified
// external_state_unsupported because no provider existed at all.
//
// Every live query/mutation this provider needs goes through the small
// ansibleExecutor seam below (mirroring internal/repair/reapply_plan.go's
// PreviewRunner boundary: "caller owns the runtime"), never a direct
// os/exec call from this package. *internal/ansible.Runner satisfies
// ansibleExecutor for real (its Run method already has this exact
// signature); every test in this package substitutes an in-package fake
// that returns canned stdout/exit codes — no live host, no real
// ansible-playbook binary, is ever touched by `go test` here (Phase 3a is
// code + fixture tests only; actual disposable FreeIPA evidence is a
// separate Phase 3b, see spec.md §37 Phase 3's own list).
//
// Two logically separate targets are involved, matching spec.md §16's own
// split between client-side and central cleanup:
//   - ClientInventory/DecommissionPlaybook: the retiring host itself,
//     running playbooks/decommission/freeipa-client-decommission.yml
//     (local enrollment removal).
//   - ServerInventory/IdentityApplyPlaybook: the FreeIPA server, running
//     playbooks/apply/freeipa-identity-apply.yml with the roster's host
//     entry converged to state: absent (central hostgroup/netgroup/HBAC/
//     sudo reference pruning, service-principal check, surgical DNS
//     deletion, host-del) — see that playbook's new
//     "Hosts marked absent" section.
//
// This provider's read-only discovery calls (the unknown-service-
// principal check in Plan, and every check in Verify) pass
// "-e pilot_decommission_query=<kind>" so a caller (real or fake) can tell
// which live-state question is being asked; the corresponding read-only
// server-side task/tag wiring in freeipa-identity-apply.yml is a Phase 3b
// finding (see that playbook's own "Hosts marked absent" section for what
// exists today: the "freeipa_host_absent_inspect" tag covers the host-
// object/hostgroup/netgroup/service-principal question this provider
// calls "host_object"). The DNS/HBAC/sudo-reference query kinds
// (host_dns/hbac_references/sudo_references) are this provider's intended
// contract for that same playbook to grow read-only entry points for in a
// later phase — deliberately not built out further here, since Phase 3a's
// job is the Go-level contract + fixture tests, not a live-validated
// playbook surface for every one of them.
package providers

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

// FreeIPAClientProviderID is this provider's stable ID — matches the
// freeipa-client component/role name (Provider.ID()).
const FreeIPAClientProviderID = "freeipa-client"

// Step actions this provider's Plan returns (providers.Step.Action). Each
// names a closed, provider-defined operation, never caller-supplied
// executable content (spec.md §8.1/§31).
const (
	ActionFreeIPAClientUninstall       = "freeipa_client_uninstall"
	ActionFreeIPARosterHostAbsent      = "freeipa_roster_host_absent"
	ActionFreeIPAIdentityApplyConverge = "freeipa_identity_apply_converge"
)

// ErrUnknownServicePrincipal is returned (wrapped) by Plan when a service
// principal other than the host's own host/<fqdn> Kerberos identity is
// still managed by the retiring host and cannot be proven safe to remove
// from here (spec.md §16.6, HD12, INV-6). Cleaning a KNOWN Pilot-owned
// principal (HTTP/<fqdn> via internal endpoints, nfs/<fqdn> via NFS
// lifecycle) through its OWNING component's ledger is Phase 4/5 work —
// this phase only ever detects and hard-blocks, it never cascade-deletes.
var ErrUnknownServicePrincipal = errors.New("freeipa-client: unknown/unproven service principal blocks host deletion")

// ansibleExecutor is the minimal seam this provider uses to run Ansible
// playbooks and read-only discovery queries. *internal/ansible.Runner
// satisfies this for real (its own Run method already has this exact
// signature); tests substitute an in-package fake.
type ansibleExecutor interface {
	Run(ctx context.Context, args ...string) (*ansible.Result, error)
}

// FreeIPAClientProviderConfig configures one FreeIPAClientProvider
// instance. Every path here is resolved by the CALLER (never accepted
// from an Agent/MCP path per INV-5, never derived from unvalidated user
// input inside Plan/Verify) — this provider only ever reads/executes
// exactly what it's configured with.
type FreeIPAClientProviderConfig struct {
	Executor ansibleExecutor

	ClientInventory string // targets the retiring host for local cleanup
	ServerInventory string // targets the FreeIPA server for central convergence

	DecommissionPlaybook  string // playbooks/decommission/freeipa-client-decommission.yml
	IdentityApplyPlaybook string // playbooks/apply/freeipa-identity-apply.yml

	// ExtraArgs is appended verbatim to every ansible-playbook invocation
	// this provider issues (e.g. "-e", "@~/.vault/main.yaml", a vault
	// password file flag) — non-secret plumbing only; never a caller-
	// supplied shell/command field (spec.md §31).
	ExtraArgs []string
}

// FreeIPAClientProvider implements providers.Provider for the FreeIPA
// client component (spec.md §16, Phase 3).
type FreeIPAClientProvider struct {
	cfg FreeIPAClientProviderConfig
}

// NewFreeIPAClientProvider builds a FreeIPAClientProvider from cfg.
func NewFreeIPAClientProvider(cfg FreeIPAClientProviderConfig) *FreeIPAClientProvider {
	return &FreeIPAClientProvider{cfg: cfg}
}

// ID implements Provider.
func (p *FreeIPAClientProvider) ID() string { return FreeIPAClientProviderID }

// ---- Inspect ---------------------------------------------------------

var enrolledMarkerPattern = regexp.MustCompile(`(?i)IPA_CLIENT_ENROLLED=true`)

// Inspect reports whether the target host currently looks like an
// enrolled FreeIPA client — best-effort, read-only (never mutates). It
// runs playbooks/decommission/freeipa-client-decommission.yml restricted
// to its "inspect" tag (a stat + debug pair, no mutating task carries
// that tag), so calling this never triggers the uninstall itself.
func (p *FreeIPAClientProvider) Inspect(ctx context.Context, in InspectInput) (Inspection, error) {
	hostName := in.HostName
	args := []string{p.cfg.DecommissionPlaybook}
	if p.cfg.ClientInventory != "" {
		args = append(args, "-i", p.cfg.ClientInventory)
	}
	if hostName != "" {
		args = append(args, "--limit", hostName)
	}
	args = append(args, "--tags", "inspect")
	args = append(args, p.cfg.ExtraArgs...)

	res, err := p.exec(ctx, args)
	if err != nil {
		return Inspection{}, fmt.Errorf("freeipa-client inspect %s: %w", hostName, err)
	}
	enrolled := enrolledMarkerPattern.MatchString(res.Stdout)
	detail := "FreeIPA client enrollment not detected (IPA_CLIENT_ENROLLED=false or marker absent)"
	if enrolled {
		detail = "FreeIPA client is currently enrolled (IPA_CLIENT_ENROLLED=true)"
	}
	return Inspection{Provider: FreeIPAClientProviderID, Detail: detail, Found: enrolled}, nil
}

// ---- Plan --------------------------------------------------------------

// Plan returns the ordered steps this provider would execute (spec.md
// §16.2/§16.3): local client uninstall, then the two central-cleanup
// steps that converge the canonical roster host to absent. It performs
// only READ-ONLY discovery itself (never mutates): a dry-run roster
// simulation (SimulateRemoveRosterHost, never writes) and a live,
// read-only service-principal check — if that check finds a service
// principal it cannot prove is safe (anything other than this host's own
// host/<fqdn> identity), Plan returns ErrUnknownServicePrincipal instead
// of scheduling the central-cleanup steps at all (HD12): the caller
// (internal/decommission's planner) turns that into a hard plan blocker,
// never a step that later fails.
func (p *FreeIPAClientProvider) Plan(ctx context.Context, in PlanInput) ([]Step, error) {
	hostName := in.HostName
	fqdn := firstNonEmpty(in.FQDN, hostName)

	if p.RosterPathSet(in) {
		violations, found, err := inventory.SimulateRemoveRosterHost(in.RosterPath, hostName)
		if err != nil {
			return nil, fmt.Errorf("freeipa-client plan %s: roster mutation would be invalid: %w", hostName, err)
		}
		// found=false just means the roster declares this host under a
		// different name/alias than the inventory host name (or not at
		// all) — not fatal to planning; the identity-apply convergence
		// step below is a no-op for a host the roster never declared.
		if found && len(violations) > 0 {
			return nil, fmt.Errorf("freeipa-client plan %s: roster would be invalid after converging this host to absent: %v", hostName, violations)
		}
	}

	unknown, err := p.discoverUnknownServicePrincipals(ctx, fqdn)
	if err != nil {
		return nil, fmt.Errorf("freeipa-client plan %s: service principal discovery: %w", hostName, err)
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%w: host %s still has service principal(s) managed by it: %s — clean them up via their owning component (e.g. internal-endpoint HTTP/<fqdn>, NFS nfs/<fqdn>) before retrying host decommission (spec.md §16.6)",
			ErrUnknownServicePrincipal, fqdn, strings.Join(unknown, ", "))
	}

	return []Step{
		{Provider: FreeIPAClientProviderID, Phase: "local_cleanup", Action: ActionFreeIPAClientUninstall, TargetIdentity: hostName},
		{Provider: FreeIPAClientProviderID, Phase: "central_cleanup", Action: ActionFreeIPARosterHostAbsent, TargetIdentity: hostName},
		{Provider: FreeIPAClientProviderID, Phase: "central_cleanup", Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: fqdn},
	}, nil
}

// RosterPathSet reports whether in carries a roster path to simulate
// against — a tiny named predicate (rather than an inline `in.RosterPath
// != ""` at each call site) so the "no roster declared for this host"
// case reads as a deliberate branch, not an accidental omission.
func (p *FreeIPAClientProvider) RosterPathSet(in PlanInput) bool {
	return strings.TrimSpace(in.RosterPath) != ""
}

// ---- Verify --------------------------------------------------------------

// Verify independently re-queries live central FreeIPA state and reports
// spec.md §16.7's full list: host object, Pilot-owned host DNS record(s),
// direct hostgroup membership, direct HBAC references, direct sudo
// references, netgroup host membership, and known Pilot-owned service
// principal references. It never trusts a prior step's exit code alone
// (INV-10) — every result here comes from a fresh query issued through
// this call.
func (p *FreeIPAClientProvider) Verify(ctx context.Context, in VerifyInput) ([]Verification, error) {
	fqdn := firstNonEmpty(in.FQDN, in.HostName)
	var out []Verification

	hostRes, err := p.queryHostObject(ctx, fqdn)
	if err != nil {
		return nil, fmt.Errorf("freeipa-client verify %s: host object query: %w", fqdn, err)
	}
	hostAbsent := notFoundPattern.MatchString(hostRes.Stdout)
	out = append(out, Verification{
		Provider: FreeIPAClientProviderID, Kind: "host_object", Identity: fqdn,
		Status: statusForAbsence(hostAbsent), Active: !hostAbsent,
		Detail: "ipa host-show " + fqdn, Ownership: "canonical_roster_exact",
	})

	if hostAbsent {
		out = append(out,
			Verification{Provider: FreeIPAClientProviderID, Kind: "hostgroup_membership", Identity: fqdn, Status: "pass", Detail: "host object absent"},
			Verification{Provider: FreeIPAClientProviderID, Kind: "netgroup_membership", Identity: fqdn, Status: "pass", Detail: "host object absent"},
			Verification{Provider: FreeIPAClientProviderID, Kind: "service_principal", Identity: fqdn, Status: "pass", Detail: "host object absent"},
		)
	} else {
		out = append(out, membershipVerification("hostgroup_membership", fqdn, memberOfHostgroupPattern.FindAllStringSubmatch(hostRes.Stdout, -1)))
		out = append(out, membershipVerification("netgroup_membership", fqdn, memberOfNetgroupPattern.FindAllStringSubmatch(hostRes.Stdout, -1)))
		out = append(out, servicePrincipalVerification(fqdn, unknownServicePrincipals(hostRes.Stdout, fqdn)))
	}

	dnsRes, err := p.query(ctx, "host_dns", fqdn)
	if err != nil {
		return nil, fmt.Errorf("freeipa-client verify %s: dns query: %w", fqdn, err)
	}
	dnsAbsent := notFoundPattern.MatchString(dnsRes.Stdout) || len(aRecordPattern.FindAllStringSubmatch(dnsRes.Stdout, -1)) == 0
	out = append(out, Verification{
		Provider: FreeIPAClientProviderID, Kind: "host_dns", Identity: fqdn,
		Status: statusForAbsence(dnsAbsent), Active: !dnsAbsent,
		Detail: "ipa dnsrecord-show for " + fqdn,
	})

	for _, q := range []struct{ query, kind string }{
		{"hbac_references", "hbac_direct"},
		{"sudo_references", "sudo_direct"},
	} {
		res, err := p.query(ctx, q.query, fqdn)
		if err != nil {
			return nil, fmt.Errorf("freeipa-client verify %s: %s query: %w", fqdn, q.query, err)
		}
		found := ruleNamePattern.FindAllStringSubmatch(res.Stdout, -1)
		out = append(out, Verification{
			Provider: FreeIPAClientProviderID, Kind: q.kind, Identity: fqdn,
			Status: statusForAbsence(len(found) == 0), Active: len(found) > 0,
			Detail: fmt.Sprintf("%d direct rule reference(s) live", len(found)),
		})
	}

	return out, nil
}

// ---- shared live-query plumbing -----------------------------------------

var (
	managedByServicePattern  = regexp.MustCompile(`(?im)^[ \t]*managedby_service:\s*(.+)$`)
	memberOfHostgroupPattern = regexp.MustCompile(`(?im)^[ \t]*memberof_hostgroup:\s*(.+)$`)
	memberOfNetgroupPattern  = regexp.MustCompile(`(?im)^[ \t]*memberof_netgroup:\s*(.+)$`)
	aRecordPattern           = regexp.MustCompile(`(?im)^[ \t]*arecord:\s*(.+)$`)
	ruleNamePattern          = regexp.MustCompile(`(?im)^[ \t]*Rule name:\s*(.+)$`)
	notFoundPattern          = regexp.MustCompile(`(?i)not found`)
)

// discoverUnknownServicePrincipals runs the same read-only host_object
// query Verify uses and classifies every managedby_service entry other
// than this host's own host/<fqdn> identity as unknown (spec.md §16.6) —
// Phase 3a has no other component's ownership ledger available to it, so
// there is no "known-owned, clean it up" branch yet (Phase 4/5).
func (p *FreeIPAClientProvider) discoverUnknownServicePrincipals(ctx context.Context, fqdn string) ([]string, error) {
	res, err := p.queryHostObject(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	if notFoundPattern.MatchString(res.Stdout) {
		return nil, nil // host object already gone -- nothing to check
	}
	return unknownServicePrincipals(res.Stdout, fqdn), nil
}

func unknownServicePrincipals(stdout, fqdn string) []string {
	hostPrincipal := "host/" + fqdn
	var unknown []string
	for _, m := range managedByServicePattern.FindAllStringSubmatch(stdout, -1) {
		svc := strings.TrimSpace(m[1])
		if svc == "" {
			continue
		}
		// Real `ipa host-show --raw` values carry the Kerberos realm
		// suffix (e.g. "host/web1.example.com@EXAMPLE.COM") — compare
		// only the principal identity, not the realm, against this
		// host's own expected host/<fqdn> identity.
		canon := svc
		if idx := strings.Index(canon, "@"); idx >= 0 {
			canon = canon[:idx]
		}
		if strings.EqualFold(canon, hostPrincipal) {
			continue
		}
		unknown = append(unknown, svc)
	}
	sort.Strings(unknown)
	return unknown
}

func (p *FreeIPAClientProvider) queryHostObject(ctx context.Context, fqdn string) (*ansible.Result, error) {
	return p.query(ctx, "host_object", fqdn)
}

// query issues one read-only central-plane discovery call against
// playbooks/apply/freeipa-identity-apply.yml, tagged so it only runs the
// relevant read-only lookup (never a mutating task) — see this file's
// package doc comment for which query kinds have a real corresponding
// playbook-side implementation today vs. remain a Phase 3b contract.
func (p *FreeIPAClientProvider) query(ctx context.Context, kind, fqdn string) (*ansible.Result, error) {
	args := []string{p.cfg.IdentityApplyPlaybook}
	if p.cfg.ServerInventory != "" {
		args = append(args, "-i", p.cfg.ServerInventory)
	}
	args = append(args, "--tags", "freeipa_host_absent_inspect")
	args = append(args, "-e", "pilot_decommission_query="+kind)
	args = append(args, "-e", "pilot_decommission_target_fqdn="+fqdn)
	args = append(args, p.cfg.ExtraArgs...)
	return p.exec(ctx, args)
}

func (p *FreeIPAClientProvider) exec(ctx context.Context, args []string) (*ansible.Result, error) {
	if p.cfg.Executor == nil {
		return nil, fmt.Errorf("freeipa-client provider: no ansible executor configured")
	}
	return p.cfg.Executor.Run(ctx, args...)
}

// ---- small parsing/formatting helpers ------------------------------------

func statusForAbsence(absent bool) string {
	if absent {
		return "pass"
	}
	return "active_residue"
}

func membershipVerification(kind, fqdn string, matches [][]string) Verification {
	live := extractCSVValues(matches)
	return Verification{
		Provider: FreeIPAClientProviderID, Kind: kind, Identity: fqdn,
		Status: statusForAbsence(len(live) == 0), Active: len(live) > 0,
		Detail: fmt.Sprintf("%d live membership(s): %s", len(live), strings.Join(live, ", ")),
	}
}

func servicePrincipalVerification(fqdn string, unknown []string) Verification {
	if len(unknown) == 0 {
		return Verification{Provider: FreeIPAClientProviderID, Kind: "service_principal", Identity: fqdn, Status: "pass", Detail: "no non-host service principal managed by this host"}
	}
	return Verification{
		Provider: FreeIPAClientProviderID, Kind: "service_principal", Identity: fqdn,
		Status: "unknown_ownership", Active: true, Ownership: "unknown",
		Detail: "unproven service principal(s) still managed by this host: " + strings.Join(unknown, ", "),
	}
}

func extractCSVValues(matches [][]string) []string {
	var out []string
	for _, m := range matches {
		v := strings.TrimSpace(m[1])
		if v == "" {
			continue
		}
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
