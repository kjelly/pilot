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
	// A genuinely failed ansible-playbook run (unreachable host, playbook
	// not found, a real infrastructure error — as opposed to the
	// "inspect" tag's own tasks, which never carry failed_when: false
	// tolerance and so only fail on a real problem) must never be
	// silently read as "not enrolled" (INV-10: an unverifiable check is
	// never a pass) — Bug found via Phase 3b live-target testing: this
	// previously ignored res.ExitCode entirely.
	if res.ExitCode != 0 {
		return Inspection{}, fmt.Errorf("freeipa-client inspect %s: ansible-playbook exited %d: %s", hostName, res.ExitCode, ansibleFailureDetail(res))
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

	rosterStepParams := map[string]string(nil)
	if p.RosterPathSet(in) {
		rosterStepParams = map[string]string{"roster_path": in.RosterPath}
	}

	return []Step{
		{Provider: FreeIPAClientProviderID, Phase: "local_cleanup", Action: ActionFreeIPAClientUninstall, TargetIdentity: hostName},
		{Provider: FreeIPAClientProviderID, Phase: "central_cleanup", Action: ActionFreeIPARosterHostAbsent, TargetIdentity: hostName, Params: rosterStepParams},
		{Provider: FreeIPAClientProviderID, Phase: "central_cleanup", Action: ActionFreeIPAIdentityApplyConverge, TargetIdentity: fqdn, Params: rosterStepParams},
	}, nil
}

// ---- Execute (Phase 3b: StepRunner) -------------------------------------

// ExecutorForStep implements providers.StepRunner: turns one of Plan's
// three ordered Steps into a real Inspect/Execute pair. step.Params carries
// the roster path Plan resolved when it built the step (see Plan above) —
// never re-derived from a caller-supplied value here.
func (p *FreeIPAClientProvider) ExecutorForStep(step Step) (StepExecutor, error) {
	switch step.Action {
	case ActionFreeIPAClientUninstall:
		return &freeipaUninstallStep{provider: p, hostName: step.TargetIdentity}, nil
	case ActionFreeIPARosterHostAbsent:
		return &freeipaRosterAbsentStep{hostName: step.TargetIdentity, rosterPath: step.Params["roster_path"]}, nil
	case ActionFreeIPAIdentityApplyConverge:
		return &freeipaIdentityConvergeStep{provider: p, fqdn: step.TargetIdentity}, nil
	default:
		return nil, fmt.Errorf("freeipa-client: unknown planned step action %q — programming/version-skew error, not a normal runtime condition", step.Action)
	}
}

// ---- step: local client uninstall (playbooks/decommission/freeipa-client-decommission.yml) ----

type freeipaUninstallStep struct {
	provider *FreeIPAClientProvider
	hostName string
}

// Inspect reuses Provider.Inspect's own enrollment marker check — Found
// means still enrolled (not converged); its absence means already
// unenrolled (converged, e.g. a resume after this step already ran).
func (e *freeipaUninstallStep) Inspect(ctx context.Context) (bool, error) {
	insp, err := e.provider.Inspect(ctx, InspectInput{HostName: e.hostName})
	if err != nil {
		return false, err
	}
	return !insp.Found, nil
}

// Execute runs the real client-side uninstall playbook (no --tags
// inspect this time — the mutating tasks are what we want).
func (e *freeipaUninstallStep) Execute(ctx context.Context) error {
	args := []string{e.provider.cfg.DecommissionPlaybook}
	if e.provider.cfg.ClientInventory != "" {
		args = append(args, "-i", e.provider.cfg.ClientInventory)
	}
	if e.hostName != "" {
		args = append(args, "--limit", e.hostName)
	}
	args = append(args, e.provider.cfg.ExtraArgs...)
	res, err := e.provider.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("freeipa-client uninstall %s: %w", e.hostName, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("freeipa-client uninstall %s: ansible-playbook exited %d: %s", e.hostName, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// ---- step: roster host absent + reference pruning (pure Go, no ansible) ----

type freeipaRosterAbsentStep struct {
	hostName   string
	rosterPath string
}

// Inspect reports converged when there is no roster to mutate (nothing
// declared this host), or when the host's roster entry is already
// state: absent with no remaining hostgroup/netgroup/HBAC/sudo direct
// reference to it (inventory.RosterHostAbsentAndUnreferenced) — i.e.
// RemoveRosterHostReferences + SetRosterHostAbsent already converged this
// on a prior attempt, so re-running them would be a pure no-op; Execute
// is skipped rather than blindly repeated (HD18).
func (e *freeipaRosterAbsentStep) Inspect(ctx context.Context) (bool, error) {
	if strings.TrimSpace(e.rosterPath) == "" {
		return true, nil
	}
	return inventory.RosterHostAbsentAndUnreferenced(e.rosterPath, e.hostName)
}

// Execute implements spec.md §16.3/§16.4's required roster-side order:
// prune every direct hostgroup/netgroup/HBAC/sudo reference first, THEN
// converge the host's own entry to state: absent.
func (e *freeipaRosterAbsentStep) Execute(ctx context.Context) error {
	if strings.TrimSpace(e.rosterPath) == "" {
		return nil
	}
	if err := inventory.RemoveRosterHostReferences(e.rosterPath, e.hostName); err != nil {
		return fmt.Errorf("freeipa-client roster-absent %s: prune references: %w", e.hostName, err)
	}
	if err := inventory.SetRosterHostAbsent(e.rosterPath, e.hostName); err != nil {
		return fmt.Errorf("freeipa-client roster-absent %s: converge host entry: %w", e.hostName, err)
	}
	return nil
}

// ---- step: central identity-apply convergence (playbooks/apply/freeipa-identity-apply.yml) ----

type freeipaIdentityConvergeStep struct {
	provider *FreeIPAClientProvider
	fqdn     string
}

// Inspect reuses the same live host-object query Verify uses: converged
// means the FreeIPA host object is already absent (e.g. a resume after
// this step's host-del already ran).
func (e *freeipaIdentityConvergeStep) Inspect(ctx context.Context) (bool, error) {
	res, err := e.provider.queryHostObject(ctx, e.fqdn)
	if err != nil {
		return false, err
	}
	return notFoundPattern.MatchString(res.Stdout), nil
}

// Execute runs the real central reconciler (playbooks/apply/freeipa-
// identity-apply.yml). This playbook's own "Hosts marked absent" section
// is itself idempotent (host-del/dnsrecord-del both tolerate "not found"),
// so a resume that re-runs this after a partial prior success converges
// cleanly rather than erroring.
func (e *freeipaIdentityConvergeStep) Execute(ctx context.Context) error {
	args := []string{e.provider.cfg.IdentityApplyPlaybook}
	if e.provider.cfg.ServerInventory != "" {
		args = append(args, "-i", e.provider.cfg.ServerInventory)
	}
	args = append(args, e.provider.cfg.ExtraArgs...)
	res, err := e.provider.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("freeipa-client identity-apply-converge %s: %w", e.fqdn, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("freeipa-client identity-apply-converge %s: ansible-playbook exited %d: %s", e.fqdn, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// ansibleFailureDetail renders a short, non-secret excerpt of a failed
// ansible-playbook run for error messages — trailing stderr, or stdout
// when stderr is empty (ansible-playbook often reports task failures on
// stdout, not stderr).
func ansibleFailureDetail(res *ansible.Result) string {
	detail := strings.TrimSpace(res.Stderr)
	if detail == "" {
		detail = strings.TrimSpace(res.Stdout)
	}
	if len(detail) > 2000 {
		detail = detail[len(detail)-2000:]
	}
	return detail
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

// fieldPattern builds a regex that extracts the value of "<label>:" from
// the console text ansible.Result.Stdout carries. Two compounding bugs
// found via Phase 3b live-target testing shape this:
//
//  1. `ipa host-show --all --raw` never actually exposes
//     "managedby_service:"/"memberof_hostgroup:"/"memberof_netgroup:"
//     attributes at all (those names never existed as real FreeIPA raw
//     output — the real raw attribute is a single generic `memberof:` DN,
//     and services are not listed by host-show at all, raw or not). Fixed
//     on the ansible side by switching to plain (non-raw) `ipa host-show`
//     for group membership ("Member of host-groups:"/"Member of
//     netgroups:") and a separate `ipa service-find --man-by-hosts=<fqdn>`
//     query for services ("Principal name:" lines).
//  2. Independently, `ansible.builtin.debug`'s default callback renders a
//     string `msg:` value with literal two-character `\n` ESCAPE TEXT
//     (backslash + 'n'), not real newline bytes, when printing it to the
//     console — confirmed by capturing raw ansible-playbook stdout to a
//     file and inspecting it byte-for-byte. Every field-extraction regex
//     here used to be anchored with `^`/`(?m)$`, which can only match at a
//     REAL line boundary — against this console text they never matched
//     ANYTHING, so every field this package reads from a debug-printed
//     HOST_INSPECT blob (service principals, hostgroup/netgroup
//     membership, DNS A records, HBAC/sudo rule names) silently found
//     zero matches regardless of live state, i.e. Verify() and
//     discoverUnknownServicePrincipals always reported "nothing found"
//     even when the real answer was "still there" — a false PASS for
//     HD10/HD11/HD12/INV-6/INV-10's zero-residue checks that unit-test
//     fixtures (built from what Phase 3a assumed real output looked like,
//     not from bytes an actual ansible-playbook run produced) could never
//     have caught. fieldPattern stops a match at whichever comes first: a
//     literal `\n` escape, a real newline, or end of string — correct
//     whether the text has real line breaks (e.g. a value read directly
//     from a registered command result, not a re-rendered debug message)
//     or not.
func fieldPattern(label string) *regexp.Regexp {
	return regexp.MustCompile(`(?i)` + regexp.QuoteMeta(label) + `:\s*(.*?)(?:\\n|\n|$)`)
}

var (
	servicePrincipalNamePattern = fieldPattern("Principal name")
	memberOfHostgroupPattern    = fieldPattern("Member of host-groups")
	memberOfNetgroupPattern     = fieldPattern("Member of netgroups")
	aRecordPattern              = fieldPattern("arecord")
	ruleNamePattern             = fieldPattern("Rule name")
	notFoundPattern             = regexp.MustCompile(`(?i)not found`)
)

// discoverUnknownServicePrincipals runs the same read-only host_object
// query Verify uses and classifies every service principal managed by
// this host OTHER than its own host/<fqdn> identity as unknown (spec.md
// §16.6) — Phase 3a has no other component's ownership ledger available
// to it, so there is no "known-owned, clean it up" branch yet (Phase
// 4/5).
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
	// The combined HOST_INSPECT text this scans carries BOTH host-show's
	// own "Principal name: host/<fqdn>@REALM" line AND service-find's
	// "Principal name: <service>@REALM" line(s) — the host's own
	// identity must be excluded here (service-find itself never returns
	// it, but this parses the concatenated blob, not service-find's
	// output alone).
	for _, m := range servicePrincipalNamePattern.FindAllStringSubmatch(stdout, -1) {
		svc := strings.TrimSpace(m[1])
		if svc == "" {
			continue
		}
		// Real `ipa` output carries the Kerberos realm suffix (e.g.
		// "host/web1.example.com@EXAMPLE.COM") — compare only the
		// principal identity, not the realm, against this host's own
		// expected host/<fqdn> identity.
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
	res, err := p.exec(ctx, args)
	if err != nil {
		return nil, err
	}
	// Bug found via Phase 3b live-target testing: this used to return res
	// unconditionally regardless of whether the ansible-playbook PLAY
	// itself actually ran (as opposed to an individual `ipa` command
	// inside it failing, which every read-only task here already tolerates
	// via failed_when: false) — a genuinely failed run (unreachable host,
	// playbook not found under the caller's cwd, a bad inventory path) was
	// silently read as empty/no-match output, which every caller's regex
	// then interpreted as "nothing found" — i.e. a false PASS for HD10-
	// HD12/INV-6/INV-10's zero-residue checks. Fail closed instead.
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("freeipa-client %s query for %s: ansible-playbook exited %d: %s", kind, fqdn, res.ExitCode, ansibleFailureDetail(res))
	}
	return res, nil
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
