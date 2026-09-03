package decommission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
)

// DefaultPlanTTL is the default plan expiry window (spec.md §9.3).
const DefaultPlanTTL = 30 * time.Minute

// PlanInput is everything Plan needs. It is deliberately read-only and
// narrow: no field lets a caller supply an executable path, shell command,
// or raw Ansible extra-vars (spec.md §31) — only workspace location, the
// host to plan for, an already-loaded contract catalog, and the small set
// of operator dispositions spec.md §20/§21 require explicitly.
type PlanInput struct {
	// WorkspaceDir contains hosts.yml (and, optionally,
	// host_vars/<host>.yml, freeipa-dns.yaml, internal-endpoints.yaml).
	WorkspaceDir string
	HostName     string
	Catalog      contract.Catalog

	Reachability       Reachability
	OfflineDisposition OfflineDisposition
	// RetentionDispositions maps component ID -> the operator's explicit
	// retention disposition for that component (spec.md §20.1).
	RetentionDispositions map[string]RetentionDisposition

	// Providers is the registry of live decommission providers, keyed by
	// component ID (spec.md §8.1) — e.g. Providers["freeipa-client"].
	// Nil/empty (the Phase 1/2 default — every existing caller/test that
	// never sets this field keeps their exact prior behavior unchanged)
	// means no provider is registered for ANY component, so every
	// component with a matched contract is still classified
	// external_state_unsupported (INV-7's fail-closed default). A
	// registered provider's Plan is consulted instead of that unconditional
	// blocker (Phase 3+) — see planComponent.
	Providers map[string]providers.Provider

	// Now overrides time.Now for deterministic tests. Nil means time.Now.
	Now func() time.Time
}

func (in PlanInput) now() time.Time {
	if in.Now != nil {
		return in.Now()
	}
	return time.Now().UTC()
}

// PlanHost produces a read-only decommission plan for one host (spec.md
// §10.1, INV-2/INV-6/INV-7/INV-13). It never writes to workspace files and
// never contacts a live/external system (see TestPlanner_PlanIsReadOnly) —
// every input is read from disk once and only used to derive an in-memory
// Plan.
//
// Exit semantics mirror spec.md §10.1: a malformed workspace or missing
// host returns a Go error; a valid-but-blocked plan returns (plan, nil)
// with plan.Blocked() == true — callers (CLI) turn that into a non-zero
// structured result, not a Go error, since it is a normal, expected Phase 1
// outcome (INV-7 fail-closed default with zero registered providers).
func PlanHost(ctx context.Context, in PlanInput) (*Plan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hostName := strings.TrimSpace(in.HostName)
	if hostName == "" {
		return nil, newError(ErrHostNotFound, "host name is required")
	}
	if strings.TrimSpace(in.WorkspaceDir) == "" {
		return nil, newError(ErrWorkspaceMalformed, "workspace dir is required")
	}

	hostsPath := filepath.Join(in.WorkspaceDir, "hosts.yml")
	data, err := os.ReadFile(hostsPath)
	if err != nil {
		return nil, newError(ErrWorkspaceMalformed, "read %s: %v", hostsPath, err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		return nil, newError(ErrWorkspaceMalformed, "parse %s: %v", hostsPath, err)
	}

	var target *inventory.Host
	for i := range hf.Hosts {
		if hf.Hosts[i].Name == hostName {
			target = &hf.Hosts[i]
			break
		}
	}
	if target == nil {
		return nil, newError(ErrHostNotFound, "host %q not found in %s", hostName, hostsPath)
	}

	now := in.now()
	plan := &Plan{
		ID:                 newPlanID(),
		Status:             PlanStatusExecutable,
		Host:               snapshotHost(*target),
		Environment:        target.Env,
		Reachability:       in.Reachability,
		OfflineDisposition: in.OfflineDisposition,
		CreatedAt:          now.Format(time.RFC3339Nano),
		ExpiresAt:          now.Add(DefaultPlanTTL).Format(time.RFC3339Nano),
		InventoryRevision:  canonicalInventoryHash(hf),
	}

	// INV-13/HD23: a control-plane FreeIPA server/replica host gets a hard
	// blocker immediately — no further generic planning, no bypass flag.
	for _, role := range target.Roles {
		if role == "freeipa-server" || role == "freeipa-server-replica" {
			plan.Blockers = append(plan.Blockers, Blocker{
				Code: ErrControlPlaneRequiresDedicated,
				Detail: fmt.Sprintf(
					"host %q has role %q — generic host decommission is blocked; FreeIPA server/replica decommission requires a separate, dedicated workflow (spec.md §16.1, INV-13) with no bypass flag",
					hostName, role,
				),
			})
			plan.Status = PlanStatusBlocked
			plan.PlanHash = computePlanHash(plan)
			return plan, nil
		}
	}

	if len(target.Roles) == 0 {
		plan.Warnings = append(plan.Warnings, Warning{Code: "no_roles", Detail: "host has no roles assigned — nothing to clean up"})
		plan.PlanHash = computePlanHash(plan)
		return plan, nil
	}

	sortedRoles := append([]string(nil), target.Roles...)
	sort.Strings(sortedRoles)

	var componentIDs []string
	for _, role := range sortedRoles {
		cp := planComponent(ctx, role, in.Catalog, in.RetentionDispositions, in.Providers, *target, in.WorkspaceDir, in.OfflineDisposition)
		if cp.RetentionRequired {
			plan.RetentionRequirements = append(plan.RetentionRequirements, RetentionRequirement{
				ComponentID: cp.ComponentID,
				Required:    true,
				Disposition: in.RetentionDispositions[cp.ComponentID],
				Satisfied:   cp.RetentionSatisfied,
			})
		}
		plan.Components = append(plan.Components, cp)
		if cp.ComponentID != "" {
			componentIDs = append(componentIDs, cp.ComponentID)
		}
	}

	// Reverse-reference scan (spec.md §12, INV-6) — read-only, best-effort
	// for optional manifests. Runs BEFORE dependency ordering below (moved
	// here in Phase 4) so a reference-driven provider component
	// (internal-endpoint) can be added to componentIDs in time to
	// participate in that same ordering pass.
	refs, refWarnings := ScanReferences(in.WorkspaceDir, *target)
	plan.Warnings = append(plan.Warnings, refWarnings...)

	// Reference-driven components (spec.md §37 Phase 4, HD13): unlike
	// every ComponentPlan built by the roles loop above, internal-endpoint
	// is keyed off a REFERENCE to this host (route.target/route.proxy
	// inventory_host in internal-endpoints.yaml), not one of the host's
	// own roles — contracts/internal-endpoint.yaml's role: freeipa-server
	// means the retiring host itself is never the one carrying that role.
	if cp := planInternalEndpointReferences(ctx, in.Providers, refs, target.Name, providerFQDN(*target)); cp != nil {
		plan.Components = append(plan.Components, *cp)
		if cp.ComponentID != "" {
			componentIDs = append(componentIDs, cp.ComponentID)
		}
	}

	// Dependency ordering (spec.md §13, HD8): consumers before providers;
	// a cycle fails planning closed.
	depResult := resolveTeardownOrder(dedupeSortedStrings(componentIDs), in.Catalog)
	plan.DependencyCycle = depResult.Cycle
	if depResult.Cycle {
		plan.Blockers = append(plan.Blockers, Blocker{Code: ErrDependencyCycle, Detail: depResult.CycleDetail})
	} else {
		plan.TeardownOrder = depResult.TeardownOrder
	}

	plan.References = refs

	// Unreachable-host disposition (spec.md §21, HD16/HD17).
	applyUnreachablePolicy(plan, in.Reachability, in.OfflineDisposition)

	if plan.Blocked() {
		plan.Status = PlanStatusBlocked
	}
	plan.PlanHash = computePlanHash(plan)
	return plan, nil
}

// decommissionPolicyShape is Phase 1's minimal, defensive read of the
// still-untyped contract.Lifecycle.Decommission field (`any`, decoded by
// yaml.v3 into map[string]any for a mapping). The fully typed
// contract.DecommissionPolicy (spec.md §14) is Phase 5's job; this only
// reads `class`/`retention` well enough to enforce the stateful-retention
// gate (INV-8) now, without waiting for that typed contract.
type decommissionPolicyShape struct {
	Class     string
	Retention string
}

func extractDecommissionPolicy(v any) (decommissionPolicyShape, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return decommissionPolicyShape{}, false
	}
	class, _ := m["class"].(string)
	retention, _ := m["retention"].(string)
	if class == "" && retention == "" {
		return decommissionPolicyShape{}, false
	}
	return decommissionPolicyShape{Class: class, Retention: retention}, true
}

// planComponent resolves one role to its contract (if any) and classifies
// it (spec.md §10.1 INV-7). When no live Provider is registered for the
// matched component (providers is nil, or has no entry for this
// component ID — the Phase 1/2 default), every component is
// external_state_unsupported exactly as before, with the blocker detail
// distinguishing "declares a decommission playbook" from "declares
// nothing" per the task brief. Starting Phase 3 (spec.md §37), a
// component WITH a registered provider consults that provider's Plan
// instead of the unconditional blocker — the provider may still block for
// its own reasons (retention below is independent either way; an
// unsupported/unproven service principal, a roster validation failure,
// etc. surface as a provider-specific blocker, never silently ignored).
func planComponent(ctx context.Context, role string, catalog contract.Catalog, dispositions map[string]RetentionDisposition, provs map[string]providers.Provider, host inventory.Host, workspaceDir string, offline OfflineDisposition) ComponentPlan {
	cp := ComponentPlan{Role: role}

	matches := catalog.ComponentsForRole(role)
	if len(matches) == 0 {
		cp.Blockers = append(cp.Blockers, Blocker{
			Code:   ErrExternalStateUnsupported,
			Detail: fmt.Sprintf("role %q has no registered component contract — decommission support unknown, fail-closed (INV-7)", role),
		})
		return cp
	}
	matched := matches[0]
	cp.HasContract = true
	cp.ComponentID = matched.ID
	cp.DeclaresDecommission = matched.Playbooks.Decommission != nil

	if provider, ok := provs[matched.ID]; ok && provider != nil {
		cp.ProviderRegistered = true
		steps, err := provider.Plan(ctx, providers.PlanInput{
			HostName:           host.Name,
			FQDN:               providerFQDN(host),
			OfflineDisposition: string(offline),
			RosterPath:         rosterPathFor(workspaceDir, host),
		})
		if err != nil {
			cp.Blockers = append(cp.Blockers, Blocker{Code: classifyProviderPlanError(err), Detail: err.Error()})
		} else {
			cp.Steps = steps
		}
	} else {
		detail := fmt.Sprintf(
			"component %q declares no decommission playbook and no registered decommission provider exists yet (zero live providers registered for this plan) — fail-closed per INV-7",
			matched.ID,
		)
		if cp.DeclaresDecommission {
			detail = fmt.Sprintf(
				"component %q declares playbooks.decommission=%q but no executor is registered yet — fail-closed per INV-7",
				matched.ID, *matched.Playbooks.Decommission,
			)
		}
		cp.Blockers = append(cp.Blockers, Blocker{Code: ErrExternalStateUnsupported, Detail: detail})
	}

	// Retention gate (spec.md §20, INV-8, HD15) — independent of provider
	// support: a component can be BOTH unsupported/blocked AND stateful-
	// retention-gated; both blockers are reported.
	if req, ok := extractDecommissionPolicy(matched.Lifecycle.Decommission); ok && req.Class == "stateful" && req.Retention == "required" {
		cp.RetentionRequired = true
		disposition := dispositions[matched.ID]
		if disposition == RetentionDispositionNone {
			cp.Blockers = append(cp.Blockers, Blocker{
				Code:   ErrRetentionRequired,
				Detail: fmt.Sprintf("component %q is stateful with retention=required — supply an explicit retention disposition before planning can proceed (spec.md §20.1)", matched.ID),
			})
		} else {
			cp.RetentionSatisfied = true
		}
	}

	return cp
}

// classifyProviderPlanError maps a providers.Provider.Plan error to a
// decommission ErrorClass. A known unproven/unknown service principal
// (spec.md §16.6, HD12) is ownership_unknown — every other provider Plan
// failure (a live query error, a roster-validation failure the provider
// itself detected, ...) is cleanup_failed_terminal: planning could not be
// completed for this component, not "unsupported" (a provider IS
// registered) and not a specific known taxonomy entry.
func classifyProviderPlanError(err error) ErrorClass {
	if errors.Is(err, providers.ErrUnknownServicePrincipal) {
		return ErrOwnershipUnknown
	}
	if errors.Is(err, providers.ErrInternalEndpointDeleteNotAllowed) {
		return ErrReferenceRequiresAuthorization
	}
	return ErrCleanupFailedTerminal
}

// applyUnreachablePolicy implements spec.md §21/HD16/HD17. Phase 1 never
// probes reachability itself — Reachability is caller-supplied — but the
// state machine here is real: a temporarily-unreachable host blocks every
// component that would need local cleanup (Phase 1 fail-closed default:
// every component needs it, since none has yet declared otherwise), and a
// permanently-lost host records local cleanup as attested-unavailable,
// never as a fabricated "verified_removed".
func applyUnreachablePolicy(plan *Plan, reach Reachability, disposition OfflineDisposition) {
	if reach != ReachabilityUnreachable {
		return
	}
	if disposition == OfflineDispositionNone {
		plan.Blockers = append(plan.Blockers, Blocker{
			Code:   ErrHostUnreachable,
			Detail: "host is unreachable and no offline disposition was supplied — pass temporarily_unreachable or permanently_lost (spec.md §21.1)",
		})
		return
	}
	for i := range plan.Components {
		c := &plan.Components[i]
		switch disposition {
		case OfflineDispositionTemporarilyUnreachable:
			c.Blockers = append(c.Blockers, Blocker{
				Code: ErrHostUnreachable,
				Detail: fmt.Sprintf(
					"host is temporarily unreachable — component %q requires local cleanup, which cannot run until the host is reachable again",
					firstNonEmpty(c.ComponentID, c.Role),
				),
			})
		case OfflineDispositionPermanentlyLost:
			c.LocalCleanupStatus = LocalCleanupUnavailableAttested
		}
	}
}

func snapshotHost(h inventory.Host) HostSnapshot {
	extra := make(map[string]string, len(h.Extra))
	for k, v := range h.Extra {
		extra[k] = v
	}
	return HostSnapshot{
		Name:        h.Name,
		AnsibleHost: h.AnsibleHost,
		AnsibleUser: h.AnsibleUser,
		Env:         h.Env,
		Roles:       append([]string(nil), h.Roles...),
		Extra:       extra,
	}
}

// canonicalInventoryHash hashes the PARSED HostsFile, not raw file bytes,
// so that semantically identical YAML in different key/host order (map
// iteration in Go, or hand-reordered YAML) produces the same hash (HD3).
// inventory.Parse already discards host-block key order (each key is
// assigned into a fixed struct field or an Extra map) and already sorts
// hf.Hosts by name; encoding/json additionally sorts map[string]X keys on
// Marshal, so this is order-independent without any extra bookkeeping here.
func canonicalInventoryHash(hf *inventory.HostsFile) string {
	type hostCanon struct {
		Name                   string
		AnsibleHost            string
		AnsibleUser            string
		SSHKeyFile             string
		Roles                  []string
		Env                    string
		DeploymentAvailability string
		Extra                  map[string]string
	}
	hosts := make([]hostCanon, 0, len(hf.Hosts))
	for _, h := range hf.Hosts {
		roles := append([]string(nil), h.Roles...)
		sort.Strings(roles)
		hosts = append(hosts, hostCanon{
			Name: h.Name, AnsibleHost: h.AnsibleHost, AnsibleUser: h.AnsibleUser,
			SSHKeyFile: h.SSHKeyFile, Roles: roles, Env: h.Env,
			DeploymentAvailability: string(h.DeploymentAvailability), Extra: h.Extra,
		})
	}
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].Name < hosts[j].Name })
	payload := struct {
		Vars  map[string]string
		Hosts []hostCanon
	}{Vars: hf.Vars, Hosts: hosts}
	return jsonHash(payload)
}

// computePlanHash implements spec.md §28: hash canonicalized data (sorted
// slices, map keys sorted by encoding/json), never raw map iteration
// order. CreatedAt/ExpiresAt/ID/Warnings are deliberately excluded — they
// are not plan-bound inputs (spec.md §28's "hash at least" list has no
// "warnings" or "timestamps" entry), so two plans derived from identical
// inputs at different instants still hash identically.
func computePlanHash(plan *Plan) string {
	type refCanon struct {
		Source, Kind, Identity string
		Classification         ReferenceClassification
	}
	refs := make([]refCanon, len(plan.References))
	for i, r := range plan.References {
		refs[i] = refCanon{r.Source, r.Kind, r.Identity, r.Classification}
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Source != refs[j].Source {
			return refs[i].Source < refs[j].Source
		}
		if refs[i].Kind != refs[j].Kind {
			return refs[i].Kind < refs[j].Kind
		}
		return refs[i].Identity < refs[j].Identity
	})

	type componentCanon struct {
		Role, ComponentID                                                        string
		HasContract, DeclaresDecommission, RetentionRequired, RetentionSatisfied bool
		LocalCleanupStatus                                                       LocalCleanupStatus
		Blocked                                                                  bool
	}
	comps := make([]componentCanon, len(plan.Components))
	for i, c := range plan.Components {
		comps[i] = componentCanon{
			Role: c.Role, ComponentID: c.ComponentID, HasContract: c.HasContract,
			DeclaresDecommission: c.DeclaresDecommission, RetentionRequired: c.RetentionRequired,
			RetentionSatisfied: c.RetentionSatisfied, LocalCleanupStatus: c.LocalCleanupStatus,
			Blocked: c.Blocked(),
		}
	}

	planLevelBlocked := len(plan.Blockers) > 0

	payload := struct {
		Host               HostSnapshot
		Environment        string
		InventoryRevision  string
		Components         []componentCanon
		TeardownOrder      []string
		DependencyCycle    bool
		References         []refCanon
		Reachability       Reachability
		OfflineDisposition OfflineDisposition
		PlanLevelBlocked   bool
	}{
		Host:               canonicalHostSnapshot(plan.Host),
		Environment:        plan.Environment,
		InventoryRevision:  plan.InventoryRevision,
		Components:         comps,
		TeardownOrder:      plan.TeardownOrder,
		DependencyCycle:    plan.DependencyCycle,
		References:         refs,
		Reachability:       plan.Reachability,
		OfflineDisposition: plan.OfflineDisposition,
		PlanLevelBlocked:   planLevelBlocked,
	}
	return jsonHash(payload)
}

func canonicalHostSnapshot(h HostSnapshot) HostSnapshot {
	roles := append([]string(nil), h.Roles...)
	sort.Strings(roles)
	return HostSnapshot{Name: h.Name, AnsibleHost: h.AnsibleHost, AnsibleUser: h.AnsibleUser, Env: h.Env, Roles: roles, Extra: h.Extra}
}

func jsonHash(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Every field feeding this is a plain struct/slice/map of strings
		// and bools built entirely within this package — a Marshal error
		// here would mean a programming error, not a runtime condition
		// callers can recover from.
		panic(fmt.Sprintf("decommission: hash payload does not marshal: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func dedupeSortedStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// providerFQDN resolves the identity a registered live provider should use
// as "this host's FQDN" (providers.PlanInput.FQDN) — Bug found via Phase 3b
// live-target testing: this used to be firstNonEmpty(host.AnsibleHost,
// host.Name), which silently prefers host.AnsibleHost even when it is
// nothing more than the SSH connection address (very commonly a bare IP —
// every vm-target-provisioned host, most cloud/DHCP-assigned hosts, ...),
// producing a value that is not the host's real FreeIPA/DNS identity at
// all. host.Name is the workspace author's own chosen identity for this
// host and, by this repo's own roster convention (every canonical roster
// example names hosts[] entries by FQDN), is what a FreeIPA-integrated
// workspace is expected to set to the real FQDN when it matters — prefer
// it over the connection address, falling back to AnsibleHost only when
// Name is somehow empty (should not happen for a matched host, but keeps
// this total rather than ever returning "").
func providerFQDN(host inventory.Host) string {
	return firstNonEmpty(host.Name, host.AnsibleHost)
}
