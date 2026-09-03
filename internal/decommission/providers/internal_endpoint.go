// internal_endpoint.go implements Phase 4's internal-endpoint decommission
// provider (docs/superpowers/specs/2026-09-02-host-decommission-spec.md
// §37 Phase 4, HD13). Unlike FreeIPAClientProvider (freeipa_client.go),
// this provider's target identity is NOT the retiring host itself: a host
// being decommissioned is only ever relevant here as a REFERENCE — the
// route.target/route.proxy inventory_host (= the TLS certificate owner,
// per internal_endpoint_manifest.go's deriveCertificateOwner) of zero or
// more internal-endpoints.yaml entries. Every Step this provider plans
// therefore carries the ENDPOINT's own fqdn as its TargetIdentity, never
// the retiring host's — internal/decommission's executeComponents/
// collectVerifications (execute.go) call Inspect/Execute/Verify once per
// distinct Step TargetIdentity within a component, precisely so a
// multi-identity provider like this one works without any change to that
// shared orchestration.
//
// Reuses the EXISTING ledger-aware delete sequence
// (playbooks/apply/tasks/internal-endpoint-delete.yml, driven by
// playbooks/apply/internal-endpoint-apply.yml's own internal_endpoint_absent
// loop) rather than reinventing endpoint teardown — the only NEW
// ansible-side surface this provider needs is a small, additive,
// read-only "endpoint_object" query block that playbook gained (its own
// "Phase 10" section) for Verify's independent re-check, mirroring
// freeipa-identity-apply.yml's freeipa_host_absent_inspect convention
// exactly.
//
// Every live query/mutation goes through the same ansibleExecutor seam
// freeipa_client.go defines (same package, reused directly) — every test
// here substitutes an in-package fake; no live host or real
// ansible-playbook binary is touched by `go test` (code + fixture tests
// only; actual disposable-target evidence is a separate follow-up pass,
// same posture Phase 3a took before Phase 3b).
package providers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

// InternalEndpointProviderID is this provider's stable ID — matches the
// internal-endpoint component/contract ID (Provider.ID()).
const InternalEndpointProviderID = "internal-endpoint"

// Step actions this provider's Plan returns (providers.Step.Action).
const (
	ActionInternalEndpointManifestAbsent = "internal_endpoint_manifest_absent"
	ActionInternalEndpointApplyConverge  = "internal_endpoint_apply_converge"
)

// ErrInternalEndpointDeleteNotAllowed is returned (wrapped) by Plan when
// the retiring host is referenced by one or more internal endpoints but
// the manifest's own safety.allow_endpoint_delete flag is not true
// (internal/inventory/internal_endpoint_validate.go's "delete safety"
// rule, spec.md §32) — this provider never flips that flag itself: it is
// an explicit, operator-owned safety opt-in, not something a host
// decommission should silently grant on someone's behalf.
var ErrInternalEndpointDeleteNotAllowed = errors.New("internal-endpoint: safety.allow_endpoint_delete is not true — cannot remove referencing endpoint(s)")

// InternalEndpointProviderConfig configures one InternalEndpointProvider
// instance. Every path here is resolved by the CALLER (never accepted
// from an Agent/MCP path per INV-5) — this provider only ever
// reads/executes exactly what it's configured with.
type InternalEndpointProviderConfig struct {
	Executor ansibleExecutor

	// ManifestPath is the workspace's internal-endpoints.yaml — "" means
	// this workspace has none, and every Plan/Inspect call is then a
	// pure no-op (nothing to reference, nothing to clean up).
	ManifestPath string

	// ServerInventory targets the FreeIPA server host (internal-endpoint's
	// contract role, contracts/internal-endpoint.yaml) — the SAME
	// inventory.yml the apply playbook always runs against regardless of
	// which backend host a given endpoint's route points at.
	ServerInventory string

	// ApplyPlaybook is playbooks/apply/internal-endpoint-apply.yml — reused
	// for both the real delete convergence (a full, untagged run, exactly
	// like FreeIPAClientProvider's own central identity-apply-converge
	// step) and, tagged iep_decommission_verify, Verify's read-only query.
	ApplyPlaybook string

	// ExtraArgs is appended verbatim to every ansible-playbook invocation
	// (e.g. a vault password file flag, the required
	// internal_endpoint_manifest_file/freeipa_dns_manifest_file/
	// ipa_admin_password extra-vars) — non-secret plumbing only.
	ExtraArgs []string
}

// InternalEndpointProvider implements providers.Provider for the
// internal-endpoint component (spec.md §37 Phase 4).
type InternalEndpointProvider struct {
	cfg InternalEndpointProviderConfig
}

// NewInternalEndpointProvider builds an InternalEndpointProvider from cfg.
func NewInternalEndpointProvider(cfg InternalEndpointProviderConfig) *InternalEndpointProvider {
	return &InternalEndpointProvider{cfg: cfg}
}

// ID implements Provider.
func (p *InternalEndpointProvider) ID() string { return InternalEndpointProviderID }

// ---- shared manifest discovery -----------------------------------------

// referencingEndpoints returns every PRESENT endpoint fqdn in the
// configured manifest whose route owner (= TLS certificate owner, direct
// target or reverse_proxy proxy host — deriveCertificateOwner's own
// definition) is hostName, in sorted order. Returns (nil, nil, nil) when
// there is no manifest at all — not an error, mirroring
// internal/decommission/references.go's scanInternalEndpoints' own
// best-effort posture for an optional manifest.
func (p *InternalEndpointProvider) referencingEndpoints(hostName string) (fqdns []string, allowDelete bool, err error) {
	if strings.TrimSpace(p.cfg.ManifestPath) == "" {
		return nil, false, nil
	}
	root, err := inventory.LoadInternalEndpointManifest(p.cfg.ManifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("internal-endpoint: load manifest %s: %w", p.cfg.ManifestPath, err)
	}
	norm := inventory.NormalizeInternalEndpointManifest(root, nil)
	for _, e := range norm.Endpoints {
		if e.State == "present" && e.RouteOwnerHost == hostName {
			fqdns = append(fqdns, e.FQDN)
		}
	}
	sort.Strings(fqdns)
	return fqdns, manifestAllowsEndpointDelete(root), nil
}

func manifestAllowsEndpointDelete(root map[string]any) bool {
	safety, _ := root["safety"].(map[string]any)
	if safety == nil {
		return false
	}
	allowed, _ := safety["allow_endpoint_delete"].(bool)
	return allowed
}

// ---- Inspect -------------------------------------------------------------

// Inspect reports whether hostName is still referenced by any present
// internal endpoint — read-only, never mutates.
func (p *InternalEndpointProvider) Inspect(ctx context.Context, in InspectInput) (Inspection, error) {
	fqdns, _, err := p.referencingEndpoints(in.HostName)
	if err != nil {
		return Inspection{}, fmt.Errorf("internal-endpoint inspect %s: %w", in.HostName, err)
	}
	if len(fqdns) == 0 {
		return Inspection{Provider: InternalEndpointProviderID, Detail: "no present internal endpoint references this host", Found: false}, nil
	}
	return Inspection{
		Provider: InternalEndpointProviderID,
		Detail:   fmt.Sprintf("referenced by %d present internal endpoint(s): %s", len(fqdns), strings.Join(fqdns, ", ")),
		Found:    true,
	}, nil
}

// ---- Plan ----------------------------------------------------------------

// Plan returns, for every present internal endpoint that references
// hostName as its route/certificate owner, two ordered steps: converge
// the manifest entry to state: absent, then reconverge the central
// FreeIPA/DNS/nginx/certmonger state via the existing apply playbook's
// own ledger-aware delete sequence. Returns (nil, nil) when nothing
// references this host — the caller (internal/decommission's planner)
// then has nothing to add for this provider. Returns
// ErrInternalEndpointDeleteNotAllowed (never partial steps) when
// something references this host but the manifest's own safety flag
// blocks removal (spec.md §32) — matching FreeIPAClientProvider's own
// "detect and hard-block, never schedule a step that would later fail"
// posture for HD12's unknown-service-principal case.
func (p *InternalEndpointProvider) Plan(ctx context.Context, in PlanInput) ([]Step, error) {
	hostName := in.HostName
	fqdns, allowDelete, err := p.referencingEndpoints(hostName)
	if err != nil {
		return nil, fmt.Errorf("internal-endpoint plan %s: %w", hostName, err)
	}
	if len(fqdns) == 0 {
		return nil, nil
	}
	if !allowDelete {
		return nil, fmt.Errorf("%w: host %s is referenced by internal endpoint(s) %s (spec.md §32)",
			ErrInternalEndpointDeleteNotAllowed, hostName, strings.Join(fqdns, ", "))
	}

	steps := make([]Step, 0, len(fqdns)*2)
	for _, fqdn := range fqdns {
		steps = append(steps,
			Step{Provider: InternalEndpointProviderID, Phase: "central_cleanup", Action: ActionInternalEndpointManifestAbsent, TargetIdentity: fqdn},
			Step{Provider: InternalEndpointProviderID, Phase: "central_cleanup", Action: ActionInternalEndpointApplyConverge, TargetIdentity: fqdn},
		)
	}
	return steps, nil
}

// ---- Execute (StepRunner) -------------------------------------------------

// ExecutorForStep implements providers.StepRunner.
func (p *InternalEndpointProvider) ExecutorForStep(step Step) (StepExecutor, error) {
	switch step.Action {
	case ActionInternalEndpointManifestAbsent:
		return &internalEndpointManifestAbsentStep{manifestPath: p.cfg.ManifestPath, fqdn: step.TargetIdentity}, nil
	case ActionInternalEndpointApplyConverge:
		return &internalEndpointApplyConvergeStep{provider: p, fqdn: step.TargetIdentity}, nil
	default:
		return nil, fmt.Errorf("internal-endpoint: unknown planned step action %q — programming/version-skew error, not a normal runtime condition", step.Action)
	}
}

// ---- step: manifest convergence to state: absent (pure Go, no ansible) ---

type internalEndpointManifestAbsentStep struct {
	manifestPath string
	fqdn         string
}

// Inspect reports converged when the endpoint entry is already gone
// entirely, or already declares state: absent.
func (e *internalEndpointManifestAbsentStep) Inspect(ctx context.Context) (bool, error) {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(e.manifestPath, e.fqdn)
	if err != nil {
		return false, fmt.Errorf("internal-endpoint manifest-absent %s: %w", e.fqdn, err)
	}
	if !found {
		return true, nil
	}
	state, _ := fields["state"].(string)
	return state == "absent", nil
}

// Execute converges the endpoint's own manifest entry to state: absent,
// preserving every other declared field exactly (same "replace, not
// erase" posture as freeipaRosterAbsentStep/SetRosterHostAbsent).
func (e *internalEndpointManifestAbsentStep) Execute(ctx context.Context) error {
	fields, found, err := inventory.InternalEndpointManifestEndpoint(e.manifestPath, e.fqdn)
	if err != nil {
		return fmt.Errorf("internal-endpoint manifest-absent %s: %w", e.fqdn, err)
	}
	if !found {
		return nil
	}
	updated := make(map[string]any, len(fields)+1)
	for k, v := range fields {
		updated[k] = v
	}
	updated["state"] = "absent"
	if err := inventory.SetInternalEndpoint(e.manifestPath, e.fqdn, updated); err != nil {
		return fmt.Errorf("internal-endpoint manifest-absent %s: %w", e.fqdn, err)
	}
	return nil
}

// ---- step: central apply-playbook convergence (playbooks/apply/internal-endpoint-apply.yml) ----

type internalEndpointApplyConvergeStep struct {
	provider *InternalEndpointProvider
	fqdn     string
}

// Inspect reuses the same live endpoint_object query Verify uses:
// converged means the endpoint's host object is already absent (e.g. a
// resume after this step's delete sequence already ran).
func (e *internalEndpointApplyConvergeStep) Inspect(ctx context.Context) (bool, error) {
	res, err := e.provider.query(ctx, "endpoint_object", e.fqdn)
	if err != nil {
		return false, err
	}
	host, _, err := parseEndpointInspect(res.Stdout)
	if err != nil {
		return false, err
	}
	return notFoundPattern.MatchString(host), nil
}

// Execute reruns the real reconciler
// (playbooks/apply/internal-endpoint-apply.yml) with no tag restriction —
// the manifest's now state: absent entry drives it through the existing
// ledger-aware delete sequence (tasks/internal-endpoint-delete.yml),
// exactly like a normal `pilot deploy` apply would. Idempotent: a resume
// that reruns this after a partial prior success converges cleanly
// (every delete-sequence task there already tolerates an already-absent
// target).
func (e *internalEndpointApplyConvergeStep) Execute(ctx context.Context) error {
	args := []string{e.provider.cfg.ApplyPlaybook}
	if e.provider.cfg.ServerInventory != "" {
		args = append(args, "-i", e.provider.cfg.ServerInventory)
	}
	args = append(args, e.provider.cfg.ExtraArgs...)
	res, err := e.provider.exec(ctx, args)
	if err != nil {
		return fmt.Errorf("internal-endpoint apply-converge %s: %w", e.fqdn, err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("internal-endpoint apply-converge %s: ansible-playbook exited %d: %s", e.fqdn, res.ExitCode, ansibleFailureDetail(res))
	}
	return nil
}

// ---- Verify ---------------------------------------------------------------

// Verify independently re-queries live state for one endpoint fqdn
// (in.FQDN/in.HostName — internal/decommission's execute.go calls this
// once per distinct planned Step TargetIdentity, which for this provider
// is always an endpoint fqdn, never the retiring host's own identity). It
// never trusts a prior step's exit code alone (INV-10).
func (p *InternalEndpointProvider) Verify(ctx context.Context, in VerifyInput) ([]Verification, error) {
	fqdn := firstNonEmpty(in.FQDN, in.HostName)
	res, err := p.query(ctx, "endpoint_object", fqdn)
	if err != nil {
		return nil, fmt.Errorf("internal-endpoint verify %s: %w", fqdn, err)
	}
	host, dns, err := parseEndpointInspect(res.Stdout)
	if err != nil {
		return nil, fmt.Errorf("internal-endpoint verify %s: %w", fqdn, err)
	}

	hostAbsent := notFoundPattern.MatchString(host)
	out := []Verification{{
		Provider: InternalEndpointProviderID, Kind: "endpoint_host_object", Identity: fqdn,
		Status: statusForAbsence(hostAbsent), Active: !hostAbsent,
		Detail: "ipa host-show " + fqdn,
	}}

	if strings.HasPrefix(strings.TrimSpace(dns), "skipped") {
		out = append(out, Verification{
			Provider: InternalEndpointProviderID, Kind: "endpoint_dns", Identity: fqdn,
			Status: "not_applicable", Detail: "dns_zone/dns_owner unresolved — " + strings.TrimSpace(dns),
		})
	} else {
		dnsAbsent := notFoundPattern.MatchString(dns)
		out = append(out, Verification{
			Provider: InternalEndpointProviderID, Kind: "endpoint_dns", Identity: fqdn,
			Status: statusForAbsence(dnsAbsent), Active: !dnsAbsent,
			Detail: "ipa dnsrecord-show for endpoint " + fqdn,
		})
	}
	return out, nil
}

// ---- shared live-query plumbing -------------------------------------------

var (
	hostResultPattern = fieldPattern("HOST_RESULT")
	dnsResultPattern  = fieldPattern("DNS_RESULT")
)

// parseEndpointInspect extracts the HOST_RESULT/DNS_RESULT fields from
// playbooks/apply/internal-endpoint-apply.yml's "Print endpoint_object
// query inspection" debug message — reuses fieldPattern (freeipa_client.go,
// same package) for the same reason that file's doc comment explains: an
// ansible.builtin.debug string msg renders literal "\n" escape text, not
// real newline bytes, in its default console callback.
func parseEndpointInspect(stdout string) (host, dns string, err error) {
	hm := hostResultPattern.FindStringSubmatch(stdout)
	dm := dnsResultPattern.FindStringSubmatch(stdout)
	if hm == nil || dm == nil {
		return "", "", fmt.Errorf("could not find HOST_RESULT/DNS_RESULT fields in query output")
	}
	return strings.TrimSpace(hm[1]), strings.TrimSpace(dm[1]), nil
}

// query issues one read-only central-plane discovery call against
// playbooks/apply/internal-endpoint-apply.yml, tagged so it only runs the
// relevant read-only lookup (never a mutating task).
func (p *InternalEndpointProvider) query(ctx context.Context, kind, fqdn string) (*ansible.Result, error) {
	args := []string{p.cfg.ApplyPlaybook}
	if p.cfg.ServerInventory != "" {
		args = append(args, "-i", p.cfg.ServerInventory)
	}
	args = append(args, "--tags", "iep_decommission_verify")
	args = append(args, "-e", "pilot_decommission_query="+kind)
	args = append(args, "-e", "pilot_decommission_target_fqdn="+fqdn)
	args = append(args, p.cfg.ExtraArgs...)
	res, err := p.exec(ctx, args)
	if err != nil {
		return nil, err
	}
	// Same fail-closed rule as freeipa_client.go's own query(): a genuinely
	// failed ansible-playbook run must never be silently read as "nothing
	// found" (INV-10).
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("internal-endpoint %s query for %s: ansible-playbook exited %d: %s", kind, fqdn, res.ExitCode, ansibleFailureDetail(res))
	}
	return res, nil
}

func (p *InternalEndpointProvider) exec(ctx context.Context, args []string) (*ansible.Result, error) {
	if p.cfg.Executor == nil {
		return nil, fmt.Errorf("internal-endpoint provider: no ansible executor configured")
	}
	return p.cfg.Executor.Run(ctx, args...)
}
