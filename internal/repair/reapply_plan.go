package repair

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/networkcheck"
)

// ReapplyPlanTTL mirrors PlanTTL — an R2 plan is meant to be reviewed and
// acted on promptly, not held as standing authorization, same reasoning
// as Phase 3's R1 Plan.
const ReapplyPlanTTL = 15 * time.Minute

// ReapplyPreviewChangeThreshold is design doc §19's "hard guard for
// unexpectedly broad change surface" — no specific number is given
// there ("threshold defined in spec"), so this is a deliberately chosen,
// documented default rather than an unstated one: 20 files is well
// above what a single-component config/binary reapply legitimately
// touches (the R1-proven alertmanager candidate changes 1-3 files), so
// a preview above it is far more likely a misconfigured/misidentified
// target than a genuine intended change. "Operator override, if any, is
// outside Agent control" (§19) — there is deliberately no override flag
// on the MCP tool a caller could set; only a human editing this
// constant and redeploying the binary can raise it.
const ReapplyPreviewChangeThreshold = 20

// Input resolution classifications (design doc §17, Task 3).
const (
	InputResolvedNonSecret       = "resolved_non_secret"
	InputResolvedSecretReference = "resolved_secret_reference"
	InputMissing                 = "missing"
	InputAmbiguous               = "ambiguous"
)

// ReapplyResolvedInput is design doc §6's ReapplyResolvedInput,
// extending the immutable repair plan with canonical-apply-specific
// resolved metadata. It never carries a secret VALUE — SecretReferenceKeys
// is a list of GroupVar NAMES that resolved to something, never the
// something itself (design doc §7: "plan output contains no plaintext
// secrets").
type ReapplyResolvedInput struct {
	PlaybookPath        string
	PlaybookHash        string
	TargetHost          string
	Stage               string
	ResolvedInputKeys   []string
	SecretReferenceKeys []string
	DependencySnapshot  []DependencyStatus
	// PreviewRef is the content hash PlanHash actually covers — a change
	// to the preview invalidates the plan like any other executable
	// field.
	PreviewRef string
	// PreviewSupported/PreviewSummary/PreviewEstimatedChanged/
	// PreviewUnsupportedReason are the DISPLAY copy of the preview
	// (design doc §12: the human approval view must show the preview
	// summary, not just its hash) — never re-hashed independently; they
	// are exactly what PreviewRef is a hash OF, kept alongside it purely
	// for readability. A caller must never trust these fields as
	// execution-relevant on their own; only PreviewRef (via PlanHash) is
	// tamper-evident.
	PreviewSupported         bool
	PreviewSummary           string
	PreviewEstimatedChanged  int
	PreviewUnsupportedReason string
}

// ReapplyPlan is Agent Monitoring Phase 5's immutable R2 plan — a
// SEPARATE type from Plan (R1), not an extension of it: an R1 approval
// can never authorize R2 (design doc §12), and mixing the two wire
// shapes would make that boundary a matter of application-logic
// discipline instead of the type system.
type ReapplyPlan struct {
	SchemaVersion     int
	ID                string
	IncidentID        string
	Host              string
	Component         string
	Action            string
	Risk              string // always "R2" — BuildReapplyPlan refuses anything else
	VerificationSpec  string
	InventoryRevision string
	ContractHash      string
	PlanHash          string
	CreatedAt         time.Time
	ExpiresAt         time.Time
	Resolved          ReapplyResolvedInput
}

// Expired reports whether now is past p.ExpiresAt.
func (p ReapplyPlan) Expired(now time.Time) bool { return now.After(p.ExpiresAt) }

// reapplyPlanHashFields is the exact, stable set of executable fields
// PlanHash covers (design doc §6) — every field that changes what the
// apply actually DOES or what evidence justified it: identity, contract
// declaration, playbook content, stage, the non-secret inputs actually
// resolved (by name, not value), which secret references were used (by
// name), the dependency snapshot, and the preview content — but never a
// secret value.
type reapplyPlanHashFields struct {
	SchemaVersion       int
	IncidentID          string
	Host                string
	Component           string
	Action              string
	Risk                string
	InventoryRevision   string
	ContractHash        string
	PlaybookPath        string
	PlaybookHash        string
	Stage               string
	ResolvedInputKeys   []string
	SecretReferenceKeys []string
	DependencySnapshot  []DependencyStatus
	PreviewRef          string
	VerificationSpec    string
}

func computeReapplyHash(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hashPlaybookFile reads playbookPath (resolved relative to repoRoot)
// and returns its content hash — part of what makes a stale/edited
// canonical playbook invalidate an already-approved plan (design doc
// §6: "playbook path/hash").
func hashPlaybookFile(repoRoot, playbookPath string) (string, error) {
	abs := playbookPath
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(repoRoot, playbookPath)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return "", fmt.Errorf("read canonical playbook %s: %w", playbookPath, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// classifyGroupVarType reports whether value is consistent with the
// declared contract GroupVar type — an inconsistency is "ambiguous"
// (design doc §17: "Missing/ambiguous blocks plan"), not silently
// coerced.
func classifyGroupVarType(typ string, value any) bool {
	switch typ {
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "integer":
		switch value.(type) {
		case float64, int, int64:
			return true
		}
		return false
	case "stringList":
		_, ok := value.([]any)
		return ok
	default: // "string", "duration", or an unrecognized type — treat as opaque scalar
		_, ok := value.(string)
		return ok
	}
}

// resolveInputs classifies every declared GroupVar for comp against
// host's actual resolved variables (design doc Task 3) — reusing the
// SAME resolved-inventory data bindings already use
// (networkcheck.ResolvedInventory.HostVars, which already carries full
// ansible group_vars precedence merging, not a second variable
// registry). Returns an error the moment any REQUIRED input is missing
// or ambiguous — "missing/ambiguous blocks plan" is not a partial-result
// state.
func resolveInputs(resolved networkcheck.ResolvedInventory, host string, comp contract.Contract) (nonSecret, secretRefs []string, err error) {
	hostVars := resolved.HostVars[host]
	for _, gv := range comp.GroupVars {
		value, has := hostVars[gv.Name]
		if !has || value == nil {
			if gv.Required {
				return nil, nil, fmt.Errorf("required input %q is missing for host %q", gv.Name, host)
			}
			continue
		}
		if !classifyGroupVarType(gv.Type, value) {
			return nil, nil, fmt.Errorf("required input %q resolved to a value inconsistent with its declared type %q — ambiguous", gv.Name, gv.Type)
		}
		if gv.Secret {
			secretRefs = append(secretRefs, gv.Name)
		} else {
			nonSecret = append(nonSecret, gv.Name)
		}
	}
	sort.Strings(nonSecret)
	sort.Strings(secretRefs)
	return nonSecret, secretRefs, nil
}

// PreviewRunner runs `ansible-playbook --check --diff` for exactly one
// host against playbookPath and returns its raw stdout. The caller owns
// Ansible runtime/env construction — same "caller owns the runtime"
// boundary internal/diagnose.AdHocRunner already establishes for R1
// (internal/repair never constructs an internal/ansible.Runner itself).
type PreviewRunner func(ctx context.Context, playbookPath, inventory, host, stage string) (stdout string, exitCode int, err error)

// ReapplyPreview is design doc §9's sanitized approval-view preview.
type ReapplyPreview struct {
	Supported         bool
	Summary           string // sanitized markdown, safe to show a human
	EstimatedChanged  int
	UnsupportedReason string
	Ref               string // content hash — what PlanHash actually covers
}

// BuildReapplyPlan resolves an Agent's recommendation (incident ID +
// exact host + component + action ID — nothing else, design doc §2)
// into an immutable ReapplyPlan. Every execution-relevant field is
// resolved HERE, server-side: canonical playbook path/hash from the
// contract + repo tree, dependency health from PreflightDependencies,
// non-secret/secret-reference inputs from the current resolved
// inventory, and a sanitized check-mode preview — never taken from the
// caller.
func BuildReapplyPlan(ctx context.Context, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, deps PreflightDependenciesFunc, preview PreviewRunner, repoRoot, inventory, newPlanID, incidentID, host, component, actionID string, now time.Time) (ReapplyPlan, error) {
	if incidentID == "" {
		return ReapplyPlan{}, fmt.Errorf("incident id is required")
	}
	if _, known := resolved.HostVars[host]; !known {
		return ReapplyPlan{}, fmt.Errorf("host %q is not a known inventory host", host)
	}

	c, ok := catalog.Component(component)
	if !ok {
		return ReapplyPlan{}, fmt.Errorf("unknown component %q", component)
	}
	assigned := false
	for _, h := range resolved.GroupHosts[c.Role] {
		if h == host {
			assigned = true
			break
		}
	}
	if !assigned {
		return ReapplyPlan{}, fmt.Errorf("component %q is not assigned to host %q", component, host)
	}

	var action *contract.RemediationAction
	for i := range c.Remediation.Actions {
		if c.Remediation.Actions[i].ID == actionID {
			action = &c.Remediation.Actions[i]
			break
		}
	}
	if action == nil {
		return ReapplyPlan{}, fmt.Errorf("component %q has no remediation action %q", component, actionID)
	}
	if action.Risk != "R2" || action.Executor.Kind != "canonical_apply" {
		return ReapplyPlan{}, fmt.Errorf("action %q is not a Phase 5 canonical_apply R2 action (risk=%s kind=%s)", actionID, action.Risk, action.Executor.Kind)
	}
	if action.MaxTargets != 1 {
		return ReapplyPlan{}, fmt.Errorf("action %q has maxTargets=%d — Phase 5 requires exactly 1", actionID, action.MaxTargets)
	}
	if c.Playbooks.Apply == "" {
		return ReapplyPlan{}, fmt.Errorf("component %q has no playbooks.apply — not R2-eligible", component)
	}

	playbookHash, err := hashPlaybookFile(repoRoot, c.Playbooks.Apply)
	if err != nil {
		return ReapplyPlan{}, err
	}

	nonSecret, secretRefs, err := resolveInputs(resolved, host, c)
	if err != nil {
		return ReapplyPlan{}, err
	}

	depStatuses, err := deps(ctx, catalog, resolved, host, component)
	if err != nil {
		return ReapplyPlan{}, fmt.Errorf("dependency preflight: %w", err)
	}
	if ok, failing := AllRequiredHealthy(depStatuses); !ok {
		return ReapplyPlan{}, fmt.Errorf("required dependencies unhealthy, blocking reapply: %v", failing)
	}

	stage := stageValue(resolved.HostVars[host], c.StagePolicy)

	prev, err := runPreview(ctx, preview, c.Playbooks.Apply, inventory, host, stage)
	if err != nil {
		return ReapplyPlan{}, fmt.Errorf("preview: %w", err)
	}
	if prev.Supported && prev.EstimatedChanged > ReapplyPreviewChangeThreshold {
		return ReapplyPlan{}, fmt.Errorf("%s: preview shows %d changed files, exceeding the %d-file hard guard for an unexpectedly broad change surface — refusing to plan",
			ReapplyPreviewBlocked, prev.EstimatedChanged, ReapplyPreviewChangeThreshold)
	}

	addr := resolved.HostAddr(host)
	if addr == "" {
		addr = host
	}
	inventoryRevision := computeReapplyHash(struct{ Host, Addr string }{Host: host, Addr: addr})
	contractHash := hashReapplyAction(*action)

	p := ReapplyPlan{
		SchemaVersion: 1, ID: newPlanID, IncidentID: incidentID, Host: host, Component: component,
		Action: actionID, Risk: "R2", VerificationSpec: action.Verification.Spec,
		InventoryRevision: inventoryRevision, ContractHash: contractHash,
		CreatedAt: now, ExpiresAt: now.Add(ReapplyPlanTTL),
		Resolved: ReapplyResolvedInput{
			PlaybookPath: c.Playbooks.Apply, PlaybookHash: playbookHash, TargetHost: host, Stage: stage,
			ResolvedInputKeys: nonSecret, SecretReferenceKeys: secretRefs, DependencySnapshot: depStatuses, PreviewRef: prev.Ref,
			PreviewSupported: prev.Supported, PreviewSummary: prev.Summary, PreviewEstimatedChanged: prev.EstimatedChanged,
			PreviewUnsupportedReason: prev.UnsupportedReason,
		},
	}
	p.PlanHash = computeReapplyHash(reapplyPlanHashFields{
		SchemaVersion: p.SchemaVersion, IncidentID: p.IncidentID, Host: p.Host, Component: p.Component, Action: p.Action, Risk: p.Risk,
		InventoryRevision: p.InventoryRevision, ContractHash: p.ContractHash,
		PlaybookPath: p.Resolved.PlaybookPath, PlaybookHash: p.Resolved.PlaybookHash, Stage: p.Resolved.Stage,
		ResolvedInputKeys: p.Resolved.ResolvedInputKeys, SecretReferenceKeys: p.Resolved.SecretReferenceKeys,
		DependencySnapshot: p.Resolved.DependencySnapshot, PreviewRef: p.Resolved.PreviewRef, VerificationSpec: p.VerificationSpec,
	})
	return p, nil
}

// PreflightDependenciesFunc matches PreflightDependencies' own shape —
// named so BuildReapplyPlan's tests can inject a fake without needing a
// real diagnose.AdHocRunner.
type PreflightDependenciesFunc func(ctx context.Context, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, host, component string) ([]DependencyStatus, error)

func hashReapplyAction(a contract.RemediationAction) string {
	return computeReapplyHash(struct {
		ID                         string
		Risk                       string
		ExecutorKind               string
		MaxTargets                 int
		RequiresApproval           bool
		VerificationSpec           string
		RequireIdempotencyEvidence bool
		RequireDependencyHealth    bool
	}{
		ID: a.ID, Risk: a.Risk, ExecutorKind: a.Executor.Kind, MaxTargets: a.MaxTargets, RequiresApproval: a.RequiresApproval,
		VerificationSpec: a.Verification.Spec, RequireIdempotencyEvidence: a.Preflight.RequireIdempotencyEvidence,
		RequireDependencyHealth: a.Preflight.RequireDependencyHealth,
	})
}

// stageValue reads the component's own stage variable (contract
// StagePolicy) from host's resolved vars, falling back to the
// contract's documented default — the SAME resolution `pilot deploy`
// itself uses (contracts/*.yaml stagePolicy.variable/default), never a
// caller-supplied override (design doc §2: Agent cannot provide a
// "stage override").
func stageValue(hostVars map[string]any, sp contract.StagePolicy) string {
	if sp.Variable != "" {
		if v, ok := hostVars[sp.Variable].(string); ok && v != "" {
			return v
		}
	}
	if sp.Default != "" {
		return sp.Default
	}
	return "sandbox"
}

// VerifyReapplyPlanFresh re-derives a ReapplyPlan from the CURRENT
// catalog/inventory/dependency health/preview (using ONLY p's identity
// fields — ID/IncidentID/Host/Component/Action, never its resolved
// fields) and returns that FRESH plan when it still matches p's
// recorded PlanHash. Mirrors repair.VerifyPlanFresh's own R1 precedent
// exactly, including its central security invariant: callers MUST
// execute using the RETURNED plan, never the caller-supplied p — p's
// PlaybookPath/DependencySnapshot/etc. are only ever a display/audit
// copy once this function has run, for the identical reason R1's
// VerifyPlanFresh doc comment explains (a tampered p could change one
// of them while leaving PlanHash untouched; only the freshly-rebuilt
// plan is safe to act on).
func VerifyReapplyPlanFresh(ctx context.Context, catalog contract.Catalog, resolved networkcheck.ResolvedInventory, deps PreflightDependenciesFunc, preview PreviewRunner, repoRoot, inventory string, p ReapplyPlan) (ReapplyPlan, error) {
	fresh, err := BuildReapplyPlan(ctx, catalog, resolved, deps, preview, repoRoot, inventory, p.ID, p.IncidentID, p.Host, p.Component, p.Action, p.CreatedAt)
	if err != nil {
		return ReapplyPlan{}, fmt.Errorf("plan no longer resolvable: %w", err)
	}
	if fresh.PlanHash != p.PlanHash {
		return ReapplyPlan{}, fmt.Errorf("plan is stale: current contract/inventory/dependencies/preview no longer resolve to the approved plan hash")
	}
	return fresh, nil
}

func runPreview(ctx context.Context, preview PreviewRunner, playbookPath, inventory, host, stage string) (ReapplyPreview, error) {
	if preview == nil {
		return ReapplyPreview{Supported: false, UnsupportedReason: "no preview runner configured", Ref: computeReapplyHash("unsupported")}, nil
	}
	stdout, exitCode, err := preview(ctx, playbookPath, inventory, host, stage)
	if err != nil {
		return ReapplyPreview{Supported: false, UnsupportedReason: err.Error(), Ref: computeReapplyHash("error:" + err.Error())}, nil
	}
	// A genuinely broken playbook (syntax error, unreachable host, a
	// task that hard-fails even under --check) reports a NONZERO exit
	// with no usable diff — do not silently present that as "zero
	// changes" (design doc §9: "do not silently treat check-mode
	// failure as skip preview").
	if exitCode != 0 && !hasRecapLine(stdout) {
		return ReapplyPreview{Supported: false, UnsupportedReason: fmt.Sprintf("check-mode run failed (exit %d)", exitCode), Ref: computeReapplyHash("failed:" + stdout)}, nil
	}
	// A task skipped under --check (commonly a `when: not
	// ansible_check_mode` guard) means the diff this run produced is
	// structurally incomplete — real drift behind a skipped task would
	// never show up, silently reporting "no changes" instead. Found via
	// a real drift-injection test against alertmanager's own canonical
	// apply playbook (2026-09-01) — see previewSkippedCount's own doc
	// comment for the full story.
	if skipped := previewSkippedCount(stdout); skipped > 0 {
		return ReapplyPreview{Supported: false,
			UnsupportedReason: fmt.Sprintf("%d task(s) were skipped during the check-mode run (commonly a `when: not ansible_check_mode` guard) — the preview cannot be trusted to reflect real changes", skipped),
			Ref:               computeReapplyHash(fmt.Sprintf("skipped:%d:%s", skipped, stdout))}, nil
	}
	summary := renderDiffSummary(stdout)
	return ReapplyPreview{Supported: true, Summary: summary.text, EstimatedChanged: summary.changed, Ref: computeReapplyHash(summary.text)}, nil
}
