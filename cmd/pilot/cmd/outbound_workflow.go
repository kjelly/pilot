// outbound_workflow.go is the shared top-level workflow coordinator
// design spec §28.2 requires: it wraps (never hides inside)
// runDeployInteractive/runSiteDeploy, runReconcileInteractive's catalog
// batch, and the dedicated gateway-scope/access reconcile/breakglass
// frontends, so a multi-component deploy/reconcile — or an
// auto-cascaded sameHosts dependency — publishes exactly one outbound
// webhook terminal event, never one per component (INV-1).
//
// Every function here is best-effort AFTER the real operation already
// finished (INV-2): a nil return from publishTerminalWorkflow's caller
// is not expected — this file never returns an error that could change
// the caller's own exit code. The only exception is
// webhookReadiness, which callers MUST check BEFORE any mutation
// begins (INV-3) — an invalid integrations.yaml or unready store fails
// the operation closed, before ansible ever runs.
package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/outbound"
	"github.com/kjelly/pilot/internal/store"
)

// ComponentDeliveryResult is one component transaction's structured
// outcome, threaded up from executeRecordedDeploymentCore (design spec
// §10, §28) so the terminal publication step never has to parse an
// error string to learn what happened.
type ComponentDeliveryResult struct {
	ComponentIDs []string
	RunID        string
	Outcome      delivery.Outcome
	FailedStep   string
}

// DeploymentExecutionResult aggregates every component transaction one
// executeRecordedDeployment*-family call actually ran: the requested
// component plus any auto-applied sameHosts dependency.
type DeploymentExecutionResult struct {
	Results []ComponentDeliveryResult
}

func (d DeploymentExecutionResult) merge(other DeploymentExecutionResult) DeploymentExecutionResult {
	return DeploymentExecutionResult{Results: append(append([]ComponentDeliveryResult{}, d.Results...), other.Results...)}
}

// webhookReadiness loads and validates the workspace's integrations.yaml
// (design spec INV-3): a missing file returns (nil, nil) — outbound
// publishing is disabled, and callers must never open the outbox store
// in that case (design spec §7.1/§37's fast path). A present-but-invalid
// config, or one whose enabled webhooks fail CheckReadiness (e.g. an
// unreadable CA file), returns an error the caller MUST fail the whole
// operation on, before any mutation begins.
func webhookReadiness(workspaceDir string) (*outbound.Config, error) {
	cfg, err := outbound.LoadConfigFile(outbound.DefaultConfigPath(workspaceDir))
	if err != nil {
		return nil, fmt.Errorf("outbound webhook integrations.yaml: %w", err)
	}
	if cfg == nil {
		return nil, nil
	}
	if err := cfg.CheckReadiness(); err != nil {
		return nil, fmt.Errorf("outbound webhook readiness: %w", err)
	}
	return cfg, nil
}

// outboundWorkflowEffects returns the sorted, deduped union of every
// named component's contract-declared effects (design spec §8.3:
// routing effects include at least the requested components' union,
// even when preflight fails before any dependency runs). Unknown
// component IDs are skipped rather than erroring — this is a routing
// convenience, not a validation gate.
func outboundWorkflowEffects(catalog contract.Catalog, componentIDs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range componentIDs {
		c, ok := catalog.Component(id)
		if !ok {
			continue
		}
		for _, e := range c.Effects {
			if !seen[string(e)] {
				seen[string(e)] = true
				out = append(out, string(e))
			}
		}
	}
	sort.Strings(out)
	return out
}

func componentIDsFromResults(results []ComponentDeliveryResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		for _, id := range r.ComponentIDs {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

func completedComponentIDs(results []ComponentDeliveryResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range results {
		if r.Outcome != delivery.OutcomeSuccess {
			continue
		}
		for _, id := range r.ComponentIDs {
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	sort.Strings(out)
	return out
}

func failedComponentID(results []ComponentDeliveryResult) string {
	for _, r := range results {
		if r.Outcome != delivery.OutcomeSuccess && r.Outcome != delivery.OutcomeCancelled {
			if len(r.ComponentIDs) > 0 {
				return r.ComponentIDs[0]
			}
		}
	}
	return ""
}

func wireDeliveryRunsFrom(results []ComponentDeliveryResult) []outbound.WireDeliveryRun {
	out := make([]outbound.WireDeliveryRun, 0, len(results))
	for _, r := range results {
		out = append(out, outbound.WireDeliveryRun{RunID: r.RunID, Outcome: string(r.Outcome), FailedStep: r.FailedStep})
	}
	return out
}

func failureInfoFrom(results []ComponentDeliveryResult, publicResult string) *outbound.FailureInfo {
	if publicResult != "failure" {
		return nil
	}
	for _, r := range results {
		if r.Outcome == delivery.OutcomeSuccess || r.Outcome == delivery.OutcomeCancelled {
			continue
		}
		class := failureClassFor(r.FailedStep)
		component := ""
		if len(r.ComponentIDs) == 1 {
			component = r.ComponentIDs[0]
		}
		return &outbound.FailureInfo{Class: class, Phase: r.FailedStep, Component: component}
	}
	return &outbound.FailureInfo{Class: "apply_failed"}
}

// failureClassFor maps a Transaction step name to design spec §19's
// bounded FailureInfo.Class allowlist.
func failureClassFor(step string) string {
	switch step {
	case "preflight":
		return "preflight_failed"
	case "preview":
		return "preview_failed"
	case "apply":
		return "apply_failed"
	case "verify":
		return "verify_failed"
	case "idempotency":
		return "idempotency_failed"
	case "rollback":
		return "rollback_failed"
	case "evidence":
		return "evidence_failed"
	default:
		return "apply_failed"
	}
}

func containsOutcome(outcomes []delivery.Outcome, targets ...delivery.Outcome) bool {
	for _, o := range outcomes {
		for _, t := range targets {
			if o == t {
				return true
			}
		}
	}
	return false
}

// aggregateWorkflowResult implements design spec §9's multi-transaction
// aggregation: the public result (deploy spec's operation.result) and
// application_consistency, deterministically, regardless of component
// execution order.
func aggregateWorkflowResult(results []ComponentDeliveryResult) (publicResult string, consistency string) {
	if len(results) == 0 {
		return "failure", "unknown"
	}
	outcomes := make([]delivery.Outcome, len(results))
	for i, r := range results {
		outcomes[i] = r.Outcome
	}

	allSuccess := true
	for _, o := range outcomes {
		if o != delivery.OutcomeSuccess {
			allSuccess = false
			break
		}
	}

	switch {
	case containsOutcome(outcomes, delivery.OutcomeFailed, delivery.OutcomePartialFailed, delivery.OutcomeRolledBack,
		delivery.OutcomeRollbackFailed, delivery.OutcomeEvidenceFailed, delivery.OutcomeAuthorizationRequired):
		publicResult = "failure"
	case containsOutcome(outcomes, delivery.OutcomeCancelled):
		publicResult = "cancelled"
	default:
		publicResult = "success"
	}

	switch {
	case allSuccess:
		consistency = "confirmed_for_effects"
	case containsOutcome(outcomes, delivery.OutcomeRollbackFailed, delivery.OutcomeEvidenceFailed):
		consistency = "unknown"
	case containsOutcome(outcomes, delivery.OutcomeFailed, delivery.OutcomePartialFailed):
		consistency = "partial_or_unknown"
	case containsOutcome(outcomes, delivery.OutcomeCancelled):
		consistency = cancelledConsistency(results)
	case containsOutcome(outcomes, delivery.OutcomeRolledBack):
		consistency = rolledBackConsistency(outcomes)
	case containsOutcome(outcomes, delivery.OutcomeAuthorizationRequired):
		// Transaction.RunResult only ever raises ErrAuthorizationRequired
		// from the preflight step, before any mutation — so this is always
		// provably "unchanged", never the unproven "unchanged_or_unknown".
		consistency = "unchanged"
	case containsOutcome(outcomes, delivery.OutcomePartialSuccess):
		consistency = "partial"
	default:
		consistency = "unknown"
	}
	return publicResult, consistency
}

// cancelledConsistency distinguishes a pre-mutation cancellation
// (preflight/preview — "unchanged") from one that could have started
// mutating (apply/verify/idempotency — "unchanged_or_partial").
func cancelledConsistency(results []ComponentDeliveryResult) string {
	for _, r := range results {
		if r.Outcome != delivery.OutcomeCancelled {
			continue
		}
		switch r.FailedStep {
		case "apply", "verify", "idempotency":
			return "unchanged_or_partial"
		}
	}
	return "unchanged"
}

// rolledBackConsistency implements design spec §9 rule 7: rolled_back
// only if every started mutation rolled back successfully and nothing
// else completed.
func rolledBackConsistency(outcomes []delivery.Outcome) string {
	for _, o := range outcomes {
		if o != delivery.OutcomeRolledBack {
			return "partial_or_unknown"
		}
	}
	return "rolled_back"
}

// PublishTerminalWorkflowInput is publishTerminalWorkflow's input. Every
// operation-outcome field here is a DIRECT value, not something derived
// internally — deploy.go's catalog-driven callers compute them via
// aggregateDeploymentResult (from a []ComponentDeliveryResult); a
// dedicated frontend with no delivery.Transaction at all (gateway-scope,
// access breakglass) just supplies its own simple success/failure
// values directly. This keeps publishTerminalWorkflow itself agnostic
// to whether a Transaction ever ran.
type PublishTerminalWorkflowInput struct {
	WorkspaceDir string
	Inventory    string
	ExtraVars    []string
	Vault        vaultInput

	Operation  outbound.OperationKind
	WorkflowID string

	RequestedComponents []string
	ExecutedComponents  []string
	CompletedComponents []string
	FailedComponent     string
	// Effects is this workflow's routing effect set — usually
	// outboundWorkflowEffects(catalog, RequestedComponents), but a
	// dedicated frontend whose routing effects are a fixed §1 subset
	// (e.g. `pilot access reconcile` routes only on access.*, never the
	// full freeipa-identity effect set) supplies it directly instead.
	Effects          []string
	ConfirmedEffects []string

	Result                 outbound.ResultClass
	ApplicationConsistency string
	DeliveryRuns           []outbound.WireDeliveryRun
	Failure                *outbound.FailureInfo

	StartedAt, FinishedAt time.Time
	Subject               *outbound.WireSubject

	BreakglassActivations []inventory.BreakglassActivationInput
}

// aggregatedDeploymentFields is aggregateDeploymentResult's output — the
// direct-value fields PublishTerminalWorkflowInput needs, computed from
// a []ComponentDeliveryResult (design spec §9).
type aggregatedDeploymentFields struct {
	Result                 outbound.ResultClass
	ApplicationConsistency string
	CompletedComponents    []string
	FailedComponent        string
	ConfirmedEffects       []string
	DeliveryRuns           []outbound.WireDeliveryRun
	Failure                *outbound.FailureInfo
}

// aggregateDeploymentResult turns a []ComponentDeliveryResult (as
// executeRecordedDeploymentResult/executeRecordedDeploymentWithAuthorizationResult/
// executeCatalogReconcileBatch's own loop produce) into
// PublishTerminalWorkflowInput's direct operation-outcome fields.
func aggregateDeploymentResult(results []ComponentDeliveryResult) aggregatedDeploymentFields {
	publicResult, consistency := aggregateWorkflowResult(results)
	completed := completedComponentIDs(results)
	var confirmedEffects []string
	if len(completed) > 0 {
		if root, rerr := resolveContractRoot(""); rerr == nil {
			if loader, lerr := contract.NewLoader(root); lerr == nil {
				if catalog, cerr := loader.LoadDefaultCatalog(); cerr == nil {
					confirmedEffects = outboundWorkflowEffects(catalog, completed)
				}
			}
		}
	}
	return aggregatedDeploymentFields{
		Result:                 outbound.ResultClass(publicResult),
		ApplicationConsistency: consistency,
		CompletedComponents:    completed,
		FailedComponent:        failedComponentID(results),
		ConfirmedEffects:       confirmedEffects,
		DeliveryRuns:           wireDeliveryRunsFrom(results),
		Failure:                failureInfoFrom(results, publicResult),
	}
}

// publishTerminalWorkflow is the shared terminal-publication step design
// spec §28.2 requires. It is always called AFTER the real operation has
// already reached its terminal outcome, and it never returns anything
// the caller must act on — every failure path here is a printed warning,
// not a propagated error (INV-2).
func publishTerminalWorkflow(ctx context.Context, out io.Writer, in PublishTerminalWorkflowInput) {
	cfg, err := outbound.LoadConfigFile(outbound.DefaultConfigPath(in.WorkspaceDir))
	if err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: %v (original operation result unaffected)\n", err)
		return
	}
	if cfg == nil {
		return
	}

	workspaceKey, err := outbound.WorkspaceKey(in.WorkspaceDir)
	if err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: %v\n", err)
		return
	}

	dataDirPath := resolvePilotDataDir()
	if err := os.MkdirAll(dataDirPath, 0o700); err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}
	dbPath := filepath.Join(dataDirPath, "history.db")
	if err := outbound.SecureHistoryDBPermissions(dbPath); err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}
	s, err := store.Open(dbPath)
	if err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}
	if err := s.Close(); err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}
	if err := outbound.SecureHistoryDBPermissions(dbPath); err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}

	db, err := outbound.OpenOutboxDB(dbPath)
	if err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}
	defer db.Close()
	o := outbound.NewSQLiteOutbox(db)

	now := in.FinishedAt
	if err := o.CheckWorkspaceBinding(ctx, workspaceKey, cfg.SourceID, now); err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: %v\n", err)
		return
	}
	if err := o.ReconcileWebhookConfig(ctx, workspaceKey, cfg); err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}

	proj := buildOutboundProjection(ctx, out, in, now)

	opMeta := outbound.OperationMetadata{
		WorkflowID:             in.WorkflowID,
		Operation:              in.Operation,
		Result:                 in.Result,
		RequestedComponents:    in.RequestedComponents,
		ExecutedComponents:     in.ExecutedComponents,
		CompletedComponents:    in.CompletedComponents,
		FailedComponent:        in.FailedComponent,
		Effects:                in.Effects,
		DeliveryRuns:           in.DeliveryRuns,
		StartedAt:              in.StartedAt,
		FinishedAt:             in.FinishedAt,
		ApplicationConsistency: in.ApplicationConsistency,
		ConfirmedEffects:       in.ConfirmedEffects,
		Subject:                in.Subject,
		Failure:                in.Failure,
	}
	// design spec §8.3/§9: only a fully successful, fully-confirmed
	// workflow is even an authoritative CANDIDATE — BuildEnvelope still
	// ANDs this with the projection's own availability (INV-6).
	authoritativeCandidate := in.Result == outbound.ResultSuccess && in.ApplicationConsistency == "confirmed_for_effects"

	var drafts []outbound.EventDraft
	for _, wh := range cfg.Webhooks {
		if !wh.Enabled {
			continue
		}
		rule, ok := outbound.MatchEventRule(wh, in.Operation, in.Result, in.Effects)
		if !ok {
			continue
		}
		base, bootstrap, berr := o.EffectiveBase(ctx, workspaceKey, cfg.SourceID, wh.Name, outbound.ProjectionUserHostAccessV1)
		if berr != nil {
			fmt.Fprintf(out, "⚠ webhook %s: %v\n", wh.Name, berr)
			continue
		}
		draft, derr := buildEventDraftForWebhook(cfg, wh, rule, workspaceKey, in.WorkflowID, opMeta, proj, base, bootstrap, authoritativeCandidate, rootCmd.Version, now)
		if derr != nil {
			fmt.Fprintf(out, "⚠ webhook %s: %v\n", wh.Name, derr)
			continue
		}
		drafts = append(drafts, draft)
	}
	if len(drafts) == 0 {
		return
	}

	if _, err := o.EnqueueBatch(ctx, drafts); err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: local enqueue failed (%v) — operation result unaffected, event NOT durable\n", err)
		return
	}

	identities := make([]outbound.WebhookIdentity, 0, len(cfg.Webhooks))
	for _, wh := range cfg.Webhooks {
		if !wh.Enabled {
			continue
		}
		identities = append(identities, outbound.WebhookIdentity{WorkspaceKey: workspaceKey, SourceID: cfg.SourceID, WebhookName: wh.Name, Config: wh})
	}
	d := &outbound.Dispatcher{
		Outbox: o, Now: time.Now, RNG: rand.New(rand.NewSource(time.Now().UnixNano())),
		PilotVersion: rootCmd.Version, SecretLookup: os.LookupEnv,
	}
	outcomes := d.FlushWebhooks(ctx, identities, outbound.DefaultFlushOptions())
	for _, oc := range outcomes {
		switch {
		case oc.Delivered:
			fmt.Fprintf(out, "✓ webhook %s delivered (event=%s)\n", oc.WebhookName, oc.EventID)
		case oc.DeadLetter:
			fmt.Fprintf(out, "⚠ webhook %s dead-lettered (event=%s, reason=%s)\n", oc.WebhookName, oc.EventID, oc.ErrorClass)
		case oc.Pending:
			fmt.Fprintf(out, "⚠ webhook %s pending retry (event=%s, reason=%s)\n", oc.WebhookName, oc.EventID, oc.ErrorClass)
		}
	}
}

// buildOutboundProjection rebuilds the current declarative state after
// the operation is already terminal (design spec §27.1 — never reuse a
// wizard-entry snapshot). A hostVars resolution failure degrades to an
// unavailable projection rather than aborting publication.
func buildOutboundProjection(ctx context.Context, out io.Writer, in PublishTerminalWorkflowInput, now time.Time) outbound.ProjectionResult {
	if in.Inventory == "" {
		return outbound.ProjectionResult{Available: false, ErrorClass: outbound.ErrorClassProjectionUnavailable}
	}
	hostVars, err := resolveInventoryVariables(ctx, in.Inventory, in.ExtraVars, in.Vault)
	if err != nil {
		fmt.Fprintf(out, "⚠ outbound webhook: state projection unavailable (%v)\n", err)
		return outbound.ProjectionResult{Available: false, ErrorClass: outbound.ErrorClassProjectionUnavailable}
	}
	return outbound.BuildProjection(outbound.ProjectionRequest{
		WorkspaceDir:          in.WorkspaceDir,
		HostVars:              hostVars,
		VaultPasswordFile:     in.Vault.VaultPasswordFile,
		BreakglassActivations: in.BreakglassActivations,
		Now:                   now,
	})
}

// buildEventDraftForWebhook builds one webhook's EventDraft. The
// envelope is built twice: once with placeholder identity to determine
// final size/authoritative-eligibility before enqueuing (so the outbox
// row's own Authoritative/StateAvailable columns are correct from the
// start), and once for real inside Finalize once the sequence is known
// (design spec §22.2) — both builds reuse the same already-computed
// projection/diff, so the second pass is cheap.
func buildEventDraftForWebhook(
	cfg *outbound.Config,
	wh outbound.WebhookConfig,
	rule *outbound.EventRule,
	workspaceKey, workflowID string,
	op outbound.OperationMetadata,
	proj outbound.ProjectionResult,
	base outbound.SnapshotRef,
	bootstrap bool,
	authoritativeCandidate bool,
	pilotVersion string,
	now time.Time,
) (outbound.EventDraft, error) {
	probeEnv, err := outbound.BuildEnvelope(outbound.BuildEnvelopeParams{
		SourceID: cfg.SourceID, PilotVersion: pilotVersion, WebhookName: wh.Name,
		Sequence: 0, EventID: "00000000-0000-0000-0000-000000000000", CreatedAt: now,
		Op: op, Payload: rule.Payload, Projection: proj, Base: base, Bootstrap: bootstrap,
		Target: proj.Snapshot, Authoritative: authoritativeCandidate,
	})
	if err != nil {
		return outbound.EventDraft{}, err
	}
	_, errClass, err := outbound.FinalizeEnvelope(probeEnv)
	if err != nil {
		return outbound.EventDraft{}, err
	}
	oversized := errClass == outbound.ErrorClassPayloadTooLarge

	finalAvailable := proj.Available && !oversized
	finalAuthoritative := authoritativeCandidate && finalAvailable

	var targetSnapshotID, targetSnapshotJSON string
	if finalAvailable {
		canon := outbound.CanonicalizeSnapshot(proj.Snapshot)
		targetSnapshotID = outbound.SnapshotID(canon)
		if body, merr := json.Marshal(canon); merr == nil {
			targetSnapshotJSON = string(body)
		}
	}

	return outbound.EventDraft{
		WorkspaceKey: workspaceKey, SourceID: cfg.SourceID, WebhookName: wh.Name, WorkflowID: workflowID,
		Operation: string(op.Operation), Result: string(op.Result),
		Projection: outbound.ProjectionUserHostAccessV1, PayloadMode: string(rule.Payload),
		Authoritative: finalAuthoritative, StateAvailable: finalAvailable, SourceComplete: finalAvailable,
		BaseSnapshotID: base.ID, TargetSnapshotID: targetSnapshotID, TargetSnapshotJSON: targetSnapshotJSON,
		Now: now,
		Finalize: func(eventID string, sequence int64) ([]byte, error) {
			env, err := outbound.BuildEnvelope(outbound.BuildEnvelopeParams{
				SourceID: cfg.SourceID, PilotVersion: pilotVersion, WebhookName: wh.Name,
				Sequence: sequence, EventID: eventID, CreatedAt: now,
				Op: op, Payload: rule.Payload, Projection: proj, Base: base, Bootstrap: bootstrap,
				Target: proj.Snapshot, Authoritative: authoritativeCandidate,
			})
			if err != nil {
				return nil, err
			}
			body, _, err := outbound.FinalizeEnvelope(env)
			return body, err
		},
	}, nil
}

// activeBreakglassActivations reads every recorded breakglass
// activation (design spec §12.4) and returns only the currently-active
// ones, for the outbound projection's breakglass login-access entities.
func activeBreakglassActivations(now time.Time) []inventory.BreakglassActivationInput {
	activations, err := accessgrants.Status(resolveDataDir(), "")
	if err != nil {
		return nil
	}
	out := make([]inventory.BreakglassActivationInput, 0, len(activations))
	for _, a := range activations {
		if a.IsActive(now) {
			out = append(out, inventory.BreakglassActivationInput{Name: a.Name, ExpiresAt: a.ExpiresAt})
		}
	}
	return out
}

// newWorkflowID generates design spec §8.1's lowercase RFC 4122 UUIDv4
// workflow identifier.
func newWorkflowID() string {
	return uuid.NewString()
}
