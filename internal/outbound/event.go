// event.go implements design spec §15 (wire contract), §31 (event
// matching), §14.7/§14.8 (effective base / dead-letter chain safety),
// and §38 (payload size). It is the layer that turns a completed
// workflow's operation metadata plus a built projection/diff into the
// exact bytes Pilot sends over HTTP.
package outbound

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// MaxPayloadBytes is design spec §38's 8 MiB default cap on a
// serialized event body.
const MaxPayloadBytes = 8 * 1024 * 1024

// MaxUnavailableEventBytes is §11.7/§38's bound on a metadata-only
// (unavailable or oversized) event.
const MaxUnavailableEventBytes = 64 * 1024

// WireDeliveryRun is one operation.delivery_runs[] entry (design spec
// §8.2/§15.1).
type WireDeliveryRun struct {
	RunID      string `json:"run_id"`
	Outcome    string `json:"outcome"`
	FailedStep string `json:"failed_step,omitempty"`
}

// WireSubject is operation.subject — the only allowed shape is the
// breakglass one (design spec §15.1.1); every other operation omits it.
type WireSubject struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// OperationMetadata is the terminal workflow metadata event.go needs to
// build a wire envelope — the output design spec §8.2 calls
// WorkflowResult, expressed here as the flat set of fields this package
// actually consumes (Phase 4's workflow coordinator is responsible for
// aggregating the real thing into this shape).
type OperationMetadata struct {
	WorkflowID             string
	Operation              OperationKind
	Result                 ResultClass
	RequestedComponents    []string
	ExecutedComponents     []string
	CompletedComponents    []string
	FailedComponent        string
	Effects                []string
	DeliveryRuns           []WireDeliveryRun
	StartedAt              time.Time
	FinishedAt             time.Time
	ApplicationConsistency string
	ConfirmedEffects       []string
	Subject                *WireSubject
	Failure                *FailureInfo
}

// FailureInfo is the wire failure{} object (design spec §19) — always
// from this bounded allowlist, never a raw error string.
type FailureInfo struct {
	Class     string `json:"class"`
	Phase     string `json:"phase,omitempty"`
	Component string `json:"component,omitempty"`
}

// StateInfo is the wire state{} object (design spec §15.1.1).
type StateInfo struct {
	Projection             string   `json:"projection"`
	ProjectionVersion      int      `json:"projection_version"`
	RequestedPayload       string   `json:"requested_payload"`
	Available              bool     `json:"available"`
	Basis                  string   `json:"basis"`
	SourceComplete         bool     `json:"source_complete"`
	ApplicationConsistency string   `json:"application_consistency"`
	ConfirmedEffects       []string `json:"confirmed_effects"`
	Authoritative          bool     `json:"authoritative"`
	SnapshotID             string   `json:"snapshot_id,omitempty"`
	BaseSnapshotID         string   `json:"base_snapshot_id,omitempty"`
	ErrorClass             string   `json:"error_class,omitempty"`
}

// Envelope is the full wire event (design spec §15.1).
type Envelope struct {
	SchemaVersion int             `json:"schema_version"`
	EventID       string          `json:"event_id"`
	EventType     string          `json:"event_type"`
	CreatedAt     string          `json:"created_at"`
	Source        EnvelopeSource  `json:"source"`
	Subscription  EnvelopeSub     `json:"subscription"`
	Operation     EnvelopeOp      `json:"operation"`
	State         StateInfo       `json:"state"`
	Snapshot      json.RawMessage `json:"snapshot,omitempty"`
	Diff          json.RawMessage `json:"diff,omitempty"`
	Failure       *FailureInfo    `json:"failure,omitempty"`
}

type EnvelopeSource struct {
	ID           string `json:"id"`
	PilotVersion string `json:"pilot_version"`
}

type EnvelopeSub struct {
	Name     string `json:"name"`
	Sequence int64  `json:"sequence"`
}

type EnvelopeOp struct {
	WorkflowID          string            `json:"workflow_id"`
	Type                string            `json:"type"`
	Result              string            `json:"result"`
	RequestedComponents []string          `json:"requested_components"`
	ExecutedComponents  []string          `json:"executed_components"`
	CompletedComponents []string          `json:"completed_components"`
	FailedComponent     string            `json:"failed_component,omitempty"`
	Effects             []string          `json:"effects"`
	DeliveryRuns        []WireDeliveryRun `json:"delivery_runs"`
	StartedAt           string            `json:"started_at"`
	FinishedAt          string            `json:"finished_at"`
	Subject             *WireSubject      `json:"subject,omitempty"`
}

const wireEventType = "pilot.operation.terminal"
const wireSchemaVersion = 1
const wireProjectionVersion = 1

// MatchEventRule finds the (first, and design spec §7.4 guarantees at
// most one) event rule matching operation/result/effects (design spec
// §7.5, §31): exact effect membership or a trailing-namespace wildcard.
// A deploy operation's rule never carries effects_any (config
// validation already enforces this), so it always matches on
// operation+result alone.
func MatchEventRule(cfg WebhookConfig, operation OperationKind, result ResultClass, effects []string) (*EventRule, bool) {
	for i := range cfg.Events {
		rule := &cfg.Events[i]
		if rule.Operation != operation || rule.Result != result {
			continue
		}
		if len(rule.EffectsAny) == 0 {
			return rule, true
		}
		if effectsMatchAny(effects, rule.EffectsAny) {
			return rule, true
		}
	}
	return nil, false
}

func effectsMatchAny(effects []string, patterns []string) bool {
	for _, e := range effects {
		for _, p := range patterns {
			if strings.HasSuffix(p, ".*") {
				if strings.HasPrefix(e, strings.TrimSuffix(p, "*")) {
					return true
				}
				continue
			}
			if e == p {
				return true
			}
		}
	}
	return false
}

// SnapshotRef is a lightweight (id, canonical JSON) pair — the shape
// both the outbox's target_snapshot_json column and cursor's
// snapshot_json column carry.
type SnapshotRef struct {
	ID   string
	JSON json.RawMessage
}

// ResolveEffectiveBase implements design spec §14.7: the base a new
// diff chains from is, in order, (1) this webhook's last not-yet-ACKed
// authoritative target snapshot (FIFO chain), (2) the current cursor
// snapshot, (3) empty (bootstrap). pendingAuthoritativeTarget is nil
// when there is no such pending row.
func ResolveEffectiveBase(pendingAuthoritativeTarget, cursor *SnapshotRef) (base SnapshotRef, bootstrap bool) {
	if pendingAuthoritativeTarget != nil {
		return *pendingAuthoritativeTarget, false
	}
	if cursor != nil {
		return *cursor, false
	}
	return SnapshotRef{}, true
}

// BuildEnvelopeParams bundles BuildEnvelope's inputs.
type BuildEnvelopeParams struct {
	SourceID      string
	PilotVersion  string
	WebhookName   string
	Sequence      int64
	EventID       string
	CreatedAt     time.Time
	Op            OperationMetadata
	Payload       PayloadMode
	Projection    ProjectionResult // Available=false => metadata-only envelope
	Base          SnapshotRef
	Bootstrap     bool
	Target        UserHostAccessSnapshotV1
	Authoritative bool // candidate authoritative flag from §8.3's table; BuildEnvelope ANDs it with projection availability per INV-6
}

// BuildEnvelope renders one full wire event (design spec §15.1). When
// the projection is unavailable, Snapshot/Diff are omitted entirely
// (never null, never an empty-but-present object — design spec §11.7)
// and Authoritative is forced false regardless of the candidate value
// (INV-6: authoritative=true requires available=true, source_complete=true).
func BuildEnvelope(p BuildEnvelopeParams) (Envelope, error) {
	env := Envelope{
		SchemaVersion: wireSchemaVersion,
		EventID:       p.EventID,
		EventType:     wireEventType,
		CreatedAt:     p.CreatedAt.UTC().Format(time.RFC3339Nano),
		Source:        EnvelopeSource{ID: p.SourceID, PilotVersion: p.PilotVersion},
		Subscription:  EnvelopeSub{Name: p.WebhookName, Sequence: p.Sequence},
		Operation: EnvelopeOp{
			WorkflowID:          p.Op.WorkflowID,
			Type:                string(p.Op.Operation),
			Result:              string(p.Op.Result),
			RequestedComponents: nonNil(p.Op.RequestedComponents),
			ExecutedComponents:  nonNil(p.Op.ExecutedComponents),
			CompletedComponents: nonNil(p.Op.CompletedComponents),
			FailedComponent:     p.Op.FailedComponent,
			Effects:             sortedOrEmpty(p.Op.Effects),
			DeliveryRuns:        nonNilRuns(p.Op.DeliveryRuns),
			StartedAt:           p.Op.StartedAt.UTC().Format(time.RFC3339Nano),
			FinishedAt:          p.Op.FinishedAt.UTC().Format(time.RFC3339Nano),
			Subject:             p.Op.Subject,
		},
		Failure: p.Op.Failure,
	}

	// INV-6: authoritative=true requires available=true and
	// source_complete=true. This package's projection model has no
	// partial-availability state (BuildProjection only ever returns
	// Available=true once every source resolved completely), so
	// Available alone stands in for source_complete here.
	authoritative := p.Authoritative && p.Projection.Available

	if !p.Projection.Available {
		env.State = StateInfo{
			Projection: ProjectionUserHostAccessV1, ProjectionVersion: wireProjectionVersion,
			RequestedPayload:       string(p.Payload),
			Available:              false,
			Basis:                  "pilot_declared",
			SourceComplete:         false,
			ApplicationConsistency: p.Op.ApplicationConsistency,
			ConfirmedEffects:       sortedOrEmpty(p.Op.ConfirmedEffects),
			Authoritative:          false,
			ErrorClass:             string(p.Projection.ErrorClass),
		}
		return env, nil
	}

	canon := CanonicalizeSnapshot(p.Target)
	snapshotID := SnapshotID(canon)
	env.State = StateInfo{
		Projection: ProjectionUserHostAccessV1, ProjectionVersion: wireProjectionVersion,
		RequestedPayload:       string(p.Payload),
		Available:              true,
		Basis:                  "pilot_declared",
		SourceComplete:         true,
		ApplicationConsistency: p.Op.ApplicationConsistency,
		ConfirmedEffects:       sortedOrEmpty(p.Op.ConfirmedEffects),
		Authoritative:          authoritative,
		SnapshotID:             snapshotID,
	}

	var diffVal *StateDiffV1
	if p.Payload == PayloadDiff || p.Payload == PayloadBoth {
		var baseSnapshot UserHostAccessSnapshotV1
		if !p.Bootstrap && len(p.Base.JSON) > 0 {
			if err := json.Unmarshal(p.Base.JSON, &baseSnapshot); err != nil {
				return Envelope{}, fmt.Errorf("event: unmarshal base snapshot: %w", err)
			}
		}
		d := Diff(baseSnapshot, canon, p.Bootstrap)
		diffVal = &d
		env.State.BaseSnapshotID = d.BaseSnapshotID
	}

	if p.Payload == PayloadSnapshot || p.Payload == PayloadBoth {
		body, err := json.Marshal(canon)
		if err != nil {
			return Envelope{}, fmt.Errorf("event: marshal snapshot: %w", err)
		}
		env.Snapshot = body
	}
	if diffVal != nil {
		body, err := json.Marshal(diffVal)
		if err != nil {
			return Envelope{}, fmt.Errorf("event: marshal diff: %w", err)
		}
		env.Diff = body
	}

	return env, nil
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func nonNilRuns(in []WireDeliveryRun) []WireDeliveryRun {
	if in == nil {
		return []WireDeliveryRun{}
	}
	return in
}

// FinalizeEnvelope renders env to deterministic JSON bytes, checks the
// §38 size cap, and — if it's too large — replaces it with a bounded
// metadata-only envelope instead (never a truncated entity list).
// cursor never advances for either an unavailable or oversized event —
// callers must not pass Authoritative=true through EnqueueBatch's
// draft for one (BuildEnvelope's own Available=false branch already
// forces Authoritative=false; the oversized case is handled here since
// it can only be discovered after marshaling).
func FinalizeEnvelope(env Envelope) ([]byte, ErrorClass, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, "", fmt.Errorf("event: marshal envelope: %w", err)
	}
	if len(body) <= MaxPayloadBytes {
		return body, "", nil
	}

	meta := env
	meta.Snapshot = nil
	meta.Diff = nil
	meta.State.Available = false
	meta.State.Authoritative = false
	meta.State.ErrorClass = string(ErrorClassPayloadTooLarge)
	meta.State.SnapshotID = ""
	meta.State.BaseSnapshotID = ""
	metaBody, err := json.Marshal(meta)
	if err != nil {
		return nil, "", fmt.Errorf("event: marshal oversized fallback envelope: %w", err)
	}
	if len(metaBody) > MaxUnavailableEventBytes {
		return nil, "", fmt.Errorf("event: metadata-only fallback envelope itself exceeds %d bytes (%d) — operation metadata is unexpectedly large", MaxUnavailableEventBytes, len(metaBody))
	}
	return metaBody, ErrorClassPayloadTooLarge, nil
}
