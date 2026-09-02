package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// AlertmanagerPayload is the alert body shape Alertmanager's POST
// /api/v2/alerts expects — one element per alert (spec §22).
type AlertmanagerPayload struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    string            `json:"startsAt"`
	EndsAt      string            `json:"endsAt"`
}

// alertmanagerRefreshWindow and alertmanagerEndsAtHorizon implement the
// refresh cadence from spec §22.1: refresh every 60s, endsAt = now+180s.
const (
	alertmanagerEndsAtHorizon = 180 * time.Second
)

// buildAlertPayload implements spec §9.8's generic alert label set: every
// alert always carries pilot_subject/pilot_subject_kind; a managed_host
// subject ADDITIONALLY keeps the legacy pilot_host label (so existing
// Alertmanager routes/silences keyed on pilot_host keep matching), and any
// other kind additionally carries pilot_target (spec §9.8: "SNMP/external
// target SHOULD 額外保留 pilot_target=<subject_id>" — generalized here to
// every non-managed-host kind, not just literally "snmp").
func buildAlertPayload(subjectID, subjectKind, site, severity, signalID string, score, confidence float64, categoryHint string, contributors []Contributor, profile string, startsAt, now time.Time) AlertmanagerPayload {
	top := make([]string, 0, len(contributors))
	for _, c := range contributors {
		top = append(top, c.Feature)
	}
	topJSON, _ := json.Marshal(top)
	labels := map[string]string{
		"alertname":          "PilotAdaptiveAnomaly",
		"source":             "detection-engine",
		"pilot_subject":      subjectID,
		"pilot_subject_kind": subjectKind,
		"site":               site,
		"severity":           severity,
	}
	if subjectKind == SubjectKindManagedHost {
		labels["pilot_host"] = subjectID
	} else {
		labels["pilot_target"] = subjectID
	}
	return AlertmanagerPayload{
		Labels: labels,
		Annotations: map[string]string{
			"signal_id":        signalID,
			"score":            formatFloat(score),
			"confidence":       formatFloat(confidence),
			"category_hint":    categoryHint,
			"top_contributors": string(topJSON),
			"profile":          profile,
		},
		StartsAt: startsAt.UTC().Format(time.RFC3339),
		EndsAt:   now.Add(alertmanagerEndsAtHorizon).UTC().Format(time.RFC3339),
	}
}

// Engine wires the source client, feature profile, per-host baseline/
// lifecycle state, and the SQLite store into one repeatable detection
// cycle (spec §10.1's Stage A-1 data flow: Thanos source -> normalize ->
// baseline/cohort -> lifecycle -> SQLite/outbox).
type Engine struct {
	Profile   FeatureProfile
	Source    *ThanosClient
	Baselines *HostBaselineStore
	Store     *Store
	// Cohorts assigns each known subject to a cohort (spec §17's
	// detection_cohort metadata); a host absent from this map has no
	// cohort and cohort-outlier-v1 is not applicable for it.
	Cohorts map[string]string

	// Provider is nil for Stage A (provider disabled): every host is then
	// fused via FuseLocalOnly, byte-identical to pre-Stage-B behavior. It
	// is a *ManagedProvider for a single-protocol deployment, or a
	// *FallbackProvider composing two of them (spec1.md §35's alternate-
	// backend fallback) — both satisfy ModelProvider and circuitReporter.
	// ProviderProtocol labels observability output ("openai-responses" |
	// "ollama-chat" | "flm"); RateLimiter is the global token bucket
	// (spec §35), also nil-safe (nil == unlimited, used only when
	// Provider is nil).
	Provider         ModelProvider
	ProviderProtocol string
	RateLimiter      *RateLimiter

	// LastModelStats is this Engine's most recent RunCycle's model-
	// provider observability (spec §37/§38) — always the zero value while
	// Provider is nil.
	LastModelStats ModelCycleStats

	// LogSource is nil when the log pipeline is disabled (spec1.md's log
	// detectors are an OPTIONAL third peer to baseline/cohort — the
	// original detection-engine spec's own Non-Goals excludes logs
	// entirely, so every existing Stage A/B behavior must stay
	// byte-identical when this is nil). LogQuery is a raw LogQL selector
	// (spec1.md §14) — this package does not assume any particular label
	// scheme beyond requiring a `pilot_host` (and optional `site`/`level`)
	// label on the returned streams, since it groups lines by whichever
	// host each stream's labels name, not by a pre-known host list.
	LogSource         *LokiClient
	LogQuery          string
	LogCurrentWindow  time.Duration
	LogBaselineWindow time.Duration

	lifecycles map[string]*HostLifecycle
}

// NewEngine constructs an Engine with empty runtime state.
func NewEngine(profile FeatureProfile, source *ThanosClient, store *Store, cohorts map[string]string) *Engine {
	return &Engine{
		Profile:    profile,
		Source:     source,
		Baselines:  NewHostBaselineStore(),
		Store:      store,
		Cohorts:    cohorts,
		lifecycles: map[string]*HostLifecycle{},
	}
}

// baselineSampleRecord fills a BaselineSampleRecord for this Engine's
// profile-fixed subject kind (spec §9.7) — every subject discovered by one
// Engine shares the same Kind (Engine.Profile.EffectiveIdentity().Kind),
// so it never needs to vary per call site.
func (e *Engine) baselineSampleRecord(subjectID, site, feature string, bucketTS int64, value float64) BaselineSampleRecord {
	kind := e.Profile.EffectiveIdentity().Kind
	pilotHost := ""
	if kind == SubjectKindManagedHost {
		pilotHost = subjectID
	}
	return BaselineSampleRecord{
		SubjectID: subjectID, SubjectKind: kind, Site: site, PilotHost: pilotHost,
		Feature: feature, BucketTS: bucketTS, Value: value,
	}
}

func (e *Engine) lifecycleFor(host string) *HostLifecycle {
	lc, ok := e.lifecycles[host]
	if !ok {
		lc = NewHostLifecycle()
		e.lifecycles[host] = lc
	}
	return lc
}

// HostCycleOutcome is one host's result from a single RunCycle call,
// returned for observability/metrics — RunCycle itself already persisted
// any lifecycle transition.
type HostCycleOutcome struct {
	Host       string
	Valid      bool
	LocalScore LocalScoreResult
	// Fused is the score/category/contributors actually used to advance
	// the lifecycle this cycle (spec §19): equal to LocalScore when the
	// provider is disabled/unavailable/insufficient_data, model-escalated
	// otherwise. Zero value when Valid is false.
	Fused      FusedResult
	Transition Transition
}

// RunCycle executes one full evaluation cycle at evaluationTime across
// every feature in the profile, for every subject the Thanos query
// discovers. It queries each feature once (an instant query already
// covers every subject via the profile's `by (pilot_host, site)` PromQL),
// classifies samples per spec §13, scores baseline/cohort per §15/§17,
// advances each valid host's lifecycle per §20, and persists any
// resulting transition atomically per §25 — including queuing the
// Alertmanager outbox rows for that transition. It deliberately does not
// call HostLifecycle.Advance for a host whose cycle was invalid (spec
// §20.7).
func (e *Engine) RunCycle(ctx context.Context, evaluationTime int64) ([]HostCycleOutcome, error) {
	identity := e.Profile.EffectiveIdentity()
	maxSampleAge := e.Profile.MaxSampleAge()
	futureSkew := e.Profile.FutureSkewTolerance()

	perHost := map[SeriesKey]map[string]FeatureSampleResult{}
	siteByHost := map[string]string{}
	cohortByHost := map[string]string{}

	for _, feature := range e.Profile.Features {
		metrics, samples, err := e.Source.InstantQuery(ctx, feature.PromQL, evaluationTime)
		if err != nil {
			return nil, fmt.Errorf("query feature %s: %w", feature.Name, err)
		}
		grouped, cohorts := GroupSamplesByKey(metrics, samples, identity)
		for key, raw := range grouped {
			value, validity := ClassifySample(raw, evaluationTime, feature, maxSampleAge, futureSkew)
			if perHost[key] == nil {
				perHost[key] = map[string]FeatureSampleResult{}
			}
			perHost[key][feature.Name] = FeatureSampleResult{Feature: feature.Name, Value: value, Validity: validity}
			siteByHost[key.PilotHost] = key.Site
			if identity.CohortLabel != "" {
				if c, ok := cohorts[key]; ok {
					cohortByHost[key.PilotHost] = c
				}
			}
		}
	}

	// Build cohort snapshots from every host with at least one valid
	// reading this cycle, regardless of whether its OWN cycle is valid —
	// a peer contributes its valid features even on a cycle where one of
	// its OTHER (unrelated) required features was invalid.
	hosts := make([]string, 0, len(siteByHost))
	for host := range siteByHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	var snapshots []HostCycleSnapshot
	for _, host := range hosts {
		key := SeriesKey{PilotHost: host, Site: siteByHost[host]}
		// spec §9.6: a profile with its own cohortLabel gets cohort
		// membership from the compiler-controlled label on the sample
		// itself (rule 4: missing label means no cohort, never a fallback
		// guess); a profile with no cohortLabel keeps the pre-Phase-4
		// static e.Cohorts lookup unchanged.
		cohort := e.Cohorts[host]
		if identity.CohortLabel != "" {
			cohort = cohortByHost[host]
		}
		snapshots = append(snapshots, HostCycleSnapshot{
			Host:    host,
			Cohort:  cohort,
			Current: ValidCurrentValues(perHost[key]),
		})
	}

	currentLogByHost, baselineLogByHost, logScale := e.queryLogWindows(ctx, evaluationTime)

	type pendingHost struct {
		snap  HostCycleSnapshot
		site  string
		local LocalScoreResult
	}

	var outcomes []HostCycleOutcome
	var pending []pendingHost
	var baselineSamples []BaselineSampleRecord
	for _, snap := range snapshots {
		key := SeriesKey{PilotHost: snap.Host, Site: siteByHost[snap.Host]}
		results := perHost[key]
		valid := HostCycleValid(e.Profile, results)

		outcome := HostCycleOutcome{Host: snap.Host, Valid: valid}
		if !valid {
			outcomes = append(outcomes, outcome)
			continue // spec §20.7: invalid cycle advances nothing
		}

		history := map[string][]float64{}
		for name := range snap.Current {
			history[name] = e.Baselines.History(snap.Host, name)
		}
		baselineResult := ComputeBaselineHostScore(e.Profile, history, snap.Current)
		cohortResult := ComputeCohortHostScore(e.Profile, snap, snapshots)
		logResult := HostFeatureScoreResult{Valid: false}
		if currentLogByHost != nil {
			logResult = ComputeLogHostScore(currentLogByHost[snap.Host], baselineLogByHost[snap.Host], logScale)
		}
		local := ComputeLocalScore(baselineResult, cohortResult, logResult)
		outcome.LocalScore = local

		if !local.Valid {
			// This host will never reach `pending`, so the usual
			// post-Advance Observe/Evict step below never runs for it
			// either — a real cold-start deadlock without this: baseline
			// only ever becomes Valid after 120 buckets of history (spec
			// §14.1), production wires no cohort assignment at all
			// (Cohorts is always nil, so cohort-outlier-v1 is
			// permanently Valid=false), and the log source is commonly
			// disabled — so local.Valid could otherwise never become
			// true even once, and the detector that's supposed to warm
			// baseline up could never run. Seed history here using the
			// lifecycle's current (pre-this-cycle) state and the raw
			// local score (0 when nothing is Valid — trivially "below
			// threshold", exactly ShouldUpdateBaseline's "no signal yet,
			// treat as normal enough to learn from" case).
			lc := e.lifecycleFor(snap.Host)
			if ShouldUpdateBaseline(lc.State, local.Score, true) {
				bucketTS := BucketOf(evaluationTime)
				for name, value := range snap.Current {
					e.Baselines.Observe(snap.Host, name, evaluationTime, value)
					baselineSamples = append(baselineSamples, e.baselineSampleRecord(snap.Host, siteByHost[snap.Host], name, bucketTS, value))
				}
			}
			for name := range snap.Current {
				e.Baselines.Evict(snap.Host, name, evaluationTime)
			}

			outcomes = append(outcomes, outcome)
			continue // both detectors invalid -> host cycle invalid (spec §18)
		}

		outcomes = append(outcomes, outcome)
		pending = append(pending, pendingHost{snap: snap, site: key.Site, local: local})
	}

	// Model-assisted fusion (spec §19/§35): disabled/unavailable candidates
	// and every non-candidate host fuse to local-only, byte-identical to
	// Stage A. Only score>=CandidateThreshold hosts ever reach the
	// provider, batched and rate/circuit-limited.
	fused := make(map[string]FusedResult, len(pending))
	var candidates []Candidate
	for _, ph := range pending {
		if e.Provider != nil && IsCandidate(ph.local.Score) {
			candidates = append(candidates, Candidate{
				Subject:    SubjectKey{ID: ph.snap.Host, Kind: identity.Kind, Site: ph.site},
				LocalScore: ph.local, Current: ph.snap.Current,
			})
			continue
		}
		fused[ph.snap.Host] = FuseLocalOnly(ph.local)
	}
	if e.Provider != nil {
		e.LastModelStats = e.scoreCandidatesWithProvider(ctx, candidates, evaluationTime, fused)
	} else {
		e.LastModelStats = ModelCycleStats{}
	}

	// Advance lifecycle for every pending host, in the same deterministic
	// order as before, using its fused (not raw local) score/category —
	// baseline learning below still uses the RAW local score, since a
	// model's influence must never bias the statistical baseline itself.
	outcomeIdx := make(map[string]int, len(outcomes))
	for i, o := range outcomes {
		outcomeIdx[o.Host] = i
	}
	for _, ph := range pending {
		fr := fused[ph.snap.Host]
		lc := e.lifecycleFor(ph.snap.Host)
		transition := lc.Advance(fr.Score)

		idx := outcomeIdx[ph.snap.Host]
		outcomes[idx].Fused = fr
		outcomes[idx].Transition = transition

		if err := e.persistTransition(ph.snap.Host, ph.site, fr, transition, evaluationTime); err != nil {
			return outcomes, fmt.Errorf("persist transition for %s: %w", ph.snap.Host, err)
		}

		if ShouldUpdateBaseline(lc.State, ph.local.Score, true) {
			bucketTS := BucketOf(evaluationTime)
			for name, value := range ph.snap.Current {
				e.Baselines.Observe(ph.snap.Host, name, evaluationTime, value)
				baselineSamples = append(baselineSamples, e.baselineSampleRecord(ph.snap.Host, ph.site, name, bucketTS, value))
			}
		}
		for name := range ph.snap.Current {
			e.Baselines.Evict(ph.snap.Host, name, evaluationTime)
		}
	}
	if len(baselineSamples) > 0 {
		// Best-effort: a persistence hiccup here must never fail the
		// cycle — the in-memory Observe already happened, so this
		// cycle's own scoring is already correct either way (same
		// "degrade silently" convention the optional log source uses).
		_ = e.Store.SaveBaselineSamples(baselineSamples, evaluationTime)
	}
	return outcomes, nil
}

// persistTransition maps one lifecycle Transition onto the SQLite
// episode/history/outbox write (spec §25) and, for warning->critical
// escalation, enqueues the two outbox rows in the resolve-then-fire order
// spec §22.2 requires. `fused` is the score/category/contributors that
// actually drove this transition — local-only for Stage A/non-candidates,
// model-escalated per spec §19 otherwise.
func (e *Engine) persistTransition(host, site string, fused FusedResult, tr Transition, evaluationTime int64) error {
	local := fused
	if tr.Action == ActionNone {
		return nil
	}
	now := time.Unix(evaluationTime, 0).UTC()
	kind := e.Profile.EffectiveIdentity().Kind
	fingerprint := Fingerprint(host, kind, site, e.Profile.ID, e.Profile.Version)
	pilotHost := ""
	if kind == SubjectKindManagedHost {
		pilotHost = host
	}

	switch tr.Action {
	case ActionCreateWarning, ActionCreateCritical:
		signalID, err := NewULID()
		if err != nil {
			return err
		}
		episode := EpisodeRecord{
			SignalID: signalID, Fingerprint: fingerprint,
			SubjectID: host, SubjectKind: kind, PilotHost: pilotHost, Site: site,
			ProfileID: e.Profile.ID, ProfileVersion: e.Profile.Version,
			State: string(StateFiring), Severity: string(tr.Severity), CategoryHint: local.Category,
			CreatedAt: now, UpdatedAt: now, Revision: 1,
			LastScore: &local.Score,
		}
		payload, _ := json.Marshal(buildAlertPayload(host, kind, site, string(tr.Severity), signalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, now, now))
		outboxID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: signalID, Revision: 1, EventType: string(tr.Action), PayloadJSON: string(payload), CreatedAt: now},
			[]OutboxRecord{{ID: outboxID, SignalID: signalID, Revision: 1, Sequence: 1, Kind: "fire", PayloadJSON: string(payload), NextAttemptAt: now}},
		)

	case ActionEscalateCritical:
		existing, err := e.Store.GetEpisodeByFingerprint(fingerprint)
		if err != nil || existing == nil {
			return fmt.Errorf("escalate: no active episode for fingerprint (host=%s): %w", host, err)
		}
		revision := existing.Revision + 1
		episode := *existing
		episode.Severity = string(SeverityCritical)
		episode.CategoryHint = local.Category
		episode.UpdatedAt = now
		episode.Revision = revision
		episode.LastScore = &local.Score

		resolvePayload, _ := json.Marshal(buildAlertPayload(host, kind, site, string(SeverityWarning), existing.SignalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, existing.CreatedAt, now))
		firePayload, _ := json.Marshal(buildAlertPayload(host, kind, site, string(SeverityCritical), existing.SignalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, now, now))
		resolveID, err := NewULID()
		if err != nil {
			return err
		}
		fireID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: existing.SignalID, Revision: revision, EventType: string(tr.Action), PayloadJSON: string(firePayload), CreatedAt: now},
			[]OutboxRecord{
				{ID: resolveID, SignalID: existing.SignalID, Revision: revision, Sequence: 1, Kind: "resolve_warning", PayloadJSON: string(resolvePayload), NextAttemptAt: now},
				{ID: fireID, SignalID: existing.SignalID, Revision: revision, Sequence: 2, Kind: "fire_critical", PayloadJSON: string(firePayload), NextAttemptAt: now},
			},
		)

	case ActionEnterRecovering, ActionReturnToFiring:
		existing, err := e.Store.GetEpisodeByFingerprint(fingerprint)
		if err != nil || existing == nil {
			return fmt.Errorf("%s: no active episode for fingerprint (host=%s): %w", tr.Action, host, err)
		}
		revision := existing.Revision + 1
		episode := *existing
		episode.State = string(tr.ToState)
		episode.Severity = string(tr.Severity)
		episode.UpdatedAt = now
		episode.Revision = revision
		episode.LastScore = &local.Score
		payload, _ := json.Marshal(buildAlertPayload(host, kind, site, string(tr.Severity), existing.SignalID, local.Score, 1, local.Category, local.Contributors, e.Profile.ID, existing.CreatedAt, now))
		outboxID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: existing.SignalID, Revision: revision, EventType: string(tr.Action), PayloadJSON: string(payload), CreatedAt: now},
			[]OutboxRecord{{ID: outboxID, SignalID: existing.SignalID, Revision: revision, Sequence: 1, Kind: "refresh", PayloadJSON: string(payload), NextAttemptAt: now}},
		)

	case ActionResolve:
		existing, err := e.Store.GetEpisodeByFingerprint(fingerprint)
		if err != nil || existing == nil {
			return fmt.Errorf("resolve: no active episode for fingerprint (host=%s): %w", host, err)
		}
		revision := existing.Revision + 1
		episode := *existing
		episode.State = "resolved"
		episode.Severity = ""
		episode.UpdatedAt = now
		episode.Revision = revision
		payload, _ := json.Marshal(map[string]any{"signal_id": existing.SignalID, "pilot_subject": host, "pilot_subject_kind": kind, "pilot_host": pilotHost, "site": site})
		outboxID, err := NewULID()
		if err != nil {
			return err
		}
		return e.Store.ApplyTransition(episode,
			HistoryRecord{SignalID: existing.SignalID, Revision: revision, EventType: string(tr.Action), PayloadJSON: string(payload), CreatedAt: now},
			[]OutboxRecord{{ID: outboxID, SignalID: existing.SignalID, Revision: revision, Sequence: 1, Kind: "resolve", PayloadJSON: string(payload), NextAttemptAt: now}},
		)
	}
	return nil
}
