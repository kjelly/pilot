// Package detection implements the Pilot Detection Engine's Stage A core:
// Thanos ingestion, robust/cohort statistical anomaly detection, SignalEvent
// lifecycle, SQLite persistence, and an Alertmanager delivery outbox. See
// docs/superpowers/specs/2026-08-28-detection-engine-spec.md for the
// normative spec this package implements.
package detection

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"sort"
	"time"

	"go.yaml.in/yaml/v3"
)

// Feature is one row of the MVP feature profile (spec §12).
type Feature struct {
	Name       string  `yaml:"name"`
	Required   bool    `yaml:"required"`
	Category   string  `yaml:"category"`
	ScaleFloor float64 `yaml:"scaleFloor"`
	Cohort     bool    `yaml:"cohort"`
	// Warning controls whether this feature can authorize a warning on its
	// own. Nil preserves the historical default (allowed); false keeps the
	// feature available as supporting evidence only.
	Warning *bool `yaml:"warning,omitempty"`
	// WarningMinValue is an optional absolute floor applied after the
	// statistical detector. A large relative deviation below this floor is
	// retained as telemetry but cannot open a warning episode.
	WarningMinValue *float64 `yaml:"warningMinValue,omitempty"`
	// WarningRequireAny is an optional corroboration gate. At least one named
	// feature must be present at or above its absolute floor before this
	// feature can authorize a warning.
	WarningRequireAny []FeatureThreshold `yaml:"warningRequireAny,omitempty"`
	// Critical controls whether this feature, on its own, can supply the
	// critical-level evidence to the lifecycle. Nil preserves the historical
	// default (allowed); false requires an independent strong symptom.
	Critical *bool `yaml:"critical,omitempty"`
	// CriticalMinValue is an optional absolute floor. A feature must be both
	// statistically anomalous and at/above this value before it can authorize
	// a critical lifecycle transition. Nil preserves historical behavior.
	CriticalMinValue *float64 `yaml:"criticalMinValue,omitempty"`
	ValidMin         float64  `yaml:"validMin"`
	ValidMax         float64  `yaml:"validMax"`
	PromQL           string   `yaml:"promql"`
}

// FeatureThreshold is one absolute corroborating metric floor used by a
// feature's warning policy.
type FeatureThreshold struct {
	Feature  string  `yaml:"feature"`
	MinValue float64 `yaml:"minValue"`
}

// NotifyPolicy selects the operator-facing destination for each severity.
// dashboard/digest remain visible to non-paging consumers; teams is reserved
// for alerts that explicitly require operator action.
type NotifyPolicy struct {
	Warning           string `yaml:"warning,omitempty"`
	Critical          string `yaml:"critical,omitempty"`
	RunbookURL        string `yaml:"runbookURL,omitempty"`
	RecommendedAction string `yaml:"recommendedAction,omitempty"`
}

// IdentityProfile names which PromQL result label identifies a subject for
// this feature profile (spec §9.3) — generalizing the historical hard-coded
// assumption that every subject is a `pilot_host`-labeled managed Linux
// host. Kind becomes the subject's SubjectKey.Kind and the persisted
// subject_kind column/label everywhere a SignalEvent from this profile
// flows; it is never inferred from the label VALUE, only fixed per profile.
type IdentityProfile struct {
	Label       string `yaml:"label"`
	Kind        string `yaml:"kind"`
	SiteLabel   string `yaml:"siteLabel"`
	CohortLabel string `yaml:"cohortLabel,omitempty"`
}

// SamplingProfile overrides the classification windows spec §13 originally
// hard-coded as global constants (45s/5s) — a profile whose PromQL source
// has different natural staleness (e.g. an SNMP device polled less
// frequently than a Linux node_exporter scrape) needs its own tolerance,
// not the Linux-host-tuned default.
type SamplingProfile struct {
	MaxSampleAge        string `yaml:"maxSampleAge,omitempty"`
	FutureSkewTolerance string `yaml:"futureSkewTolerance,omitempty"`
}

// defaultMaxSampleAge/defaultFutureSkewTolerance are spec §9.3's
// backward-compatible defaults — identical to the pre-Phase-4 hard-coded
// maxSampleAgeSeconds/futureSkewToleranceSeconds constants, so a profile
// that never sets `sampling` behaves byte-identically to before.
const (
	defaultMaxSampleAge        = "45s"
	defaultFutureSkewTolerance = "5s"
)

func defaultIdentityProfile() IdentityProfile {
	return IdentityProfile{Label: "pilot_host", Kind: SubjectKindManagedHost, SiteLabel: "site"}
}

// EffectiveIdentity returns p.Identity with spec §9.3's managed-host
// defaults filled in for any field a profile YAML left unset — so a
// profile constructed without an explicit `identity:` block (every
// existing linux-host fixture, and any FeatureProfile{} built directly in
// a test) behaves exactly as it did before this field existed.
func (p FeatureProfile) EffectiveIdentity() IdentityProfile {
	id := p.Identity
	def := defaultIdentityProfile()
	if id.Label == "" {
		id.Label = def.Label
	}
	if id.Kind == "" {
		id.Kind = def.Kind
	}
	if id.SiteLabel == "" {
		id.SiteLabel = def.SiteLabel
	}
	return id
}

// EffectiveSampling returns p.Sampling with spec §9.3's defaults filled in.
func (p FeatureProfile) EffectiveSampling() SamplingProfile {
	s := p.Sampling
	if s.MaxSampleAge == "" {
		s.MaxSampleAge = defaultMaxSampleAge
	}
	if s.FutureSkewTolerance == "" {
		s.FutureSkewTolerance = defaultFutureSkewTolerance
	}
	return s
}

// MaxSampleAge parses EffectiveSampling().MaxSampleAge, falling back to the
// spec §9.3 default if the profile was constructed with an invalid string
// bypassing Validate (e.g. directly in a test).
func (p FeatureProfile) MaxSampleAge() time.Duration {
	if d, err := time.ParseDuration(p.EffectiveSampling().MaxSampleAge); err == nil {
		return d
	}
	d, _ := time.ParseDuration(defaultMaxSampleAge)
	return d
}

// FutureSkewTolerance parses EffectiveSampling().FutureSkewTolerance, with
// the same fallback behavior as MaxSampleAge.
func (p FeatureProfile) FutureSkewTolerance() time.Duration {
	if d, err := time.ParseDuration(p.EffectiveSampling().FutureSkewTolerance); err == nil {
		return d
	}
	d, _ := time.ParseDuration(defaultFutureSkewTolerance)
	return d
}

// FeatureProfile is the parsed contents of a feature-profiles/*.yaml file.
// ID and Version together are part of the SignalEvent fingerprint (spec §21).
type FeatureProfile struct {
	ID        string          `yaml:"id"`
	Version   int             `yaml:"version"`
	Identity  IdentityProfile `yaml:"identity,omitempty"`
	Sampling  SamplingProfile `yaml:"sampling,omitempty"`
	Lifecycle LifecyclePolicy `yaml:"lifecycle,omitempty"`
	Notify    NotifyPolicy    `yaml:"notify,omitempty"`
	// NotifyByCategory lets an operator route/explain one resource category
	// (e.g. "storage", "thermal") differently than the profile-wide Notify
	// default — a runbook written for a CPU baseline alert rarely tells an
	// on-call responder anything useful about a disk saturation alert. Each
	// entry only needs to set the fields it wants to override; any field left
	// empty falls back to the profile-wide default (EffectiveNotifyPolicy),
	// never to the NotifyPolicy zero value. A category with no entry here
	// behaves exactly as before this field existed.
	NotifyByCategory map[string]NotifyPolicy `yaml:"notifyByCategory,omitempty"`
	Features         []Feature               `yaml:"features"`
}

// EffectiveNotifyPolicy fills omitted destinations with the safe default:
// warnings remain dashboard-visible without paging, while critical episodes
// are actionable Teams notifications.
func (p FeatureProfile) EffectiveNotifyPolicy() NotifyPolicy {
	n := p.Notify
	if n.Warning == "" {
		n.Warning = "dashboard"
	}
	if n.Critical == "" {
		n.Critical = "teams"
	}
	if n.RunbookURL == "" {
		n.RunbookURL = "docs/runbooks/detection-engine.md"
	}
	return n
}

// EffectiveNotifyPolicyForCategory resolves EffectiveNotifyPolicy and then
// overlays any category-specific override from NotifyByCategory. Only the
// fields an operator actually set on the override are applied — an override
// that sets only runbookURL still inherits warning/critical/recommendedAction
// from the profile-wide default. An empty or "composite_resource" category (a
// local detector spanning more than one resource category, see
// buildAlertEvidence) always resolves to the profile-wide default, since no
// single category owns that alert.
func (p FeatureProfile) EffectiveNotifyPolicyForCategory(category string) NotifyPolicy {
	effective := p.EffectiveNotifyPolicy()
	if category == "" || category == "composite_resource" {
		return effective
	}
	override, ok := p.NotifyByCategory[category]
	if !ok {
		return effective
	}
	if override.Warning != "" {
		effective.Warning = override.Warning
	}
	if override.Critical != "" {
		effective.Critical = override.Critical
	}
	if override.RunbookURL != "" {
		effective.RunbookURL = override.RunbookURL
	}
	if override.RecommendedAction != "" {
		effective.RecommendedAction = override.RecommendedAction
	}
	return effective
}

// Categories returns the sorted, de-duplicated set of categories declared by
// this profile's features.
func (p FeatureProfile) Categories() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range p.Features {
		if f.Category == "" || seen[f.Category] {
			continue
		}
		seen[f.Category] = true
		out = append(out, f.Category)
	}
	sort.Strings(out)
	return out
}

// hasCategory reports whether any feature in this profile declares category.
func (p FeatureProfile) hasCategory(category string) bool {
	for _, f := range p.Features {
		if f.Category == category {
			return true
		}
	}
	return false
}

// EffectiveLifecyclePolicy fills omitted fields with the legacy lifecycle
// values so a profile without lifecycle: remains backward compatible.
func (p FeatureProfile) EffectiveLifecyclePolicy() LifecyclePolicy {
	return p.Lifecycle.Effective()
}

// LifecycleScore returns the policy-constrained value sent to the lifecycle.
// The raw fused score remains available for alert evidence and baseline
// contamination protection. A critical:false feature can still produce a
// warning, but cannot alone create or escalate a critical episode. A
// critical-eligible contributor must be at warning strength and, when it
// declares criticalMinValue, meet that absolute current-value floor.
func (p FeatureProfile) LifecycleScore(fused FusedResult, current map[string]float64) float64 {
	if fused.Score >= WarningThreshold {
		warningAuthorized := false
		for _, contributor := range fused.Contributors {
			if contributor.Score < WarningThreshold {
				continue
			}
			feature, found := p.Feature(contributor.Feature)
			if !found || feature.allowsWarning(current) {
				warningAuthorized = true
				break
			}
		}
		if !warningAuthorized {
			return math.Nextafter(WarningThreshold, 0)
		}
	}
	if fused.Score < CriticalThreshold {
		return fused.Score
	}

	blockedCritical := false
	for _, contributor := range fused.Contributors {
		if contributor.Score < WarningThreshold {
			continue
		}
		feature, found := p.Feature(contributor.Feature)
		if !found || ((feature.Critical == nil || *feature.Critical) && feature.allowsWarning(current)) {
			if feature.CriticalMinValue != nil {
				value, present := current[contributor.Feature]
				if !present || value < *feature.CriticalMinValue {
					blockedCritical = true
					continue
				}
			}
			return fused.Score
		}
		blockedCritical = true
	}
	if blockedCritical {
		return math.Nextafter(CriticalThreshold, 0)
	}
	return fused.Score
}

func (f Feature) allowsWarning(current map[string]float64) bool {
	if f.Warning != nil && !*f.Warning {
		return false
	}
	if f.WarningMinValue != nil {
		value, present := current[f.Name]
		if !present || value < *f.WarningMinValue {
			return false
		}
	}
	if len(f.WarningRequireAny) == 0 {
		return true
	}
	for _, requirement := range f.WarningRequireAny {
		if value, present := current[requirement.Feature]; present && value >= requirement.MinValue {
			return true
		}
	}
	return false
}

// LoadFeatureProfile parses and validates a feature profile file.
func LoadFeatureProfile(path string) (FeatureProfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return FeatureProfile{}, fmt.Errorf("read feature profile %s: %w", path, err)
	}
	return ParseFeatureProfile(data)
}

// ParseFeatureProfile parses and validates feature profile YAML content.
func ParseFeatureProfile(data []byte) (FeatureProfile, error) {
	var p FeatureProfile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return FeatureProfile{}, fmt.Errorf("decode feature profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return FeatureProfile{}, err
	}
	return p, nil
}

// Validate checks the static shape invariants a feature profile must hold
// regardless of which features a deployment enables.
func (p FeatureProfile) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("feature profile: id is required")
	}
	if p.Version < 1 {
		return fmt.Errorf("feature profile: version must be >= 1")
	}
	if len(p.Features) == 0 {
		return fmt.Errorf("feature profile: at least one feature is required")
	}
	if err := p.Lifecycle.Validate(); err != nil {
		return fmt.Errorf("feature profile: lifecycle: %w", err)
	}
	allowedDestinations := map[string]bool{"none": true, "dashboard": true, "digest": true, "teams": true}
	notify := p.EffectiveNotifyPolicy()
	if !allowedDestinations[notify.Warning] {
		return fmt.Errorf("feature profile: notify.warning %q is not one of none, dashboard, digest, teams", notify.Warning)
	}
	if !allowedDestinations[notify.Critical] {
		return fmt.Errorf("feature profile: notify.critical %q is not one of none, dashboard, digest, teams", notify.Critical)
	}
	for category, override := range p.NotifyByCategory {
		if !p.hasCategory(category) {
			return fmt.Errorf("feature profile: notifyByCategory references unknown category %q", category)
		}
		if override.Warning != "" && !allowedDestinations[override.Warning] {
			return fmt.Errorf("feature profile: notifyByCategory[%q].warning %q is not one of none, dashboard, digest, teams", category, override.Warning)
		}
		if override.Critical != "" && !allowedDestinations[override.Critical] {
			return fmt.Errorf("feature profile: notifyByCategory[%q].critical %q is not one of none, dashboard, digest, teams", category, override.Critical)
		}
	}
	if p.Sampling.MaxSampleAge != "" {
		if _, err := time.ParseDuration(p.Sampling.MaxSampleAge); err != nil {
			return fmt.Errorf("feature profile: sampling.maxSampleAge: %w", err)
		}
	}
	if p.Sampling.FutureSkewTolerance != "" {
		if _, err := time.ParseDuration(p.Sampling.FutureSkewTolerance); err != nil {
			return fmt.Errorf("feature profile: sampling.futureSkewTolerance: %w", err)
		}
	}
	seen := make(map[string]bool, len(p.Features))
	haveRequired := false
	for _, f := range p.Features {
		if f.Name == "" {
			return fmt.Errorf("feature profile: feature with empty name")
		}
		if seen[f.Name] {
			return fmt.Errorf("feature profile: duplicate feature %q", f.Name)
		}
		seen[f.Name] = true
		if f.ValidMin >= f.ValidMax {
			return fmt.Errorf("feature profile: feature %q validMin must be < validMax", f.Name)
		}
		if f.Warning != nil && !*f.Warning && (f.WarningMinValue != nil || len(f.WarningRequireAny) > 0) {
			return fmt.Errorf("feature profile: feature %q cannot set warning gates when warning is false", f.Name)
		}
		if f.WarningMinValue != nil {
			if *f.WarningMinValue < f.ValidMin || *f.WarningMinValue > f.ValidMax {
				return fmt.Errorf("feature profile: feature %q warningMinValue must be within valid range", f.Name)
			}
			if f.CriticalMinValue != nil && *f.CriticalMinValue < *f.WarningMinValue {
				return fmt.Errorf("feature profile: feature %q criticalMinValue must be >= warningMinValue", f.Name)
			}
		}
		if f.CriticalMinValue != nil {
			if f.Critical != nil && !*f.Critical {
				return fmt.Errorf("feature profile: feature %q cannot set criticalMinValue when critical is false", f.Name)
			}
			if *f.CriticalMinValue < f.ValidMin || *f.CriticalMinValue > f.ValidMax {
				return fmt.Errorf("feature profile: feature %q criticalMinValue must be within valid range", f.Name)
			}
		}
		if f.ScaleFloor <= 0 {
			return fmt.Errorf("feature profile: feature %q scaleFloor must be > 0", f.Name)
		}
		if f.PromQL == "" {
			return fmt.Errorf("feature profile: feature %q has no promql", f.Name)
		}
		if f.Required {
			haveRequired = true
		}
	}
	if !haveRequired {
		return fmt.Errorf("feature profile: at least one required feature is needed")
	}
	for _, f := range p.Features {
		for _, requirement := range f.WarningRequireAny {
			if requirement.Feature == "" || requirement.Feature == f.Name {
				return fmt.Errorf("feature profile: feature %q warningRequireAny must name another feature", f.Name)
			}
			requiredFeature, found := p.Feature(requirement.Feature)
			if !found {
				return fmt.Errorf("feature profile: feature %q warningRequireAny references unknown feature %q", f.Name, requirement.Feature)
			}
			if requirement.MinValue < requiredFeature.ValidMin || requirement.MinValue > requiredFeature.ValidMax {
				return fmt.Errorf("feature profile: feature %q warningRequireAny floor for %q must be within its valid range", f.Name, requirement.Feature)
			}
		}
	}
	return nil
}

// RequiredFeatures returns the subset of features marked required.
func (p FeatureProfile) RequiredFeatures() []Feature {
	var out []Feature
	for _, f := range p.Features {
		if f.Required {
			out = append(out, f)
		}
	}
	return out
}

// CohortFeatures returns the subset of features eligible for cohort scoring.
func (p FeatureProfile) CohortFeatures() []Feature {
	var out []Feature
	for _, f := range p.Features {
		if f.Cohort {
			out = append(out, f)
		}
	}
	return out
}

// Feature looks up one feature by name.
func (p FeatureProfile) Feature(name string) (Feature, bool) {
	for _, f := range p.Features {
		if f.Name == name {
			return f, true
		}
	}
	return Feature{}, false
}
