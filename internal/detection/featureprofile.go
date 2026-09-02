// Package detection implements the Pilot Detection Engine's Stage A core:
// Thanos ingestion, robust/cohort statistical anomaly detection, SignalEvent
// lifecycle, SQLite persistence, and an Alertmanager delivery outbox. See
// docs/superpowers/specs/2026-08-28-detection-engine-spec.md for the
// normative spec this package implements.
package detection

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Feature is one row of the MVP feature profile (spec §12).
type Feature struct {
	Name       string  `yaml:"name"`
	Required   bool    `yaml:"required"`
	Category   string  `yaml:"category"`
	ScaleFloor float64 `yaml:"scaleFloor"`
	Cohort     bool    `yaml:"cohort"`
	ValidMin   float64 `yaml:"validMin"`
	ValidMax   float64 `yaml:"validMax"`
	PromQL     string  `yaml:"promql"`
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
	ID       string          `yaml:"id"`
	Version  int             `yaml:"version"`
	Identity IdentityProfile `yaml:"identity,omitempty"`
	Sampling SamplingProfile `yaml:"sampling,omitempty"`
	Features []Feature       `yaml:"features"`
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
