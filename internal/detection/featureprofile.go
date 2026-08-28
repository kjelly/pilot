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

// FeatureProfile is the parsed contents of a feature-profiles/*.yaml file.
// ID and Version together are part of the SignalEvent fingerprint (spec §21).
type FeatureProfile struct {
	ID       string    `yaml:"id"`
	Version  int       `yaml:"version"`
	Features []Feature `yaml:"features"`
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
