package monitoring

import "sort"

// FileSDEntry is one element of a Prometheus file_sd_configs JSON array
// (spec.md §16) — always one entry per target, never merged, so per-target
// labels never bleed into each other.
type FileSDEntry struct {
	Targets []string          `json:"targets"`
	Labels  map[string]string `json:"labels"`
}

// Compile turns an enabled target's own address/labels plus its profile's
// jobName into the file_sd payload every scrape profile's *.json file
// should contain (spec.md §15/§16; SNMP monitoring integration spec §8.1
// for kind:snmp profiles). The returned map is keyed by jobName (unique
// per Validate) so it can be written straight to "<jobName>.json" per
// spec.md §62. Output ordering is fully deterministic (map iteration is
// never relied on) to satisfy spec.md §72's idempotency requirement — this
// is the Go-side counterpart to playbooks/apply/prometheus-apply.yml's own
// "Render file_sd JSON" task, and MUST stay in parity with it; see
// internal/monitoring/testdata/ golden fixtures and
// internal/spec/prometheus_external_targets_regression_test.go.
//
// localSite is this Prometheus host's own prometheus_site_label. It is
// used ONLY to filter kind:snmp targets (spec §8.1 rule 2: a site-wide
// registry is shared across every site's Prometheus, but each compiles
// only the SNMP targets that belong to it — direct-Prometheus targets have
// no such filter and keep their pre-SNMP behavior unchanged regardless of
// localSite's value, preserving AC1 byte-for-byte).
func Compile(tf TargetFile, pf ProfileFile, localSite string) map[string][]FileSDEntry {
	byJob := map[string][]FileSDEntry{}
	// Every declared profile gets an entry in the map even with zero
	// targets (an empty JSON array is valid file_sd input, and lets a
	// caller GC-detect "this job now has nothing" the same way a
	// non-empty one is detected).
	for _, p := range pf.Profiles {
		if p.JobName != "" {
			byJob[p.JobName] = []FileSDEntry{}
		}
	}

	targets := append([]Target(nil), tf.Targets...)
	sort.Slice(targets, func(i, j int) bool { return targets[i].Name < targets[j].Name })

	for _, t := range targets {
		if !t.IsEnabled() {
			continue
		}
		p, ok := pf.Profiles[t.Profile]
		if !ok || p.JobName == "" {
			continue // Validate should already have rejected this; compile stays defensive, not authoritative.
		}
		if p.IsSNMP() && t.Site != localSite {
			continue // spec §8.1 rule 2/3: SNMP targets are site-scoped, no cross-site fallback.
		}
		var labels map[string]string
		if p.IsSNMP() {
			labels = map[string]string{
				"pilot_target":       t.Name,
				"pilot_source":       "external",
				"pilot_protocol":     "snmp",
				"pilot_subject_kind": p.SubjectKind,
				"site":               t.Site,
			}
			if t.DetectionCohort != "" {
				labels["detection_cohort"] = t.DetectionCohort
			}
		} else {
			labels = map[string]string{
				"pilot_target": t.Name,
				"pilot_source": "external",
			}
			if t.Site != "" {
				labels["site"] = t.Site
			}
		}
		for k, v := range t.Labels {
			labels[k] = v
		}
		byJob[p.JobName] = append(byJob[p.JobName], FileSDEntry{
			Targets: []string{t.Address},
			Labels:  labels,
		})
	}
	return byJob
}

// ResolvedTarget is a target merged with its profile's scrape behavior —
// everything `pilot monitoring target test` (spec.md §29) needs to actually
// connect, without the caller re-deriving effective scheme/metricsPath
// defaults itself.
type ResolvedTarget struct {
	Target      Target
	Profile     Profile
	Scheme      string
	MetricsPath string
}

// Resolve finds targetName in tf, joins it with its profile from pf, and
// returns the effective connection parameters. Returns an error identical
// in shape to what Validate would report, so a caller that skipped Validate
// still gets an actionable message instead of a nil-map panic.
func Resolve(tf TargetFile, pf ProfileFile, targetName string) (ResolvedTarget, bool) {
	for _, t := range tf.Targets {
		if t.Name != targetName {
			continue
		}
		p, ok := pf.Profiles[t.Profile]
		if !ok {
			return ResolvedTarget{}, false
		}
		return ResolvedTarget{
			Target:      t,
			Profile:     p,
			Scheme:      p.EffectiveScheme(),
			MetricsPath: p.EffectiveMetricsPath(),
		}, true
	}
	return ResolvedTarget{}, false
}
