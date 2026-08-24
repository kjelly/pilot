// Package monitoring implements spec.md's Monitoring Target Registry: a
// workspace-level description of Prometheus scrape endpoints Pilot does not
// (and must not) manage via Ansible/inventory lifecycle — see spec.md §2 for
// the "Managed Host != Monitoring Target" invariant this whole package
// exists to keep true.
package monitoring

// SchemaVersion is the only schemaVersion this package understands. Both
// monitoring/targets.yml and monitoring/scrape-profiles.yml carry their own
// schemaVersion field (spec.md §7.1/§9) so a future incompatible format can
// be detected explicitly instead of silently misparsed.
const SchemaVersion = 1

// ReservedLabels are label keys the target compiler always sets itself
// (spec.md §8.6) — a user-supplied label under monitoring/targets.yml with
// one of these keys must be rejected by Validate, never silently overwritten.
var ReservedLabels = []string{"pilot_target", "pilot_source"}

// ReservedJobNames are Prometheus job names with existing repo-wide meaning
// (contracts/prometheus.yaml's self-scrape job is "prometheus"; the
// host-monitoring node_exporter scrape job rendered by
// playbooks/apply/prometheus-apply.yml is "node") that a scrape profile must
// not reuse (spec.md §63).
var ReservedJobNames = []string{"prometheus", "node"}

// TargetFile is the parsed form of monitoring/targets.yml (spec.md §7).
type TargetFile struct {
	SchemaVersion int      `yaml:"schemaVersion"`
	Targets       []Target `yaml:"targets"`
}

// Target is one external monitoring target — an address Prometheus should
// scrape that Pilot has no Ansible/SSH relationship with (spec.md §8).
type Target struct {
	Name    string            `yaml:"name"`
	Address string            `yaml:"address"`
	Profile string            `yaml:"profile"`
	Site    string            `yaml:"site,omitempty"`
	Enabled *bool             `yaml:"enabled,omitempty"`
	Labels  map[string]string `yaml:"labels,omitempty"`
}

// IsEnabled reports whether t should be compiled into file_sd output.
// Enabled defaults to true when unset (spec.md §8.5).
func (t Target) IsEnabled() bool {
	return t.Enabled == nil || *t.Enabled
}

// ProfileFile is the parsed form of monitoring/scrape-profiles.yml (spec.md §9).
type ProfileFile struct {
	SchemaVersion int                `yaml:"schemaVersion"`
	Profiles      map[string]Profile `yaml:"profiles"`
}

// Profile is scrape behavior shared by every target that references it by
// name (spec.md §10) — never a place for target-instance data (spec.md §11).
type Profile struct {
	JobName        string     `yaml:"jobName"`
	Scheme         string     `yaml:"scheme,omitempty"`
	MetricsPath    string     `yaml:"metricsPath,omitempty"`
	ScrapeInterval string     `yaml:"scrapeInterval,omitempty"`
	ScrapeTimeout  string     `yaml:"scrapeTimeout,omitempty"`
	AuthRef        string     `yaml:"authRef,omitempty"`
	TLS            *TLSConfig `yaml:"tls,omitempty"`
}

// EffectiveScheme returns p.Scheme, defaulting to "http" (spec.md §10).
func (p Profile) EffectiveScheme() string {
	if p.Scheme == "" {
		return "http"
	}
	return p.Scheme
}

// EffectiveMetricsPath returns p.MetricsPath, defaulting to "/metrics" (spec.md §10).
func (p Profile) EffectiveMetricsPath() string {
	if p.MetricsPath == "" {
		return "/metrics"
	}
	return p.MetricsPath
}

// TLSConfig is a scrape profile's TLS behavior (spec.md §44). CARef is
// accepted in the schema but deliberately never resolved to a filesystem
// path by this package (spec.md §45 — "不能把 arbitrary local path 作為預設
// public schema"); it exists so a future CA-registry integration has a
// stable field to fill in without a schema migration.
type TLSConfig struct {
	CARef              string `yaml:"caRef,omitempty"`
	ServerName         string `yaml:"serverName,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecureSkipVerify,omitempty"`
}

// AuthCredential is one entry of the monitoring_auth secret map (spec.md
// §12/§46) — never persisted to monitoring/targets.yml or
// monitoring/scrape-profiles.yml; supplied only via vault/-e at apply time,
// and here only so `pilot monitoring target test` can authenticate.
type AuthCredential struct {
	Type     string `yaml:"type"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}
