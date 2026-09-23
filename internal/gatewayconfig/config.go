// Package gatewayconfig loads and validates /etc/pilot/access-gateway.yaml
// (docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md
// §26). It lives outside cmd/pilot-access-gateway so the gateway daemon and
// read-only tools such as `pilot access recording show` share one parser
// (per-host recording spec §29) instead of two diverging copies.
package gatewayconfig

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/ingesttoken"
	"gopkg.in/yaml.v3"
)

// DefaultPath is where the gateway playbook installs the config.
const DefaultPath = "/etc/pilot/access-gateway.yaml"

// Config is /etc/pilot/access-gateway.yaml (spec.md §26). Unknown fields
// are rejected — spec.md §26 explicitly forbids roster_file/
// inventory_file/vault_password_file/state_dir/audit_db ever appearing
// here, and KnownFields(true) enforces that for any such field, not just
// those five.
type Config struct {
	Gateway GatewaySection `yaml:"gateway"`
}

// GatewaySection is this gateway instance's immutable identity plus
// runtime settings (spec.md §10.2/§26).
type GatewaySection struct {
	ID              string           `yaml:"id"`
	Scope           string           `yaml:"scope"`
	FQDN            string           `yaml:"fqdn"`
	TargetHostgroup string           `yaml:"target_hostgroup"`
	SocketPath      string           `yaml:"socket_path"`
	PortalUserGroup string           `yaml:"portal_user_group"`
	FreeIPA         FreeIPASection   `yaml:"freeipa"`
	Recording       RecordingSection `yaml:"recording"`
	Metrics         MetricsSection   `yaml:"metrics"`
}

// MetricsSection configures the node_exporter textfile the gateway writes
// (per-host recording spec §31). An empty TextfilePath disables metrics.
type MetricsSection struct {
	TextfilePath string `yaml:"textfile_path"`
}

// RecordingSection configures SSH session recording (per-host recording
// spec §14). Mode is the gateway-wide DEFAULT; a host's FreeIPA
// pilot.policy.ssh-recording marker overrides it per connect. Unset, the
// built-in default is metadata, which never constructs a recorder.
//
// Recording terminal sessions requires a durable session store: when
// SessionStoreURL is set, SessionStoreIngestSigningKeyFile must name the
// PIT1 signing key shared with pilot-session-store, and a terminal Mode
// without a store is a configuration error (there is no local-file
// fallback). The former static session_store_ingest_token_file is gone;
// KnownFields(true) rejects it.
type RecordingSection struct {
	Mode               string   `yaml:"mode"`
	FailurePolicy      string   `yaml:"failure_policy"`
	QueueEvents        int      `yaml:"queue_events"`
	FlushInterval      Duration `yaml:"flush_interval"`
	FailureGrace       Duration `yaml:"failure_grace"`
	MaxSessionDuration Duration `yaml:"max_session_duration"`

	SessionStoreURL                  string `yaml:"session_store_url"`
	SessionStoreCAFile               string `yaml:"session_store_ca_file"`
	SessionStoreIngestSigningKeyFile string `yaml:"session_store_ingest_signing_key_file"`
}

// FreeIPASection configures the read-only internal/freeipaaccess.Client.
//
// cache_ttl/connect_max_age existed here (and in every generated
// access-gateway.yaml) from spec.md §26's original example config, but no
// resolver, client, or connect path in this codebase ever read them —
// internal/accessportal.LoadUserAccess has always hit FreeIPA fresh on
// every call, with no caching layer at any point. Removed 2026-09-16
// rather than left in place misleading operators into believing access
// decisions are cached (they are not — Refresh's whole reason to exist is
// that nothing else ever re-fetches). Reintroducing real caching later is
// a deliberate feature with real revocation-latency trade-offs to weigh,
// not something to half-wire back in under these same field names.
type FreeIPASection struct {
	Servers          []string `yaml:"servers"`
	CAFile           string   `yaml:"ca_file"`
	ServicePrincipal string   `yaml:"service_principal"`
	Keytab           string   `yaml:"keytab"`
	RequestTimeout   Duration `yaml:"request_timeout"`
}

// Duration unmarshals a Go duration string ("5s") from YAML — yaml.v3's
// default time.Duration handling is an integer nanosecond count, not the
// human-readable string spec.md §26's example config uses.
type Duration time.Duration

// UnmarshalYAML parses a Go duration string.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// Defaults.
const (
	DefaultSocketPath     = "/run/pilot/access-gateway.sock"
	DefaultRequestTimeout = 5 * time.Second

	// DefaultRecordingMode is the built-in default: no terminal recording.
	DefaultRecordingMode = "metadata"
	// DefaultRecordingFailurePolicy is fail_closed (per-host recording spec
	// §14): a host an operator marked for recording must never silently
	// continue unrecorded. It has no effect on metadata sessions.
	DefaultRecordingFailurePolicy      = "fail_closed"
	DefaultRecordingQueueEvents        = 1024
	DefaultRecordingFlushInterval      = 500 * time.Millisecond
	DefaultRecordingFailureGrace       = 10 * time.Second
	DefaultRecordingMaxSessionDuration = 24 * time.Hour

	minFailureGrace       = time.Second
	minMaxSessionDuration = time.Hour
	maxMaxSessionDuration = 168 * time.Hour
)

var validRecordingModes = map[string]bool{
	"metadata": true, "terminal_output": true, "terminal_io": true,
}

var validRecordingFailurePolicies = map[string]bool{
	"best_effort": true, "fail_closed": true,
}

// Load reads and validates a gateway config file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		if strings.Contains(err.Error(), "session_store_ingest_token_file") {
			return Config{}, fmt.Errorf("parse config %s: gateway.recording.session_store_ingest_token_file was replaced by session_store_ingest_signing_key_file (per-session ingest tokens): %w", path, err)
		}
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var missing []string
	if c.Gateway.ID == "" {
		missing = append(missing, "gateway.id")
	}
	if c.Gateway.Scope == "" {
		missing = append(missing, "gateway.scope")
	}
	if c.Gateway.FQDN == "" {
		missing = append(missing, "gateway.fqdn")
	}
	if c.Gateway.TargetHostgroup == "" {
		missing = append(missing, "gateway.target_hostgroup")
	}
	if len(c.Gateway.FreeIPA.Servers) == 0 {
		missing = append(missing, "gateway.freeipa.servers")
	}
	if c.Gateway.FreeIPA.CAFile == "" {
		missing = append(missing, "gateway.freeipa.ca_file")
	}
	if c.Gateway.FreeIPA.ServicePrincipal == "" {
		missing = append(missing, "gateway.freeipa.service_principal")
	}
	if c.Gateway.FreeIPA.Keytab == "" {
		missing = append(missing, "gateway.freeipa.keytab")
	}
	if len(missing) > 0 {
		return fmt.Errorf("config missing required fields: %s", strings.Join(missing, ", "))
	}

	rec := c.Gateway.Recording
	if rec.Mode != "" && !validRecordingModes[rec.Mode] {
		return fmt.Errorf("gateway.recording.mode %q is not one of metadata|terminal_output|terminal_io", rec.Mode)
	}
	if rec.FailurePolicy != "" && !validRecordingFailurePolicies[rec.FailurePolicy] {
		return fmt.Errorf("gateway.recording.failure_policy %q is not one of best_effort|fail_closed", rec.FailurePolicy)
	}
	if grace := c.RecordingFailureGrace(); grace < minFailureGrace || grace < 2*c.RecordingFlushInterval() {
		return fmt.Errorf("gateway.recording.failure_grace %s must be >= %s and >= 2x flush_interval (%s)", grace, minFailureGrace, c.RecordingFlushInterval())
	}
	if d := c.RecordingMaxSessionDuration(); d < minMaxSessionDuration || d > maxMaxSessionDuration {
		return fmt.Errorf("gateway.recording.max_session_duration %s must be between %s and %s", d, minMaxSessionDuration, maxMaxSessionDuration)
	}
	if rec.SessionStoreURL != "" {
		if !strings.HasPrefix(rec.SessionStoreURL, "https://") {
			return fmt.Errorf("gateway.recording.session_store_url %q must be an https:// URL", rec.SessionStoreURL)
		}
		if rec.SessionStoreIngestSigningKeyFile == "" {
			return fmt.Errorf("gateway.recording.session_store_url is set but gateway.recording.session_store_ingest_signing_key_file is empty")
		}
	}
	if p := c.Gateway.Metrics.TextfilePath; p != "" && (!filepath.IsAbs(p) || filepath.Ext(p) != ".prom") {
		return fmt.Errorf("gateway.metrics.textfile_path %q must be an absolute path ending in .prom", p)
	}
	if (rec.Mode == "terminal_output" || rec.Mode == "terminal_io") && rec.SessionStoreURL == "" {
		return fmt.Errorf("gateway.recording.mode %q records terminal sessions but gateway.recording.session_store_url is empty (there is no local recording fallback)", rec.Mode)
	}
	return nil
}

// SocketPath returns the gateway API socket path.
func (c Config) SocketPath() string {
	if c.Gateway.SocketPath != "" {
		return c.Gateway.SocketPath
	}
	return DefaultSocketPath
}

// RequestTimeout returns the FreeIPA request timeout.
func (c Config) RequestTimeout() time.Duration {
	if c.Gateway.FreeIPA.RequestTimeout > 0 {
		return time.Duration(c.Gateway.FreeIPA.RequestTimeout)
	}
	return DefaultRequestTimeout
}

// RecordingDefaultModeRaw returns recording.mode exactly as configured ("" when
// unset). Callers resolving the effective per-host mode must use this raw
// value so "unset" (built-in default) stays distinguishable from an
// explicit "metadata" (per-host recording spec §13, F29).
func (c Config) RecordingDefaultModeRaw() string { return c.Gateway.Recording.Mode }

// RecordingFailurePolicy returns the configured failure policy or the
// fail_closed default.
func (c Config) RecordingFailurePolicy() string {
	if c.Gateway.Recording.FailurePolicy != "" {
		return c.Gateway.Recording.FailurePolicy
	}
	return DefaultRecordingFailurePolicy
}

// RecordingQueueEvents returns the recorder queue size.
func (c Config) RecordingQueueEvents() int {
	if c.Gateway.Recording.QueueEvents > 0 {
		return c.Gateway.Recording.QueueEvents
	}
	return DefaultRecordingQueueEvents
}

// RecordingFlushInterval returns the longest an event waits in a batch.
func (c Config) RecordingFlushInterval() time.Duration {
	if c.Gateway.Recording.FlushInterval > 0 {
		return time.Duration(c.Gateway.Recording.FlushInterval)
	}
	return DefaultRecordingFlushInterval
}

// RecordingFailureGrace returns how long pending events may go
// unacknowledged before fail_closed ends a session.
func (c Config) RecordingFailureGrace() time.Duration {
	if c.Gateway.Recording.FailureGrace > 0 {
		return time.Duration(c.Gateway.Recording.FailureGrace)
	}
	return DefaultRecordingFailureGrace
}

// RecordingMaxSessionDuration returns the per-session ingest token lifetime.
func (c Config) RecordingMaxSessionDuration() time.Duration {
	if c.Gateway.Recording.MaxSessionDuration > 0 {
		return time.Duration(c.Gateway.Recording.MaxSessionDuration)
	}
	return DefaultRecordingMaxSessionDuration
}

// RecordingSigningKey loads the PIT1 ingest signing key named by
// session_store_ingest_signing_key_file. It returns (nil, nil) when no
// session store is configured, and an error for a key file that is not 64
// hex characters or is group/world accessible.
func (c Config) RecordingSigningKey() ([]byte, error) {
	if c.Gateway.Recording.SessionStoreURL == "" {
		return nil, nil
	}
	return ingesttoken.LoadKeyFile(c.Gateway.Recording.SessionStoreIngestSigningKeyFile)
}

// MetricsTextfilePath returns the metrics textfile path ("" = disabled).
func (c Config) MetricsTextfilePath() string { return c.Gateway.Metrics.TextfilePath }
