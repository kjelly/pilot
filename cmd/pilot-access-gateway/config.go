package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

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
	Transport       TransportSection `yaml:"transport"`
}

// TransportSection configures the captive opaque SSH transport
// (`pilot-transport-v1`, docs/superpowers/specs/2026-09-23-pilot-access-
// gateway-captive-ssh-transport-spec.md §12.1). A config without a
// transport: block — every config written before this feature — gets
// Enabled == false, so upgrading never silently opens a new data plane.
type TransportSection struct {
	Enabled bool `yaml:"enabled"`
}

// RecordingSection configures Phase 7's PTY session recorder (docs/tmp/
// now/spec.md §23/§27). Every field is optional — the unconditional
// default is Mode "metadata" (D8), which never constructs a recorder at
// all.
//
// SessionStore* (spec.md §28/§34, Phase 8) are also optional: when unset,
// terminal_output/terminal_io recording still works exactly as Phase 7
// shipped it (a local FileSink under the connecting user's own runtime
// directory) — this deployment simply has no durable, encrypted,
// centrally-replayable copy. Per spec.md §35, a Gateway recording
// locally without a configured session store must not be described as
// production-ready for terminal_output/terminal_io; only "metadata" mode
// carries that claim unconditionally.
type RecordingSection struct {
	Mode          string   `yaml:"mode"`
	FailurePolicy string   `yaml:"failure_policy"`
	QueueEvents   int      `yaml:"queue_events"`
	FlushInterval duration `yaml:"flush_interval"`

	SessionStoreURL             string `yaml:"session_store_url"`
	SessionStoreIngestTokenFile string `yaml:"session_store_ingest_token_file"`
	SessionStoreCAFile          string `yaml:"session_store_ca_file"`
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
	RequestTimeout   duration `yaml:"request_timeout"`
}

// duration unmarshals a Go duration string ("5s") from YAML — yaml.v3's
// default time.Duration handling is an integer nanosecond count, not the
// human-readable string spec.md §26's example config uses.
type duration time.Duration

func (d *duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = duration(parsed)
	return nil
}

const (
	defaultSocketPath     = "/run/pilot/access-gateway.sock"
	defaultRequestTimeout = 5 * time.Second

	// Recording defaults (spec.md §23/§27) — "metadata"/"best_effort" are
	// the unconditional defaults everywhere in this codebase (D8); an
	// operator must explicitly opt into anything else.
	defaultRecordingMode          = "metadata"
	defaultRecordingFailurePolicy = "best_effort"
	defaultRecordingQueueEvents   = 1024
	defaultRecordingFlushInterval = 500 * time.Millisecond
)

var validRecordingModes = map[string]bool{
	"metadata": true, "terminal_output": true, "terminal_io": true,
}

var validRecordingFailurePolicies = map[string]bool{
	"best_effort": true, "fail_closed": true,
}

// LoadConfig reads and validates a gateway config file.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
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
	if mode := c.Gateway.Recording.Mode; mode != "" && !validRecordingModes[mode] {
		return fmt.Errorf("gateway.recording.mode %q is not one of metadata|terminal_output|terminal_io", mode)
	}
	if fp := c.Gateway.Recording.FailurePolicy; fp != "" && !validRecordingFailurePolicies[fp] {
		return fmt.Errorf("gateway.recording.failure_policy %q is not one of best_effort|fail_closed", fp)
	}
	if c.Gateway.Recording.SessionStoreURL != "" && c.Gateway.Recording.SessionStoreIngestTokenFile == "" {
		return fmt.Errorf("gateway.recording.session_store_url is set but gateway.recording.session_store_ingest_token_file is empty")
	}
	return nil
}

func (c Config) recordingMode() string {
	if c.Gateway.Recording.Mode != "" {
		return c.Gateway.Recording.Mode
	}
	return defaultRecordingMode
}

func (c Config) recordingFailurePolicy() string {
	if c.Gateway.Recording.FailurePolicy != "" {
		return c.Gateway.Recording.FailurePolicy
	}
	return defaultRecordingFailurePolicy
}

func (c Config) recordingQueueEvents() int {
	if c.Gateway.Recording.QueueEvents > 0 {
		return c.Gateway.Recording.QueueEvents
	}
	return defaultRecordingQueueEvents
}

func (c Config) recordingFlushInterval() time.Duration {
	if c.Gateway.Recording.FlushInterval > 0 {
		return time.Duration(c.Gateway.Recording.FlushInterval)
	}
	return defaultRecordingFlushInterval
}

func (c Config) sessionStoreURL() string    { return c.Gateway.Recording.SessionStoreURL }
func (c Config) sessionStoreCAFile() string { return c.Gateway.Recording.SessionStoreCAFile }

// loadSessionStoreIngestToken reads the ingest bearer token from a
// vault-provided, mode-0600 file (spec.md §28.2) — same discipline as
// cmd/pilot-session-store/config.go's loadIngestToken. Called only when
// SessionStoreURL is configured; the token is held only in memory from
// here on and handed to a connecting client over the already-
// SO_PEERCRED-authenticated Unix socket response (never written to disk
// again, never a CLI argument).
func loadSessionStoreIngestToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat session-store ingest token file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("session-store ingest token file %s must not be group/world accessible (mode %04o)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read session-store ingest token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("session-store ingest token file %s is empty", path)
	}
	return token, nil
}

func (c Config) socketPath() string {
	if c.Gateway.SocketPath != "" {
		return c.Gateway.SocketPath
	}
	return defaultSocketPath
}

func (c Config) requestTimeout() time.Duration {
	if c.Gateway.FreeIPA.RequestTimeout > 0 {
		return time.Duration(c.Gateway.FreeIPA.RequestTimeout)
	}
	return defaultRequestTimeout
}
