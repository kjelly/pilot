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
}

// RecordingSection configures Phase 7's PTY session recorder (docs/tmp/
// now/spec.md §23/§27). Every field is optional — the unconditional
// default is Mode "metadata" (D8), which never constructs a recorder at
// all. Deliberately does NOT have a session-store URL/token field yet
// (spec.md §35/§49.14): that is Phase 8's contract to define once a real
// pilot-session-store exists, not something to forward-declare here
// unused.
type RecordingSection struct {
	Mode          string   `yaml:"mode"`
	FailurePolicy string   `yaml:"failure_policy"`
	QueueEvents   int      `yaml:"queue_events"`
	FlushInterval duration `yaml:"flush_interval"`
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
