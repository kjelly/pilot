package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is /etc/pilot/access-directory.yaml (docs/tmp/now/spec.md
// §12.1). Unknown fields are rejected — KnownFields(true) enforces that,
// matching cmd/pilot-access-gateway's own config discipline (spec.md
// §26): this file has no roster_file/inventory_file/vault_password_file/
// state_dir/audit_db, or any other field spec.md §12.1's schema doesn't
// name.
type Config struct {
	Directory DirectorySection `yaml:"directory"`
	FreeIPA   FreeIPASection   `yaml:"freeipa"`
	Routing   RoutingSection   `yaml:"routing"`
}

// DirectorySection is this Directory instance's identity plus runtime
// settings (spec.md §12.1). TargetHostgroupPrefix/GatewayHostgroupPrefix
// are FreeIPA hostgroup-naming convention (default "pilot-target-"/
// "pilot-gateway-"), never derived from this host's own hostname (D3).
type DirectorySection struct {
	ID                     string `yaml:"id"`
	TargetHostgroupPrefix  string `yaml:"target_hostgroup_prefix"`
	GatewayHostgroupPrefix string `yaml:"gateway_hostgroup_prefix"`
	PortalUserGroup        string `yaml:"portal_user_group"`
	SocketPath             string `yaml:"socket_path"`
}

// FreeIPASection configures the read-only internal/freeipaaccess.Client —
// same shape as cmd/pilot-access-gateway's FreeIPASection. Deliberately
// no cache_ttl/connect_max_age field: this package has no caching layer
// at any point (D1), so there is nothing such a field could honestly
// configure.
type FreeIPASection struct {
	Servers          []string `yaml:"servers"`
	CAFile           string   `yaml:"ca_file"`
	ServicePrincipal string   `yaml:"service_principal"`
	Keytab           string   `yaml:"keytab"`
	RequestTimeout   duration `yaml:"request_timeout"`
}

// RoutingSection is reserved for the Directory -> Gateway SSH handoff
// (spec.md §15/§16, Phase 5) — parsed and validated now so the config
// schema does not need to change shape later, but nothing in this
// binary reads these fields yet: Phase 3's API only returns route
// metadata from POST /v1/connect/resolve, it does not exec ssh.
type RoutingSection struct {
	SSHConfig      string   `yaml:"ssh_config"`
	ConnectTimeout duration `yaml:"connect_timeout"`
}

// duration unmarshals a Go duration string ("5s") from YAML — same
// helper as internal/gatewayconfig/config.go's, duplicated rather than
// shared because these are two independent binaries with no shared
// internal config package (matching the rest of this repo's per-command
// config.go convention).
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
	defaultSocketPath             = "/run/pilot/access-directory.sock"
	defaultRequestTimeout         = 5 * time.Second
	defaultTargetHostgroupPrefix  = "pilot-target-"
	defaultGatewayHostgroupPrefix = "pilot-gateway-"
)

// LoadConfig reads and validates a Directory config file.
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
	if c.Directory.ID == "" {
		missing = append(missing, "directory.id")
	}
	if len(c.FreeIPA.Servers) == 0 {
		missing = append(missing, "freeipa.servers")
	}
	if c.FreeIPA.CAFile == "" {
		missing = append(missing, "freeipa.ca_file")
	}
	if c.FreeIPA.ServicePrincipal == "" {
		missing = append(missing, "freeipa.service_principal")
	}
	if c.FreeIPA.Keytab == "" {
		missing = append(missing, "freeipa.keytab")
	}
	if len(missing) > 0 {
		return fmt.Errorf("config missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c Config) socketPath() string {
	if c.Directory.SocketPath != "" {
		return c.Directory.SocketPath
	}
	return defaultSocketPath
}

func (c Config) targetHostgroupPrefix() string {
	if c.Directory.TargetHostgroupPrefix != "" {
		return c.Directory.TargetHostgroupPrefix
	}
	return defaultTargetHostgroupPrefix
}

func (c Config) gatewayHostgroupPrefix() string {
	if c.Directory.GatewayHostgroupPrefix != "" {
		return c.Directory.GatewayHostgroupPrefix
	}
	return defaultGatewayHostgroupPrefix
}

func (c Config) requestTimeout() time.Duration {
	if c.FreeIPA.RequestTimeout > 0 {
		return time.Duration(c.FreeIPA.RequestTimeout)
	}
	return defaultRequestTimeout
}
