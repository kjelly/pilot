package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is /etc/pilot/session-store.yaml (docs/tmp/now/spec.md §28).
// Unknown fields are rejected via KnownFields(true), matching every
// other pilot-access-* config.go's discipline.
type Config struct {
	Ingest    IngestSection    `yaml:"ingest"`
	Storage   StorageSection   `yaml:"storage"`
	Read      ReadSection      `yaml:"read"`
	Retention RetentionSection `yaml:"retention"`
}

// IngestSection is the TLS-mandatory write-only API (spec.md §28.1/28.2).
// SigningKeyFile holds the per-session ingest token (PIT1) HMAC key shared
// with pilot-access-gateway (per-host recording spec §16/§21.1). It must be
// a vault-provided file that is not group/world accessible — the key is
// never accepted as a config value or CLI argument. The former static
// bearer `token_file` is gone; KnownFields(true) rejects it.
type IngestSection struct {
	ListenAddr     string `yaml:"listen_addr"`
	TLSCertFile    string `yaml:"tls_cert_file"`
	TLSKeyFile     string `yaml:"tls_key_file"`
	SigningKeyFile string `yaml:"signing_key_file"`
}

// StorageSection configures the encrypted index (spec.md §28.3/28.4).
// KeyID is operator-assigned metadata (internal/sessionstore.NewEncryptor's
// doc comment), never derived from MasterKeyFile's contents.
type StorageSection struct {
	IndexDBPath   string `yaml:"index_db_path"`
	MasterKeyFile string `yaml:"master_key_file"`
	KeyID         string `yaml:"key_id"`
}

// ReadSection is the admin read/replay Unix socket (spec.md §29) — a
// separate credential space from Ingest by construction (a different
// listener entirely, not just a different token).
type ReadSection struct {
	SocketPath   string `yaml:"socket_path"`
	AuditorGroup string `yaml:"auditor_group"`
}

// RetentionSection has no default: spec.md §28.5 explicitly forbids
// hardcoding a company retention policy, so RetentionDays must be set
// by the deploying operator. Zero/absent fails config validation.
type RetentionSection struct {
	RetentionDays int `yaml:"retention_days"`
}

const (
	defaultReadSocketPath = "/run/pilot/session-store.sock"
)

// LoadConfig reads and validates a pilot-session-store config file.
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
	if c.Ingest.ListenAddr == "" {
		missing = append(missing, "ingest.listen_addr")
	}
	if c.Ingest.TLSCertFile == "" {
		missing = append(missing, "ingest.tls_cert_file")
	}
	if c.Ingest.TLSKeyFile == "" {
		missing = append(missing, "ingest.tls_key_file")
	}
	if c.Ingest.SigningKeyFile == "" {
		missing = append(missing, "ingest.signing_key_file")
	}
	if c.Storage.IndexDBPath == "" {
		missing = append(missing, "storage.index_db_path")
	}
	if c.Storage.MasterKeyFile == "" {
		missing = append(missing, "storage.master_key_file")
	}
	if c.Storage.KeyID == "" {
		missing = append(missing, "storage.key_id")
	}
	if c.Retention.RetentionDays <= 0 {
		missing = append(missing, "retention.retention_days (must be > 0, no implicit default per spec.md §28.5)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("config missing required fields: %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c Config) readSocketPath() string {
	if c.Read.SocketPath != "" {
		return c.Read.SocketPath
	}
	return defaultReadSocketPath
}

func (c Config) retentionPeriod() time.Duration {
	return time.Duration(c.Retention.RetentionDays) * 24 * time.Hour
}
