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
// TokenFile must be a vault-provided, mode-0600 file — the raw token
// value is never accepted as a config field or CLI argument, only a
// path to read it from at startup.
type IngestSection struct {
	ListenAddr  string `yaml:"listen_addr"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	TokenFile   string `yaml:"token_file"`
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
	if c.Ingest.TokenFile == "" {
		missing = append(missing, "ingest.token_file")
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

// loadIngestToken reads the ingest bearer token from a vault-provided,
// mode-0600 file (spec.md §28.2). The token value is held only in
// memory from here on — never logged, never re-written to disk, never
// passed as a CLI argument.
func loadIngestToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat ingest token file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("ingest token file %s must not be group/world accessible (mode %04o)", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read ingest token file: %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", fmt.Errorf("ingest token file %s is empty", path)
	}
	return token, nil
}
