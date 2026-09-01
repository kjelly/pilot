package monitoring

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SNMPCatalogSchemaVersion is the only schemaVersion this package
// understands for monitoring/snmp/catalog.yml.
const SNMPCatalogSchemaVersion = 1

// snmpCatalogNamePattern is the required shape for every module and
// auth profile ID (spec §6.4 rule 1).
var snmpCatalogNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// snmpAuthSecurityLevels are the only securityLevel values the exporter
// understands, regardless of SNMP version (spec §6.4 example uses
// noAuthNoPriv even for a v2c profile — the field always exists, only
// authPriv is meaningful for the v3 production baseline).
var snmpAuthSecurityLevels = map[string]bool{
	"noAuthNoPriv": true,
	"authNoPriv":   true,
	"authPriv":     true,
}

// SNMPCatalog is the parsed form of monitoring/snmp/catalog.yml — the
// version-controlled, secret-free registry of SNMP modules and auth
// profiles (spec §6.4).
type SNMPCatalog struct {
	SchemaVersion int                        `yaml:"schemaVersion"`
	Modules       map[string]SNMPModule      `yaml:"modules"`
	AuthProfiles  map[string]SNMPAuthProfile `yaml:"authProfiles"`
}

// SNMPModule names the generated module file backing one catalog module
// ID (spec §6.4) — never the module's SNMP content itself.
type SNMPModule struct {
	File string `yaml:"file"`
}

// SNMPAuthProfile is one non-secret SNMP auth profile entry (spec §6.4).
// CredentialRef is a lookup key into the vault-supplied
// snmp_exporter_credentials map, never a credential value itself —
// this type MUST NOT gain a username/password/privPassword/community
// field.
type SNMPAuthProfile struct {
	Version       int    `yaml:"version"`
	SecurityLevel string `yaml:"securityLevel"`
	AuthProtocol  string `yaml:"authProtocol,omitempty"`
	PrivProtocol  string `yaml:"privProtocol,omitempty"`
	CredentialRef string `yaml:"credentialRef"`
}

// LoadSNMPCatalog reads path and returns its parsed SNMPCatalog. A
// missing file is equivalent to schemaVersion:1 with no modules/auth
// profiles declared, matching LoadTargets/LoadProfiles' empty-workspace
// convention. Decoding rejects any unknown field — including
// community/username/password/privPassword — so a secret accidentally
// pasted into the catalog fails to load rather than being silently
// dropped (spec §6.4 rule 3).
func LoadSNMPCatalog(path string) (SNMPCatalog, error) {
	if path == "" {
		return SNMPCatalog{SchemaVersion: SNMPCatalogSchemaVersion}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SNMPCatalog{SchemaVersion: SNMPCatalogSchemaVersion}, nil
		}
		return SNMPCatalog{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return SNMPCatalog{SchemaVersion: SNMPCatalogSchemaVersion}, nil
	}
	var catalog SNMPCatalog
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&catalog); err != nil {
		return SNMPCatalog{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if catalog.SchemaVersion == 0 {
		catalog.SchemaVersion = SNMPCatalogSchemaVersion
	}
	return catalog, nil
}

// Validate checks c's own structural rules (spec §6.4 rules 1, 2, 4):
// name pattern, relative/non-escaping module file paths, and
// non-empty credentialRef. It does NOT check that a module file
// actually exists or declares its own module ID (spec §6.4 rule 5) —
// that requires filesystem access and is the apply playbook's
// preflight gate (mirroring how prometheus-apply.yml's own registry
// gates stand in for a not-yet-built CLI validator) — nor does it
// enforce the production version-policy gate (spec §6.4 rule 6), which
// depends on the deployment stage, not the catalog alone.
func (c SNMPCatalog) Validate() error {
	if c.SchemaVersion != SNMPCatalogSchemaVersion {
		return fmt.Errorf("unsupported snmp catalog schemaVersion %d", c.SchemaVersion)
	}
	for id, module := range c.Modules {
		if !snmpCatalogNamePattern.MatchString(id) {
			return fmt.Errorf("module %q: name must match %s", id, snmpCatalogNamePattern.String())
		}
		if err := validateSNMPCatalogRelativePath(module.File); err != nil {
			return fmt.Errorf("module %q: %w", id, err)
		}
	}
	for id, auth := range c.AuthProfiles {
		if !snmpCatalogNamePattern.MatchString(id) {
			return fmt.Errorf("authProfile %q: name must match %s", id, snmpCatalogNamePattern.String())
		}
		if !snmpAuthSecurityLevels[auth.SecurityLevel] {
			return fmt.Errorf("authProfile %q: invalid securityLevel %q", id, auth.SecurityLevel)
		}
		if strings.TrimSpace(auth.CredentialRef) == "" {
			return fmt.Errorf("authProfile %q: credentialRef is required", id)
		}
	}
	return nil
}

// validateSNMPCatalogRelativePath rejects an absolute path, a `..`
// traversal, or an empty path (spec §6.4 rule 2). It does not resolve
// symlinks — that check needs the actual monitoring/snmp/ directory on
// disk and belongs to the apply playbook's own file-existence gate.
func validateSNMPCatalogRelativePath(rel string) error {
	if strings.TrimSpace(rel) == "" {
		return fmt.Errorf("module file path is required")
	}
	if filepath.IsAbs(rel) {
		return fmt.Errorf("module file path must be relative: %s", rel)
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("module file path escapes monitoring/snmp/: %s", rel)
	}
	return nil
}
