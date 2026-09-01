package monitoring

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// SNMPCatalogSchemaVersion is the only schemaVersion this package
// understands for monitoring/snmp/catalog.yml.
const SNMPCatalogSchemaVersion = 1

// SNMPCatalog is the parsed form of monitoring/snmp/catalog.yml — the
// version-controlled, secret-free registry of SNMP modules and auth
// profiles (spec §6.4). Phase 0 defines the shape only; Phase 1 adds
// the loader/validator behavior: module-file cross-check, path
// traversal/symlink-escape rejection, name-pattern enforcement, and the
// production version-policy gate (spec §6.4 rules 1-6).
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
// convention.
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
	var catalog SNMPCatalog
	if err := yaml.Unmarshal(data, &catalog); err != nil {
		return SNMPCatalog{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if catalog.SchemaVersion == 0 {
		catalog.SchemaVersion = SNMPCatalogSchemaVersion
	}
	return catalog, nil
}
