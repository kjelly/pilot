package monitoring

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadTargets reads path and returns its parsed TargetFile. A missing file
// is equivalent to schemaVersion:1, targets:[] (spec.md §64) — an empty
// workspace with no monitoring/ directory must behave exactly as it did
// before this feature existed, not error. An empty path is likewise treated
// as "no targets declared" so callers don't need a separate branch for
// "monitoring not configured at all". Decoding rejects any unknown field —
// including community/username/password/privPassword — so a secret
// accidentally pasted into the registry fails to load rather than being
// silently dropped (SNMP monitoring integration spec §7.4 rule 10).
func LoadTargets(path string) (TargetFile, error) {
	if path == "" {
		return TargetFile{SchemaVersion: SchemaVersion}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return TargetFile{SchemaVersion: SchemaVersion}, nil
		}
		return TargetFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return TargetFile{SchemaVersion: SchemaVersion}, nil
	}
	var tf TargetFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&tf); err != nil {
		return TargetFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if tf.SchemaVersion == 0 {
		tf.SchemaVersion = SchemaVersion
	}
	return tf, nil
}

// LoadProfiles reads path and returns its parsed ProfileFile, with the same
// missing-file/empty-path-is-empty-registry/strict-decode semantics as
// LoadTargets.
func LoadProfiles(path string) (ProfileFile, error) {
	if path == "" {
		return ProfileFile{SchemaVersion: SchemaVersion, Profiles: map[string]Profile{}}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ProfileFile{SchemaVersion: SchemaVersion, Profiles: map[string]Profile{}}, nil
		}
		return ProfileFile{}, fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return ProfileFile{SchemaVersion: SchemaVersion, Profiles: map[string]Profile{}}, nil
	}
	var pf ProfileFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&pf); err != nil {
		return ProfileFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if pf.SchemaVersion == 0 {
		pf.SchemaVersion = SchemaVersion
	}
	if pf.Profiles == nil {
		pf.Profiles = map[string]Profile{}
	}
	return pf, nil
}

// SaveTargets writes tf to path as YAML, creating parent directories as
// needed. Used by the CLI/TUI mutation paths (Phase 3/4) — always preceded
// by Validate so an invalid registry is never persisted. schemaVersion is
// left at 1 if every target only uses v1 fields, and forced to 2 the
// moment any target uses a v2-only field (SNMP monitoring integration
// spec §7.1's writer rule) — never silently downgraded once a caller
// explicitly set 2.
func SaveTargets(path string, tf TargetFile) error {
	if tf.SchemaVersion == 0 {
		tf.SchemaVersion = SchemaVersion
	}
	for _, t := range tf.Targets {
		if t.UsesV2Fields() {
			tf.SchemaVersion = MaxSchemaVersion
			break
		}
	}
	data, err := yaml.Marshal(tf)
	if err != nil {
		return fmt.Errorf("marshal targets: %w", err)
	}
	return writeFile(path, data)
}

// SaveProfiles writes pf to path as YAML, same v1/v2 writer conventions as
// SaveTargets.
func SaveProfiles(path string, pf ProfileFile) error {
	if pf.SchemaVersion == 0 {
		pf.SchemaVersion = SchemaVersion
	}
	for _, p := range pf.Profiles {
		if p.UsesV2Fields() {
			pf.SchemaVersion = MaxSchemaVersion
			break
		}
	}
	data, err := yaml.Marshal(pf)
	if err != nil {
		return fmt.Errorf("marshal profiles: %w", err)
	}
	return writeFile(path, data)
}

func writeFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
