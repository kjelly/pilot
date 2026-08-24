package monitoring

import (
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
// "monitoring not configured at all".
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
	var tf TargetFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return TargetFile{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if tf.SchemaVersion == 0 {
		tf.SchemaVersion = SchemaVersion
	}
	return tf, nil
}

// LoadProfiles reads path and returns its parsed ProfileFile, with the same
// missing-file/empty-path-is-empty-registry semantics as LoadTargets.
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
	var pf ProfileFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
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
// by Validate so an invalid registry is never persisted.
func SaveTargets(path string, tf TargetFile) error {
	if tf.SchemaVersion == 0 {
		tf.SchemaVersion = SchemaVersion
	}
	data, err := yaml.Marshal(tf)
	if err != nil {
		return fmt.Errorf("marshal targets: %w", err)
	}
	return writeFile(path, data)
}

// SaveProfiles writes pf to path as YAML, same conventions as SaveTargets.
func SaveProfiles(path string, pf ProfileFile) error {
	if pf.SchemaVersion == 0 {
		pf.SchemaVersion = SchemaVersion
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
