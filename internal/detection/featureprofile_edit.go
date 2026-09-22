package detection

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// NotifyOverrideEdit describes one `pilot detection-engine feature-profile
// set-notify` change. A nil field means "leave whatever is already in the
// file alone" (the CLI only sets a field when its flag was explicitly
// passed, via cobra's Flags().Changed) — a pointer to an empty string is a
// deliberate "clear this field back to the profile-wide default", since
// EffectiveNotifyPolicyForCategory already treats an empty override field
// that way.
type NotifyOverrideEdit struct {
	Category          string
	Warning           *string
	Critical          *string
	RunbookURL        *string
	RecommendedAction *string
	// ClearCategory removes the entire notifyByCategory[Category] entry,
	// ignoring the other fields.
	ClearCategory bool
}

// CategoryNotifySummary is one row of `pilot detection-engine feature-profile
// show`'s output: a category this profile actually declares, its resolved
// notify policy, and whether that resolution came from a category-specific
// override or the profile-wide default.
type CategoryNotifySummary struct {
	Category   string
	Policy     NotifyPolicy
	Overridden bool
}

// NotifySummaryByCategory reports, for every category this profile's
// features declare, the effective notify policy an alert of that category
// would carry.
func (p FeatureProfile) NotifySummaryByCategory() []CategoryNotifySummary {
	categories := p.Categories()
	out := make([]CategoryNotifySummary, 0, len(categories))
	for _, category := range categories {
		_, overridden := p.NotifyByCategory[category]
		out = append(out, CategoryNotifySummary{
			Category:   category,
			Policy:     p.EffectiveNotifyPolicyForCategory(category),
			Overridden: overridden,
		})
	}
	return out
}

// SetFeatureProfileNotifyOverride edits the notifyByCategory override for one
// category in a feature-profile YAML file on disk, preserving the rest of
// the document's formatting and comments (the file is hand-authored,
// committed source — see monitoring/detection/feature-profiles/*.yaml — not
// a machine-generated artifact it is safe to fully re-marshal). The result is
// re-parsed and re-validated before anything is written, so a caller never
// ends up with a file the daemon would refuse to load.
//
// Known limitation: yaml.v3's Node round-trip preserves comments but not
// blank lines between block-sequence items (e.g. the blank line between two
// `- name: ...` feature entries), so an edited file's features: list loses
// that spacing even though every comment and value survives untouched.
func SetFeatureProfileNotifyOverride(path string, edit NotifyOverrideEdit) error {
	if edit.Category == "" {
		return fmt.Errorf("set feature profile notify override: category is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat feature profile %s: %w", path, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read feature profile %s: %w", path, err)
	}
	profile, err := ParseFeatureProfile(data)
	if err != nil {
		return fmt.Errorf("parse feature profile %s: %w", path, err)
	}
	if !profile.hasCategory(edit.Category) {
		return fmt.Errorf("feature profile %s has no feature with category %q", path, edit.Category)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse feature profile %s as yaml: %w", path, err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("feature profile %s: unexpected yaml document shape", path)
	}
	root := doc.Content[0]

	notifyByCategory := findMapValue(root, "notifyByCategory")

	if edit.ClearCategory {
		if notifyByCategory != nil {
			deleteMapKey(notifyByCategory, edit.Category)
			if len(notifyByCategory.Content) == 0 {
				deleteMapKey(root, "notifyByCategory")
			}
		}
	} else {
		if notifyByCategory == nil {
			notifyByCategory = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			appendMapPair(root, "notifyByCategory", notifyByCategory)
		}
		override := findMapValue(notifyByCategory, edit.Category)
		if override == nil {
			override = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			appendMapPair(notifyByCategory, edit.Category, override)
		}
		if edit.Warning != nil {
			setOrDeleteScalar(override, "warning", *edit.Warning)
		}
		if edit.Critical != nil {
			setOrDeleteScalar(override, "critical", *edit.Critical)
		}
		if edit.RunbookURL != nil {
			setOrDeleteScalar(override, "runbookURL", *edit.RunbookURL)
		}
		if edit.RecommendedAction != nil {
			setOrDeleteScalar(override, "recommendedAction", *edit.RecommendedAction)
		}
		if len(override.Content) == 0 {
			deleteMapKey(notifyByCategory, edit.Category)
			if len(notifyByCategory.Content) == 0 {
				deleteMapKey(root, "notifyByCategory")
			}
		}
	}

	// yaml.v3's package-level Marshal defaults to a 4-space indent, which
	// would reindent this hand-authored, 2-space-indented file on every
	// line touched by nothing more than a re-encode. An explicit Encoder
	// keeps the diff limited to the notifyByCategory change itself.
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("render feature profile %s: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("render feature profile %s: %w", path, err)
	}
	rendered := buf.Bytes()
	if _, err := ParseFeatureProfile(rendered); err != nil {
		return fmt.Errorf("edited feature profile %s would no longer be valid: %w", path, err)
	}
	return atomicWriteFile(path, rendered, info.Mode())
}

// findMapValue returns the value node for key in a MappingNode, or nil.
func findMapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// appendMapPair appends a new key/value pair to a MappingNode.
func appendMapPair(m *yaml.Node, key string, value *yaml.Node) {
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	m.Content = append(m.Content, keyNode, value)
}

// deleteMapKey removes key (and its value) from a MappingNode, if present.
func deleteMapKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// setOrDeleteScalar sets key=value on a MappingNode, creating the entry if
// needed; an empty value deletes the key instead, since an absent key and an
// empty override field mean the same thing to EffectiveNotifyPolicyForCategory.
func setOrDeleteScalar(m *yaml.Node, key, value string) {
	if value == "" {
		deleteMapKey(m, key)
		return
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].SetString(value)
			return
		}
	}
	valueNode := &yaml.Node{}
	valueNode.SetString(value)
	appendMapPair(m, key, valueNode)
}

// atomicWriteFile writes data to path via temp file + rename, preserving
// mode, so a reader never observes a partially-written feature profile.
func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".feature-profile-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}
