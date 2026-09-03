package monitoring

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"gopkg.in/yaml.v3"
)

// SNMPCredentialsKey is the vault variable name snmp-exporter-apply.yml
// reads (contracts/snmp-exporter.yaml, group_vars/snmp-exporter.example.yml)
// — a map of credentialRef -> secret fields, never committed in plaintext.
const SNMPCredentialsKey = "snmp_exporter_credentials"

// SNMPCredentialFields is one credentialRef's raw field values. Which keys
// are meaningful depends on the referencing authProfile's version (spec
// §6.4): version 3 uses username/authPassword/privPassword, version 1/2c
// uses community — but this type stores whatever keys are present, so an
// existing entry with a field this package doesn't know about is never
// silently dropped on save.
type SNMPCredentialFields map[string]string

// SNMPCredentialDoc is a vault-shaped YAML file loaded for editing just its
// top-level snmp_exporter_credentials block. Every other top-level key in
// the file — and any comment or formatting on it — is preserved untouched,
// the same discipline internal/vaultfile documents for its own (scalar-
// only) top-level keys; this type instead owns exactly one nested key.
type SNMPCredentialDoc struct {
	root  *yaml.Node
	top   *yaml.Node
	block *yaml.Node // the snmp_exporter_credentials mapping node
}

// LoadSNMPCredentialDoc reads path for editing. A missing file starts a
// fresh empty document, matching LoadSNMPCatalog/vaultfile's
// missing-file-is-empty convention.
func LoadSNMPCredentialDoc(path string) (*SNMPCredentialDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		data = nil
	}
	var root yaml.Node
	if len(bytes.TrimSpace(data)) > 0 {
		if err := yaml.Unmarshal(data, &root); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}

	doc := &SNMPCredentialDoc{root: &root}
	if len(root.Content) == 0 || isNullSNMPScalar(root.Content[0]) {
		root.Kind = yaml.DocumentNode
		doc.top = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = []*yaml.Node{doc.top}
	} else if root.Content[0].Kind == yaml.MappingNode {
		doc.top = root.Content[0]
	} else {
		return nil, fmt.Errorf("%s: top-level content is not a mapping", path)
	}

	for i := 0; i+1 < len(doc.top.Content); i += 2 {
		if doc.top.Content[i].Value == SNMPCredentialsKey {
			if doc.top.Content[i+1].Kind != yaml.MappingNode {
				return nil, fmt.Errorf("%s: %s must be a mapping", path, SNMPCredentialsKey)
			}
			doc.block = doc.top.Content[i+1]
			break
		}
	}
	if doc.block == nil {
		doc.block = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.top.Content = append(doc.top.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: SNMPCredentialsKey},
			doc.block,
		)
	}
	return doc, nil
}

func isNullSNMPScalar(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

// OtherTopLevelKeys returns every top-level key in the file besides
// snmp_exporter_credentials — used by callers that want to refuse editing a
// file that turns out to hold something else entirely (a FreeIPA roster,
// for instance) via this narrow, single-key editor.
func (d *SNMPCredentialDoc) OtherTopLevelKeys() []string {
	var keys []string
	for i := 0; i+1 < len(d.top.Content); i += 2 {
		if d.top.Content[i].Value != SNMPCredentialsKey {
			keys = append(keys, d.top.Content[i].Value)
		}
	}
	return keys
}

// Refs returns every credentialRef currently in the block, sorted.
func (d *SNMPCredentialDoc) Refs() []string {
	var refs []string
	for i := 0; i+1 < len(d.block.Content); i += 2 {
		refs = append(refs, d.block.Content[i].Value)
	}
	sort.Strings(refs)
	return refs
}

// Get returns ref's fields, if present.
func (d *SNMPCredentialDoc) Get(ref string) (SNMPCredentialFields, bool) {
	for i := 0; i+1 < len(d.block.Content); i += 2 {
		if d.block.Content[i].Value != ref {
			continue
		}
		fields := SNMPCredentialFields{}
		node := d.block.Content[i+1]
		for j := 0; j+1 < len(node.Content); j += 2 {
			fields[node.Content[j].Value] = node.Content[j+1].Value
		}
		return fields, true
	}
	return nil, false
}

// Set replaces (or adds) ref's entire field set.
func (d *SNMPCredentialDoc) Set(ref string, fields SNMPCredentialFields) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, k := range keys {
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fields[k], Style: yaml.DoubleQuotedStyle},
		)
	}
	for i := 0; i+1 < len(d.block.Content); i += 2 {
		if d.block.Content[i].Value == ref {
			d.block.Content[i+1] = node
			return
		}
	}
	d.block.Content = append(d.block.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: ref},
		node,
	)
}

// Delete removes ref if present; a no-op otherwise.
func (d *SNMPCredentialDoc) Delete(ref string) {
	var content []*yaml.Node
	for i := 0; i+1 < len(d.block.Content); i += 2 {
		if d.block.Content[i].Value == ref {
			continue
		}
		content = append(content, d.block.Content[i], d.block.Content[i+1])
	}
	d.block.Content = content
}

// Bytes renders the whole document back to YAML.
func (d *SNMPCredentialDoc) Bytes() []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(d.root)
	_ = enc.Close()
	return buf.Bytes()
}

// WriteSNMPCredentialDoc writes d to path with vault-file permissions
// (0600), creating parent directories as needed.
func WriteSNMPCredentialDoc(path string, d *SNMPCredentialDoc) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, d.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
