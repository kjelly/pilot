// Package vaultfile edits the plaintext ".vault/*.yaml" secret
// skeletons `pilot inventory generate` creates — normally a top-level mapping
// of scalar (or block-scalar/multiline) values.
//
// It deliberately exposes only scalar entries for generic editing. A caller
// that owns one named nested mapping may opt to preserve that mapping via
// EditableWithPreservedNestedMappings; all other complex YAML remains
// ineligible so the generic editor cannot silently mangle it. Unlike
// internal/groupvars (a line-oriented editor that never touches structure it
// doesn't recognize),
// this package parses into a real yaml.v3 node tree so multiline
// values round-trip as literal block scalars — but it only ever
// mutates that tree through Add/Set/Delete, never by re-marshaling
// arbitrary Go values, so comments and key order on untouched entries
// survive a Bytes() round-trip.
package vaultfile

import (
	"bytes"
	"strings"

	"gopkg.in/yaml.v3"
)

// Entry is one top-level scalar key in a vault file.
type Entry struct {
	Key   string
	Value *yaml.Node
}

// DisplayValue renders the entry's value for a menu row, with any
// newline in a multiline value shown as the literal two characters
// `\n` rather than a real line break.
func (e Entry) DisplayValue() string {
	return strings.ReplaceAll(e.Value.Value, "\n", `\n`)
}

// EditValue is the value to pre-fill a text-entry field with when
// modifying this entry — currently identical to DisplayValue.
func (e Entry) EditValue() string {
	return e.DisplayValue()
}

// Doc is a vault file loaded for editing.
type Doc struct {
	root    *yaml.Node
	mapping *yaml.Node
	entries []Entry
}

// Parse loads data for editing.
func Parse(data []byte) (*Doc, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	doc := &Doc{root: &root}
	// A brand-new "---\n" skeleton (what pilot edit writes for a
	// missing file) doesn't unmarshal to zero content — it's one
	// ScalarNode with tag !!null representing the empty document — so
	// that case needs the same "start a fresh empty mapping" treatment
	// as truly empty content, or Editable() below rejects every new
	// vault file before a single key is ever added.
	if len(root.Content) == 0 || isNullScalar(root.Content[0]) {
		doc.mapping = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = []*yaml.Node{doc.mapping}
		return doc, nil
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return doc, nil
	}
	doc.mapping = root.Content[0]
	doc.refresh()
	return doc, nil
}

func isNullScalar(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

func (d *Doc) refresh() {
	d.entries = nil
	if d.mapping == nil {
		return
	}
	for i := 0; i+1 < len(d.mapping.Content); i += 2 {
		d.entries = append(d.entries, Entry{
			Key:   d.mapping.Content[i].Value,
			Value: d.mapping.Content[i+1],
		})
	}
}

// Entries returns every top-level key, in file order. Callers rendering a
// generic scalar editor should use ScalarEntries instead.
func (d *Doc) Entries() []Entry {
	return d.entries
}

// ScalarEntries returns only editable top-level scalar keys, in file order.
// Nested YAML is deliberately omitted so a generic vault UI cannot offer it
// for mutation.
func (d *Doc) ScalarEntries() []Entry {
	entries := make([]Entry, 0, len(d.entries))
	for _, e := range d.entries {
		if e.Value.Kind == yaml.ScalarNode {
			entries = append(entries, e)
		}
	}
	return entries
}

// Editable reports whether every top-level value is a plain (or
// block-literal) scalar — i.e. whether this package's Add/Set/Delete
// can safely represent the whole document.
func (d *Doc) Editable() bool {
	return d.EditableWithPreservedNestedMappings()
}

// EditableWithPreservedNestedMappings reports whether every top-level value
// is scalar, except for the explicitly named nested mappings the caller owns
// and promises to leave untouched. Lists, aliases, and all unlisted mappings
// remain unsupported.
func (d *Doc) EditableWithPreservedNestedMappings(keys ...string) bool {
	if d.mapping == nil {
		return false
	}
	preserved := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		preserved[key] = struct{}{}
	}
	for _, e := range d.entries {
		if e.Value.Kind == yaml.ScalarNode {
			continue
		}
		if e.Value.Kind == yaml.MappingNode {
			if _, ok := preserved[e.Key]; ok {
				continue
			}
		}
		return false
	}
	return true
}

// HasKey reports whether key exists as a top-level entry.
func (d *Doc) HasKey(key string) bool {
	for _, e := range d.entries {
		if e.Key == key {
			return true
		}
	}
	return false
}

// HasNestedMapping reports whether key is present with a YAML mapping value.
// Callers that own a specific nested schema can use this to hand the document
// to that schema's editor instead of treating every complex vault file as an
// unsupported generic-vault document.
func (d *Doc) HasNestedMapping(key string) bool {
	for _, e := range d.entries {
		if e.Key == key {
			return e.Value.Kind == yaml.MappingNode
		}
	}
	return false
}

// Add appends a new top-level key: value entry. value containing a
// newline is rendered as a literal block scalar; otherwise double-
// quoted.
func (d *Doc) Add(key, value string) {
	style := yaml.DoubleQuotedStyle
	if strings.Contains(value, "\n") {
		style = yaml.LiteralStyle
	}
	d.mapping.Content = append(d.mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: style},
	)
	d.refresh()
}

// Set updates key's value in place (adding it if not already present),
// preserving the entry's position among its siblings.
func (d *Doc) Set(key, value string) {
	for _, e := range d.entries {
		if e.Key == key {
			// Generic vault editing must never replace a nested value with a
			// scalar. Such keys are not exposed by ScalarEntries, but keep the
			// document API conservative for non-UI callers too.
			if e.Value.Kind != yaml.ScalarNode {
				return
			}
			e.Value.Value = value
			if strings.Contains(value, "\n") {
				e.Value.Style = yaml.LiteralStyle
			} else {
				e.Value.Style = yaml.DoubleQuotedStyle
			}
			return
		}
	}
	d.Add(key, value)
}

// Delete removes key if present; a no-op otherwise.
func (d *Doc) Delete(key string) {
	if d.mapping == nil {
		return
	}
	var content []*yaml.Node
	for i := 0; i+1 < len(d.mapping.Content); i += 2 {
		if d.mapping.Content[i].Value == key {
			// As with Set, a generic editor must not delete a nested schema it
			// does not own.
			if d.mapping.Content[i+1].Kind == yaml.ScalarNode {
				continue
			}
		}
		content = append(content, d.mapping.Content[i], d.mapping.Content[i+1])
	}
	d.mapping.Content = content
	d.refresh()
}

// Bytes renders the document back to YAML.
func (d *Doc) Bytes() []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(d.root)
	_ = enc.Close()
	return buf.Bytes()
}
