package docs

import (
	"fmt"
	"sort"
	"strings"
)

// Source identifies where a chunk came from.
type Source string

const (
	SourceModule   Source = "modules"
	SourcePlaybook Source = "playbooks"
)

// Chunk is a single indexed piece of text plus its metadata.
type Chunk struct {
	ID       string         `json:"id"`        // unique: "<source>:<ref>:<section>"
	Source   Source         `json:"source"`    // modules | playbooks
	Ref      string         `json:"ref"`       // module name | playbook path
	Section  string         `json:"section"`   // description | options | examples | ...
	Text     string         `json:"text"`      // the text content
	Metadata map[string]any `json:"metadata"`  // extra: filename, version, etc.
}

// ChunkModule turns one Ansible module into one or more chunks.
// Strategy: one chunk per logical section (description, options,
// examples, notes). This gives the retriever fine-grained matching
// at the cost of slightly more vectors.
func ChunkModule(m ModuleDoc) []Chunk {
	out := []Chunk{}
	base := map[string]any{
		"name":     m.Name,
		"category": m.Category,
		"version":  m.Version,
		"filename": m.Filename,
	}

	add := func(section, text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		// Truncate very long sections to keep embedding model happy.
		if len(text) > 4000 {
			text = text[:4000] + "..."
		}
		out = append(out, Chunk{
			ID:       fmt.Sprintf("modules:%s:%s", m.Name, section),
			Source:   SourceModule,
			Ref:      m.Name,
			Section:  section,
			Text:     text,
			Metadata: base,
		})
	}

	if m.ShortDesc != "" || m.Description != "" {
		body := strings.TrimSpace(m.ShortDesc + "\n\n" + m.Description)
		add("description", body)
	}
	if m.Synopsis != "" {
		add("synopsis", m.Synopsis)
	}
	if len(m.Options) > 0 {
		var b strings.Builder
		// Stable order for reproducibility
		keys := make([]string, 0, len(m.Options))
		for k := range m.Options {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "- %s: %s\n", k, m.Options[k])
		}
		add("options", b.String())
	}
	if m.Examples != "" {
		add("examples", m.Examples)
	}
	if m.Notes != "" {
		add("notes", m.Notes)
	}
	if m.Requirements != "" {
		add("requirements", m.Requirements)
	}
	return out
}
