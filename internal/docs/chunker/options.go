// Package chunker turns raw ansible-doc data into per-fact chunks
// suitable for LLM retrieval. The previous docs.ChunkModule produced
// one big "options" chunk per module; that's the wrong granularity
// for a tool that wants to answer "what is the `enabled` parameter
// of `service`?". This package splits options into one chunk per
// parameter, and adds natural-language search text on top of the
// raw description so BM25 hits common LLM phrasings.
package chunker

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anomalyco/pilot/internal/docs"
)

// Section identifies what kind of fact a chunk represents. The LLM
// uses this to know what to do with the chunk (e.g. emit a YAML
// parameter vs. emit a task body).
type Section string

const (
	SectionSynopsis Section = "synopsis"
	SectionParam    Section = "param"
	SectionExample  Section = "example"
	SectionNote     Section = "note"
	SectionRequire  Section = "requirements"
	SectionReturn   Section = "return"
)

// Chunk is the unit of retrieval. It is structurally compatible with
// docs.Chunk but carries an explicit Kind so the LLM can branch on it
// without parsing strings.
type Chunk struct {
	ID      string // "modules:<fqcn>:param:<paramname>"
	Ref     string // module FQCN
	Section Section
	Text    string         // what the LLM actually reads
	Search  string         // BM25-visible expanded query text
	Meta    map[string]any // structured: name/type/default/choices/required/version_added/aliases
}

// OptionsEntry mirrors one element of `options` from ansible-doc's
// JSON output. We type it explicitly here so the chunker doesn't
// depend on docs.ModuleDoc's loose map[string]string layout.
type OptionsEntry struct {
	Name         string
	Type         string
	Description  string
	Required     bool
	Default      any
	Choices      []any
	Aliases      []string
	VersionAdded string
	SubOptions   map[string]OptionsEntry
}

// ModuleInput is what ChunkModule consumes. It is intentionally
// decoupled from docs.ModuleDoc so the chunker has no hidden
// dependencies on the docs package's evolution.
type ModuleInput struct {
	Name         string
	ShortDesc    string
	Description  string
	Synopsis     string
	Notes        string
	Requirements string
	Examples     string
	Options      map[string]OptionsEntry
	Returns      map[string]OptionsEntry
}

// ChunkModule is the entry point. It produces a deterministic set of
// chunks (one per logical fact) for a single ansible module.
func ChunkModule(m ModuleInput) []Chunk {
	var out []Chunk
	if s := synopsisChunk(m); s != nil {
		out = append(out, *s)
	}
	for _, name := range sortedKeys(m.Options) {
		out = append(out, paramChunks(m.Name, name, m.Options[name])...)
	}
	if m.Examples != "" {
		out = append(out, exampleChunk(m))
	}
	if m.Notes != "" {
		out = append(out, noteChunk(m))
	}
	if m.Requirements != "" {
		out = append(out, reqChunk(m))
	}
	for _, name := range sortedKeys(m.Returns) {
		out = append(out, returnChunk(m.Name, name, m.Returns[name]))
	}
	return out
}

func synopsisChunk(m ModuleInput) *Chunk {
	body := strings.TrimSpace(m.ShortDesc)
	if m.Description != "" && !strings.Contains(body, m.Description) {
		body = body + "\n\n" + strings.TrimSpace(m.Description)
	}
	if m.Synopsis != "" {
		body = body + "\n\nSynopsis: " + strings.TrimSpace(m.Synopsis)
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return nil
	}
	return &Chunk{
		ID:      chunkID(m.Name, SectionSynopsis, ""),
		Ref:     m.Name,
		Section: SectionSynopsis,
		Text:    truncate(body, 1500),
		Search:  "What is the " + moduleShortName(m.Name) + " module used for? " + body,
		Meta:    map[string]any{"name": m.Name},
	}
}

func paramChunks(module, paramName string, opt OptionsEntry) []Chunk {
	main := Chunk{
		ID:      chunkID(module, SectionParam, paramName),
		Ref:     module,
		Section: SectionParam,
		Meta: map[string]any{
			"param_name":    paramName,
			"param_type":    opt.Type,
			"required":      opt.Required,
			"default":       opt.Default,
			"choices":       stringifyChoices(opt.Choices),
			"aliases":       opt.Aliases,
			"version_added": opt.VersionAdded,
		},
		Text:   renderParam(module, paramName, opt),
		Search: buildParamSearch(module, paramName, opt),
	}
	out := []Chunk{main}
	for _, subName := range sortedKeys(opt.SubOptions) {
		sub := opt.SubOptions[subName]
		out = append(out, Chunk{
			ID:      chunkID(module, SectionParam, paramName+"."+subName),
			Ref:     module,
			Section: SectionParam,
			Meta: map[string]any{
				"param_name": paramName + "." + subName,
				"parent":     paramName,
				"param_type": sub.Type,
				"required":   sub.Required,
				"default":    sub.Default,
				"choices":    stringifyChoices(sub.Choices),
			},
			Text:   renderParam(module, paramName+"."+subName, sub),
			Search: buildParamSearch(module, paramName+"."+subName, sub),
		})
	}
	return out
}

func exampleChunk(m ModuleInput) Chunk {
	return Chunk{
		ID:      chunkID(m.Name, SectionExample, ""),
		Ref:     m.Name,
		Section: SectionExample,
		Text:    truncate(m.Examples, 2500),
		Search:  "Example playbook using " + moduleShortName(m.Name) + " module:\n" + m.Examples,
		Meta:    map[string]any{"name": m.Name},
	}
}

func noteChunk(m ModuleInput) Chunk {
	return Chunk{
		ID:      chunkID(m.Name, SectionNote, ""),
		Ref:     m.Name,
		Section: SectionNote,
		Text:    truncate(m.Notes, 1500),
		Search:  "Notes and gotchas about " + moduleShortName(m.Name) + ": " + m.Notes,
		Meta:    map[string]any{"name": m.Name},
	}
}

func reqChunk(m ModuleInput) Chunk {
	return Chunk{
		ID:      chunkID(m.Name, SectionRequire, ""),
		Ref:     m.Name,
		Section: SectionRequire,
		Text:    truncate(m.Requirements, 800),
		Search:  "Requirements to run " + moduleShortName(m.Name) + ": " + m.Requirements,
		Meta:    map[string]any{"name": m.Name},
	}
}

func returnChunk(module, name string, opt OptionsEntry) Chunk {
	return Chunk{
		ID:      chunkID(module, SectionReturn, name),
		Ref:     module,
		Section: SectionReturn,
		Meta: map[string]any{
			"return_name": name,
			"return_type": opt.Type,
		},
		Text:   truncate(opt.Description, 800),
		Search: "Return value " + name + " from " + moduleShortName(module) + ": " + opt.Description,
	}
}

func renderParam(module, name string, opt OptionsEntry) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s.%s (type=%s", moduleShortName(module), name, opt.Type)
	if opt.Required {
		b.WriteString(", required=true")
	}
	if opt.Default != nil {
		fmt.Fprintf(&b, ", default=%v", opt.Default)
	}
	if len(opt.Choices) > 0 {
		fmt.Fprintf(&b, ", choices=%s", joinStrings(stringifyChoices(opt.Choices), "|"))
	}
	if len(opt.Aliases) > 0 {
		fmt.Fprintf(&b, ", aliases=%s", strings.Join(opt.Aliases, ","))
	}
	if opt.VersionAdded != "" {
		fmt.Fprintf(&b, ", version_added=%s", opt.VersionAdded)
	}
	b.WriteString(")\n")
	if strings.TrimSpace(opt.Description) != "" {
		b.WriteString("\n")
		b.WriteString(opt.Description)
	}
	return strings.TrimSpace(b.String())
}

func buildParamSearch(module, name string, opt OptionsEntry) string {
	short := moduleShortName(module)
	verb := VerbFor(name)
	pieces := []string{
		fmt.Sprintf("How to %s in %s. What does the %s parameter do in %s.", verb, short, name, short),
		fmt.Sprintf("Parameter %s of module %s has type %s.", name, short, opt.Type),
	}
	if desc := strings.TrimSpace(opt.Description); desc != "" {
		pieces = append(pieces, desc)
	}
	if len(opt.Choices) > 0 {
		pieces = append(pieces, fmt.Sprintf("Allowed values for %s: %s.", name, strings.Join(stringifyChoices(opt.Choices), ", ")))
	}
	return strings.Join(pieces, " ")
}

func chunkID(module string, section Section, name string) string {
	switch section {
	case SectionParam:
		return "modules:" + module + ":param:" + name
	case SectionReturn:
		return "modules:" + module + ":return:" + name
	}
	if name == "" {
		return "modules:" + module + ":" + string(section)
	}
	return "modules:" + module + ":" + string(section) + ":" + name
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func stringifyChoices(c []any) []string {
	out := make([]string, 0, len(c))
	for _, v := range c {
		out = append(out, fmt.Sprintf("%v", v))
	}
	return out
}

func joinStrings(s []string, sep string) string {
	return strings.Join(s, sep)
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func moduleShortName(fqcn string) string {
	if i := strings.LastIndex(fqcn, "."); i >= 0 {
		return fqcn[i+1:]
	}
	return fqcn
}

// ToDocsChunk converts a chunker.Chunk into the docs.Chunk shape that
// the existing ModuleIndex knows how to store. The Section is preserved
// as a string so legacy readers don't break.
func ToDocsChunk(c Chunk) docs.Chunk {
	meta := map[string]any{
		"name":       c.Ref,
		"section":    string(c.Section),
		"param_name": c.Meta["param_name"],
	}
	for k, v := range c.Meta {
		meta[k] = v
	}
	combined := c.Text
	if c.Search != "" {
		combined = c.Text + "\n\n[search-text]\n" + c.Search
	}
	return docs.Chunk{
		ID:       c.ID,
		Source:   docs.SourceModule,
		Ref:      c.Ref,
		Section:  string(c.Section),
		Text:     combined,
		Metadata: meta,
	}
}
