package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/anomalyco/pilot/internal/docs"
)

// searchDocsArgs is the JSON schema exposed to the LLM. The shape is
// deliberately flat: query / module / section / limit. We do NOT
// expose the bleve query DSL — the LLM is not expected to write
// MatchQuery / ConjunctionQuery.
var searchDocsArgs = json.RawMessage(`{
  "type": "object",
  "properties": {
    "query": {
      "type": "string",
      "description": "Search text. Can be a module name ('service'), a parameter ('enabled'), a phrase ('how to make a service start at boot'), or any combination. The LLM-friendly retriever uses natural-language hints in the index so question phrasings usually work."
    },
    "module": {
      "type": "string",
      "description": "Optional FQCN filter (e.g. 'ansible.builtin.service'). Use when you already know the module."
    },
    "section": {
      "type": "string",
      "enum": ["synopsis", "param", "example", "note", "requirements", "return"],
      "description": "Optional section filter. 'param' is the most useful for picking the right module options."
    },
    "limit": {
      "type": "integer",
      "description": "Max results to return (default 5)."
    },
    "source": {
      "type": "string",
      "enum": ["modules", "playbooks", "all"],
      "description": "Restrict to a source. Default 'all'."
    }
  },
  "required": ["query"]
}`)

// SearchDocsTool searches the local index of Ansible documentation
// and user playbooks. The LLM is expected to call this when it needs
// to verify module syntax, options, or how a previous playbook did X.
//
// Module docs use the LLM-friendly BM25 retriever (chunker per-param
// + param-preferring rank + prefix ref match). Playbook docs use the
// legacy vector index. Both are returned as a compact JSON array so
// the LLM can parse the fields directly without parsing prose.
type SearchDocsTool struct {
	modIdx *docs.ModuleIndex
	pbIdx  *docs.Index
	pbEmb  docs.Embedder
}

func NewSearchDocsTool(modIdx *docs.ModuleIndex, pbIdx *docs.Index, pbEmb docs.Embedder) *SearchDocsTool {
	return &SearchDocsTool{modIdx: modIdx, pbIdx: pbIdx, pbEmb: pbEmb}
}

func (t *SearchDocsTool) Spec() *Spec {
	return &Spec{
		Name:        "search_docs",
		Description: "Search the local index of Ansible module documentation and previously-seen playbooks. Use this BEFORE writing a task to verify the correct module name, parameter names, types, and allowed values. The module index is built locally from `ansible-doc` (BM25, no embeddings). Returns compact JSON with one record per result; each record has 'ref' (module FQCN), 'section' (param/example/etc.), structured 'param' fields when the section is 'param', the body text, a normalised confidence score in [0,1], plus 'related_example_id' pointing at the example block for the same module and 'suggested_next' listing plausible follow-up tools.",
		RiskLevel:   "low",
		Reversible:  true,
		DryRunSafe:  true,
		Parameters:  searchDocsArgs,
	}
}

// SearchHit is the LLM-facing result shape. JSON-friendly and
// structured: when section=="param" the structured fields are filled.
//
// Task B additions: RelatedExampleID points at the example chunk for
// the same module so the LLM can chain a follow-up call. SuggestedNext
// is a tiny workflow hint the LLM can echo back to the user.
type SearchHit struct {
	ID         string   `json:"id"`
	Ref        string   `json:"ref"`
	Section    string   `json:"section"`
	Score      float64  `json:"score"`
	Confidence float64  `json:"confidence"`
	Text       string   `json:"text"`
	ParamName  string   `json:"param_name,omitempty"`
	ParamType  string   `json:"param_type,omitempty"`
	Required   bool     `json:"required,omitempty"`
	Default    any      `json:"default,omitempty"`
	Choices    []string `json:"choices,omitempty"`
	Aliases    []string `json:"aliases,omitempty"`
	FromPlaybook bool   `json:"from_playbook,omitempty"`

	// RelatedExampleID is the chunk ID of the example block for the
	// same module, if one exists in the index. The LLM can either
	// surface it in its answer or call search_docs with that ID as a
	// filter to pull the full example.
	RelatedExampleID string `json:"related_example_id,omitempty"`
	// SuggestedNext is a short list of plausible next actions the
	// LLM can take. Stays tiny (≤ 3 entries) so the LLM does not
	// have to read a wall of text to figure out what to do.
	SuggestedNext []ToolSuggestion `json:"suggested_next,omitempty"`
}

func (t *SearchDocsTool) Execute(ctx context.Context, args json.RawMessage) (*Result, error) {
	var a struct {
		Query   string `json:"query"`
		Module  string `json:"module"`
		Section string `json:"section"`
		Limit   int    `json:"limit"`
		Source  string `json:"source"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return nil, fmt.Errorf("search_docs: invalid args: %w", err)
	}
	if a.Query == "" {
		return nil, fmt.Errorf("search_docs: query is required")
	}
	if a.Limit <= 0 {
		a.Limit = 5
	}
	if a.Limit > 20 {
		a.Limit = 20
	}
	source := a.Source
	if source == "" {
		source = "modules"
	}

	// Enforce a per-result text budget so the LLM context doesn't blow up.
	const maxBodyChars = 800

	var hits []SearchHit
	var notes []string

	switch source {
	case "modules":
		if t.modIdx == nil || t.modIdx.Size() == 0 {
			return &Result{Content: "search_docs: module index not built. Run `pilot index-docs`.", IsError: true}, nil
		}
		hits = t.searchModules(a.Query, a.Module, a.Section, a.Limit, maxBodyChars)
	case "playbooks":
		if t.pbIdx == nil || t.pbIdx.Size() == 0 {
			return &Result{Content: "search_docs: no playbooks indexed yet.", IsError: true}, nil
		}
		if t.pbEmb == nil {
			return &Result{Content: "search_docs: playbook index requires an embedder.", IsError: true}, nil
		}
		h, err := t.searchPlaybooks(ctx, a.Query, a.Limit, maxBodyChars)
		if err != nil {
			return &Result{Content: fmt.Sprintf("ERROR: %v", err), IsError: true}, nil
		}
		hits = h
	default: // "all"
		if t.modIdx != nil && t.modIdx.Size() > 0 {
			hits = append(hits, t.searchModules(a.Query, a.Module, a.Section, a.Limit, maxBodyChars)...)
		}
		if t.pbIdx != nil && t.pbIdx.Size() > 0 && t.pbEmb != nil {
			h, err := t.searchPlaybooks(ctx, a.Query, a.Limit, maxBodyChars)
			if err == nil {
				hits = append(hits, h...)
			} else {
				notes = append(notes, fmt.Sprintf("playbook search failed: %v", err))
			}
		}
	}

	if len(hits) == 0 {
		return &Result{Content: fmt.Sprintf("search_docs: no matches for %q.", a.Query)}, nil
	}

	// Stable sort by descending confidence, then take limit.
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Confidence > hits[j].Confidence })
	if len(hits) > a.Limit {
		hits = hits[:a.Limit]
	}

	// Dedupe near-duplicate param hits so the LLM doesn't see the
	// same module:param twice.
	hits = dedupeHits(hits)

	payload := map[string]any{
		"query":   a.Query,
		"count":   len(hits),
		"results": hits,
	}
	if len(notes) > 0 {
		payload["notes"] = notes
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Result{Content: string(out)}, nil
}

func (t *SearchDocsTool) searchModules(query, moduleFilter, sectionFilter string, limit, maxBodyChars int) []SearchHit {
	matches, err := t.modIdx.SearchLLM(query, docs.SearchLLMOpts{
		Limit:          limit * 2, // over-fetch, we dedupe + trim
		Module:         moduleFilter,
		Section:        sectionFilter,
		PreferParam:    true,
		PrefixMatchRef: true,
	})
	if err != nil || len(matches) == 0 {
		return nil
	}
	matches = docs.DedupeByParam(matches, t.modIdx)
	if len(matches) > limit {
		matches = matches[:limit]
	}
	confidences := docs.ScoreSummary(matches)
	hits := make([]SearchHit, 0, len(matches))
	for i, m := range matches {
		c := t.modIdx.ChunkByIndex(m.Index)
		hit := SearchHit{
			ID:         c.ID,
			Ref:        c.Ref,
			Section:    sectionOf(c),
			Score:      m.Score,
			Confidence: confidences[i],
			Text:       truncateBody(c.Text, maxBodyChars),
		}
		// When this is a param chunk, surface the structured fields so
		// the LLM can emit YAML without re-parsing the body text.
		if hit.Section == "param" {
			if v, ok := c.Metadata["param_name"].(string); ok {
				hit.ParamName = v
			}
			if v, ok := c.Metadata["param_type"].(string); ok {
				hit.ParamType = v
			}
			if v, ok := c.Metadata["required"].(bool); ok {
				hit.Required = v
			}
			if v, ok := c.Metadata["default"]; ok && v != nil {
				hit.Default = v
			}
			if v, ok := c.Metadata["choices"].([]string); ok {
				hit.Choices = v
			}
			if v, ok := c.Metadata["aliases"].([]string); ok {
				hit.Aliases = v
			}
		}
		hits = append(hits, hit)
	}
	// Attach cross-references and workflow hints.
	attachRelatedExamples(t.modIdx, hits)
	attachSuggestedNext(hits)
	return hits
}

// attachRelatedExamples looks up the example chunk for each hit's
// module (if not already a section="example" hit) and sets the ID.
// We do this in one pass over the in-memory chunk slice rather than
// firing N+1 bleve queries.
func attachRelatedExamples(idx *docs.ModuleIndex, hits []SearchHit) {
	if idx == nil {
		return
	}
	exampleByModule := make(map[string]string, 64)
	for i := 0; i < idx.Size(); i++ {
		c := idx.ChunkByIndex(i)
		if c.Section == "example" {
			if _, ok := exampleByModule[c.Ref]; !ok {
				exampleByModule[c.Ref] = c.ID
			}
		}
	}
	for i := range hits {
		if hits[i].FromPlaybook {
			continue
		}
		if hits[i].Section == "example" {
			continue
		}
		if ex, ok := exampleByModule[hits[i].Ref]; ok {
			hits[i].RelatedExampleID = ex
		}
	}
}

// attachSuggestedNext maps each hit section to a tiny workflow hint
// list. The LLM uses this to decide whether to call
// generate_playbook, search for examples, or stop.
func attachSuggestedNext(hits []SearchHit) {
	for i := range hits {
		if hits[i].FromPlaybook {
			continue
		}
		switch hits[i].Section {
		case "param":
			hits[i].SuggestedNext = []ToolSuggestion{
				{Tool: "generate_playbook", Rationale: "Generate a task using parameter " + hits[i].ParamName + " from " + hits[i].Ref},
			}
			if hits[i].RelatedExampleID != "" {
				hits[i].SuggestedNext = append(hits[i].SuggestedNext,
					ToolSuggestion{Tool: "search_docs", Rationale: "Pull the full playbook example for " + hits[i].Ref})
			}
		case "example":
			hits[i].SuggestedNext = []ToolSuggestion{
				{Tool: "generate_playbook", Rationale: "Generate a playbook adapted from this example"},
			}
		case "synopsis":
			hits[i].SuggestedNext = []ToolSuggestion{
				{Tool: "search_docs", Rationale: "Look up parameters or examples for " + hits[i].Ref},
			}
		}
		// Cap at 3 to keep the JSON compact.
		if len(hits[i].SuggestedNext) > 3 {
			hits[i].SuggestedNext = hits[i].SuggestedNext[:3]
		}
	}
}

func (t *SearchDocsTool) searchPlaybooks(ctx context.Context, query string, limit, maxBodyChars int) ([]SearchHit, error) {
	matches, err := t.pbIdx.Search(ctx, t.pbEmb, query, limit, docs.SourcePlaybook)
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, nil
	}
	confidences := docs.ScoreSummary(matches)
	hits := make([]SearchHit, 0, len(matches))
	for i, m := range matches {
		c := t.pbIdx.ChunkByIndex(m.Index)
		hit := SearchHit{
			ID:           c.ID,
			Ref:          c.Ref,
			Section:      sectionOf(c),
			Score:        m.Score,
			Confidence:   confidences[i],
			Text:         truncateBody(c.Text, maxBodyChars),
			FromPlaybook: true,
		}
		hits = append(hits, hit)
	}
	return hits, nil
}

// sectionOf extracts the chunk's section from metadata, falling back
// to the docs.Chunk.Section field for legacy chunks written by the
// older chunker.
func sectionOf(c docs.Chunk) string {
	if s, ok := c.Metadata["section"].(string); ok && s != "" {
		return s
	}
	return c.Section
}

// truncateBody caps the body to maxChars to keep the LLM context
// under control. We strip the BM25-only "[search-text]\n..." tail
// added by the chunker so the LLM only sees the human text.
func truncateBody(text string, maxChars int) string {
	if i := strings.Index(text, "\n\n[search-text]\n"); i >= 0 {
		text = text[:i]
	}
	text = strings.TrimSpace(text)
	if len(text) <= maxChars {
		return text
	}
	return text[:maxChars] + "..."
}

// dedupeHits removes duplicates by (ref, param_name, from_playbook).
// Two hits with the same key almost always mean the LLM is seeing
// the same fact twice.
func dedupeHits(hits []SearchHit) []SearchHit {
	seen := make(map[string]bool, len(hits))
	out := make([]SearchHit, 0, len(hits))
	for _, h := range hits {
		key := h.Ref + "|" + h.Section + "|" + h.ParamName
		if h.FromPlaybook {
			key = "pb|" + key
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out
}
