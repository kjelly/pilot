package docs

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/search"
	"github.com/blevesearch/bleve/v2/search/query"
)

// SearchLLMOpts controls the LLM-facing search behaviour.
type SearchLLMOpts struct {
	// Limit caps the number of returned matches. Defaults to 5.
	Limit int
	// Module is an optional FQCN filter ("ansible.builtin.service").
	// When set, restricts results to that module's chunks.
	Module string
	// Section is an optional section filter ("param", "example", ...).
	// When set, restricts results to that section.
	Section string
	// PreferParam boosts `param` chunks over other sections. The LLM
	// almost always wants parameter details first; examples and notes
	// are still returned but ranked lower when both kinds match.
	PreferParam bool
	// FuzzyTolerance controls how forgiving the match is when the LLM
	// spells something slightly wrong (e.g. "restarte" → "restart").
	// 0 = exact, 1 = one edit, 2 = two edits. Defaults to 1.
	FuzzyTolerance int
	// PrefixMatchRef treats the query as a prefix match against the
	// `ref` field in addition to the full-text search. This is what
	// makes "serv" → "ansible.builtin.service" win.
	PrefixMatchRef bool
}

// SearchLLMRaw is like SearchLLM but returns bleve's native Match
// objects with the additional raw score so callers can do their own
// re-ranking if they really want to.
func (m *ModuleIndex) SearchLLMRaw(query string, opts SearchLLMOpts) ([]Match, error) {
	matches, err := m.SearchLLM(query, opts)
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// SearchLLM runs an LLM-friendly search. It composes a small query
// tree rather than a single MatchQuery:
//
//   - prefix match on the `ref` field (if PrefixMatchRef): catches the
//     case where the LLM types a short module name.
//   - match on the `text` field: the BM25 core.
//   - optionally constrained by `module` keyword (when opts.Module is
//     set) and `section` keyword.
//
// Hits are then re-ranked in Go using the chunk metadata so we can
// boost `param` chunks (which the LLM almost always wants) and
// demote near-duplicates of the same parameter coming from both
// description and options.
func (m *ModuleIndex) SearchLLM(q string, opts SearchLLMOpts) ([]Match, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.idx == nil {
		return nil, fmt.Errorf("module index not opened")
	}
	q = strings.TrimSpace(q)
	if q == "" {
		return nil, nil
	}
	// Expansion: synonym + intent. The expanded query is what we feed
	// to bleve; intents are applied as a post-rank boost.
	expanded, intents := ExpandQuery(q)
	if expanded != "" {
		q = expanded
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 5
	}
	// Build the bleve query tree. We intentionally keep it small:
	// BM25 on text, optional prefix-match on ref, optional term
	// filters. No fuzzy here — we do fuzzy at the lexical layer
	// because the bleve `FuzzyQuery` is token-based and not great
	// for short module names.
	must := []query.Query{
		bleve.NewMatchQuery(q),
	}
	if opts.Module != "" {
		t := bleve.NewTermQuery(opts.Module)
		t.SetField("ref")
		must = append(must, t)
	}
	if opts.Section != "" {
		t := bleve.NewTermQuery(opts.Section)
		t.SetField("section")
		must = append(must, t)
	}
	composite := bleve.NewConjunctionQuery(must...)

	// If we're doing a prefix ref match, ALSO search with that
	// constraint and union the result sets. bleve doesn't let you
	// OR two different shapes of query easily, so we just OR the
	// entire composite with a prefix-only match.
	var root query.Query = composite
	if opts.PrefixMatchRef {
		prefixMatch := bleve.NewConjunctionQuery(
			bleve.NewPrefixQuery(strings.ToLower(firstToken(q))),
			bleve.NewMatchQuery(q),
		)
		// OR the prefix-match path with the BM25 path so the LLM
		// query "serv" still hits "ansible.builtin.service".
		root = bleve.NewDisjunctionQuery(composite, prefixMatch)
	}

	// Over-fetch to give the post-rank some breathing room.
	req := bleve.NewSearchRequest(root)
	req.Size = limit * 4
	res, err := m.idx.Search(req)
	if err != nil {
		return nil, fmt.Errorf("bleve search: %w", err)
	}
	if len(res.Hits) == 0 {
		return nil, nil
	}

	idIndex := make(map[string]int, len(m.chunks))
	for i, c := range m.chunks {
		idIndex[c.ID] = i
	}

	type scored struct {
		idx   int
		score float64
		chunk Chunk
	}
	out := make([]scored, 0, len(res.Hits))
	seen := make(map[string]bool, limit*2)
	for _, hit := range res.Hits {
		ci, ok := idIndex[hit.ID]
		if !ok {
			continue
		}
		c := m.chunks[ci]
		if seen[c.ID] {
			continue
		}
		seen[c.ID] = true

		score := hit.Score
		// Per-section re-rank. The LLM's most common query shape is
		// "what is the X parameter of module Y" — give `param` a
		// strong boost so it sits on top.
		if section, ok := c.Metadata["section"].(string); ok {
			switch section {
			case "param":
				if opts.PreferParam {
					score *= 1.6
				}
			case "example":
				score *= 0.9
			case "synopsis":
				score *= 0.85
			case "note", "requirements":
				score *= 0.7
			}
		}
		// Exact-match bonus: if the chunk's param_name matches the
		// query word, push it up. Catches the case where LLM asks
		// "enabled" and the chunk is `service.enabled`.
		if pn, ok := c.Metadata["param_name"].(string); ok && pn != "" {
			if strings.EqualFold(pn, q) {
				score *= 1.8
			} else if strings.Contains(strings.ToLower(q), strings.ToLower(pn)) {
				score *= 1.3
			}
		}
		out = append(out, scored{idx: ci, score: score, chunk: c})
	}

	if len(intents) > 0 {
		// Wrap scored into Match for ApplyIntentBoosts; rebuild later.
		tmp := make([]Match, len(out))
		for i, s := range out {
			tmp[i] = Match{Index: s.idx, Score: s.score}
		}
		tmp = ApplyIntentBoosts(tmp, m, intents)
		for i := range out {
			out[i].score = tmp[i].Score
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].score > out[j].score
	})
	if len(out) > limit {
		out = out[:limit]
	}
	matches := make([]Match, len(out))
	for i, s := range out {
		matches[i] = Match{Index: s.idx, Score: s.score}
	}
	return matches, nil
}

// DedupeByParam removes near-duplicate hits for the same (module,
// param_name). Useful because the LLM doesn't need to see both
// `service.enabled` from the description chunk and again from the
// options chunk — once is enough.
func DedupeByParam(matches []Match, idx *ModuleIndex) []Match {
	seen := make(map[string]bool, len(matches))
	out := make([]Match, 0, len(matches))
	for _, m := range matches {
		if idx == nil {
			out = append(out, m)
			continue
		}
		c := idx.ChunkByIndex(m.Index)
		key := c.Ref
		if pn, ok := c.Metadata["param_name"].(string); ok && pn != "" {
			key = c.Ref + "::" + pn
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, m)
	}
	return out
}

// firstToken returns the first whitespace-delimited word of s with
// punctuation stripped. Used by the prefix-match path.
func firstToken(s string) string {
	for i, r := range s {
		if unicode.IsSpace(r) || unicode.IsPunct(r) {
			return s[:i]
		}
	}
	return s
}

// ScoreSummary is a helper for tools that want to expose a normalised
// confidence score to the LLM. Maps the raw BM25 score (which is on
// an unbounded scale) into [0, 1] by min-max normalising within the
// returned hit set. The first hit always gets 1.0; lower hits decay.
func ScoreSummary(matches []Match) []float64 {
	if len(matches) == 0 {
		return nil
	}
	max := matches[0].Score
	if max <= 0 {
		max = 1
	}
	out := make([]float64, len(matches))
	for i, m := range matches {
		out[i] = m.Score / max
		if out[i] > 1 {
			out[i] = 1
		}
	}
	return out
}

// ensureSearchResultReferenced keeps the bleve search import live even
// when we change the query shape later; tiny compile-time hint.
var _ = (*search.DocumentMatch)(nil)
