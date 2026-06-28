package chunker

import (
	"github.com/anomalyco/pilot/internal/docs"
)

// BuildFromModuleDoc converts a docs.ModuleDoc into the per-parameter
// chunk list, then to docs.Chunk, ready to feed to docs.ModuleIndex.
// This is the canonical adapter used by the cmd layer; we expose it
// from the chunker package so test code (which lives outside cmd) can
// reuse the same logic without reimplementing it.
func BuildFromModuleDoc(m docs.ModuleDoc) []docs.Chunk {
	in := ModuleInput{
		Name:         m.Name,
		ShortDesc:    m.ShortDesc,
		Description:  m.Description,
		Synopsis:     m.Synopsis,
		Notes:        m.Notes,
		Requirements: m.Requirements,
		Examples:     m.Examples,
		Options:      convertRich(m.RichOptions),
	}
	out := []docs.Chunk{}
	for _, c := range ChunkModule(in) {
		out = append(out, ToDocsChunk(c))
	}
	return out
}

// convertRich is the same adapter logic as cmd/pilot/cmd/chunk_adapter.go.
// Kept inline here so callers outside cmd don't have to depend on cmd.
func convertRich(rich map[string]docs.OptionDoc) map[string]OptionsEntry {
	out := make(map[string]OptionsEntry, len(rich))
	for k, r := range rich {
		subs := make(map[string]OptionsEntry, len(r.SubOptions))
		for sk, sv := range r.SubOptions {
			subs[sk] = OptionsEntry{
				Name:         sk,
				Type:         sv.Type,
				Description:  sv.Description,
				Required:     sv.Required,
				Default:      sv.Default,
				Choices:      sv.Choices,
				Aliases:      sv.Aliases,
				VersionAdded: sv.VersionAdded,
			}
		}
		if r.Type == "" {
			r.Type = "str"
		}
		out[k] = OptionsEntry{
			Name:         k,
			Type:         r.Type,
			Description:  r.Description,
			Required:     r.Required,
			Default:      r.Default,
			Choices:      r.Choices,
			Aliases:      r.Aliases,
			VersionAdded: r.VersionAdded,
			SubOptions:   subs,
		}
	}
	return out
}
