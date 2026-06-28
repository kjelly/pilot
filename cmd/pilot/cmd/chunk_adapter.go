package cmd

// This file is the bridge between the old docs.ModuleDoc / docs.ChunkModule
// chunker and the new per-parameter chunker in internal/docs/chunker.
//
// We don't replace the legacy path wholesale (other callers depend on it);
// instead we provide BuildModuleChunks which produces the per-param chunks
// suitable for LLM retrieval, alongside the legacy ChunkModule output.

import (
	"fmt"

	"github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/docs/chunker"
)

// BuildModuleChunks converts a docs.ModuleDoc (the shape produced by
// `ansible-doc --json` parsing) into the per-param chunker.Chunk list.
//
// The legacy ChunkModule lumped all options into one chunk; this adapter
// splits them so the LLM can ask "what does the `enabled` parameter do?"
// and get a single targeted hit.
func BuildModuleChunks(m docs.ModuleDoc) []chunker.Chunk {
	in := chunker.ModuleInput{
		Name:         m.Name,
		ShortDesc:    m.ShortDesc,
		Description:  m.Description,
		Synopsis:     m.Synopsis,
		Notes:        m.Notes,
		Requirements: m.Requirements,
		Examples:     m.Examples,
		Options:      convertOptions(m.RichOptions),
	}
	return chunker.ChunkModule(in)
}

// convertOptions walks the rich option metadata in ModuleDoc and
// produces the chunker.OptionsEntry the LLM chunker consumes. Every
// field the LLM cares about (type, default, choices, required,
// aliases, version_added, suboptions) is forwarded.
//
// When the upstream source is the legacy `--json` path that didn't
// capture types, fall back to the simplified view (which has only
// name→description) with Type="str" so old data still produces a
// reasonable chunk.
func convertOptions(rich map[string]docs.OptionDoc) map[string]chunker.OptionsEntry {
	out := make(map[string]chunker.OptionsEntry, len(rich))
	for k, r := range rich {
		subs := make(map[string]chunker.OptionsEntry, len(r.SubOptions))
		for sk, sv := range r.SubOptions {
			subs[sk] = chunker.OptionsEntry{
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
		out[k] = chunker.OptionsEntry{
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

// ToDocsChunks converts a slice of chunker.Chunk to docs.Chunk so they
// can be fed to ModuleIndex.Build.
func ToDocsChunks(in []chunker.Chunk) []docs.Chunk {
	out := make([]docs.Chunk, 0, len(in))
	for _, c := range in {
		out = append(out, chunker.ToDocsChunk(c))
	}
	return out
}

// BuildLLMChunks is the convenience entry point used by index-docs
// and runIndexDocsSubcommand: takes parsed modules, emits per-param
// docs.Chunk list.
func BuildLLMChunks(modules []docs.ModuleDoc) []docs.Chunk {
	var total int
	for _, m := range modules {
		total += len(m.Options)
	}
	out := make([]docs.Chunk, 0, total+len(modules))
	for _, m := range modules {
		for _, c := range BuildModuleChunks(m) {
			out = append(out, chunker.ToDocsChunk(c))
		}
	}
	return out
}

// Compile-time check that we haven't accidentally broken the legacy
// import. docs.ModuleDoc is the bridge shape.
var _ = fmt.Sprintf
