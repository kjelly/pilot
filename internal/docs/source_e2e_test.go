//go:build e2e
// +build e2e

package docs_test

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	docs "github.com/anomalyco/pilot/internal/docs"
	"github.com/anomalyco/pilot/internal/docs/chunker"
)

// TestE2E_RealAnsibleDoc is an end-to-end smoke test: invoke the
// real `ansible-doc --metadata-dump`, parse it through the full
// chunker, build a bleve index, and verify the LLM-facing search
// returns the expected hits.
//
// Run with:  go test -tags=e2e ./internal/docs/ -run TestE2E_RealAnsibleDoc -v
//
// Skipped automatically when ansible-doc is not on PATH.
func TestE2E_RealAnsibleDoc(t *testing.T) {
	bin, err := exec.LookPath("ansible-doc")
	if err != nil {
		t.Skipf("ansible-doc not on PATH: %v", err)
	}
	t.Logf("using %s", bin)

	ctx := context.Background()
	ver, err := docs.AnsibleVersion(ctx)
	if err != nil {
		t.Skipf("ansible --version failed: %v", err)
	}
	t.Logf("ansible version: %s", ver)

	// Fetch via the metadata-dump path (newer) or --json (older).
	// Fetch a small targeted set of modules via `ansible-doc -j` so
	// the test stays under 30s even on slow CI. We exercise service
	// (state machine), copy (file ops with sub-options), lineinfile
	// (regexp), and user (uid/gid).
	names := []string{
		"ansible.builtin.service",
		"ansible.builtin.copy",
		"ansible.builtin.lineinfile",
		"ansible.builtin.user",
	}
	var mods []docs.ModuleDoc
	for _, name := range names {
		bin := binOverrideForTest(t)
		cmd := exec.CommandContext(ctx, bin, "-t", "module", "-j", name)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("ansible-doc -j %s: %v", name, err)
		}
		parsed, err := docs.ParseModuleJSON(out)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		mods = append(mods, parsed...)
	}
	t.Logf("fetched %d modules: %v", len(mods), names)

	var serviceMod *docs.ModuleDoc
	for i := range mods {
		if mods[i].Name == "ansible.builtin.service" || mods[i].Name == "service" {
			serviceMod = &mods[i]
			break
		}
	}
	if serviceMod == nil {
		t.Fatalf("service module not found")
	}
	t.Logf("service: short_desc=%q options=%d", serviceMod.ShortDesc, len(serviceMod.RichOptions))
	if got, want := len(serviceMod.RichOptions) > 0, true; got != want {
		t.Errorf("service.RichOptions empty (metadata-dump didn't capture types)")
	}
	stateOpt, ok := serviceMod.RichOptions["state"]
	if !ok {
		t.Fatal("service.state missing")
	}
	if stateOpt.Type != "str" {
		t.Errorf("service.state.Type = %q, want str", stateOpt.Type)
	}
	if len(stateOpt.Choices) == 0 {
		t.Errorf("service.state.Choices empty; ansible-doc format unexpected?")
	}
	t.Logf("service.state: type=%s choices=%v", stateOpt.Type, stateOpt.Choices)

	enabledOpt, ok := serviceMod.RichOptions["enabled"]
	if !ok {
		t.Fatal("service.enabled missing")
	}
	if enabledOpt.Type != "bool" {
		t.Errorf("service.enabled.Type = %q, want bool", enabledOpt.Type)
	}

	// Build a small index from just the service module so we can
	// test the LLM retrieval path quickly without polluting the
	// bleve index with thousands of modules.
	dir := t.TempDir()
	blevePath := filepath.Join(dir, "modules.bleve")
	idx := docs.NewModuleIndex(blevePath)
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer idx.Close()

	// Chunk via the chunker package via the cmd adapter equivalent.
	// Since this is a docs-package test, inline the conversion.
	chunks := serviceChunksForTest(*serviceMod)
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Logf("indexed %d chunks for service", idx.Size())

	// LLM queries — verify the right chunks win.
	tests := []struct {
		query       string
		wantParam   string
		wantType    string
		description string
		inTop       int
	}{
		{
			query:       "restart the nginx service",
			wantParam:   "state",
			wantType:    "str",
			description: "intent: restart → state",
		},
		{
			query:       "make nginx start at boot",
			wantParam:   "enabled",
			wantType:    "bool",
			description: "intent: at-boot → enabled",
		},
		{
			query:       "enabled",
			wantParam:   "enabled",
			wantType:    "bool",
			description: "direct param name",
		},

	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			matches, err := idx.SearchLLM(tc.query, docs.SearchLLMOpts{
				Limit:          5,
				Module:         "ansible.builtin.service",
				PreferParam:    true,
				PrefixMatchRef: true,
			})
			if err != nil {
				t.Fatalf("SearchLLM: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("no matches for %q", tc.query)
			}
			topK := tc.inTop
			if topK <= 0 {
				topK = 1
			}
			found := false
			for i := 0; i < topK && i < len(matches); i++ {
				c := idx.ChunkByIndex(matches[i].Index)
				if pn, _ := c.Metadata["param_name"].(string); pn == tc.wantParam {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("query=%q: param %q not in top %d (got: %v)", tc.query, tc.wantParam, topK, paramNames(idx, matches))
			}
			top := idx.ChunkByIndex(matches[0].Index)
			if tc.wantType != "" {
				if got, _ := top.Metadata["param_type"].(string); got != tc.wantType {
					t.Errorf("query=%q: param_type = %q, want %q", tc.query, got, tc.wantType)
				}
			}
			t.Logf("query=%q → top=%s score=%.3f confidence=%.3f",
				tc.query, top.ID, matches[0].Score,
				docs.ScoreSummary(matches)[0])
		})
	}

	// Confirm the LLM gets the structured choices.
	t.Run("choices_in_metadata", func(t *testing.T) {
		var stateChunk *docs.Chunk
		for i := 0; i < idx.Size(); i++ {
			c := idx.ChunkByIndex(i)
			if pn, _ := c.Metadata["param_name"].(string); pn == "state" {
				stateChunk = &c
			}
		}
		if stateChunk == nil {
			t.Fatal("no state chunk")
		}
		cs, ok := stateChunk.Metadata["choices"].([]string)
		if !ok {
			t.Fatalf("choices not []string: %T", stateChunk.Metadata["choices"])
		}
		for _, want := range []string{"started", "stopped", "restarted"} {
			found := false
			for _, c := range cs {
				if strings.Contains(c, want) {
					found = true
				}
			}
			if !found {
				t.Errorf("missing %s in choices %v", want, cs)
			}
		}
	})

	// Confirm the chunker.Text mentions the type so the LLM sees
	// "service.state (type=str, choices=started|stopped|...)".
	t.Run("text_carries_type", func(t *testing.T) {
		var stateChunk *docs.Chunk
		for i := 0; i < idx.Size(); i++ {
			c := idx.ChunkByIndex(i)
			if pn, _ := c.Metadata["param_name"].(string); pn == "state" {
				stateChunk = &c
			}
		}
		if stateChunk == nil {
			t.Fatal("no state chunk")
		}
		// Pull the body without the [search-text] tail.
		text := stateChunk.Text
		if i := strings.Index(text, "\n\n[search-text]"); i >= 0 {
			text = text[:i]
		}
		if !strings.Contains(text, "type=str") {
			t.Errorf("body missing type=str: %q", text)
		}
		if !strings.Contains(text, "choices=") {
			t.Errorf("body missing choices=: %q", text)
		}
	})
}

// serviceChunksForTest builds the chunk list for a single module by
// delegating to the canonical chunker adapter. Equivalent to
// cmd/pilot/cmd/BuildModuleChunks but accessible from a test package.
func serviceChunksForTest(m docs.ModuleDoc) []docs.Chunk {
	return chunker.BuildFromModuleDoc(m)
}

/*
*/

// binOverrideForTest returns the ansible-doc binary, or skips when
// not available.
func binOverrideForTest(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("ansible-doc")
	if err != nil {
		t.Skipf("ansible-doc not on PATH: %v", err)
	}
	return bin
}

func paramNames(idx *docs.ModuleIndex, matches []docs.Match) []string {
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		c := idx.ChunkByIndex(m.Index)
		if pn, ok := c.Metadata["param_name"].(string); ok {
			out = append(out, pn)
		} else {
			out = append(out, c.Section)
		}
	}
	return out
}
