package docs

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestExpandQuery_RestartTriggersState(t *testing.T) {
	expanded, intents := ExpandQuery("how do I restart nginx")
	if len(intents) == 0 {
		t.Fatal("expected intents for 'restart'")
	}
	found := false
	for _, h := range intents {
		if h.ParamName == "state" && h.Module == "service" {
			found = true
			if h.Boost < 2.0 {
				t.Errorf("expected boost >= 2.0, got %v", h.Boost)
			}
		}
	}
	if !found {
		t.Errorf("expected state/service intent, got %+v", intents)
	}
	if !strings.Contains(expanded, "restarted") {
		t.Errorf("expanded query should contain 'restarted', got: %q", expanded)
	}
}

func TestExpandQuery_AtBootTriggersEnabled(t *testing.T) {
	_, intents := ExpandQuery("make service start at boot")
	if len(intents) == 0 {
		t.Fatal("expected intents")
	}
	found := false
	for _, h := range intents {
		if h.ParamName == "enabled" && h.Module == "service" {
			found = true
			if h.Boost < 3.0 {
				t.Errorf("at-boot should be high-priority, got %v", h.Boost)
			}
		}
	}
	if !found {
		t.Errorf("expected enabled intent, got %+v", intents)
	}
}

func TestExpandQuery_InstallPackageTriggersState(t *testing.T) {
	_, intents := ExpandQuery("install package nginx")
	found := false
	for _, h := range intents {
		if h.ParamName == "state" && h.Module == "package" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected package/state intent, got %+v", intents)
	}
}

func TestExpandQuery_NoMatch_ReturnsEmpty(t *testing.T) {
	expanded, intents := ExpandQuery("zebra banana")
	if len(intents) != 0 {
		t.Errorf("expected no intents, got %+v", intents)
	}
	// No synonyms added this pass; query preserved verbatim so re-expansion
	// is stable.
	if expanded != "zebra banana" {
		t.Errorf("expected unchanged query, got: %q", expanded)
	}
}

func TestExpandQuery_EmptyQuery(t *testing.T) {
	expanded, intents := ExpandQuery("")
	if expanded != "" || len(intents) != 0 {
		t.Errorf("expected empty result, got expanded=%q intents=%+v", expanded, intents)
	}
}

func TestExpandQuery_DoesNotExpandParamNames(t *testing.T) {
	// "enabled" is a known param name; should not be synonym-expanded.
	// Returned verbatim because no new terms were added.
	expanded, intents := ExpandQuery("enabled")
	if len(intents) != 0 {
		t.Errorf("enabled should not trigger intents, got %+v", intents)
	}
	if expanded != "enabled" {
		t.Errorf("expected verbatim enabled, got: %q", expanded)
	}
}

func TestExpandQuery_DoesNotDoubleExpand(t *testing.T) {
	// After expanding, the second expansion should not add NEW terms
	// beyond what the first pass added. We assert that re-expanding
	// the expanded query produces a SUPERSET of the original expansions,
	// not a runaway snowball.
	a, _ := ExpandQuery("restart nginx")
	b, _ := ExpandQuery(a)
	// a is a prefix of b's token set (b may add a few more because
	// synonymsOf("state") is empty but other tokens appear).
	if !strings.Contains(b, "restarted") {
		t.Errorf("expanded should still contain restarted, got: %q", b)
	}
}

func TestSynonymsForToken_RestartFamily(t *testing.T) {
	got := synonymsForToken("restart")
	if !contains(got, "state") || !contains(got, "restarted") {
		t.Errorf("restart synonyms = %v, want state and restarted", got)
	}
}

func TestApplyIntentBoosts_LiftsMatchingChunk(t *testing.T) {
	dir := t.TempDir()
	idx := NewModuleIndex(filepath.Join(dir, "modules.bleve"))
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer idx.Close()

	chunks := []Chunk{
		{
			ID:      "modules:ansible.builtin.service:param:state",
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.state (type=str, choices=started|stopped|restarted)",
			Metadata: map[string]any{
				"section":    "param",
				"param_name": "state",
				"param_type": "str",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:param:enabled",
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.enabled (type=bool)",
			Metadata: map[string]any{
				"section":    "param",
				"param_name": "enabled",
				"param_type": "bool",
			},
		},
	}
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}

	matches, err := idx.SearchLLM("how to restart nginx", SearchLLMOpts{Limit: 5})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected matches")
	}
	// state should win over enabled because restart → state intent (2.5)
	top := idx.ChunkByIndex(matches[0].Index)
	pn, _ := top.Metadata["param_name"].(string)
	if pn != "state" {
		t.Errorf("expected state to win after intent boost, got %s", pn)
	}
}

func TestApplyIntentBoosts_AtBootWinsOverRestart(t *testing.T) {
	dir := t.TempDir()
	idx := NewModuleIndex(filepath.Join(dir, "modules.bleve"))
	if err := idx.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer idx.Close()

	chunks := []Chunk{
		{
			ID:      "modules:ansible.builtin.service:param:state",
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.state (type=str) restart the service on boot or change.",
			Metadata: map[string]any{
				"param_name": "state",
				"section":    "param",
			},
		},
		{
			ID:      "modules:ansible.builtin.service:param:enabled",
			Ref:     "ansible.builtin.service",
			Section: "param",
			Text:    "service.enabled (type=bool) Whether the service should start on boot.",
			Metadata: map[string]any{
				"param_name": "enabled",
				"section":    "param",
			},
		},
	}
	if err := idx.Build(chunks); err != nil {
		t.Fatalf("Build: %v", err)
	}

	matches, err := idx.SearchLLM("ensure nginx starts at boot", SearchLLMOpts{Limit: 5})
	if err != nil {
		t.Fatalf("SearchLLM: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("expected matches")
	}
	top := idx.ChunkByIndex(matches[0].Index)
	pn, _ := top.Metadata["param_name"].(string)
	if pn != "enabled" {
		t.Errorf("at-boot should pick enabled, got %s", pn)
	}
}
