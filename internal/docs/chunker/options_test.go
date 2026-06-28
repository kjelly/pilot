package chunker

import (
	"strings"
	"testing"
)

func TestChunkModule_SynopsisOnly(t *testing.T) {
	m := ModuleInput{
		Name:      "ansible.builtin.ping",
		ShortDesc: "Try to connect to host",
	}
	chunks := ChunkModule(m)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1 (synopsis)", len(chunks))
	}
	c := chunks[0]
	if c.Section != SectionSynopsis {
		t.Errorf("section = %s, want synopsis", c.Section)
	}
	if !strings.Contains(c.Search, "What is") && !strings.Contains(c.Search, "How") {
		t.Errorf("Search should contain natural-language hint, got: %q", c.Search)
	}
}

func TestChunkModule_OneChunkPerParam(t *testing.T) {
	m := ModuleInput{
		Name:      "ansible.builtin.service",
		ShortDesc: "Manage services.",
		Options: map[string]OptionsEntry{
			"name":    {Type: "str", Required: true, Description: "Name of the service."},
			"enabled": {Type: "bool", Description: "Whether the service starts at boot."},
			"state":   {Type: "str", Choices: []any{"started", "stopped", "restarted"}, Description: "Desired state."},
		},
	}
	chunks := ChunkModule(m)
	// 3 params + 1 synopsis = 4
	if len(chunks) != 4 {
		t.Fatalf("got %d chunks, want 4 (synopsis + 3 params)", len(chunks))
	}
	got := map[string]bool{}
	for _, c := range chunks {
		if c.Section == SectionParam {
			if got[c.Meta["param_name"].(string)] {
				t.Errorf("duplicate chunk for param %s", c.Meta["param_name"])
			}
			got[c.Meta["param_name"].(string)] = true
		}
	}
	for _, want := range []string{"name", "enabled", "state"} {
		if !got[want] {
			t.Errorf("missing chunk for param %s", want)
		}
	}
}

func TestChunkModule_IDsAreStable(t *testing.T) {
	m := ModuleInput{
		Name:      "ansible.builtin.service",
		ShortDesc: "Service control.",
		Options: map[string]OptionsEntry{
			"enabled": {Type: "bool"},
		},
	}
	a := ChunkModule(m)
	b := ChunkModule(m)
	if len(a) != len(b) {
		t.Fatalf("non-deterministic: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			t.Errorf("ID drift: %s vs %s", a[i].ID, b[i].ID)
		}
	}
}

func TestChunkModule_SearchTextContainsQuestion(t *testing.T) {
	m := ModuleInput{
		Name:      "ansible.builtin.service",
		ShortDesc: "Service control.",
		Options: map[string]OptionsEntry{
			"enabled": {Type: "bool", Description: "Whether the service starts at boot."},
		},
	}
	chunks := ChunkModule(m)
	var param *Chunk
	for i := range chunks {
		if chunks[i].Section == SectionParam {
			param = &chunks[i]
		}
	}
	if param == nil {
		t.Fatal("no param chunk")
	}
	if !strings.Contains(param.Search, "How to") {
		t.Errorf("Search should contain 'How to', got: %q", param.Search)
	}
	if !strings.Contains(param.Search, "service") {
		t.Errorf("Search should mention module name, got: %q", param.Search)
	}
}

func TestChunkModule_MetaCarriesChoices(t *testing.T) {
	m := ModuleInput{
		Name:      "ansible.builtin.service",
		ShortDesc: "Service control.",
		Options: map[string]OptionsEntry{
			"state": {Type: "str", Choices: []any{"started", "stopped", "restarted"}},
		},
	}
	chunks := ChunkModule(m)
	var param *Chunk
	for i := range chunks {
		if chunks[i].Section == SectionParam && chunks[i].Meta["param_name"] == "state" {
			param = &chunks[i]
		}
	}
	if param == nil {
		t.Fatal("no state chunk")
	}
	cs, ok := param.Meta["choices"].([]string)
	if !ok {
		t.Fatalf("choices not []string: %T", param.Meta["choices"])
	}
	want := map[string]bool{"started": false, "stopped": false, "restarted": false}
	for _, c := range cs {
		want[c] = true
	}
	for k, v := range want {
		if !v {
			t.Errorf("missing choice %s", k)
		}
	}
}

func TestChunkModule_TextShowsRequiredFlag(t *testing.T) {
	m := ModuleInput{
		Name:      "ansible.builtin.service",
		ShortDesc: "Service control.",
		Options: map[string]OptionsEntry{
			"name": {Type: "str", Required: true},
		},
	}
	chunks := ChunkModule(m)
	var param *Chunk
	for i := range chunks {
		if chunks[i].Section == SectionParam {
			param = &chunks[i]
		}
	}
	if param == nil {
		t.Fatal("no param chunk")
	}
	if !strings.Contains(param.Text, "required=true") {
		t.Errorf("Text should show required=true, got: %q", param.Text)
	}
}

func TestChunkModule_SubOptions(t *testing.T) {
	m := ModuleInput{
		Name:      "ansible.builtin.copy",
		ShortDesc: "Copy files.",
		Options: map[string]OptionsEntry{
			"validate": {
				Type: "str",
				SubOptions: map[string]OptionsEntry{
					"remote_addr": {Type: "str"},
				},
			},
		},
	}
	chunks := ChunkModule(m)
	// synopsis + validate + validate.remote_addr = 3
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	found := false
	for _, c := range chunks {
		if c.ID == "modules:ansible.builtin.copy:param:validate.remote_addr" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing sub-option chunk; got IDs: %+v", chunks)
	}
}

func TestVerbFor_KnownParam(t *testing.T) {
	if v := VerbFor("enabled"); !strings.Contains(v, "boot") {
		t.Errorf("VerbFor(enabled) = %q, want something with 'boot'", v)
	}
}

func TestVerbFor_UnknownFallsBack(t *testing.T) {
	if v := VerbFor("totally_made_up_param"); !strings.HasPrefix(v, "configure ") {
		t.Errorf("fallback should be 'configure <name>', got: %q", v)
	}
}

func TestSynonymsFor_KnownParam(t *testing.T) {
	got := SynonymsFor("enabled")
	if len(got) == 0 {
		t.Fatal("expected synonyms for 'enabled'")
	}
	found := false
	for _, s := range got {
		if strings.Contains(s, "boot") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'boot' synonym, got: %v", got)
	}
}

func TestToDocsChunk_PreservesStructuredMeta(t *testing.T) {
	c := Chunk{
		ID:      "modules:ansible.builtin.service:param:enabled",
		Ref:     "ansible.builtin.service",
		Section: SectionParam,
		Text:    "service.enabled (type=bool)\nWhether the service starts at boot.",
		Search:  "How to control whether a service starts at boot in service.",
		Meta: map[string]any{
			"param_name": "enabled",
			"param_type": "bool",
			"required":   false,
		},
	}
	dc := ToDocsChunk(c)
	if dc.Ref != c.Ref {
		t.Errorf("ref: %s vs %s", dc.Ref, c.Ref)
	}
	if dc.Metadata["param_name"] != "enabled" {
		t.Errorf("param_name not preserved in meta")
	}
	if !strings.Contains(dc.Text, "service.enabled") {
		t.Errorf("Text not in docs.Chunk.Text: %q", dc.Text)
	}
}
