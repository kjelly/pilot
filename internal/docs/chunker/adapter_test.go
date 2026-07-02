package chunker

import (
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/docs"
)

// TestBuildLLMChunks_PreservesRichTypes is the integration test for
// Task 1: confirm that docs.ModuleDoc.RichOptions flows through the
// chunker into the chunk Text and Meta with type/choices/default
// intact.
func TestBuildLLMChunks_PreservesRichTypes(t *testing.T) {
	_ = docs.ModuleDoc{} // smoke import
	m := docs.ModuleDoc{
		Name:      "ansible.builtin.service",
		ShortDesc: "Manage services.",
		RichOptions: map[string]docs.OptionDoc{
			"enabled": {
				Name:        "enabled",
				Type:        "bool",
				Description: "Whether the service should start on boot.",
			},
			"state": {
				Name:         "state",
				Type:         "str",
				Default:      "started",
				Choices:      []any{"started", "stopped", "restarted", "reloaded"},
				Description:  "Desired state of the service.",
				VersionAdded: "0.1",
				Aliases:      []string{"status"},
			},
			"validate": {
				Name:        "validate",
				Type:        "str",
				Description: "Validation command.",
				SubOptions: map[string]docs.OptionDoc{
					"remote_addr": {
						Name:    "remote_addr",
						Type:    "str",
						Default: "127.0.0.1",
					},
				},
			},
		},
	}
	in := ModuleInput{
		Name:      m.Name,
		ShortDesc: m.ShortDesc,
		Options:   convertOptionsForTest(m.RichOptions),
	}
	chunks := ChunkModule(in)
	var state, enabled, validate *Chunk
	for i := range chunks {
		switch chunks[i].Meta["param_name"] {
		case "state":
			state = &chunks[i]
		case "enabled":
			enabled = &chunks[i]
		case "validate":
			validate = &chunks[i]
		}
	}
	if state == nil {
		t.Fatal("no state chunk")
	}
	if state.Meta["param_type"] != "str" {
		t.Errorf("state param_type = %v, want str", state.Meta["param_type"])
	}
	if got, _ := state.Meta["default"].(string); got != "started" {
		t.Errorf("state default = %v, want \"started\"", state.Meta["default"])
	}
	choices, ok := state.Meta["choices"].([]string)
	if !ok || len(choices) != 4 {
		t.Fatalf("state choices = %v, want 4 entries", state.Meta["choices"])
	}
	if !contains(choices, "restarted") {
		t.Errorf("state choices missing restarted: %v", choices)
	}
	if state.Meta["version_added"] != "0.1" {
		t.Errorf("state version_added = %v", state.Meta["version_added"])
	}
	if !strings.Contains(state.Text, "default=started") {
		t.Errorf("state Text missing default=started, got: %q", state.Text)
	}
	if !strings.Contains(state.Text, "choices=started|stopped|restarted|reloaded") {
		t.Errorf("state Text missing choices, got: %q", state.Text)
	}

	if enabled == nil {
		t.Fatal("no enabled chunk")
	}
	if enabled.Meta["param_type"] != "bool" {
		t.Errorf("enabled param_type = %v, want bool", enabled.Meta["param_type"])
	}

	// Sub-option recursion
	var validateSub *Chunk
	for i := range chunks {
		if chunks[i].ID == "modules:ansible.builtin.service:param:validate.remote_addr" {
			validateSub = &chunks[i]
		}
	}
	if validateSub == nil {
		t.Fatal("no sub-option chunk")
	}
	if validateSub.Meta["param_type"] != "str" {
		t.Errorf("sub param_type = %v, want str", validateSub.Meta["param_type"])
	}
	if got, _ := validateSub.Meta["default"].(string); got != "127.0.0.1" {
		t.Errorf("sub default = %v, want 127.0.0.1", validateSub.Meta["default"])
	}
	_ = validate
}

// convertOptionsForTest mirrors what cmd/pilot/cmd/chunk_adapter.go
// does so we can test it in isolation without the cmd package.
func convertOptionsForTest(rich map[string]docs.OptionDoc) map[string]OptionsEntry {
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
