package docs

import (
	"strings"
	"testing"
)

func TestParseModuleJSON_RichOptions(t *testing.T) {
	raw := []byte(`{
		"service": {
			"doc": {
				"short_description": "Manage services.",
				"options": {
					"name": {
						"description": "Name of the service.",
						"required": true,
						"type": "str"
					},
					"state": {
						"description": "Desired state.",
						"type": "str",
						"choices": ["started", "stopped", "restarted"],
						"default": "started"
					},
					"enabled": {
						"description": "Start at boot.",
						"type": "bool"
					},
					"validate": {
						"type": "str",
						"description": "Validate command",
						"suboptions": {
							"remote_addr": {
								"type": "str",
								"default": "127.0.0.1"
							}
						}
					}
				}
			},
			"filename": "/x.py"
		}
	}`)
	mods, err := ParseModuleJSON(raw)
	if err != nil {
		t.Fatalf("ParseModuleJSON: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("got %d modules, want 1", len(mods))
	}
	m := mods[0]
	if got, want := len(m.RichOptions), 4; got != want {
		t.Fatalf("RichOptions size = %d, want %d", got, want)
	}

	// state: choices/default/type all preserved
	state := m.RichOptions["state"]
	if state.Type != "str" {
		t.Errorf("state.Type = %q, want str", state.Type)
	}
	if len(state.Choices) != 3 {
		t.Errorf("state.Choices len = %d, want 3", len(state.Choices))
	}
	if got, ok := state.Default.(string); !ok || got != "started" {
		t.Errorf("state.Default = %v, want \"started\"", state.Default)
	}

	// name: required flag
	name := m.RichOptions["name"]
	if !name.Required {
		t.Errorf("name.Required should be true")
	}

	// validate: suboptions recurse
	val := m.RichOptions["validate"]
	if len(val.SubOptions) != 1 {
		t.Errorf("validate.SubOptions size = %d, want 1", len(val.SubOptions))
	}
	sub := val.SubOptions["remote_addr"]
	if sub.Default != "127.0.0.1" {
		t.Errorf("remote_addr.Default = %v", sub.Default)
	}

	// Legacy Options still populated (description-only)
	if m.Options["name"] != "Name of the service." {
		t.Errorf("legacy Options[name] lost: %q", m.Options["name"])
	}
}

func TestParseModuleJSON_RichOptions_MetadataDumpShape(t *testing.T) {
	// Real metadata-dump envelope, with structured options under each module.
	raw := []byte(`{
		"all": {
			"module": {
				"ansible.builtin.lineinfile": {
					"doc": {
						"short_description": "Manage lines in text files.",
						"options": {
							"path": {
								"description": ["The file to modify."],
								"required": true,
								"type": "path",
								"aliases": ["dest", "destfile", "name"]
							},
							"backrefs": {
								"description": ["Used with state=present."],
								"type": "bool",
								"default": false,
								"version_added": "1.1"
							}
						}
					}
				}
			}
		}
	}`)
	mods, err := ParseModuleJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 1 {
		t.Fatalf("got %d modules, want 1", len(mods))
	}
	m := mods[0]
	path := m.RichOptions["path"]
	if !path.Required {
		t.Error("path.Required should be true")
	}
	if path.Type != "path" {
		t.Errorf("path.Type = %q, want path", path.Type)
	}
	if len(path.Aliases) != 3 {
		t.Errorf("path.Aliases = %v, want 3 entries", path.Aliases)
	}
	if !contains(path.Aliases, "dest") {
		t.Errorf("path.Aliases missing dest: %v", path.Aliases)
	}
	// Description is a list of strings — joined.
	if path.Description != "The file to modify." {
		t.Errorf("path.Description = %q, want joined single line", path.Description)
	}
	back := m.RichOptions["backrefs"]
	if back.VersionAdded != "1.1" {
		t.Errorf("backrefs.VersionAdded = %q, want 1.1", back.VersionAdded)
	}
	if got, ok := back.Default.(bool); !ok || got != false {
		t.Errorf("backrefs.Default = %v, want false", back.Default)
	}
}

func TestParseOptionEntry_HandlesLooseTypes(t *testing.T) {
	// Some options have description: "single string" rather than ["list"].
	raw := map[string]any{
		"description": "Single-string description.",
		"type":        "bool",
		"default":     nil,
		"choices":     []any{true, false},
	}
	o := parseOptionEntry("flag", raw)
	if o.Description != "Single-string description." {
		t.Errorf("description = %q", o.Description)
	}
	if o.Type != "bool" {
		t.Errorf("type = %q", o.Type)
	}
	if o.Default != nil {
		t.Errorf("default should be nil, got %v", o.Default)
	}
	if len(o.Choices) != 2 {
		t.Errorf("choices len = %d, want 2", len(o.Choices))
	}
}

func TestCoerceStringList(t *testing.T) {
	got := coerceStringList([]any{"a", 42, "b"})
	want := []string{"a", "42", "b"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("coerceStringList = %v, want %v", got, want)
	}
}
