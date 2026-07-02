package docs

import (
	"strings"
	"testing"
)

func TestParseModuleJSON(t *testing.T) {
	// Real-ish output from `ansible-doc --json` for two modules.
	raw := []byte(`{
		"lineinfile": {
			"doc": {
				"short_description": "Manage lines in text files",
				"description": "This module ensures a particular line is in a file.",
				"options": {
					"path": {"description": "The file to modify."},
					"state": {"description": "Whether the line should be present or absent."}
				},
				"examples": "- lineinfile: path=/etc/ssh/sshd_config regexp='^PermitRootLogin' line='PermitRootLogin no'"
			},
			"filename": "/usr/lib/python3/dist-packages/ansible/modules/lineinfile.py",
			"category": "Files",
			"collection": "ansible.builtin"
		},
		"ping": {
			"doc": {
				"short_description": "Try to connect to host",
				"description": "A trivial test module."
			},
			"filename": "/usr/lib/python3/dist-packages/ansible/modules/ping.py",
			"category": "Command",
			"collection": "ansible.builtin"
		}
	}`)

	mods, err := ParseModuleJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 {
		t.Fatalf("got %d modules, want 2", len(mods))
	}
	// Sorted by name
	if mods[0].Name != "lineinfile" {
		t.Errorf("first: %s", mods[0].Name)
	}
	if mods[0].ShortDesc != "Manage lines in text files" {
		t.Errorf("short desc: %s", mods[0].ShortDesc)
	}
	if len(mods[0].Options) != 2 {
		t.Errorf("options: %d", len(mods[0].Options))
	}
	if mods[0].Options["path"] != "The file to modify." {
		t.Errorf("path option: %s", mods[0].Options["path"])
	}
	if mods[0].Category != "Files" {
		t.Errorf("category: %s", mods[0].Category)
	}
	if mods[0].Version != "ansible.builtin" {
		t.Errorf("version: %s", mods[0].Version)
	}
	if mods[1].Name != "ping" {
		t.Errorf("second: %s", mods[1].Name)
	}
}

func TestParseModuleJSONInvalid(t *testing.T) {
	_, err := ParseModuleJSON([]byte(`not json`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestStringOf(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"hello", "hello"},
		{[]any{"a", "b"}, "a b"},
		{map[string]any{"k": "v"}, "k=v"},
	}
	for _, c := range cases {
		if got := stringOf(c.in); got != c.want {
			t.Errorf("stringOf(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestChunkModuleBasic(t *testing.T) {
	m := ModuleDoc{
		Name:        "lineinfile",
		ShortDesc:   "Manage lines",
		Description: "Detailed description here.",
		Options: map[string]string{
			"path":  "File to modify",
			"state": "present|absent",
		},
		Examples: "- lineinfile: path=/etc/foo line=bar",
	}
	chunks := ChunkModule(m)
	if len(chunks) == 0 {
		t.Fatal("no chunks produced")
	}
	// Expected sections
	wantSections := map[string]bool{"description": false, "options": false, "examples": false}
	for _, c := range chunks {
		if _, ok := wantSections[c.Section]; ok {
			wantSections[c.Section] = true
		}
		if !strings.HasPrefix(c.ID, "modules:lineinfile:") {
			t.Errorf("bad ID: %s", c.ID)
		}
		if c.Source != SourceModule {
			t.Errorf("source: %s", c.Source)
		}
	}
	for sec, found := range wantSections {
		if !found {
			t.Errorf("missing section: %s", sec)
		}
	}
}

func TestChunkModuleEmpty(t *testing.T) {
	chunks := ChunkModule(ModuleDoc{Name: "empty"})
	if len(chunks) != 0 {
		t.Errorf("expected 0 chunks for empty module, got %d", len(chunks))
	}
}

func TestChunkModuleTruncates(t *testing.T) {
	m := ModuleDoc{
		Name:        "long",
		Description: strings.Repeat("x", 10000),
	}
	chunks := ChunkModule(m)
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks", len(chunks))
	}
	if len(chunks[0].Text) > 4100 {
		t.Errorf("chunk not truncated: %d bytes", len(chunks[0].Text))
	}
}

func TestParseModuleJSON_MetadataDumpEnvelope(t *testing.T) {
	// Real shape from `ansible-doc --metadata-dump` on ansible-core 2.18+.
	// Everything is wrapped under an "all" envelope keyed by plugin type;
	// only the "module" category is what we care about.
	raw := []byte(`{
		"all": {
			"become": {
				"ansible.builtin.runas": {"doc": {"short_description": "Run as user"}}
			},
			"module": {
				"lineinfile": {
					"doc": {
						"short_description": "Manage lines in text files",
						"description": "Ensure a particular line is in a file.",
						"options": {
							"path": {"description": "The file to modify."}
						},
						"filename": "/x.py",
						"collection": "ansible.builtin"
					}
				},
				"ping": {
					"doc": {
						"short_description": "Try to connect to host",
						"collection": "ansible.builtin"
					}
				}
			}
		}
	}`)

	mods, err := ParseModuleJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(mods) != 2 {
		t.Fatalf("got %d modules, want 2 (became-plugin must be ignored)", len(mods))
	}
	if mods[0].Name != "lineinfile" {
		t.Errorf("first: %s", mods[0].Name)
	}
	if mods[0].ShortDesc != "Manage lines in text files" {
		t.Errorf("short desc: %s", mods[0].ShortDesc)
	}
	if len(mods[0].Options) != 1 || mods[0].Options["path"] != "The file to modify." {
		t.Errorf("options: %+v", mods[0].Options)
	}
	if mods[0].Version != "ansible.builtin" {
		t.Errorf("version: %s", mods[0].Version)
	}
}
