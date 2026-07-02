package docs

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Playbook is a minimal representation of a parsed Ansible playbook.
// We use the YAML library's raw map round-trip so we don't depend on
// the (heavy) ansible runner being importable from this package.
type Playbook struct {
	Path  string
	Plays []Play
	Raw   []byte
}

// Play is one entry in a playbook's top-level list.
type Play struct {
	Name       string
	Hosts      string
	Tasks      []Task
	Tags       []string
	Vars       map[string]any
	Become     bool
	LineNumber int // 1-based
}

// Task is a single task within a play.
type Task struct {
	Name   string
	Module string
	Args   map[string]any
	Tags   []string
	When   string
	Become bool
	Line   int
}

// ParsePlaybook reads a YAML playbook file and returns a Playbook
// structure. It is tolerant of malformed files: best-effort parsing,
// errors are returned but partial results are still useful for indexing.
func ParsePlaybook(path string) (*Playbook, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pb := &Playbook{Path: path, Raw: raw}
	var entries []yaml.Node
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		// Some playbooks are a single map, not a list; try that.
		var single yaml.Node
		if err := yaml.Unmarshal(raw, &single); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		entries = []yaml.Node{single}
	}
	for i := range entries {
		play := parsePlay(&entries[i])
		play.LineNumber = entries[i].Line
		pb.Plays = append(pb.Plays, play)
	}
	return pb, nil
}

func parsePlay(node *yaml.Node) Play {
	p := Play{}
	if node.Kind != yaml.MappingNode {
		return p
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1]
		switch k {
		case "name":
			p.Name = v.Value
		case "hosts":
			p.Hosts = v.Value
		case "tags":
			p.Tags = readStringList(v)
		case "become":
			if v.Value == "true" || v.Value == "True" {
				p.Become = true
			}
		case "vars":
			if v.Kind == yaml.MappingNode {
				_ = v.Decode(&p.Vars)
			}
		case "tasks":
			if v.Kind == yaml.SequenceNode {
				for j := range v.Content {
					t := parseTask(v.Content[j])
					t.Line = v.Content[j].Line
					p.Tasks = append(p.Tasks, t)
				}
			}
		}
	}
	return p
}

// taskMetaKeys are the well-known keys that are NOT module directives.
// Any other key is the task's module.
var taskMetaKeys = map[string]bool{
	"name": true, "tags": true, "when": true, "become": true,
	"register": true, "vars": true, "loop": true, "with_items": true,
	"notify": true, "listen": true, "ignore_errors": true, "no_log": true,
	"delegate_to": true, "run_once": true, "changed_when": true,
	"failed_when": true, "until": true, "retries": true, "delay": true,
	"check_mode": true, "diff": true, "environment": true,
	"any_errors_fatal": true, "block": true, "rescue": true, "always": true,
}

func parseTask(node *yaml.Node) Task {
	t := Task{}
	if node.Kind != yaml.MappingNode {
		return t
	}
	// Tasks may be a "free form" module: a single key that is the
	// module name, e.g. `shell: [echo, hi]`. We detect this by:
	// exactly 2 mapping entries AND the value is not a scalar.
	if len(node.Content) == 2 {
		k := node.Content[0]
		v := node.Content[1]
		if k.Tag == "!!str" && v.Kind != yaml.ScalarNode {
			t.Module = k.Value
			_ = v.Decode(&t.Args)
			return t
		}
	}
	moduleFound := false
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i].Value
		v := node.Content[i+1]
		switch k {
		case "name":
			t.Name = v.Value
		case "tags":
			t.Tags = readStringList(v)
		case "when":
			t.When = v.Value
		case "become":
			if v.Value == "true" || v.Value == "True" {
				t.Become = true
			}
		case "register":
			t.Args = map[string]any{"register": v.Value}
		case "loop", "with_items":
			if t.Args == nil {
				t.Args = map[string]any{}
			}
			t.Args[k] = decodeScalar(v)
		default:
			// The first non-meta key is the module. Subsequent
			// non-meta keys (like notify, listen) are meta-like and
			// stored in Args so we don't lose them.
			if !moduleFound && !taskMetaKeys[k] {
				t.Module = k
				moduleFound = true
				switch v.Kind {
				case yaml.ScalarNode:
					if t.Args == nil {
						t.Args = map[string]any{}
					}
					t.Args[k] = decodeScalar(v)
				default:
					_ = v.Decode(&t.Args)
				}
			} else {
				if t.Args == nil {
					t.Args = map[string]any{}
				}
				t.Args[k] = decodeScalar(v)
			}
		}
	}
	return t
}

func readStringList(node *yaml.Node) []string {
	if node.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]string, 0, len(node.Content))
	for i := range node.Content {
		if node.Content[i].Kind == yaml.ScalarNode {
			out = append(out, node.Content[i].Value)
		}
	}
	return out
}

func decodeScalar(node *yaml.Node) any {
	if node == nil {
		return nil
	}
	switch node.Tag {
	case "!!int":
		var n int
		_, _ = fmt.Sscanf(node.Value, "%d", &n)
		return n
	case "!!bool":
		return node.Value == "true" || node.Value == "True"
	case "!!str", "":
		return node.Value
	}
	return node.Value
}

// ChunkPlaybook turns a Playbook into Chunks. Strategy: one chunk
// per play (with all its tasks summarised), plus per-task chunks
// for fine-grained retrieval.
func ChunkPlaybook(pb *Playbook) []Chunk {
	if pb == nil {
		return nil
	}
	out := []Chunk{}
	base := map[string]any{
		"path": pb.Path,
		"size": len(pb.Raw),
	}
	// Per-play chunk
	for i, play := range pb.Plays {
		var b strings.Builder
		fmt.Fprintf(&b, "Play %d (line %d): %s\n", i+1, play.LineNumber, play.Name)
		if play.Hosts != "" {
			fmt.Fprintf(&b, "Hosts: %s\n", play.Hosts)
		}
		if len(play.Tags) > 0 {
			fmt.Fprintf(&b, "Tags: %s\n", strings.Join(play.Tags, ", "))
		}
		if len(play.Tasks) > 0 {
			b.WriteString("Tasks:\n")
			for _, t := range play.Tasks {
				fmt.Fprintf(&b, "  - %s\n", taskSummary(t))
			}
		}
		body := strings.TrimSpace(b.String())
		if body == "" {
			continue
		}
		if len(body) > 4000 {
			body = body[:4000] + "..."
		}
		out = append(out, Chunk{
			ID:       fmt.Sprintf("playbooks:%s:play:%d", pb.Path, i+1),
			Source:   SourcePlaybook,
			Ref:      pb.Path,
			Section:  fmt.Sprintf("play-%d", i+1),
			Text:     body,
			Metadata: base,
		})

		// Per-task chunks
		for j, t := range play.Tasks {
			tb := taskSummary(t)
			if tb == "" {
				continue
			}
			out = append(out, Chunk{
				ID:       fmt.Sprintf("playbooks:%s:task:%d:%d", pb.Path, i+1, j+1),
				Source:   SourcePlaybook,
				Ref:      pb.Path,
				Section:  fmt.Sprintf("task-%d-%d", i+1, j+1),
				Text:     tb,
				Metadata: base,
			})
		}
	}
	return out
}

func taskSummary(t Task) string {
	if t.Name == "" && t.Module == "" {
		return ""
	}
	var b strings.Builder
	if t.Name != "" {
		fmt.Fprintf(&b, "Task: %s\n", t.Name)
	}
	if t.Module != "" {
		fmt.Fprintf(&b, "Module: %s\n", t.Module)
	}
	if t.When != "" {
		fmt.Fprintf(&b, "When: %s\n", t.When)
	}
	if t.Become {
		b.WriteString("Become: true\n")
	}
	if len(t.Tags) > 0 {
		fmt.Fprintf(&b, "Tags: %s\n", strings.Join(t.Tags, ", "))
	}
	if len(t.Args) > 0 {
		// Stable key order
		keys := make([]string, 0, len(t.Args))
		for k := range t.Args {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&b, "  %s: %v\n", k, t.Args[k])
		}
	}
	return strings.TrimSpace(b.String())
}

// DiscoverPlaybooks walks the given directories (non-recursive by
// default to keep things predictable; recursive=true goes deep)
// and returns all *.yml/*.yaml files that look like Ansible
// playbooks. We skip obvious test/backups.
func DiscoverPlaybooks(dirs []string, recursive bool) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	skip := func(name string) bool {
		l := strings.ToLower(name)
		return strings.HasPrefix(l, ".") ||
			strings.Contains(l, "test") ||
			strings.HasSuffix(l, ".bak") ||
			strings.HasSuffix(l, "~")
	}
	walk := func(dir string) error {
		if recursive {
			return filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}
				if info.IsDir() {
					return nil
				}
				if skip(info.Name()) {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(p))
				if ext != ".yml" && ext != ".yaml" {
					return nil
				}
				if !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
				return nil
			})
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() || skip(e.Name()) {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext != ".yml" && ext != ".yaml" {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
		return nil
	}
	for _, d := range dirs {
		if err := walk(d); err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// VersionHash computes a stable hash from a version string and a
// list of module names. The list is sorted internally so the order
// doesn't affect the result. Used to detect ansible-core version
// changes that would invalidate the index.
func VersionHash(ansibleVersion string, modules []string) string {
	sorted := make([]string, len(modules))
	copy(sorted, modules)
	sort.Strings(sorted)
	h := sha256.New()
	h.Write([]byte(ansibleVersion))
	h.Write([]byte{0})
	for _, m := range sorted {
		h.Write([]byte(m))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
