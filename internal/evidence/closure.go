package evidence

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/kjelly/pilot/internal/spec"
)

// File is one execution input of the run, named the way `git ls-tree -r`
// names it, so a gate can compare the tested tree with HEAD without trusting
// a hand-written list.
type File struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Blob    string `json:"blob"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Dynamic bool   `json:"dynamic,omitempty"` // matched through a templated reference turned into a glob
	Via     string `json:"via,omitempty"`     // the file that referenced it
}

// Reference is a file reference the resolver could not turn into a file.
type Reference struct {
	From   string `json:"from"`
	Ref    string `json:"ref"`
	Reason string `json:"reason"`
}

const ResolutionVersion = 2

// Closure is the set of repository files whose content decided what the run
// did: the playbooks, every statically or dynamically included task file,
// the templates, files and scripts they ship, the vars files, the
// verification specs, the contracts of the roles those specs declare, the
// extra-vars files inside the repository, and ansible.cfg/requirements.yml
// when present. Go code is not listed: the pilot binary's hash is recorded
// separately and the gates prove Go changes through the pure-base-import
// rule (.agents/skills/_shared/target-evidence-reuse.md).
type Closure struct {
	ResolutionVersion int         `json:"resolution_version"`
	Frozen            bool        `json:"frozen"` // pre-run closure matched the post-run inputs
	Files             []File      `json:"files"`
	Patterns          []string    `json:"patterns"` // searched paths, including misses; detect new inputs at reuse time
	Unresolved        []Reference `json:"unresolved,omitempty"`
	External          []string    `json:"external,omitempty"` // referenced files outside the repository (vault files); path only, never hashed
}

// ClosureInput names what the run executed. Paths are relative to Root or absolute.
type ClosureInput struct {
	Root      string   // repository root the run executed from (a checkout or a `git archive` copy)
	Playbooks []string // the playbooks the chain ran
	Specs     []string // the verification specs it verified
	Inputs    []string // additional execution inputs, such as the topology YAML
	ExtraArgs []string // the forwarded ansible-playbook arguments (`-e @file` names extra-vars files)
}

const maxIncludeDepth = 12

type resolver struct {
	root         string
	files        map[string]*File
	unresolved   []Reference
	external     map[string]bool
	visiting     map[string]bool
	playbookDirs map[string]bool
	patterns     map[string]bool
}

// ComputeClosure resolves the execution closure of a run. It never fails on
// an unresolvable reference: those are listed under Unresolved so the record
// says what the machine could not follow.
func ComputeClosure(in ClosureInput) (*Closure, error) {
	root, err := filepath.Abs(in.Root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("closure root %s is not a directory", in.Root)
	}
	r := &resolver{root: root, files: map[string]*File{}, external: map[string]bool{}, visiting: map[string]bool{}, patterns: map[string]bool{}, playbookDirs: map[string]bool{}}
	for _, pb := range in.Playbooks {
		abs := r.abs(pb)
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("playbook %s: %w", pb, err)
		}
		r.visitPlaybook(abs, 0)
	}
	for _, input := range in.Inputs {
		r.addPath(r.abs(input), "", false, "execution input")
	}
	// Ansible loads these implicitly beside inventory/playbooks. Hash entire
	// directories and record missing search paths so newly added inputs matter.
	dirs := []string{root}
	for dir := range r.playbookDirs {
		dirs = append(dirs, dir)
	}
	for _, dir := range dirs {
		for _, name := range []string{"group_vars", "host_vars", "library", "filter_plugins", "action_plugins", "lookup_plugins", "vars_plugins", "callback_plugins"} {
			abs := filepath.Join(dir, name)
			r.patterns[r.rel(abs)+"/**"] = true
			if _, err := os.Stat(abs); err == nil {
				r.addPath(abs, "", false, "implicit Ansible input")
			}
		}
	}
	// Ambient Ansible configuration can change lookup/plugin/vars behavior.
	// Name unsupported environment settings without persisting their values.
	for _, item := range os.Environ() {
		key, value, _ := strings.Cut(item, "=")
		if strings.HasPrefix(key, "ANSIBLE_") && value != "" {
			if key == "ANSIBLE_CONFIG" {
				r.addPath(r.abs(value), "", false, "ANSIBLE_CONFIG")
			}
			r.unresolved = append(r.unresolved, Reference{From: "environment", Ref: key, Reason: "ambient Ansible configuration is not statically resolved"})
		}
	}
	if _, err := os.Stat(filepath.Join(root, "ansible.cfg")); os.Getenv("ANSIBLE_CONFIG") == "" && os.IsNotExist(err) {
		configs := []string{"/etc/ansible/ansible.cfg"}
		if home, err := os.UserHomeDir(); err == nil {
			configs = append(configs, filepath.Join(home, ".ansible.cfg"))
		}
		for _, cfg := range configs {
			if _, err := os.Stat(cfg); err == nil {
				r.addPath(cfg, "", false, "ambient Ansible configuration")
			}
		}
	}

	for _, sp := range in.Specs {
		abs := r.abs(sp)
		if _, err := os.Stat(abs); err != nil {
			return nil, fmt.Errorf("spec %s: %w", sp, err)
		}
		r.addPath(abs, "", false, "spec")
		// The contract of the component the spec verifies: contracts/<stem>.yaml
		// for the Markdown specs, plus the roles a v2 spec declares.
		names := []string{strings.TrimSuffix(filepath.Base(abs), filepath.Ext(abs))}
		if parsed, err := spec.Parse(abs); err == nil {
			names = append(names, parsed.Roles...)
		}
		for _, name := range names {
			contract := filepath.Join(root, "contracts", name+".yaml")
			r.patterns[r.rel(contract)] = true
			if _, err := os.Stat(contract); err == nil {
				r.addPath(contract, "", false, sp)
			}
		}
	}
	for _, f := range extraVarsFiles(in.ExtraArgs) {
		abs := r.abs(f)
		if strings.HasPrefix(f, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				abs = filepath.Join(home, f[2:])
			}
		}
		if r.rel(abs) == "" {
			// A vault or other file outside the repository: named, never read or hashed.
			r.external[filepath.Clean(abs)] = true
			continue
		}
		if _, err := os.Stat(abs); err != nil {
			r.unresolved = append(r.unresolved, Reference{From: "extra-vars", Ref: f, Reason: "file not found"})
			continue
		}
		r.addPath(abs, "", false, "extra-vars")
	}
	for _, name := range []string{"ansible.cfg", "requirements.yml"} {
		r.patterns[name] = true
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			r.addPath(filepath.Join(root, name), "", false, "repository")
		}
	}
	out := &Closure{ResolutionVersion: ResolutionVersion, Patterns: []string{}}
	for _, f := range r.files {
		out.Files = append(out.Files, *f)
	}
	sort.Slice(out.Files, func(i, j int) bool { return out.Files[i].Path < out.Files[j].Path })
	out.Unresolved = r.unresolved
	sort.Slice(out.Unresolved, func(i, j int) bool {
		if out.Unresolved[i].From != out.Unresolved[j].From {
			return out.Unresolved[i].From < out.Unresolved[j].From
		}
		return out.Unresolved[i].Ref < out.Unresolved[j].Ref
	})
	for p := range r.external {
		out.External = append(out.External, p)
	}
	for p := range r.patterns {
		out.Patterns = append(out.Patterns, p)
	}
	sort.Strings(out.Patterns)
	sort.Strings(out.External)
	return out, nil
}

// extraVarsPayloads recognizes Ansible's separated, equals and compact -e forms.
func extraVarsPayloads(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-e" || a == "--extra-vars":
			if i+1 < len(args) {
				i++
				out = append(out, args[i])
			}
		case strings.HasPrefix(a, "--extra-vars="):
			out = append(out, strings.TrimPrefix(a, "--extra-vars="))
		case strings.HasPrefix(a, "-e") && len(a) > 2:
			out = append(out, strings.TrimPrefix(a[2:], "="))
		}
	}
	return out
}
func extraVarsFiles(args []string) []string {
	var out []string
	for _, val := range extraVarsPayloads(args) {
		if strings.HasPrefix(val, "@") {
			out = append(out, val[1:])
		}
	}
	return out
}

func (r *resolver) abs(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(r.root, p)
}

// rel returns the repository-relative path of abs, or "" when abs is outside the root.
func (r *resolver) rel(abs string) string {
	rel, err := filepath.Rel(r.root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.ToSlash(rel)
}

// addPath records a regular file (or every regular file below a directory).
// Files outside the root are listed as external; symlinks are recorded with
// Git's symlink mode and the link target as content, as `git ls-tree` does.
func (r *resolver) addPath(abs, from string, dynamic bool, via string) {
	abs = filepath.Clean(abs)
	rel := r.rel(abs)
	if rel == "" {
		r.external[abs] = true
		return
	}
	st, err := os.Lstat(abs)
	if err != nil {
		r.unresolved = append(r.unresolved, Reference{From: from, Ref: rel, Reason: err.Error()})
		return
	}
	if st.IsDir() {
		r.patterns[rel+"/**"] = true
		_ = filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				r.unresolved = append(r.unresolved, Reference{From: from, Ref: r.rel(p), Reason: "input directory could not be read"})
				return nil
			}
			if d.IsDir() {
				return nil
			}
			r.addPath(p, from, dynamic, via)
			return nil
		})
		return
	}
	if existing, ok := r.files[rel]; ok {
		existing.Dynamic = existing.Dynamic || dynamic
		return
	}
	f := &File{Path: rel, Dynamic: dynamic, Via: via}
	var content []byte
	switch {
	case st.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(abs)
		if err != nil {
			r.unresolved = append(r.unresolved, Reference{From: from, Ref: rel, Reason: err.Error()})
			return
		}
		f.Mode = "120000"
		r.unresolved = append(r.unresolved, Reference{From: from, Ref: rel, Reason: "symlink target requires independent execution-input resolution"})
		content = []byte(target)
	default:
		if !st.Mode().IsRegular() {
			r.unresolved = append(r.unresolved, Reference{From: from, Ref: rel, Reason: "not a regular file"})
			return
		}
		content, err = os.ReadFile(abs)
		if err != nil {
			r.unresolved = append(r.unresolved, Reference{From: from, Ref: rel, Reason: err.Error()})
			return
		}
		f.Mode = "100644"
		if st.Mode()&0o111 != 0 {
			f.Mode = "100755"
		}
	}
	f.Blob = GitBlobOID(content)
	f.SHA256 = SHA256Hex(content)
	f.Size = int64(len(content))
	r.files[rel] = f
	// Scan every loaded YAML/template, including play vars, included vars and
	// templates loaded by other templates. Unsupported expressions fail closed.
	if f.Mode != "120000" && via != "spec" {
		r.scanExpressions(string(content), rel, filepath.Dir(abs), filepath.Dir(abs))
	}
	if filepath.Base(abs) == "ansible.cfg" {
		r.unresolved = append(r.unresolved, Reference{From: rel, Ref: "ansible.cfg", Reason: "custom Ansible configuration may select plugins or external paths; automatic reuse requires independent resolution"})
	}
}

// loadYAML parses a YAML file into its document node.
func loadYAML(abs string) (*yaml.Node, error) {
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	return doc.Content[0], nil
}

func (r *resolver) visitPlaybook(abs string, depth int) {
	rel := r.rel(abs)
	if depth > maxIncludeDepth {
		r.unresolved = append(r.unresolved, Reference{From: rel, Ref: rel, Reason: "maximum include depth exceeded"})
		return
	}
	if rel == "" {
		r.external[abs] = true
		return
	}
	if r.visiting[abs] {
		return
	}
	r.visiting[abs] = true
	r.playbookDirs[filepath.Dir(abs)] = true
	r.addPath(abs, "", false, "playbook")
	root, err := loadYAML(abs)
	if err != nil || root.Kind != yaml.SequenceNode {
		r.unresolved = append(r.unresolved, Reference{From: rel, Ref: rel, Reason: "playbook is not a YAML list of plays"})
		return
	}
	dir := filepath.Dir(abs)
	for _, play := range root.Content {
		if play.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(play.Content); i += 2 {
			key, val := play.Content[i].Value, play.Content[i+1]
			switch key {
			case "import_playbook", "ansible.builtin.import_playbook":
				for _, target := range r.resolveRef(rel, val.Value, "tasks", dir, dir) {
					r.visitPlaybook(target.abs, depth+1)
				}
			case "vars_files":
				for _, ref := range scalarList(val) {
					for _, target := range r.resolveRef(rel, ref, "tasks", dir, dir) {
						r.addPath(target.abs, rel, target.dynamic, rel)
					}
				}
			case "roles", "import_role", "include_role":
				r.unresolved = append(r.unresolved, Reference{From: rel, Ref: key, Reason: "roles are not resolved by the closure"})
			case "pre_tasks", "tasks", "post_tasks", "handlers":
				r.visitTasks(val, rel, dir, dir, depth)
			}
		}
	}
}

func (r *resolver) visitTaskFile(abs, playbookDir string, depth int) {
	rel := r.rel(abs)
	if depth > maxIncludeDepth {
		r.unresolved = append(r.unresolved, Reference{From: rel, Ref: rel, Reason: "maximum include depth exceeded"})
		return
	}
	if rel == "" {
		return
	}
	if r.visiting[abs] {
		return
	}
	r.visiting[abs] = true
	root, err := loadYAML(abs)
	if err != nil || root.Kind != yaml.SequenceNode {
		r.unresolved = append(r.unresolved, Reference{From: rel, Ref: rel, Reason: "task file is not a YAML list"})
		return
	}
	r.visitTasks(root, rel, filepath.Dir(abs), playbookDir, depth)
}

// visitTasks walks a task list, blocks included, and follows every file
// reference it knows about.
func (r *resolver) visitTasks(list *yaml.Node, from, fileDir, playbookDir string, depth int) {
	if list == nil || list.Kind != yaml.SequenceNode {
		return
	}
	for _, task := range list.Content {
		if task.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(task.Content); i += 2 {
			key, val := task.Content[i].Value, task.Content[i+1]
			switch strings.TrimPrefix(key, "ansible.builtin.") {
			case "block", "rescue", "always":
				r.visitTasks(val, from, fileDir, playbookDir, depth)
			case "include_tasks", "import_tasks":
				ref := fileArg(val, "file")
				for _, target := range r.resolveRef(from, ref, "tasks", fileDir, playbookDir) {
					r.addPath(target.abs, from, target.dynamic, from)
					r.visitTaskFile(target.abs, playbookDir, depth+1)
				}
			case "include_vars":
				ref := fileArg(val, "file")
				if ref == "" {
					ref = fileArg(val, "dir")
				}
				for _, target := range r.resolveRef(from, ref, "vars", fileDir, playbookDir) {
					r.addPath(target.abs, from, target.dynamic, from)
				}
			case "template":
				for _, target := range r.resolveRef(from, fileArg(val, "src"), "templates", fileDir, playbookDir) {
					r.addPath(target.abs, from, target.dynamic, from)
				}
			case "copy", "assemble", "unarchive":
				if src := fileArg(val, "src"); src != "" && !strings.Contains(src, "://") {
					for _, target := range r.resolveRef(from, src, "files", fileDir, playbookDir) {
						r.addPath(target.abs, from, target.dynamic, from)
					}
				}
			case "script":
				if ref := scriptPath(val); ref != "" {
					for _, target := range r.resolveRef(from, ref, "files", fileDir, playbookDir) {
						r.addPath(target.abs, from, target.dynamic, from)
					}
				}
			case "with_file", "with_fileglob", "with_first_found", "with_template":
				r.unresolved = append(r.unresolved, Reference{From: from, Ref: key, Reason: "implicit file-reading lookup requires runtime resolution"})
			case "import_role", "include_role":
				r.unresolved = append(r.unresolved, Reference{From: from, Ref: key, Reason: "roles are not resolved by the closure"})
			}
		}

	}
}

// fileArg returns a module's file argument: the mapping key `name`, or the
// bare scalar form (`include_tasks: file.yml`), or `name=value` inside a
// free-form string.
func fileArg(val *yaml.Node, name string) string {
	switch val.Kind {
	case yaml.ScalarNode:
		s := strings.TrimSpace(val.Value)
		if name == "file" && !strings.Contains(s, "=") {
			return s
		}
		for _, tok := range strings.Fields(s) {
			if strings.HasPrefix(tok, name+"=") {
				return strings.Trim(tok[len(name)+1:], `"'`)
			}
		}
		if name == "src" && !strings.Contains(s, "=") && !strings.Contains(s, " ") {
			return s
		}
	case yaml.MappingNode:
		for j := 0; j+1 < len(val.Content); j += 2 {
			if val.Content[j].Value == name && val.Content[j+1].Kind == yaml.ScalarNode {
				return strings.TrimSpace(val.Content[j+1].Value)
			}
		}
	}
	return ""
}

// scriptPath is the script a `script:` task runs: the first word of the
// free-form string, or `cmd`/`_raw_params` of the mapping form.
func scriptPath(val *yaml.Node) string {
	var cmd string
	switch val.Kind {
	case yaml.ScalarNode:
		cmd = val.Value
	case yaml.MappingNode:
		cmd = fileArg(val, "cmd")
		if cmd == "" {
			cmd = fileArg(val, "_raw_params")
		}
	}
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func scalarList(val *yaml.Node) []string {
	switch val.Kind {
	case yaml.ScalarNode:
		return []string{val.Value}
	case yaml.SequenceNode:
		var out []string
		for _, item := range val.Content {
			if item.Kind == yaml.ScalarNode {
				out = append(out, item.Value)
			}
		}
		return out
	}
	return nil
}

// Recognize calls even when their arguments cannot be statically resolved.
// Only a single literal path (optionally playbook_dir-relative) is supported;
// expressions, multiple terms and unknown plugins remain unresolved.
var lookupCallRe = regexp.MustCompile(`\b(?:lookup|query|q)\s*\(`)
var literalLookupRe = regexp.MustCompile(`^\s*['"](?:ansible\.builtin\.)?(file|template|fileglob)['"]\s*,\s*(playbook_dir\s*~\s*)?['"]([^'"]+)['"]\s*\)`)
var jinjaIncludeRe = regexp.MustCompile(`\{%[-+]?\s*(?:include|import|from|extends)\b`)

func (r *resolver) scanExpressions(raw, from, fileDir, playbookDir string) {
	for _, loc := range lookupCallRe.FindAllStringIndex(raw, -1) {
		rest := raw[loc[1]:]
		m := literalLookupRe.FindStringSubmatch(rest)
		if m == nil {
			// Do not persist expression text: inline lookup arguments can be secrets.
			r.unresolved = append(r.unresolved, Reference{From: from, Ref: "lookup/query expression", Reason: "lookup plugin or arguments cannot be resolved statically"})
			continue
		}
		if !r.playbookDirs[fileDir] {
			r.unresolved = append(r.unresolved, Reference{From: from, Ref: "lookup search context", Reason: "lookup in a loaded vars/template/task file requires runtime Ansible search-path resolution"})
		}
		ref := m[3]
		if m[2] != "" {
			ref = "{{ playbook_dir }}/" + strings.TrimPrefix(ref, "/")
		}
		kind := "files"
		if m[1] == "template" {
			kind = "templates"
		}
		for _, target := range r.resolveRef(from, ref, kind, fileDir, playbookDir) {
			r.addPath(target.abs, from, target.dynamic || m[1] == "fileglob", from)
		}
	}
	if jinjaIncludeRe.MatchString(raw) {
		r.unresolved = append(r.unresolved, Reference{From: from, Ref: "Jinja template import", Reason: "Jinja imports/includes require runtime resolution"})
	}
}

type resolved struct {
	abs     string
	dynamic bool
}

var jinjaRe = regexp.MustCompile(`\{\{[^}]*\}\}|\{%[^%]*%\}`)

// resolveRef turns a file reference into files, the way Ansible would look
// it up: `{{ playbook_dir }}/x` is relative to the playbook, a path with
// other templating becomes a glob (every match is listed as dynamic), and
// the search order is the including file's directory (`templates/` or
// `files/` first for those kinds), then the playbook's. An unresolvable
// reference is recorded, never silently dropped.
func (r *resolver) resolveRef(from, ref, kind, fileDir, playbookDir string) []resolved {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil
	}
	dirs := []string{fileDir, playbookDir}
	if strings.HasPrefix(ref, "{{ playbook_dir }}/") || strings.HasPrefix(ref, "{{playbook_dir}}/") {
		ref = ref[strings.Index(ref, "}}/")+3:]
		dirs = []string{playbookDir}
	}
	if strings.Contains(ref, "role_path") || strings.Contains(ref, "inventory_dir") {
		r.unresolved = append(r.unresolved, Reference{From: from, Ref: ref, Reason: "templated with a variable the closure cannot evaluate"})
		return nil
	}
	dynamic := jinjaRe.MatchString(ref)
	pattern := ref
	if dynamic {
		r.unresolved = append(r.unresolved, Reference{From: from, Ref: ref, Reason: "dynamic path is a conservative glob; runtime variable values can escape its membership"})
		pattern = jinjaRe.ReplaceAllString(ref, "*")
		// A basename that is nothing but wildcards ("{{ roster_file }}", "{{ item }}")
		// names a value that comes from inventory or extra-vars, not a set of files
		// in the tree; matching it as a glob would pull in a whole directory.
		if strings.Trim(path.Base(pattern), "*?") == "" {
			r.unresolved = append(r.unresolved, Reference{From: from, Ref: ref, Reason: "reference is a variable; the file it names is an input of the run, not of the tree"})
			return nil
		}
	}
	var search []string
	if filepath.IsAbs(pattern) {
		search = []string{""}
	} else {
		for _, d := range dirs {
			switch kind {
			case "templates", "files":
				search = append(search, filepath.Join(d, kind))
			}
			search = append(search, d)
		}
	}
	for _, d := range search {
		full := pattern
		if d != "" {
			full = filepath.Join(d, pattern)
		}
		if rel := r.rel(full); rel != "" {
			r.patterns[rel] = true
		}
		matches, err := filepath.Glob(full)
		if err != nil || len(matches) == 0 {
			continue
		}
		sort.Strings(matches)
		var out []resolved
		for _, m := range matches {
			// A templated reference expands to files only; a directory is
			// followed when the reference names it statically (copy src: dir/).
			if dynamic {
				if st, err := os.Stat(m); err != nil || st.IsDir() {
					continue
				}
			}
			out = append(out, resolved{abs: filepath.Clean(m), dynamic: dynamic})
		}
		if len(out) == 0 {
			continue
		}
		return out
	}
	reason := "file not found in the Ansible search path"
	if dynamic {
		reason = "templated reference matched no file as a glob (" + path.Clean(pattern) + ")"
	}
	r.unresolved = append(r.unresolved, Reference{From: from, Ref: ref, Reason: reason})
	return nil
}
