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

const ResolutionVersion = 8

// Native Ansible get_all_plugin_loaders().subdir, with each loader's default
// ~/.ansible/plugins and /usr/share/ansible/plugins suffix. shell_plugins is
// relative to the run root and is covered by the repository search below.
// Native parity tests reject additions rather than silently losing discovery.
var ansiblePluginDirectories = []struct{ subdir, defaultSuffix string }{
	{"action_plugins", "action"}, {"become_plugins", "become"},
	{"cache_plugins", "cache"}, {"callback_plugins", "callback"},
	{"cliconf_plugins", "cliconf"}, {"connection_plugins", "connection"},
	{"doc_fragments", "doc_fragments"}, {"filter_plugins", "filter"},
	{"httpapi_plugins", "httpapi"}, {"inventory_plugins", "inventory"},
	{"library", "modules"}, {"lookup_plugins", "lookup"},
	{"module_utils", "module_utils"}, {"netconf_plugins", "netconf"},
	{"shell_plugins", ""}, {"strategy_plugins", "strategy"},
	{"terminal_plugins", "terminal"}, {"test_plugins", "test"},
	{"vars_plugins", "vars"},
}

// Closure is the set of repository files whose content decided what the run
// did: the playbooks, every statically or dynamically included task file,
// the templates, files and scripts they ship, the vars files, the
// verification specs, the contracts of the roles those specs declare, the
// extra-vars files inside the repository, and ansible.cfg/requirements.yml
// when present. The pinned controller also binds the executed binary to a
// reproducible rebuild and records its transitive Go source/embed closure.
// Default ambient records retain unresolved controller context.
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
	Root       string      // repository root the run executed from (a checkout or a `git archive` copy)
	Playbooks  []string    // the playbooks the chain ran
	Specs      []string    // the verification specs it verified
	Inputs     []string    // additional execution inputs, such as the topology YAML
	Controller *Controller // live runner context; a zero value cannot clear ambient refusal
	ExtraArgs  []string    // the forwarded ansible-playbook arguments (`-e @file` names extra-vars files)
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
	implicitDirectories := []string{"group_vars", "host_vars"}
	if in.Controller.Ready() {
		implicitDirectories = nil
	}
	for _, plugin := range ansiblePluginDirectories {
		implicitDirectories = append(implicitDirectories, plugin.subdir)
	}
	implicitDirectories = append(implicitDirectories, "collections", "ansible_collections", "roles")
	for _, dir := range dirs {
		for _, name := range implicitDirectories {
			abs := filepath.Join(dir, name)
			r.patterns[r.rel(abs)+"/**"] = true
			if _, err := os.Stat(abs); err == nil {
				r.addPath(abs, "", false, "implicit Ansible input")
				if name != "group_vars" && name != "host_vars" {
					r.dispatchUnresolved("repository", "custom Ansible code", "custom modules/plugins can read additional controller inputs")
				}
			}
		}
	}
	if in.Controller.Ready() {
		if err := in.Controller.addGoSourceClosure(r); err != nil {
			r.dispatchUnresolved("controller", "unproved Go build closure", err.Error())
		}
		if !in.Controller.InventoryProven() {
			r.dispatchUnresolved("inventory", "unsupported controlled inventory", "automatic reuse requires validated rendered SSH inventory")
		}
		inv := in.Controller.Inventory()
		for _, dir := range dirs {
			groups := []string{"all", "ungrouped"}
			for group, members := range inv.Groups {
				if len(members) > 0 && group != "all" && group != "ungrouped" {
					groups = append(groups, group)
				}
			}
			for _, kind := range []struct {
				dir   string
				names []string
			}{{"group_vars", groups}, {"host_vars", inv.Hosts}} {
				for _, name := range kind.names {
					if !safeInventoryName(name) {
						r.dispatchUnresolved("inventory", "unsupported inventory names", "vars discovery requires literal safe host/group names")
						continue
					}
					for _, suffix := range []string{"", ".yml", ".yaml", ".json"} {
						abs := filepath.Join(dir, kind.dir, name+suffix)
						r.patterns[r.rel(abs)] = true
						if suffix == "" {
							r.patterns[r.rel(abs)+"/**"] = true
						}
						if _, err := os.Lstat(abs); err == nil {
							r.addPath(abs, "", false, "inventory-matched vars")
						}
					}
				}
			}
		}
		for _, name := range controllerProfileFiles {
			abs := filepath.Join(root, ControllerProfile, name)
			r.patterns[r.rel(abs)] = true
			// Profile configuration is proved by the native image probe, rather
			// than interpreted as arbitrary repository Ansible configuration.
			raw, err := os.ReadFile(abs)
			if err != nil {
				return nil, err
			}
			r.files[r.rel(abs)] = &File{Path: r.rel(abs), Mode: "100644", Blob: GitBlobOID(raw), SHA256: digestBytes(raw), Size: int64(len(raw)), Via: "pinned controller profile"}
		}
	}
	if !in.Controller.Ready() {
		// Native loader defaults can contain custom code even without ANSIBLE_*
		// overrides or ansible.cfg. Existing external defaults cannot be hashed as
		// repository inputs, so record them and refuse automatic reuse.
		pluginRoots := []string{"/usr/share/ansible/plugins"}
		if home, err := os.UserHomeDir(); err == nil {
			pluginRoots = append(pluginRoots, filepath.Join(home, ".ansible", "plugins"))
		}
		for _, base := range pluginRoots {
			for _, plugin := range ansiblePluginDirectories {
				if plugin.defaultSuffix == "" {
					continue
				}
				abs := filepath.Join(base, plugin.defaultSuffix)
				if _, err := os.Stat(abs); err == nil {
					r.addPath(abs, "", false, "ambient Ansible plugin input")
					r.dispatchUnresolved("environment", "ambient Ansible plugin code", "default plugin search paths contain custom controller inputs")
				} else if !os.IsNotExist(err) {
					r.dispatchUnresolved("environment", "ambient Ansible plugin code", "default plugin search paths could not be inspected")
				}
			}
		}
		// Git cannot prove absent external loader roots/collection paths/sys.path stay
		// absent at reuse time. Until there is a controlled-controller fingerprint,
		// even the literal task subset does not prove a complete reusable closure.
		r.dispatchUnresolved("environment", "ambient Ansible plugin discovery", "external plugin, collection and Python discovery paths are not fingerprinted")
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
			if in.Controller.Ready() && parsed.SchemaVersion != 1 {
				r.dispatchUnresolved(sp, "unsupported verification schema", "controlled reuse initially supports V1 verification only")
			}
		} else if in.Controller.Ready() {
			r.dispatchUnresolved(sp, "unsupported verification schema", "verification schema could not be proved")
		}
		for _, name := range names {
			contract := filepath.Join(root, "contracts", name+".yaml")
			r.patterns[r.rel(contract)] = true
			if _, err := os.Stat(contract); err == nil {
				r.addPath(contract, "", false, sp)
			}
		}
	}
	if forwardedDispatchOptions(in.ExtraArgs) {
		r.dispatchUnresolved("extra-vars", "forwarded Ansible options", "forwarded options can change input paths or module/plugin dispatch")
	}
	// Extra-vars values are lazy Jinja expressions too. Without evaluating Jinja,
	// the resolver cannot know their runtime file dependencies. Never serialize
	// the inline payload: it can contain secret literals or lookup arguments.
	for _, payload := range extraVarsPayloads(in.ExtraArgs) {
		if strings.HasPrefix(payload, "@") {
			continue
		}
		if inlineVarsNeedRuntimeResolution(payload) {
			r.unresolved = append(r.unresolved, Reference{From: "extra-vars", Ref: "inline extra-vars expression", Reason: "inline syntax, templating or dispatch variables require unsupported runtime resolution"})
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
	configFiles := []string{"ansible.cfg", "requirements.yml"}
	if in.Controller.Ready() {
		configFiles = nil
	}
	for _, name := range configFiles {
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
		if out.Unresolved[i].Ref != out.Unresolved[j].Ref {
			return out.Unresolved[i].Ref < out.Unresolved[j].Ref
		}
		return out.Unresolved[i].Reason < out.Unresolved[j].Reason
	})
	// A YAML input is inspected both as text and as decoded scalars. Keep one
	// stable marker per boundary instead of duplicating the same refusal.
	unique := out.Unresolved[:0]
	for _, ref := range out.Unresolved {
		if len(unique) == 0 || unique[len(unique)-1] != ref {
			unique = append(unique, ref)
		}
	}
	out.Unresolved = unique
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
	// Decode loaded YAML once so aliases/merge keys cannot hide dispatch or
	// dependency fields, and escaped scalars cannot hide file-reading expressions.
	// This walk is linear in parser nodes and never follows Alias pointers.
	if f.Mode != "120000" && via != "spec" {
		var document yaml.Node
		if err := yaml.Unmarshal(content, &document); err == nil && len(document.Content) > 0 && (document.Content[0].Kind == yaml.SequenceNode || document.Content[0].Kind == yaml.MappingNode) {
			r.inspectYAMLLayout(&document, rel, filepath.Dir(abs))
		}
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
			r.dispatchUnresolved(rel, "unsupported play layout", "play dispatch or attributes require runtime Ansible resolution")
			continue
		}
		r.checkPlayLayout(play, rel)
		for i := 0; i+1 < len(play.Content); i += 2 {
			key, val := play.Content[i].Value, play.Content[i+1]
			switch key {
			case "import_playbook", "ansible.builtin.import_playbook":
				r.dispatchUnresolved(rel, "unsupported play layout", "imported playbook execution requires full runtime Ansible search context")
				if val.Kind != yaml.ScalarNode || val.Tag == "!!null" {
					continue
				}
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
		r.dispatchUnresolved(from, "unsupported task layout", "task dispatch or arguments require runtime Ansible resolution")
		return
	}
	for _, task := range list.Content {
		if task.Kind != yaml.MappingNode {
			r.dispatchUnresolved(from, "unsupported task layout", "task dispatch or arguments require runtime Ansible resolution")
			continue
		}
		r.checkTaskDispatch(task, from)
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
	if hasJinjaSyntax(raw) {
		r.dispatchUnresolved(from, "unsupported expression", "automatic reuse requires proven file-independent expressions")
	}
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

// Inspect decoded scalar values as well: JSON Unicode escapes and quoted
// assignments must not hide a lazy Jinja expression from the closure boundary.
func inlineVarsNeedRuntimeResolution(payload string) bool {
	isExpression := func(value string) bool {
		return hasJinjaSyntax(value) || lookupCallRe.MatchString(value)
	}
	if isExpression(payload) {
		return true
	}
	if strings.HasPrefix(strings.TrimSpace(payload), "{") {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(payload), &doc); err != nil {
			return true
		}
		var walk func(*yaml.Node) bool
		walk = func(node *yaml.Node) bool {
			if node.Kind == yaml.AliasNode {
				return true
			}
			if node.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(node.Content); i += 2 {
					if strings.HasPrefix(node.Content[i].Value, "ansible_") {
						return true
					}
				}
			}
			if node.Kind == yaml.ScalarNode && isExpression(node.Value) {
				return true
			}
			for _, child := range node.Content {
				if walk(child) {
					return true
				}
			}
			return false
		}
		return walk(&doc)
	}
	fields, ok := splitInlineVars(payload)
	if !ok {
		return true
	}
	for _, field := range fields {
		key, value, _ := strings.Cut(field, "=")
		if strings.HasPrefix(key, "ansible_") || isExpression(value) {
			return true
		}
	}
	return false
}

// These are parser boundaries, not execution restrictions. Tasks outside this
// deliberately small subset still run; their records cannot be reused by a
// machine without an independent resolution of the omitted runtime behavior.
func (r *resolver) dispatchUnresolved(from, label, reason string) {
	r.unresolved = append(r.unresolved, Reference{From: from, Ref: label, Reason: reason})
}

var taskMetadata = map[string]bool{
	"name": true, "when": true, "vars": true, "tags": true, "register": true,
	"changed_when": true, "failed_when": true, "no_log": true, "run_once": true,
	"ignore_errors": true, "ignore_unreachable": true, "become": true, "become_user": true,
	"check_mode": true, "diff": true, "notify": true, "listen": true, "until": true,
	"retries": true, "delay": true, "timeout": true, "throttle": true, "any_errors_fatal": true,
}
var knownDirectActions = map[string]bool{
	"copy": true, "template": true, "script": true, "include_tasks": true,
	"import_tasks": true, "include_vars": true,
	// Known actions remain available for diagnostic source discovery. Only copy
	// and debug.msg can pass the separate argument proof below.
	"debug": true, "set_fact": true, "assert": true, "fail": true,
}

func (r *resolver) checkPlayLayout(play *yaml.Node, from string) {
	allowed := map[string]bool{
		"name": true, "hosts": true, "vars": true, "vars_files": true, "gather_facts": true,
		"become": true, "become_user": true, "remote_user": true, "serial": true, "tags": true,
		"check_mode": true, "force_handlers": true, "any_errors_fatal": true, "max_fail_percentage": true,
		"pre_tasks": true, "tasks": true, "post_tasks": true, "handlers": true,
		"import_playbook": true, "ansible.builtin.import_playbook": true,
	}
	for i := 0; i+1 < len(play.Content); i += 2 {
		key, value := play.Content[i], play.Content[i+1]
		if !supportedPlayValue(key.Value, value) {
			r.dispatchUnresolved(from, "unsupported play layout", "play dispatch or attributes require runtime Ansible resolution")
		}
		if key.Kind != yaml.ScalarNode || !allowed[key.Value] || value.Kind == yaml.AliasNode || key.Value == "vars_files" && !plainScalarList(value) || (key.Value == "import_playbook" || key.Value == "ansible.builtin.import_playbook") && (value.Kind != yaml.ScalarNode || value.Tag == "!!null" || strings.TrimSpace(value.Value) == "") {
			r.dispatchUnresolved(from, "unsupported play layout", "play dispatch or attributes require runtime Ansible resolution")
		}
	}
}

func (r *resolver) checkTaskDispatch(task *yaml.Node, from string) {
	actions, blocks := 0, 0
	layoutBad := false
	for i := 0; i+1 < len(task.Content); i += 2 {
		key, value := task.Content[i], task.Content[i+1]
		if key.Kind != yaml.ScalarNode {
			layoutBad = true
			continue
		}
		name := key.Value
		if taskMetadata[name] {
			if !supportedTaskMetadata(name, value) {
				layoutBad = true
			}
			continue
		}
		if name == "block" || name == "rescue" || name == "always" {
			blocks++
			continue
		}
		if strings.HasPrefix(name, "with_") {
			r.dispatchUnresolved(from, "unsupported task dispatch", "automatic reuse supports only literal copy and debug.msg actions")
			continue
		}
		module := strings.TrimPrefix(name, "ansible.builtin.")
		if !knownDirectActions[module] {
			actions++
			r.dispatchUnresolved(from, "unsupported task dispatch", "automatic reuse supports only literal copy and debug.msg actions")
			continue
		}
		actions++
		switch module {
		case "copy", "debug":
			if !supportedActionArguments(module, value) {
				layoutBad = true
			}
		case "template":
			r.dispatchUnresolved(from, "unsupported task dispatch", "template execution is opaque to automatic reuse")
		case "include_tasks", "import_tasks":
			r.dispatchUnresolved(from, "unsupported task dispatch", "included task execution requires full runtime Ansible search context")
		case "script":
			r.dispatchUnresolved(from, "unsupported task dispatch", "opaque executable input requires runtime dependency resolution")
		default:
			r.dispatchUnresolved(from, "unsupported task dispatch", "automatic reuse supports only literal copy and debug.msg actions")
		}
	}
	if (actions != 1 && blocks == 0) || (actions > 0 && blocks > 0) || actions > 1 {
		layoutBad = true
	}
	if layoutBad {
		r.dispatchUnresolved(from, "unsupported task layout", "task dispatch or arguments require runtime Ansible resolution")
	}
}

// No implicit expression field is accepted here. In particular debug.var,
// free-form arguments and every template execution remain outside the subset.
func supportedActionArguments(module string, value *yaml.Node) bool {
	if value == nil || value.Kind != yaml.MappingNode {
		return false
	}
	args := map[string]*yaml.Node{}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key, val := value.Content[i], value.Content[i+1]
		if key.Kind != yaml.ScalarNode || args[key.Value] != nil {
			return false
		}
		args[key.Value] = val
	}
	if module == "debug" {
		for key, val := range args {
			switch key {
			case "msg":
				if !literalScalar(val) {
					return false
				}
			case "verbosity":
				if val.Kind != yaml.ScalarNode || val.Tag != "!!int" {
					return false
				}
			default:
				return false
			}
		}
		return args["msg"] != nil
	}
	if module != "copy" {
		return false
	}
	for key, val := range args {
		switch key {
		case "src", "dest", "content", "owner", "group":
			if !literalString(val) {
				return false
			}
		case "mode":
			if !literalString(val) && (val.Kind != yaml.ScalarNode || val.Tag != "!!int") {
				return false
			}
		case "backup", "force", "remote_src":
			if val.Kind != yaml.ScalarNode || val.Tag != "!!bool" {
				return false
			}
		default:
			return false
		}
	}
	has := func(key string) bool { return args[key] != nil }
	return has("dest") && strings.TrimSpace(args["dest"].Value) != "" && has("src") != has("content") && (!has("src") || strings.TrimSpace(args["src"].Value) != "") && (!has("remote_src") || args["remote_src"].Value == "false")
}

func literalScalar(value *yaml.Node) bool {
	if value == nil || value.Kind != yaml.ScalarNode {
		return false
	}
	switch value.Tag {
	case "!!str", "!!int", "!!float", "!!bool":
	default:
		return false
	}
	return !hasJinjaSyntax(value.Value)
}
func literalString(value *yaml.Node) bool { return literalScalar(value) && value.Tag == "!!str" }
func literalStringList(value *yaml.Node) bool {
	if literalString(value) {
		return true
	}
	if value == nil || value.Kind != yaml.SequenceNode {
		return false
	}
	for _, child := range value.Content {
		if !literalString(child) {
			return false
		}
	}
	return true
}
func literalNumber(value *yaml.Node) bool {
	return value != nil && value.Kind == yaml.ScalarNode && (value.Tag == "!!int" || value.Tag == "!!float")
}

func supportedTaskMetadata(name string, value *yaml.Node) bool {
	switch name {
	case "name", "register", "become_user":
		return literalString(value)
	case "tags", "notify", "listen":
		return literalStringList(value)
	case "vars":
		return value.Kind == yaml.MappingNode
	case "when", "until", "changed_when", "failed_when":
		return literalBooleanCondition(value)
	case "no_log", "run_once", "ignore_errors", "ignore_unreachable", "become", "check_mode", "diff", "any_errors_fatal":
		return value.Kind == yaml.ScalarNode && value.Tag == "!!bool"
	case "retries", "delay", "timeout", "throttle":
		return literalNumber(value)
	default:
		return false
	}
}

func forwardedDispatchOptions(args []string) bool {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-e" || arg == "--extra-vars" {
			if i+1 >= len(args) {
				return true
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "--extra-vars=") || strings.HasPrefix(arg, "-e") && len(arg) > 2 {
			continue
		}
		// Only extra-vars forms are understood here. Other forwarded options may
		// replace inventories, secrets providers, connections or module search paths.
		return true
	}
	return false
}

func plainScalarList(value *yaml.Node) bool {
	if value.Kind == yaml.ScalarNode {
		return value.Tag != "!!null" && strings.TrimSpace(value.Value) != ""
	}
	if value.Kind != yaml.SequenceNode {
		return false
	}
	for _, child := range value.Content {
		if child.Kind != yaml.ScalarNode || child.Tag == "!!null" {
			return false
		}
	}
	return true
}

func (r *resolver) inspectYAMLLayout(node *yaml.Node, from, dir string) {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i].Value, node.Content[i+1]
			if strings.HasPrefix(key, "ansible_") {
				r.dispatchUnresolved(from, "unsupported YAML layout", "custom Ansible dispatch variables require runtime resolution")
			}
			if (key == "when" || key == "until" || key == "changed_when" || key == "failed_when" || key == "that") && !literalBooleanCondition(value) {
				r.dispatchUnresolved(from, "unsupported expression", "automatic reuse requires proven file-independent expressions")
			}
		}
	}

	if node.Kind == yaml.AliasNode || node.Tag == "!!merge" {
		r.dispatchUnresolved(from, "unsupported YAML layout", "YAML aliases or merge keys require runtime dependency resolution")
		return
	}
	if node.Kind == yaml.ScalarNode {
		r.scanExpressions(node.Value, from, dir, dir)
	}
	for _, child := range node.Content {
		r.inspectYAMLLayout(child, from, dir)
	}
}

func literalBooleanCondition(value *yaml.Node) bool {
	if value.Kind == yaml.ScalarNode {
		return value.Tag == "!!bool"
	}
	if value.Kind != yaml.SequenceNode {
		return false
	}
	for _, child := range value.Content {
		if child.Kind != yaml.ScalarNode || child.Tag != "!!bool" {
			return false
		}
	}
	return true
}

func supportedPlayValue(name string, value *yaml.Node) bool {
	switch name {
	case "name", "become_user", "remote_user", "import_playbook", "ansible.builtin.import_playbook":
		return literalString(value)
	case "hosts", "tags":
		return literalStringList(value)
	case "vars":
		return value.Kind == yaml.MappingNode
	case "vars_files":
		return plainScalarList(value)
	case "gather_facts", "become", "check_mode", "force_handlers", "any_errors_fatal":
		return value.Kind == yaml.ScalarNode && value.Tag == "!!bool"
	case "serial", "max_fail_percentage":
		return literalNumber(value)
	case "pre_tasks", "tasks", "post_tasks", "handlers":
		return value.Kind == yaml.SequenceNode
	default:
		return false
	}
}

func safeInventoryName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	for _, ch := range name {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-", rune(ch)) {
			return false
		}
	}
	return true
}
