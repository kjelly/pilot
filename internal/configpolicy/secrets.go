// Package configpolicy enforces the storage boundary for inventory variable
// files. It never evaluates Jinja or includes input values in diagnostics.
package configpolicy

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"unicode"

	shipped "github.com/kjelly/pilot/contracts"
	"github.com/kjelly/pilot/internal/contract"
	"go.yaml.in/yaml/v3"
)

const guidance = "store credentials outside group_vars/ and host_vars/ in encrypted Vault vars or an external secret source; use a pure reference such as {{ vault_grafana_admin_password }} (docs/config-secret-storage.md)"

// Violation deliberately contains only location metadata, never the value.
type Violation struct {
	File string
	Path string
	Line int
}

func (v Violation) String() string {
	return fmt.Sprintf("%s:%d: %s: forbidden secret storage; %s", v.File, v.Line, v.Path, guidance)
}

// Policy combines the complete contract catalog (secret wins over public) with
// credential-name detection for Ansible and undeclared/nested inputs.
type Policy struct {
	secret map[string]bool
	public map[string]bool
}

func New(catalog contract.Catalog) Policy {
	p := Policy{secret: map[string]bool{}, public: map[string]bool{}}
	components := append([]contract.Contract(nil), shippedInputs()...)
	components = append(components, catalog.Components()...)
	for _, c := range components {
		for _, input := range c.GroupVars {
			if input.Secret {
				p.secret[input.Name] = true
			}
			if !input.Secret {
				p.public[input.Name] = true
			}
		}
	}
	return p
}

// Embedded trusted contracts preserve metadata when CWD is a standalone
// inventory workspace. A custom installed catalog may add sensitivity but
// cannot downgrade a secret declared by the shipped version.
var shippedInputs = sync.OnceValue(func() []contract.Contract {
	files, err := shipped.Files.ReadDir(".")
	if err != nil {
		panic("embedded component contracts are unavailable")
	}
	var out []contract.Contract
	for _, file := range files {
		data, err := shipped.Files.ReadFile(file.Name())
		if err != nil {
			panic("embedded component contract is unavailable")
		}
		var c contract.Contract
		if yaml.Unmarshal(data, &c) != nil {
			panic("embedded component contract is invalid")
		}
		out = append(out, c)
	}
	return out
})

// PureReference is intentionally a grammar, not a '{{' substring check. Filters,
// concatenation, defaults and quoted literals can embed credentials. Complex
// lookups belong in the external vars source; inventory keeps only its variable.
var pureReference = regexp.MustCompile(`^\{\{\s*[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\s*\}\}$`)

func PureReference(value string) bool { return pureReference.MatchString(strings.TrimSpace(value)) }

func normalizedKey(key string) string {
	var out strings.Builder
	runes := []rune(key)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			if i > 0 && (unicode.IsLower(runes[i-1]) || unicode.IsDigit(runes[i-1]) || (unicode.IsUpper(runes[i-1]) && i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
				out.WriteRune('_')
			}
			out.WriteRune(unicode.ToLower(r))
		} else if r == '-' || r == '.' {
			out.WriteRune('_')
		} else {
			out.WriteRune(r)
		}
	}
	return strings.Trim(out.String(), "_")
}

func referenceKey(key string) bool {
	for _, suffix := range []string{"_file", "_path", "_ref", "_reference", "_file_path", "_command", "_command_file"} {
		if strings.HasSuffix(key, suffix) {
			return true
		}
	}
	return false
}

func (p Policy) SensitiveKey(key string) bool {
	k := normalizedKey(key)
	// This contract input explicitly names an external roster file, rather
	// than the contents of that secret-bearing file.
	if p.secret[key] && key != "freeipa_roster_file" {
		return true
	}
	if referenceKey(k) {
		return false
	}
	if p.public[key] {
		return false
	}
	for _, suffix := range []string{"_enabled", "_length", "_expiration", "_ttl", "_seconds", "_duration", "_algorithm", "_policy", "_policies", "_url", "_endpoint"} {
		if strings.HasSuffix(k, suffix) {
			return false
		}
	}
	for _, marker := range []string{"password", "passwd", "passphrase", "secret", "token", "private_key", "privatekey", "api_key", "apikey", "access_key", "community", "auth_password", "priv_password", "credential"} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return k == "ansible_ssh_pass" || k == "ansible_become_pass" || k == "ansible_sudo_pass" || k == "ansible_su_pass"
}

// ValidateValue validates a proposed scalar/list edit before a UI can echo it.
func (p Policy) ValidateValue(file, key string, value any) []Violation {
	data, err := yaml.Marshal(map[string]any{key: value})
	if err != nil {
		return []Violation{{File: file, Path: key}}
	}
	return p.Validate(file, data)
}

// Validate walks the syntax tree, preserving lines and following aliases in
// their use-site context. The recursion stack rejects cyclic aliases. YAML
// merge sources are traversed, including values overridden by another key:
// this is a storage rule, so even an ineffective stored secret is forbidden.
func (p Policy) Validate(file string, data []byte) []Violation {
	bad := func(path string, line int) []Violation { return []Violation{{File: file, Path: path, Line: line}} }
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var doc, extra yaml.Node
	if err := decoder.Decode(&doc); err == io.EOF {
		return nil
	} else if err != nil {
		return bad("<invalid YAML>", 0)
	}
	if decoder.Decode(&extra) != io.EOF {
		return bad("<multiple or invalid YAML documents>", 0)
	}
	if len(doc.Content) == 0 {
		return nil
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" && root.Value == "" {
		return nil // empty/comment-only skeleton
	}
	if root.Kind != yaml.MappingNode {
		return bad("<expected variable map>", root.Line)
	}
	var decoded map[string]any
	if root.Decode(&decoded) != nil {
		return bad("<invalid YAML mapping>", root.Line)
	}
	var out []Violation
	stack := map[*yaml.Node]bool{}
	var walk func(*yaml.Node, string, bool)
	walk = func(n *yaml.Node, path string, sensitive bool) {
		if stack[n] {
			out = append(out, bad(path, n.Line)...)
			return
		}
		stack[n] = true
		defer delete(stack, n)
		if n.Kind == yaml.AliasNode {
			if n.Alias == nil {
				out = append(out, bad(path, n.Line)...)
				return
			}
			walk(n.Alias, path, sensitive)
			return
		}
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, value := n.Content[i], n.Content[i+1]
				if key.Value == "<<" && key.Tag == "!!merge" {
					walk(value, path, sensitive)
					continue
				}
				// Do not put arbitrary YAML keys into an error: keys themselves
				// can contain pasted secrets, control characters or templates.
				name := key.Value
				if key.Kind != yaml.ScalarNode {
					out = append(out, bad(path+".<invalid key>", key.Line)...)
					continue
				}
				if !safeKey.MatchString(name) {
					name = fmt.Sprintf("<key at line %d>", key.Line)
				}
				childPath := name
				if path != "" {
					childPath = path + "." + name
				}
				walk(value, childPath, sensitive || p.SensitiveKey(key.Value))
			}
		case yaml.SequenceNode:
			for i, item := range n.Content {
				walk(item, fmt.Sprintf("%s[%d]", path, i), sensitive)
			}
		case yaml.ScalarNode:
			if n.Tag == "!!null" || (n.Tag == "!!str" && strings.TrimSpace(n.Value) == "") {
				return
			}
			if PureReference(n.Value) {
				return
			}
			if sensitive || n.Tag == "!vault" || containsCredentialMaterial(n.Value) {
				out = append(out, bad(path, n.Line)...)
				return
			}
			// Embedded YAML configurations (e.g. alertmanager_config) must not
			// conceal nested credentials by quoting/folding the entire map.
			if strings.Contains(n.Value, ":") {
				var embedded yaml.Node
				if yaml.Unmarshal([]byte(n.Value), &embedded) == nil && len(embedded.Content) == 1 && (embedded.Content[0].Kind == yaml.MappingNode || embedded.Content[0].Kind == yaml.SequenceNode) {
					walk(embedded.Content[0], path, false)
				}
			}
		default:
			out = append(out, bad(path, n.Line)...)
		}
	}
	walk(root, "", false)
	return out
}

var safeKey = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)

func containsCredentialMaterial(value string) bool {
	if strings.Contains(value, "PRIVATE KEY-----") || strings.Contains(value, "-----BEGIN PGP PRIVATE KEY BLOCK-----") || strings.Contains(value, "$ANSIBLE_VAULT;") {
		return true
	}
	// URL userinfo is credential material even under an otherwise public key.
	for {
		_, rest, found := strings.Cut(value, "://")
		if !found {
			return false
		}
		authority := rest
		if end := strings.IndexAny(authority, "/?#"); end >= 0 {
			authority = authority[:end]
		}
		if strings.Contains(authority, "@") {
			return true
		}
		value = rest
	}
}

// Workspace recursively checks both Ansible vars trees. Symlinked files are
// checked; symlinked directories are rejected so traversal cannot skip secrets.
func (p Policy) Workspace(dir string) ([]Violation, error) {
	var out []Violation
	for _, tree := range []string{"group_vars", "host_vars"} {
		base := filepath.Join(dir, tree)
		err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
			if os.IsNotExist(err) && path == base {
				return nil
			}
			if err != nil {
				return fmt.Errorf("cannot inspect inventory vars tree %s", tree)
			}
			if entry.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(dir, path)
			if entry.Type()&os.ModeSymlink != 0 {
				info, err := os.Stat(path)
				if err != nil || info.IsDir() {
					out = append(out, Violation{File: rel, Path: "<unreadable or directory symlink>"})
					return nil
				}
			}
			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".yml" && ext != ".yaml" && ext != ".json" && ext != "" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("cannot read inventory vars file %s", rel)
			}
			out = append(out, p.Validate(filepath.ToSlash(rel), data)...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
