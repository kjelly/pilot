package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// SecretSource is one value the captured output must not contain. The value
// never leaves this package: a Hit names the key, not the value.
type SecretSource struct {
	Key   string // where it came from: "<file>:<yaml.path>" or "-e <key>"
	value string
}

// Hit is a secret value found in a captured step output.
type Hit struct {
	Step  string `json:"step"`
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Redaction is the result of scanning every captured output for the values
// of the secret-named variables the run was given.
type Redaction struct {
	Sources int      `json:"sources"`           // secret values scanned for
	Keys    []string `json:"keys,omitempty"`    // their names (never values)
	Skipped []string `json:"skipped,omitempty"` // extra-vars files that could not be read as plaintext YAML (ansible-vault encrypted, missing)
	Hits    []Hit    `json:"hits"`              // empty when the output is clean
}

var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|credential|private_key|api_key|master_key|_pass$|_pw$)`)

// isSecretKey classifies a key name. Container secrecy is propagated by the
// traversal, so credentials.value and password list entries stay secret.
func isSecretKey(key string) bool {
	last := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		last = key[i+1:]
	}
	return secretKeyRe.MatchString(last)
}

// Only explicit file-reference keys are exempt. A secret literal beginning
// with /, ~ or {{ is still a secret value, not evidence of a file reference.
func secretFileKey(key string) bool {
	return strings.HasSuffix(strings.ToLower(key), "_file")
}
func secretValue(v string) bool { return v != "" }

// SecretSources collects the secret-named values the run was given: the
// scalars under secret-named keys of every plaintext `-e @file`, and every
// `-e key=value` with a secret-named key. Encrypted or unreadable files are
// listed in skipped, so the record says what was not scanned for.
func SecretSources(root string, extraArgs []string) (sources []SecretSource, skipped []string) {
	for _, f := range extraVarsFiles(extraArgs) {
		abs := f
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(root, f)
		}
		if strings.HasPrefix(f, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				abs = filepath.Join(home, f[2:])
			}
		}
		raw, err := os.ReadFile(abs)
		if err != nil {
			skipped = append(skipped, f+" (unreadable)")
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(string(raw)), "$ANSIBLE_VAULT") {
			skipped = append(skipped, f+" (ansible-vault encrypted)")
			continue
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			skipped = append(skipped, f+" (not YAML)")
			continue
		}
		collectSecrets(f, "", &doc, false, 0, &sources, &skipped)
	}
	for _, payload := range extraVarsPayloads(extraArgs) {
		if payload == "" || strings.HasPrefix(payload, "@") {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(payload), "{") {
			var doc yaml.Node
			if err := yaml.Unmarshal([]byte(payload), &doc); err != nil || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
				skipped = append(skipped, "inline extra-vars (unsupported JSON/YAML mapping)")
			} else {
				collectSecrets("-e", "", &doc, false, 0, &sources, &skipped)
			}
			continue
		}
		fields, ok := splitInlineVars(payload)
		if !ok {
			skipped = append(skipped, "inline extra-vars (unsupported quoting or assignments)")
			continue
		}
		for _, field := range fields {
			key, val, _ := strings.Cut(field, "=")
			if isSecretKey(key) && !secretFileKey(key) && secretValue(val) {
				appendSecretSources(&sources, "-e "+key, val)
				if strings.Contains(val, "{{") || strings.Contains(val, "{%") {
					skipped = append(skipped, "templated secret value (runtime result not scanned)")
				}
			}
		}
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].Key < sources[j].Key })
	return sources, skipped
}

func collectSecrets(file, prefix string, node *yaml.Node, inherited bool, depth int, out *[]SecretSource, skipped *[]string) {
	if node == nil {
		return
	}
	if depth > 64 {
		*skipped = append(*skipped, "secret scalar traversal exceeds supported depth")
		return
	}
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, item := range node.Content {
			collectSecrets(file, prefix, item, inherited, depth+1, out, skipped)
		}
	case yaml.AliasNode:
		collectSecrets(file, prefix, node.Alias, inherited, depth+1, out, skipped)
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i].Value
			if secretFileKey(key) {
				continue
			}
			path := key
			if prefix != "" {
				path = prefix + "." + key
			}
			collectSecrets(file, path, node.Content[i+1], inherited || isSecretKey(key), depth+1, out, skipped)
		}
	case yaml.ScalarNode:
		if !inherited || prefix == "" {
			return
		}
		values := []string{node.Value}
		if strings.Contains(node.Value, "{{") || strings.Contains(node.Value, "{%") {
			*skipped = append(*skipped, "templated secret value (runtime result not scanned)")
		}
		if node.Tag != "!!str" {
			var canonical any
			if err := node.Decode(&canonical); err != nil {
				*skipped = append(*skipped, "secret scalar cannot be decoded")
				return
			}
			values = append(values, fmt.Sprint(canonical))
			if raw, err := json.Marshal(canonical); err == nil {
				values = append(values, string(raw))
			}
			if v, ok := canonical.(bool); ok {
				if v {
					values = append(values, "True")
				} else {
					values = append(values, "False")
				}
			}
		}
		seen := map[string]bool{}
		for _, value := range values {
			if secretValue(value) && !seen[value] {
				appendSecretSources(out, file+":"+prefix, value)
				seen[value] = true
			}
		}
	}
}

// JSON callbacks encode quotes, slashes and line breaks inside a scalar. Scan
// their standard JSON spelling too; this is a bounded encoding boundary rather
// than an attempt to guess every transformation of a secret.
func appendSecretSources(out *[]SecretSource, key, value string) {
	*out = append(*out, SecretSource{Key: key, value: value})
	if raw, err := json.Marshal(value); err == nil && len(raw) >= 2 {
		escaped := string(raw[1 : len(raw)-1])
		if escaped != value {
			*out = append(*out, SecretSource{Key: key, value: escaped})
		}
	}
}

// Scan reports every captured output that contains a secret value. Outputs
// are keyed by step name.
func Scan(outputs map[string]string, sources []SecretSource) []Hit {
	var hits []Hit
	steps := make([]string, 0, len(outputs))
	for s := range outputs {
		steps = append(steps, s)
	}
	sort.Strings(steps)
	for _, step := range steps {
		for _, src := range sources {
			if n := strings.Count(outputs[step], src.value); n > 0 {
				hits = append(hits, Hit{Step: step, Key: src.Key, Count: n})
			}
		}
	}
	return hits
}

// Redact scans outputs for sources and returns the record section.
func Redact(outputs map[string]string, sources []SecretSource, skipped []string) Redaction {
	red := Redaction{Sources: len(sources), Skipped: skipped, Hits: Scan(outputs, sources)}
	for _, s := range sources {
		red.Keys = append(red.Keys, s.Key)
	}
	if red.Hits == nil {
		red.Hits = []Hit{}
	}
	return red
}

// splitInlineVars supports Ansible's quoted key=value terms, without evaluating
// Jinja or shell code. Anything outside this grammar is explicitly unscanned.
func splitInlineVars(raw string) ([]string, bool) {
	var fields []string
	var word strings.Builder
	var quote rune
	escaped := false
	flush := func() bool {
		if word.Len() == 0 {
			return true
		}
		field := word.String()
		word.Reset()
		key, _, ok := strings.Cut(field, "=")
		if !ok || key == "" {
			return false
		}
		fields = append(fields, field)
		return true
	}
	for _, ch := range raw {
		if escaped {
			word.WriteRune(ch)
			escaped = false
			continue
		}
		if ch == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				word.WriteRune(ch)
			}
		} else if ch == '\'' || ch == '"' {
			quote = ch
		} else if ch == ' ' || ch == '\n' || ch == '\t' {
			if !flush() {
				return nil, false
			}
		} else {
			word.WriteRune(ch)
		}
	}
	if quote != 0 || escaped || !flush() {
		return nil, false
	}
	return fields, len(fields) > 0
}

// Sanitize replaces known secret values in persisted metadata as well as errors.
// Step stdout stays outside the committed record and is reported through Hits.
func Sanitize(value string, sources []SecretSource) string {
	// Replace longer values first when one value contains another.
	ordered := append([]SecretSource(nil), sources...)
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i].value) > len(ordered[j].value) })
	for _, source := range ordered {
		value = strings.ReplaceAll(value, source.value, "<redacted>")
	}
	return value
}

// SanitizeRecord handles every string field, including error notes, caller flags,
// paths and inventory identifiers. Decode first so JSON escaping cannot hide a
// known value from replacement or make replacement corrupt the encoded record.
func SanitizeRecord(record *Record, sources []SecretSource) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var clean func(any, string) any
	clean = func(v any, key string) any {
		switch node := v.(type) {
		case string:
			// Derived cryptographic identities are public fingerprints, not secret payloads.
			switch key {
			case "commit", "tree", "blob", "sha256", "base_image_sha256":
				return node
			}
			return Sanitize(node, sources)
		case []any:
			for i := range node {
				node[i] = clean(node[i], key)
			}
			return node
		case map[string]any:
			out := make(map[string]any, len(node))
			for k, val := range node {
				out[Sanitize(k, sources)] = clean(val, k)
			}
			return out
		default:
			return v
		}
	}
	raw, err = json.Marshal(clean(decoded, ""))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, record)
}
