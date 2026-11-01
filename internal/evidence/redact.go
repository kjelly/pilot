package evidence

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode"

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
	Skipped []string `json:"skipped,omitempty"` // inputs not completely scanned (unsupported syntax, encrypted, missing)
	Hits    []Hit    `json:"hits"`              // empty means no known value found; Skipped may still be nonempty
}

var yaml11Sexagesimal = regexp.MustCompile(`^[+-]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$`)

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
		found, unscanned := collectSecretDocument(f, &doc)
		sources = append(sources, found...)
		skipped = append(skipped, unscanned...)
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
				found, unscanned := collectSecretDocument("-e", &doc)
				sources = append(sources, found...)
				skipped = append(skipped, unscanned...)
			}
			continue
		}
		fields, ok := splitInlineVars(payload)
		if !ok {
			if strings.Contains(payload, `\`) {
				skipped = append(skipped, "inline extra-vars (backslash escape syntax not scanned)")
			} else {
				skipped = append(skipped, "inline extra-vars (unsupported quoting or assignments)")
			}
			continue
		}
		for _, field := range fields {
			key, val, _ := strings.Cut(field, "=")
			if isSecretKey(key) && !secretFileKey(key) && secretValue(val) {
				appendSecretSources(&sources, "-e "+key, val)
				if hasJinjaSyntax(val) {
					skipped = append(skipped, "templated secret value (runtime result not scanned)")
				}
			}
		}
	}

	sort.Slice(sources, func(i, j int) bool { return sources[i].Key < sources[j].Key })
	return sources, skipped
}

// A depth limit alone cannot bound alias fan-out. Count every visit (including
// repeated alias targets) and track the active path to reject cycles promptly.
const maxSecretTraversalNodes = 16384

type secretTraversal struct {
	remaining int
	active    map[*yaml.Node]bool
	failed    bool
}

func collectSecretDocument(file string, node *yaml.Node) ([]SecretSource, []string) {
	var sources []SecretSource
	var skipped []string
	traversal := secretTraversal{remaining: maxSecretTraversalNodes, active: map[*yaml.Node]bool{}}
	collectSecrets(file, "", node, false, 0, &sources, &skipped, &traversal)
	if traversal.failed {
		// A partial scan must never look complete. Discard all results for this input,
		// including any values/notes visited before the excessive expansion or cycle.
		return nil, []string{file + " (secret source traversal limit or cyclic alias)"}
	}
	return sources, skipped
}

func collectSecrets(file, prefix string, node *yaml.Node, inherited bool, depth int, out *[]SecretSource, skipped *[]string, traversal *secretTraversal) {
	if node == nil || traversal.failed {
		return
	}
	if depth > 64 || traversal.remaining <= 0 || traversal.active[node] {
		traversal.failed = true
		return
	}
	traversal.remaining--
	traversal.active[node] = true
	defer delete(traversal.active, node)
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, item := range node.Content {
			collectSecrets(file, prefix, item, inherited, depth+1, out, skipped, traversal)
			if traversal.failed {
				return
			}
		}
	case yaml.AliasNode:
		collectSecrets(file, prefix, node.Alias, inherited, depth+1, out, skipped, traversal)
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
			collectSecrets(file, path, node.Content[i+1], inherited || isSecretKey(key), depth+1, out, skipped, traversal)
			if traversal.failed {
				return
			}
		}
	case yaml.ScalarNode:
		if !inherited || prefix == "" {
			return
		}
		values := []string{node.Value}
		// These YAML native-type conversions are not proved equivalent to
		// Ansible's loader/serialization. Preserve partial raw detection, but
		// never report a complete scan of their possible effective values.
		switch node.Tag {
		case "!!str", "!!bool", "!!int":
		default:
			*skipped = append(*skipped, "YAML secret scalar type (runtime value not scanned)")
		}
		// Ansible's YAML 1.1 loader resolves these plain spellings as booleans,
		// whereas yaml.v3 keeps them as strings. Quoted/explicit strings retain
		// their literal value; collecting both forms is safe and bounded.
		if node.Style == 0 && node.Tag == "!!str" {
			if yaml11Sexagesimal.MatchString(node.Value) {
				*skipped = append(*skipped, "YAML 1.1 sexagesimal secret scalar (runtime value not scanned)")
			}
			switch strings.ToLower(node.Value) {
			case "yes", "on":
				values = append(values, "true", "True")
			case "no", "off":
				values = append(values, "false", "False")
			}
		}
		if hasJinjaSyntax(node.Value) {
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

// hasJinjaSyntax covers every standard Jinja opener. Comments can transform a
// value just as interpolation and statements can; no runtime result is inferred.
func hasJinjaSyntax(value string) bool {
	return strings.Contains(value, "{{") || strings.Contains(value, "{%") || strings.Contains(value, "{#")
}

// splitInlineVars admits only a native-checked subset of Ansible assignments:
// bare ASCII identifier keys, ASCII-space-separated terms, and either unquoted
// values or one whole quoted value. Opposite quotes inside that pair are literal.
// Concatenated quotes, escaped syntax and other whitespace are unproved, so the
// entire payload is refused rather than partly scanned using shell semantics.
func splitInlineVars(raw string) ([]string, bool) {
	if strings.ContainsAny(raw, "\\\t\r\n\v\f") || strings.IndexFunc(raw, func(ch rune) bool { return ch != ' ' && unicode.IsSpace(ch) }) >= 0 {
		return nil, false
	}
	var fields []string
	for i := 0; i < len(raw); {
		for i < len(raw) && raw[i] == ' ' {
			i++
		}
		if i == len(raw) {
			break
		}
		start := i
		if !asciiIdentifierStart(raw[i]) {
			return nil, false
		}
		i++
		for i < len(raw) && (asciiIdentifierStart(raw[i]) || raw[i] >= '0' && raw[i] <= '9') {
			i++
		}
		if i == len(raw) || raw[i] != '=' {
			return nil, false
		}
		key := raw[start:i]
		i++
		var value string
		if i < len(raw) && (raw[i] == '\'' || raw[i] == '"') {
			quote := raw[i]
			i++
			start = i
			for i < len(raw) && raw[i] != quote {
				i++
			}
			if i == len(raw) {
				return nil, false
			}
			value = raw[start:i]
			i++
			if i < len(raw) && raw[i] != ' ' {
				return nil, false
			}
		} else {
			start = i
			for i < len(raw) && raw[i] != ' ' {
				if raw[i] == '\'' || raw[i] == '"' {
					return nil, false
				}
				i++
			}
			value = raw[start:i]
		}
		fields = append(fields, key+"="+value)
	}
	return fields, len(fields) > 0
}
func asciiIdentifierStart(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch == '_'
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

// SanitizeRecord visits string data without renaming the record schema's field
// names. Dynamic map keys are data too. Working on decoded Go strings preserves
// JSON escaping correctly and avoids short secrets deleting fields such as note.
func SanitizeRecord(record *Record, sources []SecretSource, identityRoot ...string) error {
	root := ""
	if len(identityRoot) == 1 {
		root = identityRoot[0]
	}
	if _, err := json.Marshal(record); err != nil {
		return err
	}
	var clean func(reflect.Value, string) reflect.Value
	clean = func(v reflect.Value, key string) reflect.Value {
		if !v.IsValid() {
			return v
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		switch v.Kind() {
		case reflect.String:
			out.SetString(Sanitize(v.String(), sources))
		case reflect.Pointer:
			if !v.IsNil() {
				out.Set(reflect.New(v.Type().Elem()))
				out.Elem().Set(clean(v.Elem(), key))
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				field := v.Type().Field(i)
				if field.IsExported() {
					if typedProtocolString(v.Type(), field.Name, v.Field(i), v, root) {
						continue
					}
					name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
					out.Field(i).Set(clean(v.Field(i), name))
				}
			}
		case reflect.Slice:
			if !v.IsNil() {
				out.Set(reflect.MakeSlice(v.Type(), v.Len(), v.Len()))
				for i := 0; i < v.Len(); i++ {
					out.Index(i).Set(clean(v.Index(i), key))
				}
			}
		case reflect.Map:
			if !v.IsNil() {
				out.Set(reflect.MakeMapWithSize(v.Type(), v.Len()))
				iter := v.MapRange()
				for iter.Next() {
					out.SetMapIndex(clean(iter.Key(), ""), clean(iter.Value(), key))
				}
			}
		}
		return out
	}
	*record = clean(reflect.ValueOf(*record), "").Interface().(Record)
	return nil
}

// Only validated protocol fields are exempt. Their spellings are still secret
// data when present in operator notes, command text or dynamic map keys/values.
func typedProtocolString(owner reflect.Type, field string, value reflect.Value, parent reflect.Value, root string) bool {
	if owner == reflect.TypeOf(Closure{}) && field == "Patterns" && root != "" {
		for _, pattern := range value.Interface().([]string) {
			if !safeClosureIdentityPath(pattern) {
				return false
			}
		}
		return true
	}
	if owner == reflect.TypeOf(ControllerProof{}) && field == "NativeProbe" && !value.IsNil() {
		return validNativeProbe(value.Interface().(*ControllerNativeProbe))
	}
	if value.Kind() != reflect.String {
		return false
	}
	text := value.String()
	oneOf := func(allowed ...string) bool {
		for _, item := range allowed {
			if text == item {
				return true
			}
		}
		return false
	}
	hash := func(size int) bool {
		if len(text) != size {
			return false
		}
		_, err := hex.DecodeString(text)
		return err == nil
	}
	switch owner {
	case reflect.TypeOf(ControllerBuild{}):
		switch field {
		case "GoVersion":
			return text == "go1.26.8"
		case "Path":
			return text == pilotMain
		case "Module":
			return text == pilotModule
		case "GOOS":
			return text == "linux"
		case "GOARCH":
			return text == "amd64"
		case "GOAMD64":
			return text == "v1"
		case "CGO":
			return text == "0"
		case "SettingsSHA256", "ModulesSHA256", "SourcesSHA256", "RebuiltBinarySHA256":
			return hash(64)
		}
	case reflect.TypeOf(ControllerProfileProof{}):
		return hash(64)
	case reflect.TypeOf(ControllerProof{}):
		switch field {
		case "Schema":
			return text == ControllerSchema
		case "InventoryKind":
			return text == "pilot-rendered-ssh/v1" || text == "unsupported"
		case "ImageID":
			return validImageID(text)
		case "ConfigSHA256", "InventorySHA256", "RenderedInventorySHA256", "BinarySHA256", "PreProbeSHA256", "PostProbeSHA256":
			return hash(64)
		}
	case reflect.TypeOf(Record{}):
		switch field {
		case "Schema":
			return text == Schema
		case "FailedStep":
			return oneOf("L1 syntax check", "L3 check-mode dry-run", "L4 apply", "L5 verify", "L6 idempotency", "rollback")
		case "Outcome":
			return oneOf("success", "failed", "rolled_back", "rollback_failed", "invalid-inputs", "cleanup_failed", "partial_success", "partial_failed", "cancelled", "evidence_failed", "authorization_required")
		}
	case reflect.TypeOf(Candidate{}):
		switch field {
		case "Source":
			return oneOf("git", "flag", "unknown")
		case "Commit", "Tree":
			return hash(40)
		}
	case reflect.TypeOf(Step{}):
		switch field {
		case "Status":
			return oneOf("pass", "fail", "skipped", "not-run")
		case "Name":
			return oneOf("L1 syntax check", "L3 check-mode dry-run", "L4 apply", "L5 verify", "L6 idempotency", "rollback")
		}
	case reflect.TypeOf(VerifyVerdict{}):
		return field == "Verdict" && oneOf("PASS", "FAIL")
	case reflect.TypeOf(File{}):
		switch field {
		case "Path":
			if root == "" || !safeClosureIdentityPath(text) || strings.ContainsAny(text, "*?[]") {
				return false
			}
			actual, err := rawClosureFile(root, filepath.Join(root, text), "")
			if err != nil {
				return false
			}
			entry := parent.Interface().(File)
			return (entry.Mode == "100644" || entry.Mode == "100755") && entry.Mode == actual.Mode && entry.Blob == actual.Blob && entry.SHA256 == actual.SHA256
		case "Mode":
			return oneOf("100644", "100755", "120000")
		case "Blob":
			return hash(40)
		case "SHA256":
			return hash(64)
		}
	case reflect.TypeOf(Binary{}):
		return field == "SHA256" && hash(64)
	case reflect.TypeOf(Target{}):
		return field == "BaseImageSHA256" && hash(64)
	}
	return false
}

func safeClosureIdentityPath(path string) bool {
	if path == "" || filepath.IsAbs(path) || strings.ContainsAny(path, "\\\x00\r\n[]") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}
