package evidence

import (
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

// isSecretKey reports whether a variable name sounds like a secret. Path
// variables that happen to mention a key file (`ssh_private_key_file`) are
// excluded by the value filter in secretValue.
func isSecretKey(key string) bool {
	last := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		last = key[i+1:]
	}
	return secretKeyRe.MatchString(last)
}

// secretValue reports whether a value is worth scanning for: long enough to
// be a secret rather than a common word, and not a file path.
func secretValue(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) < 8 || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "{{") {
		return false
	}
	return true
}

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
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			skipped = append(skipped, f+" (not YAML)")
			continue
		}
		collectSecrets(f, "", doc, &sources)
	}
	for i := 0; i < len(extraArgs); i++ {
		a := extraArgs[i]
		var kv string
		switch {
		case a == "-e" || a == "--extra-vars":
			if i+1 < len(extraArgs) {
				i++
				kv = extraArgs[i]
			}
		case strings.HasPrefix(a, "-e="):
			kv = a[3:]
		case strings.HasPrefix(a, "--extra-vars="):
			kv = a[len("--extra-vars="):]
		}
		if kv == "" || strings.HasPrefix(kv, "@") {
			continue
		}
		key, val, ok := strings.Cut(kv, "=")
		if ok && isSecretKey(key) && secretValue(val) {
			sources = append(sources, SecretSource{Key: "-e " + key, value: strings.TrimSpace(val)})
		}
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Key < sources[j].Key })
	return sources, skipped
}

func collectSecrets(file, prefix string, node any, out *[]SecretSource) {
	switch v := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			collectSecrets(file, p, v[k], out)
		}
	case []any:
		for _, item := range v {
			collectSecrets(file, prefix, item, out)
		}
	case string:
		if prefix != "" && isSecretKey(prefix) && secretValue(v) {
			*out = append(*out, SecretSource{Key: file + ":" + prefix, value: strings.TrimSpace(v)})
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
