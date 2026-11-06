package freeiparpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Captured FreeIPA answers are committed as fixtures, and an `--all` read
// of a user carries the user's credential material: the NT hash, the
// password, the Kerberos keys and an OTP token's secret. A fixture keeps
// the attribute, because the shape is the fact under test, and replaces
// its value with the same placeholder every time. AGENTS.md §5.6 requires
// fixtures to come from real captures, not to publish what the capture
// held (the NT hash of a lab account was committed once; the hash is still
// in the history of the branch that added it).

// secretFixtureAttributes are the FreeIPA attributes that hold a secret
// when a read is taken with all=true, lower-cased.
var secretFixtureAttributes = []string{"ipanthash", "userpassword", "krbprincipalkey", "ipatokenotpkey"}

// fixtureSecretPlaceholder is the one value a secret attribute may hold in
// a fixture: sixteen zero bytes in FreeIPA's binary-value encoding.
const fixtureSecretPlaceholder = "AAAAAAAAAAAAAAAAAAAAAA=="

// secretFixtureFindings lists where a captured JSON document holds a
// secret-bearing attribute with anything but the placeholder. Findings name
// the attribute and where it sits, never the value.
func secretFixtureFindings(data []byte) ([]string, error) {
	var doc any
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	var findings []string
	var walk func(v any, path string)
	walk = func(v any, path string) {
		switch v := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				at := path + "/" + k
				if isSecretFixtureAttribute(k) {
					if !isPlaceholderList(v[k]) {
						findings = append(findings, at+": a secret attribute that is not the placeholder")
					}
					continue
				}
				walk(v[k], at)
			}
		case []any:
			for i, e := range v {
				walk(e, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(doc, "")
	return findings, nil
}

func isSecretFixtureAttribute(name string) bool {
	name = strings.ToLower(name)
	for _, secret := range secretFixtureAttributes {
		if name == secret {
			return true
		}
	}
	return false
}

// isPlaceholderList reports whether v is a non-empty list whose every value
// is exactly {"__base64__": <placeholder>}.
func isPlaceholderList(v any) bool {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return false
	}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok || len(m) != 1 || m["__base64__"] != fixtureSecretPlaceholder {
			return false
		}
	}
	return true
}

// The check has to fire on what it exists to catch and stay quiet on what
// it allows (AGENTS.md §5.12). The unsafe values here are made up.
func TestSecretFixtureFindingsFire(t *testing.T) {
	const placeholder = `{"__base64__": "` + fixtureSecretPlaceholder + `"}`
	for _, tc := range []struct {
		name, doc string
		want      []string // finding paths, in order
	}{
		{name: "placeholder everywhere", doc: `{"result":{"result":[{"uid":["u"],"ipanthash":[` + placeholder + `],"krbprincipalkey":[` + placeholder + `,` + placeholder + `]}]}}`},
		{name: "no secret attribute", doc: `{"result":{"result":[{"uid":["u"],"sshpubkeyfp":["SHA256:abc"]}]}}`},
		{name: "case is not an escape", doc: `[{"IPANTHash":[{"__base64__":"QUJDREVGR0hJSktMTU5PUA=="}]}]`, want: []string{"[0]/IPANTHash"}},
		{name: "a real-looking nt hash", doc: `{"result":{"result":[{"ipanthash":[{"__base64__":"QUJDREVGR0hJSktMTU5PUA=="}]}]}}`, want: []string{"/result/result[0]/ipanthash"}},
		{name: "a plain string", doc: `{"userpassword":["not-a-placeholder"]}`, want: []string{"/userpassword"}},
		{name: "not a list", doc: `{"krbprincipalkey":"x"}`, want: []string{"/krbprincipalkey"}},
		{name: "an empty list", doc: `{"ipatokenotpkey":[]}`, want: []string{"/ipatokenotpkey"}},
		{name: "one bad value among placeholders", doc: `{"ipatokenotpkey":[` + placeholder + `,{"__base64__":"QUJD"}]}`, want: []string{"/ipatokenotpkey"}},
		{name: "extra keys beside the placeholder", doc: `{"userpassword":[{"__base64__":"` + fixtureSecretPlaceholder + `","other":"x"}]}`, want: []string{"/userpassword"}},
		{name: "deep in a batch answer", doc: `{"result":{"results":[{"result":{"result":[{"userpassword":[{"__base64__":"QUJD"}]}]}}]}}`, want: []string{"/result/results[0]/result/result[0]/userpassword"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := secretFixtureFindings([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, "\n") != strings.Join(withReason(tc.want), "\n") {
				t.Fatalf("findings = %q, want %q", got, withReason(tc.want))
			}
			for _, f := range got {
				if strings.Contains(f, "QUJD") || strings.Contains(f, "not-a-placeholder") {
					t.Fatalf("a finding shows the value: %s", f)
				}
			}
		})
	}
	if _, err := secretFixtureFindings([]byte(`{"ipanthash":`)); err == nil {
		t.Fatal("an unparsable document passed")
	}
}

func withReason(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = p + ": a secret attribute that is not the placeholder"
	}
	return out
}

// Every committed fixture: a JSON capture holds no secret attribute but the
// placeholder, and no other file (HTTP bodies and headers) names one.
func TestCapturedFixturesCarryNoSecrets(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	var scanned int
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		if filepath.Ext(file) == ".json" {
			findings, err := secretFixtureFindings(data)
			if err != nil {
				t.Errorf("%s: %v", file, err)
			}
			for _, f := range findings {
				t.Errorf("%s %s; replace the value with {\"__base64__\": %q}", file, f, fixtureSecretPlaceholder)
			}
			continue
		}
		lower := strings.ToLower(string(data))
		for _, attr := range secretFixtureAttributes {
			if strings.Contains(lower, attr) {
				t.Errorf("%s names the secret attribute %s", file, attr)
			}
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d fixture files; the glob no longer finds them", scanned)
	}
}
