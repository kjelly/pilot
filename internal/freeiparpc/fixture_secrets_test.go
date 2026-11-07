package freeiparpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// The one-time passwords the live captures send are never stored: no request
// is kept, and the answers to passwd do not carry the password. A fixture
// directory is checked for them anyway, because the password of a capture is
// random (nothing here knows its value), so what is looked for is what the
// harnesses make: the prefix the P2-4 harness gives every password it sends,
// the P0 live test's P0-<24 hex>, and the password of the fake server.
var oneTimePasswordPatterns = map[string]*regexp.Regexp{
	"the P2-4 harness's password prefix":    regexp.MustCompile(`(?i)` + regexp.QuoteMeta(p24CapPasswordPrefix)),
	"the P0 live test's one-time password":  regexp.MustCompile(`P0-[0-9a-f]{24}`),
	"the password of the fake test server":  regexp.MustCompile(regexp.QuoteMeta(testPassword)),
	"a stored request's password option":    regexp.MustCompile(`"(current_|new_|old_)?password"\s*:\s*"[^"]`),
	"the admin login form's password field": regexp.MustCompile(`(^|&)password=[^&\s]`),
	"a password in a stored session cookie": regexp.MustCompile(`(?i)ipa_session=[0-9a-f]{8,}`),
}

// requestKeys are the keys of a JSON-RPC request: an answer has none of them,
// so a fixture that has one is a stored request.
var requestKeys = []string{"method", "params"}

// passwordKeys are the keys that would carry a password; a passwd answer has
// none (its error data names the parameter as a value, not as a key).
var passwordKeys = []string{"password", "current_password", "new_password", "old_password", "userpassword"}

// passwordFindings lists what in the fixtures of dir could hold a password:
// a pattern of oneTimePasswordPatterns in any file (the finding names the
// pattern, never what matched), a JSON document that is a request, and a
// passwd answer with a key that carries a password.
func passwordFindings(t *testing.T, dir string) []string {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var findings []string
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for what, re := range oneTimePasswordPatterns {
			if re.Match(data) {
				findings = append(findings, f.Name()+": holds "+what)
			}
		}
		if filepath.Ext(f.Name()) != ".json" {
			continue
		}
		var doc any
		if err := json.Unmarshal(data, &doc); err != nil {
			continue // not JSON: the patterns above are all that applies
		}
		isPasswd := strings.HasPrefix(f.Name(), "passwd-")
		var walk func(v any, path string)
		walk = func(v any, path string) {
			switch v := v.(type) {
			case map[string]any:
				for k, e := range v {
					lk := strings.ToLower(k)
					if path == "" && slices.Contains(requestKeys, lk) {
						findings = append(findings, f.Name()+": is shaped like a request (a top-level "+k+" key)")
					}
					if isPasswd && slices.Contains(passwordKeys, lk) {
						findings = append(findings, f.Name()+": a passwd answer has the key "+k+" at "+path+"/"+k)
					}
					walk(e, path+"/"+k)
				}
			case []any:
				for i, e := range v {
					walk(e, fmt.Sprintf("%s[%d]", path, i))
				}
			}
		}
		walk(doc, "")
	}
	sort.Strings(findings)
	return findings
}

// No fixture holds a password the captures sent, a request, or a key that
// carries one.
func TestFixtureDirectoryHoldsNoPassword(t *testing.T) {
	if findings := passwordFindings(t, "testdata"); len(findings) != 0 {
		t.Fatalf("%d findings:\n%s", len(findings), strings.Join(findings, "\n"))
	}
	passwd, err := filepath.Glob(filepath.Join("testdata", "passwd-*.json"))
	if err != nil || len(passwd) < 7 {
		t.Fatalf("%d passwd fixtures found (%v): the scan above would have nothing to say about them", len(passwd), err)
	}
}

// The scan has to fire on what it is for (AGENTS.md §5.12), with the kinds of
// fixture it exists to keep out; the real fixtures are the case that passes.
func TestPasswordFindingsFire(t *testing.T) {
	realPasswd, err := os.ReadFile(filepath.Join("testdata", "passwd-success.json"))
	if err != nil {
		t.Fatal(err)
	}
	dirWith := func(extra map[string]string) string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "passwd-success.json"), realPasswd, 0o600); err != nil {
			t.Fatal(err)
		}
		for name, content := range extra {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	if got := passwordFindings(t, dirWith(nil)); len(got) != 0 {
		t.Fatalf("a real passwd answer has findings: %q", got)
	}
	for name, tc := range map[string]struct {
		extra map[string]string
		want  string
	}{
		"the harness's prefix in an answer":  {map[string]string{"x.json": `{"error":{"message":"` + p24CapPasswordPrefix + `-0123456789abcdef0123"}}`}, "the P2-4 harness's password prefix"},
		"the prefix in lower case":           {map[string]string{"x.json": `{"summary":"` + strings.ToLower(p24CapPasswordPrefix) + `x"}`}, "the P2-4 harness's password prefix"},
		"a P0 one-time password in a header": {map[string]string{"x.headers": "X-Debug: P0-0123456789abcdef01234567\n"}, "the P0 live test's one-time password"},
		"the fake server's password":         {map[string]string{"x.body": "password=" + testPassword}, "the password of the fake test server"},
		"a stored request with its password": {map[string]string{"passwd-request.json": `{"method":"passwd","params":[["u"],{"password":"hunter2hunter2"}],"id":0}`}, "a stored request's password option"},
		"a request shape without a password": {map[string]string{"passwd-request.json": `{"method":"passwd","params":[["u"],{}],"id":0}`}, "is shaped like a request"},
		"a login form":                       {map[string]string{"login.body": "user=admin&password=x"}, "the admin login form's password field"},
		"a session cookie":                   {map[string]string{"login.headers": "Set-Cookie: ipa_session=0123456789abcdef; Path=/ipa\n"}, "a password in a stored session cookie"},
		"a password key in a passwd answer":  {map[string]string{"passwd-leak.json": `{"result":{"result":true,"password":"x"}}`}, "a passwd answer has the key password"},
		"a nested current_password":          {map[string]string{"passwd-leak.json": `{"result":{"value":{"Current_Password":"x"}}}`}, "a passwd answer has the key Current_Password"},
	} {
		t.Run(name, func(t *testing.T) {
			got := passwordFindings(t, dirWith(tc.extra))
			if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Fatalf("findings = %q, want one containing %q", got, tc.want)
			}
			for _, f := range got {
				if strings.Contains(f, "hunter2") || strings.Contains(f, testPassword) || strings.Contains(f, "0123456789abcdef") {
					t.Fatalf("a finding shows what it found: %s", f)
				}
			}
		})
	}
	// An error answer may name the parameter as a value, as the empty-password
	// answer does; and a key named password in a non-passwd fixture is not this
	// scan's business (user_show has krbpasswordexpiration).
	for name, extra := range map[string]map[string]string{
		"the parameter named as a value": {"passwd-empty.json": `{"error":{"name":"RequirementError","data":{"name":"password"}}}`},
		"a krb attribute elsewhere":      {"user-show.json": `{"result":{"result":{"krbpasswordexpiration":[{"__datetime__":"20261106141734Z"}]}}}`},
	} {
		if got := passwordFindings(t, dirWith(extra)); len(got) != 0 {
			t.Fatalf("%s: findings %q", name, got)
		}
	}
}

// The P2-4 fixtures name no lab: no address, no host of another domain, no
// path of the machine that took them (the home directories FreeIPA gives its
// users, /home/<uid>, are the server's own and are in the answers). The realm
// and domain are the lab's, as in every earlier capture, so a dotted name has
// to be one of those, the example domain of the mail addresses, or a version.
var labIdentifierPatterns = map[string]*regexp.Regexp{
	"an IPv4 address":                     regexp.MustCompile(`\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b`),
	"a path of the machine that captured": regexp.MustCompile(`/home/kjelly|/Users/|/tmp/|/var/lib/libvirt|/root/`),
}

var (
	dottedNameRe   = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+\b`)
	versionRe      = regexp.MustCompile(`^[0-9]+(\.[0-9]+){1,2}$`)
	allowedDomains = []string{"ipa.pilot.internal", "pilot.internal", "example.test"}
	// the marker's description (pilot.group-history/v1) is a name, not a host
	allowedNames = []string{"pilot.group-history"}
)

func labIdentifierFindings(t *testing.T, dir string, names []string) []string {
	t.Helper()
	var findings []string
	for _, n := range names {
		for _, ext := range []string{".status", ".headers", ".json"} {
			data, err := os.ReadFile(filepath.Join(dir, n+ext))
			if err != nil {
				t.Fatal(err)
			}
			for what, re := range labIdentifierPatterns {
				if re.Match(data) {
					findings = append(findings, n+ext+": holds "+what)
				}
			}
			if ext == ".headers" {
				continue // Content-Type: application/json; charset=utf-8
			}
			for _, tok := range dottedNameRe.FindAllString(string(data), -1) {
				low := strings.ToLower(tok)
				ok := versionRe.MatchString(low) || slices.Contains(allowedNames, low)
				for _, d := range allowedDomains {
					ok = ok || low == d || strings.HasSuffix(low, "."+d)
				}
				if !ok {
					findings = append(findings, n+ext+": holds a hostname outside the lab's domain")
					break
				}
			}
		}
	}
	sort.Strings(findings)
	return findings
}

func TestWriteCapturesHoldNoLabIdentifiers(t *testing.T) {
	if got := labIdentifierFindings(t, "testdata", p24Fixtures); len(got) != 0 {
		t.Fatalf("%d findings:\n%s", len(got), strings.Join(got, "\n"))
	}
	dir := t.TempDir()
	for what, content := range map[string]string{
		"an IPv4 address":                     `{"x":"connected from 203.0.113.9"}`,
		"a hostname outside the lab's domain": `{"x":"vm-ipa.lab.example.org"}`,
		"a path of the machine that captured": `{"x":"/home/kjelly/file"}`,
	} {
		for _, ext := range []string{".status", ".headers"} {
			if err := os.WriteFile(filepath.Join(dir, "probe"+ext), []byte("200\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, "probe.json"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		got := labIdentifierFindings(t, dir, []string{"probe"})
		if len(got) == 0 || !strings.Contains(strings.Join(got, "\n"), what) {
			t.Fatalf("%s: findings = %q", what, got)
		}
	}
	// the lab's own names pass
	if err := os.WriteFile(filepath.Join(dir, "probe.json"), []byte(`{"x":"ipa1.ipa.pilot.internal a@example.test 4.13.4 IPA.PILOT.INTERNAL pilot.group-history/v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := labIdentifierFindings(t, dir, []string{"probe"}); len(got) != 0 {
		t.Fatalf("the lab's own names are findings: %q", got)
	}
}
