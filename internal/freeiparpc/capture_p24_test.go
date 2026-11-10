package freeiparpc

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"unicode"
)

// The parts of the P2-4 capture harness that need no server: what it does to
// an answer before it is written, and the passwords it sends.

const (
	rawUserShowWithSecrets = `{"result":{"result":{"uid":["u"],"ipanthash":[{"__base64__":"QUJDREVGR0hJSktMTU5PUA=="}],` +
		`"krbprincipalkey":[{"__base64__":"QUJD"},{"__base64__":"REVG"}],"userpassword":[{"__base64__":"R0hJ"}],` +
		`"mail":["a<b>&c@example.test"],"ipatokenotpkey":"QUJD","krbextradata":[{"__base64__":"AAJm"}]},"value":"u","summary":null},` +
		`"error":null,"id":0,"principal":"admin@IPA.PILOT.INTERNAL","version":"4.13.4"}`
)

func TestRedactCaptureReplacesEverySecretAndKeepsTheShape(t *testing.T) {
	out, n, err := redactCapture([]byte(rawUserShowWithSecrets))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Fatalf("replaced %d attributes, want 4 (ipanthash, krbprincipalkey, userpassword, ipatokenotpkey)", n)
	}
	for _, leaked := range []string{"QUJDREVGR0hJSktMTU5PUA", "QUJD", "REVG", "R0hJ"} {
		if strings.Contains(string(out), leaked) {
			t.Fatalf("the redacted answer still holds %s", leaked)
		}
	}
	findings, err := secretFixtureFindings(out)
	if err != nil || len(findings) != 0 {
		t.Fatalf("the fixture-secret check reads findings %q (%v) in the redacted answer", findings, err)
	}
	// One placeholder per value: the two Kerberos keys stay two values, a
	// scalar becomes a one-value list.
	if got := strings.Count(string(out), fixtureSecretPlaceholder); got != 1+2+1+1 {
		t.Fatalf("%d placeholders, want 5", got)
	}
	// What is not a secret is kept as it was, in the server's order.
	for _, kept := range []string{`"AAJm"`, `"mail": [` + "\n        \"a<b>&c@example.test\"", `"version": "4.13.4"`} {
		if !strings.Contains(string(out), kept) {
			t.Fatalf("the redacted answer lost %s:\n%s", kept, out)
		}
	}
	if strings.Index(string(out), `"result"`) > strings.Index(string(out), `"error"`) {
		t.Fatal("the redacted answer reorders the server's keys")
	}
	if !strings.HasSuffix(string(out), "}\n") || strings.Contains(string(out), "\t") {
		t.Fatal("the redacted answer is not indented with spaces and ended by a newline")
	}
}

// The check has to fire on what it is for (AGENTS.md §5.12): the same answer
// without the redaction is what the fixture-secret test refuses.
func TestRedactionIsWhatKeepsTheFixtureSecretCheckQuiet(t *testing.T) {
	findings, err := secretFixtureFindings([]byte(rawUserShowWithSecrets))
	if err != nil || len(findings) != 4 {
		t.Fatalf("the raw answer has %d findings (%v), want 4: %q", len(findings), err, findings)
	}
}

func TestRedactCaptureRefusesWhatIsNotOneJSONDocument(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":         ``,
		"cut off":       `{"result":{"ipanthash":`,
		"trailing data": `{"result":null}{"result":null}`,
		"not an object": `nope`,
	} {
		if _, _, err := redactCapture([]byte(raw)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	out, n, err := redactCapture([]byte(`{"IPANTHash":["x"],"userpasswordx":["kept"],"nested":[{"krbPrincipalKey":[]}]}`))
	if err != nil || n != 2 {
		t.Fatalf("redacted %d, %v", n, err)
	}
	if !strings.Contains(string(out), `"userpasswordx"`) || !strings.Contains(string(out), `"kept"`) {
		t.Fatalf("a name that only starts like a secret attribute was replaced:\n%s", out)
	}
}

// The passwords the harness sends are what the passwd captures rest on.
func TestCapturePasswordsHaveTheShapeTheCapturesAssume(t *testing.T) {
	p := &p24Capture{t: t}
	classes := func(s string) (upper, lower, digit, other int) {
		for _, r := range s {
			switch {
			case unicode.IsUpper(r):
				upper++
			case unicode.IsLower(r):
				lower++
			case unicode.IsDigit(r):
				digit++
			default:
				other++
			}
		}
		return
	}
	normal, short, few := p.password(), p.shortPassword(), p.lowerPassword()
	for _, s := range []string{normal, short, few} {
		if !strings.HasPrefix(s, p24CapPasswordPrefix) {
			t.Fatalf("a password without the prefix the directory scan looks for: %d characters", len(s))
		}
	}
	// the global policy asks for 8 characters (pwpolicy-show-global-at-capture)
	if len(short) >= 8 || len(normal) < 8 || len(few) < 8 {
		t.Fatalf("lengths %d, %d, %d: the short one must be under 8 and the others not", len(normal), len(short), len(few))
	}
	if u, l, d, o := classes(normal); u == 0 || l == 0 || d == 0 || o == 0 {
		t.Fatal("the ordinary password must have four character classes")
	}
	if u, l, d, o := classes(few); u == 0 || l == 0 || d == 0 || o != 0 {
		t.Fatal("the few-classes password must have exactly three (upper, lower, digit), under the four a policy asks for")
	}
	if more := p.password(); more == normal || len(p.secrets) != 4 {
		t.Fatalf("passwords repeat, or are not all registered (%d)", len(p.secrets))
	}
}

func TestScanDirForLiteralsFindsWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"x":"has the-secret in it"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"x":"nothing"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := scanDirForLiterals(t, dir, []string{"the-secret"}); !slices.Equal(got, []string{"a.json"}) {
		t.Fatalf("hits = %v", got)
	}
	if got := scanDirForLiterals(t, dir, []string{"", "absent"}); len(got) != 0 {
		t.Fatalf("hits = %v for literals that are not there (and an empty one)", got)
	}
}
