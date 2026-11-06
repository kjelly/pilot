package freeiparpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// Two captures of the same harness differ in the values the server makes up:
// identifiers, the numbers it allocates, the time. Everything else (the
// names, the error names and codes, which attribute is there and which is
// not, the order of the members) is what the fixtures are for, so it has to
// be the same. normalizeCapture masks the first kind and keeps the second.

var (
	captureUUIDRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	captureNumberRe = regexp.MustCompile(`^[0-9]{8,}$`)
	captureSIDRe    = regexp.MustCompile(`^S-1-5-21-[0-9-]+$`)
)

func normalizeCaptureValue(v any) any {
	switch v := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, e := range v {
			if k == "__base64__" {
				if s, _ := e.(string); s != fixtureSecretPlaceholder {
					out[k] = "<base64>"
					continue
				}
			}
			out[k] = normalizeCaptureValue(e)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, e := range v {
			out[i] = normalizeCaptureValue(e)
		}
		return out
	case string:
		switch {
		case captureUUIDRe.MatchString(v):
			return "<uuid>"
		case captureSIDRe.MatchString(v):
			return "<sid>"
		case stampFormat.MatchString(v):
			return "<time>"
		case captureNumberRe.MatchString(v):
			return "<number>"
		}
	}
	return v
}

// normalizeCapture decodes one answer and masks the volatile values.
func normalizeCapture(raw []byte) (any, error) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return normalizeCaptureValue(doc), nil
}

// firstDifference names the first place two normalized documents differ.
func firstDifference(a, b any, path string) string {
	if reflect.DeepEqual(a, b) {
		return ""
	}
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return path + ": an object against " + fmt.Sprintf("%T", b)
		}
		keys := map[string]bool{}
		for k := range av {
			keys[k] = true
		}
		for k := range bv {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			x, xok := av[k]
			y, yok := bv[k]
			switch {
			case !xok:
				return path + "/" + k + ": only in the second"
			case !yok:
				return path + "/" + k + ": only in the first"
			}
			if d := firstDifference(x, y, path+"/"+k); d != "" {
				return d
			}
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return path + ": a list against " + fmt.Sprintf("%T", b)
		}
		if len(av) != len(bv) {
			return fmt.Sprintf("%s: %d values against %d", path, len(av), len(bv))
		}
		for i := range av {
			if d := firstDifference(av[i], bv[i], fmt.Sprintf("%s[%d]", path, i)); d != "" {
				return d
			}
		}
	}
	return path + ": values differ"
}

// captureNames lists the fixture names (file stems) of a directory.
func captureNames(t *testing.T, dir string) []string {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var names []string
	for _, f := range files {
		stem := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
		if !seen[stem] {
			seen[stem] = true
			names = append(names, stem)
		}
	}
	sort.Strings(names)
	return names
}

// compareCaptureDirs returns what differs between a capture directory and the
// committed fixtures, restricted to the names in want.
func compareCaptureDirs(t *testing.T, capture, committed string, want []string) []string {
	t.Helper()
	var problems []string
	have := captureNames(t, capture)
	for _, n := range want {
		if !slices.Contains(have, n) {
			problems = append(problems, n+": not captured")
		}
	}
	for _, n := range have {
		if !slices.Contains(want, n) {
			problems = append(problems, n+": captured but not a committed fixture")
		}
	}
	for _, n := range want {
		if !slices.Contains(have, n) {
			continue
		}
		for _, ext := range []string{".status", ".headers"} {
			a, errA := os.ReadFile(filepath.Join(capture, n+ext))
			b, errB := os.ReadFile(filepath.Join(committed, n+ext))
			if errA != nil || errB != nil || !bytes.Equal(a, b) {
				problems = append(problems, n+ext+": differs")
			}
		}
		a, errA := os.ReadFile(filepath.Join(capture, n+".json"))
		b, errB := os.ReadFile(filepath.Join(committed, n+".json"))
		if errA != nil || errB != nil {
			problems = append(problems, n+".json: unreadable")
			continue
		}
		na, errA := normalizeCapture(a)
		nb, errB := normalizeCapture(b)
		if errA != nil || errB != nil {
			problems = append(problems, n+".json: not JSON")
			continue
		}
		if d := firstDifference(na, nb, ""); d != "" {
			problems = append(problems, n+".json "+d)
		}
	}
	return problems
}

// A new run of the harness (TestLiveCaptureP24) must give back the committed
// fixtures: the same names, the same answers.
func TestCaptureDirMatchesFixtures(t *testing.T) {
	dir := os.Getenv("PILOT_FREEIPA_CAPTURE_COMPARE")
	if dir == "" {
		t.Skip("PILOT_FREEIPA_CAPTURE_COMPARE is not set")
	}
	if problems := compareCaptureDirs(t, dir, "testdata", p24Fixtures); len(problems) != 0 {
		t.Fatalf("%d differences from the committed fixtures:\n%s", len(problems), strings.Join(problems, "\n"))
	}
}

func TestNormalizeCaptureMasksOnlyWhatChangesFromRunToRun(t *testing.T) {
	run1 := `{"result":{"result":{"ipauniqueid":["5dc06d5a-d9ed-11f1-8e23-5254001b059e"],"uidnumber":["1927600354"],
		"krblastpwdchange":[{"__datetime__":"20261106142126Z"}],"krbextradata":[{"__base64__":"AAJm4u1q"}],
		"ipantsecurityidentifier":["S-1-5-21-3998632271-3893472475-798555519-1367"],"uid":["p24cap-u"],
		"krbprincipalkey":[{"__base64__":"` + fixtureSecretPlaceholder + `"}]}},"error":null,"id":0}`
	run2 := `{"result":{"result":{"ipauniqueid":["6e2217ab-d9ed-11f1-8e23-5254001b059e"],"uidnumber":["1927600399"],
		"krblastpwdchange":[{"__datetime__":"20261107010101Z"}],"krbextradata":[{"__base64__":"AAKx9v2z"}],
		"ipantsecurityidentifier":["S-1-5-21-3998632271-3893472475-798555519-1400"],"uid":["p24cap-u"],
		"krbprincipalkey":[{"__base64__":"` + fixtureSecretPlaceholder + `"}]}},"error":null,"id":0}`
	a, errA := normalizeCapture([]byte(run1))
	b, errB := normalizeCapture([]byte(run2))
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if d := firstDifference(a, b, ""); d != "" {
		t.Fatalf("two runs that differ only in made-up values differ: %s", d)
	}
	// and the things a capture is for are not masked: each of these is a
	// different answer
	for name, change := range map[string]func(string) string{
		"another name":      func(s string) string { return strings.Replace(s, `"p24cap-u"`, `"p24cap-v"`, 1) },
		"an attribute gone": func(s string) string { return strings.Replace(s, `"uidnumber":["1927600399"],`, ``, 1) },
		"an error appears": func(s string) string {
			return strings.Replace(s, `"error":null`, `"error":{"name":"NotFound","code":4001}`, 1)
		},
		"a short number": func(s string) string { return strings.Replace(s, `"id":0`, `"id":7`, 1) },
		"another placeholder": func(s string) string {
			return strings.Replace(s, fixtureSecretPlaceholder, "QUJDREVGR0hJSktMTU5PUA==", 1)
		},
		"another time shape": func(s string) string { return strings.Replace(s, `20261107010101Z`, `soon`, 1) },
	} {
		c, err := normalizeCapture([]byte(change(run2)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if firstDifference(a, c, "") == "" {
			t.Fatalf("%s is masked, so a capture that changed this would still match", name)
		}
	}
}

func TestCompareCaptureDirsFindsWhatDiffers(t *testing.T) {
	write := func(dir, name, status, body string) {
		t.Helper()
		for ext, data := range map[string]string{".status": status, ".headers": "Content-Type: application/json; charset=utf-8\n", ".json": body} {
			if err := os.WriteFile(filepath.Join(dir, name+ext), []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	committed, fresh := t.TempDir(), t.TempDir()
	body := `{"result":null,"error":{"name":"NotFound","code":4001,"message":"x: user not found"}}`
	write(committed, "a", "200\n", body)
	write(fresh, "a", "200\n", body)
	if got := compareCaptureDirs(t, fresh, committed, []string{"a"}); len(got) != 0 {
		t.Fatalf("identical directories differ: %v", got)
	}
	write(fresh, "a", "200\n", strings.Replace(body, "NotFound", "EmptyResult", 1))
	if got := compareCaptureDirs(t, fresh, committed, []string{"a"}); len(got) != 1 || !strings.Contains(got[0], "a.json /error/name") {
		t.Fatalf("a changed error name = %v", got)
	}
	write(fresh, "a", "500\n", body)
	if got := compareCaptureDirs(t, fresh, committed, []string{"a"}); len(got) != 1 || !strings.Contains(got[0], "a.status") {
		t.Fatalf("a changed status = %v", got)
	}
	write(fresh, "a", "200\n", body)
	write(fresh, "extra", "200\n", body)
	got := compareCaptureDirs(t, fresh, committed, []string{"a"})
	if len(got) != 1 || !strings.Contains(got[0], "extra: captured but not a committed fixture") {
		t.Fatalf("an extra capture = %v", got)
	}
	got = compareCaptureDirs(t, fresh, committed, []string{"a", "missing"})
	if len(got) != 2 || !slices.Contains(got, "missing: not captured") {
		t.Fatalf("a missing capture = %v", got)
	}
}
