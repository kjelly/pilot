package gateledger

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// holder is a function with three gates, a success return, a closure whose
// returns are not the function's, and a rejected-or-allowed path.
const holder = `package p

import "errors"

func check(a, b int) error {
	if a < 0 {
		return errors.New("a") // gate: a-negative
	}
	if b < 0 {
		// gate: b-negative
		return errors.New("b")
	}
	f := func() error { return errors.New("closure") }
	if err := f(); err != nil {
		return err // gate: closure-failed
	}
	return nil
}
`

func scan(t *testing.T, src string) Result {
	t.Helper()
	res, err := Scan("p.go", []byte(src), "check")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ids(res Result) []string {
	var out []string
	for _, r := range res.Returns {
		out = append(out, r.Gate)
	}
	return out
}

func TestScanFindsEveryNonNilReturn(t *testing.T) {
	res := scan(t, holder)
	if got, want := ids(res), []string{"a-negative", "b-negative", "closure-failed"}; !slices.Equal(got, want) {
		t.Fatalf("gates = %v, want %v (the closure's return and `return nil` are not gates)", got, want)
	}
	if len(res.Stray) != 0 {
		t.Fatalf("stray = %v", res.Stray)
	}
}

func rows(ids ...string) map[string]int {
	m := map[string]int{}
	for _, id := range ids {
		m[id]++
	}
	return m
}

// Each way the ledger can go wrong is reported: these are the cases the
// callers' tests rely on to fire when a gate is added without a row, loses
// its name, or is removed.
func TestCheckFiresOnEveryDrift(t *testing.T) {
	full := rows("a-negative", "b-negative", "closure-failed")
	if p := Check(scan(t, holder), full, nil); len(p) != 0 {
		t.Fatalf("a complete ledger reported %v", p)
	}
	for _, tc := range []struct {
		name   string
		mutate func(src string) string
		rows   map[string]int
		exempt map[string]string
		want   string
	}{
		{
			name:   "a gate loses its comment",
			mutate: func(s string) string { return strings.Replace(s, " // gate: a-negative", "", 1) },
			rows:   full,
			want:   "return without a `// gate: <id>` comment",
		},
		{
			name: "a new return without a comment",
			mutate: func(s string) string {
				return strings.Replace(s, "\treturn nil\n}", "\tif a == 7 {\n\t\treturn errors.New(\"seven\")\n\t}\n\treturn nil\n}", 1)
			},
			rows: full,
			want: "return without a `// gate: <id>` comment",
		},
		{
			name: "a new gate without a row",
			mutate: func(s string) string {
				return strings.Replace(s, "\treturn nil\n}", "\tif a == 7 {\n\t\treturn errors.New(\"seven\") // gate: seven\n\t}\n\treturn nil\n}", 1)
			},
			rows: full,
			want: `gate "seven" has no row`,
		},
		{
			name:   "two returns share an id",
			mutate: func(s string) string { return strings.Replace(s, "closure-failed", "a-negative", 1) },
			rows:   full,
			want:   `gate "a-negative" is also at line`,
		},
		{
			name: "a row's gate was deleted from the code",
			mutate: func(s string) string {
				return strings.Replace(s, "\t\treturn err // gate: closure-failed\n", "\t\tpanic(err)\n", 1)
			},
			rows: full,
			want: `a test row names gate "closure-failed", which no return carries`,
		},
		{
			name:   "a gate lost its row",
			mutate: func(s string) string { return s },
			rows:   rows("a-negative", "b-negative"),
			want:   `gate "closure-failed" has no row`,
		},
		{
			name:   "an exemption outlives its need",
			mutate: func(s string) string { return s },
			rows:   full,
			exempt: map[string]string{"a-negative": "unreachable"},
			want:   `gate "a-negative" has a row now`,
		},
		{
			name:   "an exemption names nothing",
			mutate: func(s string) string { return s },
			rows:   full,
			exempt: map[string]string{"gone": "was unreachable"},
			want:   `exemption "gone" names no gate`,
		},
		{
			name:   "an exemption without a reason",
			mutate: func(s string) string { return s },
			rows:   rows("a-negative", "b-negative"),
			exempt: map[string]string{"closure-failed": " "},
			want:   `exemption "closure-failed" has no reason`,
		},
		{
			name: "a gate comment on something that is not a gate",
			mutate: func(s string) string {
				return strings.Replace(s, "\treturn nil\n}", "\t// gate: orphan\n\treturn nil\n}", 1)
			},
			rows: full,
			want: "gate comment that is not on a counted return",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			problems := Check(scan(t, tc.mutate(holder)), tc.rows, tc.exempt)
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.want) }) {
				t.Fatalf("problems = %v, want one holding %q", problems, tc.want)
			}
		})
	}
}

// An exemption stands in for a row; with its reason the ledger is complete.
func TestCheckAcceptsAnExemptionWithAReason(t *testing.T) {
	if p := Check(scan(t, holder), rows("a-negative", "b-negative"), map[string]string{"closure-failed": "defense in depth"}); len(p) != 0 {
		t.Fatalf("problems = %v", p)
	}
}

// A function the caller names but the file lacks is an error, so renaming a
// gate holder cannot make the check pass by scanning nothing.
func TestScanRefusesAMissingFunction(t *testing.T) {
	if _, err := Scan("p.go", []byte(holder), "check", "renamed"); err == nil || !strings.Contains(err.Error(), "renamed") {
		t.Fatalf("err = %v", err)
	}
}

func TestRowGatesReadsGateFieldsOfCompositeLiterals(t *testing.T) {
	src := `package p

var rowsA = []struct{ name, gate string }{
	{name: "x", gate: "one"},
	{name: "y", gate: "two, three"},
	{name: "z"},
	{name: "w", gate: ""},
}

var other = map[string]string{"gate": "not-a-field"}
`
	path := filepath.Join(t.TempDir(), "rows_test.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := RowGates(path)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"one": 1, "two": 1, "three": 1}
	if len(got) != len(want) {
		t.Fatalf("rows = %v, want %v", got, want)
	}
	for id, n := range want {
		if got[id] != n {
			t.Fatalf("rows = %v, want %v", got, want)
		}
	}
}
