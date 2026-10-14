package ansible

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var updateRedactionGolden = flag.Bool("update-redaction-golden", false, "rewrite testdata/redaction-golden.json from the current redaction")

const redactionGoldenPath = "testdata/redaction-golden.json"

// redactionGoldenCase is a log written in pieces, with maintenance after the
// pieces maintain_after marks and once at the end, and what maintenance
// leaves of it.
type redactionGoldenCase struct {
	Name          string   `json:"name"`
	Pieces        []string `json:"pieces"`
	MaintainAfter []bool   `json:"maintain_after,omitempty"`
	Want          string   `json:"want"`
}

type redactionGolden struct {
	Format string                `json:"format"`
	Cases  []redactionGoldenCase `json:"cases"`
}

func runRedactionGoldenCase(t *testing.T, c redactionGoldenCase) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ansible.log")
	for i, piece := range c.Pieces {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(piece); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if i < len(c.MaintainAfter) && c.MaintainAfter[i] {
			maintain(t, path)
		}
	}
	return maintainTwice(t, path)
}

// The redaction rules are fingerprinted in the record (redactionRules), but
// only by their regexes and constants: a change in the code around them
// (how a key, a loop or a cut line is judged) would leave records made under
// the old behaviour trusted. This pins the behaviour to redactionFormat
// (AGENTS.md §5.7): when an output changes, redactionFormat must change too,
// and the golden file is rewritten with -update-redaction-golden.
func TestRedactionGolden(t *testing.T) {
	data, err := os.ReadFile(redactionGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var golden redactionGolden
	if err := json.Unmarshal(data, &golden); err != nil {
		t.Fatal(err)
	}
	var changed []string
	for i, c := range golden.Cases {
		if got := runRedactionGoldenCase(t, c); got != c.Want {
			changed = append(changed, c.Name)
			golden.Cases[i].Want = got
		}
	}
	if *updateRedactionGolden {
		golden.Format = redactionFormat
		data, err := json.MarshalIndent(golden, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(redactionGoldenPath, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	const update = "go test ./internal/ansible -run TestRedactionGolden -update-redaction-golden"
	switch {
	case len(changed) > 0 && golden.Format == redactionFormat:
		t.Fatalf("redaction changed for %v, but redactionFormat is still %q, so records written under the old behaviour would still be trusted. Change redactionFormat, then run %s", changed, redactionFormat, update)
	case len(changed) > 0:
		t.Fatalf("redaction changed for %v under redactionFormat %q; run %s", changed, redactionFormat, update)
	case golden.Format != redactionFormat:
		t.Fatalf("redactionFormat is %q but the golden file records %q; run %s", redactionFormat, golden.Format, update)
	}
}
