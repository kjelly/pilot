package rosteroracletest

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The harness runs the real apply playbooks' pre_tasks under ansible-playbook.
// It is test support: if a package of the binary imported it, a run of the
// identity playbook could bypass the funnels that take the identity lock
// (cmd/pilot/cmd's TestRegression_EveryRunOfTheIdentityPlaybookHoldsTheLock
// lists its reference as data on that ground). The twin of this check is a file
// outside _test.go that imports it: this test must see it.
func TestNothingInTheBinaryImportsTheOracle(t *testing.T) {
	root := filepath.Join(ApplyDir(t), "..", "..")
	const imp = `"github.com/kjelly/pilot/internal/rosteroracletest"`
	var importers []string
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if strings.Contains(string(data), imp) {
				rel, _ := filepath.Rel(root, path)
				importers = append(importers, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(importers) != 0 {
		t.Fatalf("non-test files import the oracle harness: %v", importers)
	}
}
