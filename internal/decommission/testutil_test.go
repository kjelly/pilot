package decommission

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/store"
)

// writeWorkspaceFile writes rel (workspace-relative) under dir, creating
// parent directories as needed.
func writeWorkspaceFile(t *testing.T, dir, rel, content string) string {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// newCatalog builds a contract.Catalog directly from in-memory contracts,
// bypassing contract.Loader's file-existence/schema validation entirely —
// fixtures below only need Role/ID/Playbooks/Dependencies/Lifecycle
// populated, none of the rest contract.Loader.LoadFile would otherwise
// require (specs, stagePolicy, evidenceRequirement, ...).
func newCatalog(t *testing.T, contracts ...contract.Contract) contract.Catalog {
	t.Helper()
	cat, err := contract.NewCatalog(contracts)
	if err != nil {
		t.Fatalf("contract.NewCatalog: %v", err)
	}
	return cat
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// simpleHostsYAML renders a minimal single-host hosts.yml. extraLines, if
// non-empty, are appended verbatim (indented under the host block) for
// per-test extras like freeipa_roster_file.
func simpleHostsYAML(hostName, ansibleHost string, roles []string, extraLines string) string {
	out := "hosts:\n  " + hostName + ":\n    ansible_host: \"" + ansibleHost + "\"\n"
	if len(roles) > 0 {
		out += "    roles:\n"
		for _, r := range roles {
			out += "      - " + r + "\n"
		}
	}
	if extraLines != "" {
		out += extraLines
	}
	return out
}
