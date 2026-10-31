package mcpremote

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/mcpwire"
)

func writeFiles(t *testing.T, root string, files map[string]string) []string {
	t.Helper()
	var paths []string
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	return paths
}

func TestCheckPathScope(t *testing.T) {
	denied := map[string]string{
		"vault":           "key: /pilot/vault/id_ed25519\n",
		"data":            "roster: /pilot/data/mcp/sessions/x/work/r.yaml\n",
		"tmp":             "x: /tmp/pilot-mcp/abc\n",
		"dot dot":         "x: /pilot/config/../data/state.db\n",
		"nested list":     "a:\n  - b: [/pilot/vault]\n",
		"second document": "a: 1\n---\nb: /pilot/data\n",
	}
	for name, content := range denied {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			err := CheckPathScope(root, writeFiles(t, root, map[string]string{"group_vars/x.yml": content}))
			if CodeOf(err) != mcpwire.CodePathOutOfScope {
				t.Fatalf("err = %v, want PATH_OUT_OF_SCOPE", err)
			}
		})
	}
	allowed := "key: /pilot/config/.vault/id_ed25519\nroster: /pilot/config/freeipa-roster.yaml\ndist: /pilot/dist/pilot-linux-amd64\nhost: /opt/pilot/wazuh-docker\netc: /etc/pilot/x\nrel: group_vars/x\nnot: /pilot/vaultx\n"
	root := t.TempDir()
	if err := CheckPathScope(root, writeFiles(t, root, map[string]string{"group_vars/ok.yml": allowed, "notes.txt": "/pilot/vault"})); err != nil {
		t.Fatalf("allowed paths rejected: %v", err)
	}
	bad := t.TempDir()
	if err := CheckPathScope(bad, writeFiles(t, bad, map[string]string{"x.yaml": "a: [1, 2\n"})); CodeOf(err) != mcpwire.CodeSnapshotInvalid {
		t.Fatalf("invalid YAML: %v", err)
	}
}

func TestCheckPathScopeIsLinearOnAliasBombsAndCycles(t *testing.T) {
	var b strings.Builder
	b.WriteString("l0: &l0 [x, x, x, x, x, x, x, x, x, x]\n")
	for i := 1; i < 40; i++ {
		b.WriteString("l" + itoa(i) + ": &l" + itoa(i) + " [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteString(", ")
			}
			b.WriteString("*l" + itoa(i-1))
		}
		b.WriteString("]\n")
	}
	root := t.TempDir()
	paths := writeFiles(t, root, map[string]string{"bomb.yml": b.String(), "cycle.yml": "a: &a\n  <<: *a\n"})
	done := make(chan error, 1)
	go func() { done <- CheckPathScope(root, paths) }()
	select {
	case err := <-done:
		if err != nil && CodeOf(err) != mcpwire.CodeSnapshotInvalid {
			t.Fatalf("unexpected error %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("CheckPathScope did not finish on an alias bomb")
	}
}

func itoa(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoa(i/10) + string(rune('0'+i%10))
}

func TestCheckHostsEnv(t *testing.T) {
	cases := []struct {
		hosts, env string
		ok         bool
	}{
		{hostsFor("prod"), "prod", true},
		{hostsFor("prod"), "staging", false},
		{hostsFor("sandbox"), "sandbox", true}, // no env line means sandbox
		{hostsFor("sandbox"), "prod", false},
		{"vars: {}\nhosts: {}\n", "prod", true},
	}
	for _, tc := range cases {
		root := t.TempDir()
		writeFiles(t, root, map[string]string{"hosts.yml": tc.hosts})
		err := CheckHostsEnv(root, tc.env)
		if tc.ok && err != nil {
			t.Errorf("env %s: %v", tc.env, err)
		}
		if !tc.ok && CodeOf(err) != mcpwire.CodeEnvMismatch {
			t.Errorf("env %s: err = %v, want ENV_MISMATCH", tc.env, err)
		}
	}
	if err := CheckHostsEnv(t.TempDir(), "prod"); CodeOf(err) != mcpwire.CodeSnapshotInvalid {
		t.Errorf("missing hosts.yml: %v", err)
	}
}

func TestCheckSecretPolicy(t *testing.T) {
	pilotRoot := repoRoot(t)
	clean := t.TempDir()
	writeFiles(t, clean, map[string]string{"hosts.yml": hostsFor("prod"), "group_vars/dashboard.yml": "grafana_admin_password: \"{{ vault_grafana_admin_password }}\"\n"})
	if err := CheckSecretPolicy(pilotRoot, clean); err != nil {
		t.Fatalf("vault reference rejected: %v", err)
	}
	leaky := t.TempDir()
	writeFiles(t, leaky, map[string]string{"hosts.yml": hostsFor("prod"), "group_vars/dashboard.yml": "grafana_admin_password: \"s3cr3t-value\"\n"})
	err := CheckSecretPolicy(pilotRoot, leaky)
	if CodeOf(err) != mcpwire.CodeSecretPolicyViolation {
		t.Fatalf("plaintext secret: err = %v", err)
	}
	if strings.Contains(err.Error(), "s3cr3t-value") {
		t.Fatal("the violation message printed the secret value")
	}
	if err := CheckSecretPolicy(t.TempDir(), clean); err == nil || CodeOf(err) != mcpwire.CodeRuntimeError {
		t.Fatalf("missing contracts must fail closed, got %v", err)
	}
}
