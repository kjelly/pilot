package cmd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/delivery"
)

// typedInputsInventory writes the inventory that
// testdata/inventory-list-typed-inputs.json was captured from with
// `ansible-inventory -i inventory.yml --list` (ansible-core 2.19.2): numbers
// written unquoted, one port quoted, and dns_cache_max_ttl, an integer input
// that existed before the SIEM inputs.
func typedInputsInventory(t *testing.T, logrotate string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"inventory.yml": "all:\n  children:\n" +
			"    log-server:\n      hosts:\n        siem-1: {ansible_host: 192.0.2.10}\n" +
			"    audit-log-forwarding:\n      hosts:\n        siem-1: {}\n        client-1: {ansible_host: 192.0.2.20}\n" +
			"    dns:\n      hosts:\n        client-1: {}\n",
		"group_vars/log-server.yml":           "siem_receiver_tcp_port: 2514\nsiem_logrotate_rotate: " + logrotate + "\nsiem_log_root: /var/log/siem-site\n",
		"group_vars/audit-log-forwarding.yml": "siem_forward_port: \"2514\"\naudit_logrotate_maxage: 120\n",
		"group_vars/dns.yml":                  "dns_cache_max_ttl: 600\n",
	}
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "inventory.yml")
}

// typedInputsPreflight resolves the selected components' inputs the way
// `pilot deploy` does (ansible-inventory --list with the same -e arguments) and
// runs the contract preflight on them.
func typedInputsPreflight(t *testing.T, inv string, extraVars []string) error {
	t.Helper()
	loader, err := contract.NewLoader(repoRootForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := loader.LoadDefaultCatalog()
	if err != nil {
		t.Fatal(err)
	}
	var selected []contract.Contract
	for _, id := range []string{"log-server", "audit-log-forwarding", "dns"} {
		c, ok := catalog.Component(id)
		if !ok {
			t.Fatalf("contract %s not found", id)
		}
		selected = append(selected, c)
	}
	scope := delivery.Scope{HostsByRole: map[string][]string{
		"log-server":           {"siem-1"},
		"audit-log-forwarding": {"siem-1", "client-1"},
		"dns":                  {"client-1"},
	}}
	inputs, err := resolveDeploymentInputs(context.Background(), selected, scope, inv, extraVars, vaultInput{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = delivery.ValidateContractPreflight(delivery.PreflightRequest{Selected: selected, Scope: scope, Inputs: inputs})
	return err
}

// TestDeployPreflightAcceptsInventoryNumbers covers integer and port inputs
// from both entry points `pilot deploy` reads them from. `ansible-inventory
// --list` JSON turns inventory numbers into float64 and preserves
// `-e siem_receiver_tcp_port=2514` as a string, while preflight used to accept
// only an int for "integer" and only a string for the ports: an unquoted
// siem_logrotate_rotate: 30 or siem_forward_port: 2514 in group_vars, which
// Ansible applies as written, failed preflight. dns_cache_max_ttl was
// already declared integer, so a dns deploy with it set in group_vars failed
// the same way.
func TestDeployPreflightAcceptsInventoryNumbers(t *testing.T) {
	fake := func(t *testing.T) {
		t.Helper()
		capture, err := filepath.Abs("testdata/inventory-list-typed-inputs.json")
		if err != nil {
			t.Fatal(err)
		}
		bin := t.TempDir()
		script := "#!/bin/sh\ncat '" + capture + "'\n"
		if err := os.WriteFile(filepath.Join(bin, "ansible-inventory"), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	t.Run("captured ansible-inventory output", func(t *testing.T) {
		fake(t)
		if err := typedInputsPreflight(t, "unused.yml", nil); err != nil {
			t.Fatalf("preflight rejected inventory numbers: %v", err)
		}
	})
	t.Run("real ansible-inventory", func(t *testing.T) {
		if _, err := exec.LookPath("ansible-inventory"); err != nil {
			t.Skipf("ansible-inventory not installed: %v", err)
		}
		if err := typedInputsPreflight(t, typedInputsInventory(t, "30"), nil); err != nil {
			t.Fatalf("preflight rejected inventory numbers: %v", err)
		}
		extra := []string{"siem_receiver_tcp_port=2514", "siem_forward_port=2514", "dns_cache_max_ttl=900", "siem_logrotate_rotate=\"21\""}
		if err := typedInputsPreflight(t, typedInputsInventory(t, "30"), extra); err != nil {
			t.Fatalf("preflight rejected -e numbers: %v", err)
		}
		for _, bad := range []string{"14.5", "fourteen", "[14]"} {
			err := typedInputsPreflight(t, typedInputsInventory(t, bad), nil)
			if err == nil || !strings.Contains(err.Error(), `input "siem_logrotate_rotate": must be integer`) {
				t.Errorf("siem_logrotate_rotate: %s: want 'must be integer', got %v", bad, err)
			}
		}
	})
}
