package tools

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/spec"
	"github.com/kjelly/pilot/internal/sshcontrol"
	"github.com/kjelly/pilot/internal/vmtarget"
)

// TestResolveRemoteHosts_VMTargetAliasesSatisfyV1SpecGroups goes from a real
// vm-target inventory through real `ansible --list-hosts` to the expected-host
// resolver, the way `pilot vm-target test` verifies: core-infra-provider.md
// targets the groups dns/ntp, the VM is named vb-ntp-cand with aliases
// core,ntp, and verification is limited to the VM name. With aliases as
// hosts (the rendering before this test) the VM name fell outside the spec
// targets; with aliases as groups of the VM it is the spec target.
func TestResolveRemoteHosts_VMTargetAliasesSatisfyV1SpecGroups(t *testing.T) {
	if _, err := exec.LookPath("ansible"); err != nil {
		t.Skip("ansible not installed")
	}
	t.Setenv(sshcontrol.BaseEnv, t.TempDir())
	parsed, err := spec.Parse(filepath.Join("..", "..", "docs", "verification", "core-infra-provider.md"))
	if err != nil {
		t.Fatal(err)
	}
	vm := func(aliases ...string) string {
		tgt := &vmtarget.Target{Name: "vb-ntp-cand", IP: "192.0.2.10", SSHUser: "root", SSHPort: 22, KeyPath: "/k", Hosts: append([]string{"vb-ntp-cand"}, aliases...)}
		inv, err := tgt.RenderInventory()
		if err != nil {
			t.Fatal(err)
		}
		return inv
	}
	// The pre-change rendering: every alias a second host at the same address.
	aliasHosts := "all:\n  hosts:\n" +
		"    vb-ntp-cand:\n      ansible_host: 192.0.2.10\n" +
		"    core:\n      ansible_host: 192.0.2.10\n" +
		"    ntp:\n      ansible_host: 192.0.2.10\n"

	cases := []struct {
		name    string
		inv     string
		want    string
		wantErr string
	}{
		{name: "aliases are groups", inv: vm("core", "ntp"), want: "vb-ntp-cand"},
		{name: "aliases are hosts", inv: aliasHosts, wantErr: "execution scope contains hosts outside spec targets: vb-ntp-cand"},
		{name: "VM without the spec's groups", inv: vm("keycloak"), wantErr: "spec targets matched zero inventory hosts"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "inv.yml")
			if err := os.WriteFile(path, []byte(tc.inv), 0o600); err != nil {
				t.Fatal(err)
			}
			tool := &VerifySpecTool{
				Inventory: path,
				Limit:     "vb-ntp-cand",
				Env:       []string{"ANSIBLE_HOME=" + filepath.Join(dir, "home"), "ANSIBLE_LOCAL_TEMP=" + filepath.Join(dir, "tmp")},
			}
			resolved, err := tool.resolveRemoteHosts(context.Background(), parsed, "")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q (resolved %v)", err, tc.wantErr, resolved.Hosts)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(resolved.Hosts, ",") != tc.want {
				t.Fatalf("resolved %v, want [%s]", resolved.Hosts, tc.want)
			}
		})
	}
}
