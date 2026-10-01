package targetalias

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGroups(t *testing.T) {
	got := Groups("core", []string{"core", "dns", "", "ntp", "dns", "all", "ungrouped", "keycloak"})
	if strings.Join(got, ",") != "dns,ntp,keycloak" {
		t.Fatalf("Groups = %v, want [dns ntp keycloak]", got)
	}
	if got := Groups("core", nil); len(got) != 0 {
		t.Fatalf("Groups(nil) = %v", got)
	}
}

func TestWriteChildren(t *testing.T) {
	var sb strings.Builder
	WriteChildren(&sb, "core", []string{"core"})
	if sb.Len() != 0 {
		t.Fatalf("no aliases should write nothing, got %q", sb.String())
	}
	WriteChildren(&sb, "core", []string{"core", "dns", "ntp"})
	want := "  children:\n" +
		"    dns:\n      hosts:\n        core: {}\n" +
		"    ntp:\n      hosts:\n        core: {}\n"
	if sb.String() != want {
		t.Fatalf("WriteChildren =\n%s\nwant\n%s", sb.String(), want)
	}
}

// TestWriteChildren_RealAnsible: Ansible resolves every alias to the one
// host, `all` holds one host, and there is no host/group name warning.
func TestWriteChildren_RealAnsible(t *testing.T) {
	if _, err := exec.LookPath("ansible"); err != nil {
		t.Skip("ansible not installed")
	}
	var sb strings.Builder
	sb.WriteString("all:\n  hosts:\n    vb-ntp:\n      ansible_connection: local\n")
	WriteChildren(&sb, "vb-ntp", []string{"vb-ntp", "core", "ntp"})
	dir := t.TempDir()
	inv := filepath.Join(dir, "inv.yml")
	if err := os.WriteFile(inv, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for pattern, want := range map[string]string{"ntp": "vb-ntp", "core": "vb-ntp", "all": "vb-ntp", "ntp:core:vb-ntp": "vb-ntp"} {
		cmd := exec.Command("ansible", pattern, "-i", inv, "--list-hosts")
		cmd.Env = append(os.Environ(), "ANSIBLE_HOME="+filepath.Join(dir, "home"), "ANSIBLE_LOCAL_TEMP="+filepath.Join(dir, "tmp"))
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("ansible %s --list-hosts: %v\n%s", pattern, err, stderr.String())
		}
		if strings.Contains(stderr.String(), "Found both group and host") {
			t.Errorf("host/group name warning for %s:\n%s", pattern, stderr.String())
		}
		fields := strings.Fields(stdout.String())
		// "hosts (1):" then the host names.
		if len(fields) != 3 || fields[1] != "(1):" || fields[2] != want {
			t.Errorf("ansible %s --list-hosts = %q, want only %s", pattern, stdout.String(), want)
		}
	}
}
