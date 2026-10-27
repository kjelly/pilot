package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	syncOldPassword = `Old"pass#1`
	syncNewPassword = `New'pass\2 密碼`
)

func syncTestRoster(password string) string {
	return "schema_version: 3\n# kept as is\nfreeipa:\n  admin:\n    principal: admin\n    password: " + password + "\nnetgroups: []\ngrants: []\n"
}

func writeSyncFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func syncRosterPassword(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var roster struct {
		FreeIPA struct {
			Admin struct{ Password string }
		} `yaml:"freeipa"`
	}
	if err := yaml.Unmarshal(data, &roster); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return roster.FreeIPA.Admin.Password
}

// syncWorkspace has one roster per outcome: the editor's default roster
// and a hosts.yml roster still holding the old password, one already
// diverged, one encrypted and one that references the vault.
func syncWorkspace(t *testing.T) (dir string, rosters map[string]string) {
	t.Helper()
	dir = t.TempDir()
	quotedOld := `"Old\"pass#1"`
	rosters = map[string]string{
		"default":   filepath.Join(dir, ".vault", "ipa-identity.yaml"),
		"nfs":       filepath.Join(dir, ".vault", "nfs-roster.yaml"),
		"diverged":  filepath.Join(dir, ".vault", "diverged.yaml"),
		"encrypted": filepath.Join(dir, ".vault", "encrypted.yaml"),
		"reference": filepath.Join(dir, ".vault", "reference.yaml"),
	}
	writeSyncFile(t, rosters["default"], syncTestRoster(quotedOld))
	writeSyncFile(t, rosters["nfs"], syncTestRoster(quotedOld))
	writeSyncFile(t, rosters["diverged"], syncTestRoster(`"Other-pass_3"`))
	writeSyncFile(t, rosters["encrypted"], "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
	writeSyncFile(t, rosters["reference"], syncTestRoster(`"{{ ipa_admin_password }}"`))
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "---\n# FreeIPA\nipa_admin_password: "+quotedOld+"\ngrafana_admin_password: \"Grafana-pass_1\"\n")
	hosts := "hosts:\n"
	for i, name := range []string{"nfs", "diverged", "encrypted", "reference"} {
		hosts += "  h" + string(rune('1'+i)) + ":\n    ansible_host: 10.0.0." + string(rune('1'+i)) + "\n    roles: [freeipa-client]\n" +
			"    freeipa_roster_file: .vault/" + filepath.Base(rosters[name]) + "\n"
	}
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), hosts)
	return dir, rosters
}

// Rotating ipa_admin_password through the real vault editor carries the new
// value into every roster that held the old one, and reports the rest.
func TestEditAutomationDriverVaultAdminPasswordSyncsRosters(t *testing.T) {
	dir, rosters := syncWorkspace(t)
	before := map[string][]byte{}
	for name, path := range rosters {
		before[name], _ = os.ReadFile(path)
	}

	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	vault, _ := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	var vars map[string]string
	if err := yaml.Unmarshal(vault, &vars); err != nil || vars["ipa_admin_password"] != syncNewPassword {
		t.Fatalf("vault not saved: %v\n%s", err, vault)
	}
	for _, name := range []string{"default", "nfs"} {
		if got := syncRosterPassword(t, rosters[name]); got != syncNewPassword {
			t.Errorf("%s roster freeipa.admin.password = %q, want the new password", name, got)
		}
		after, _ := os.ReadFile(rosters[name])
		if !bytes.Contains(after, []byte("# kept as is\n")) {
			t.Errorf("%s roster lost its comment:\n%s", name, after)
		}
	}
	for _, name := range []string{"diverged", "encrypted", "reference"} {
		if after, _ := os.ReadFile(rosters[name]); !bytes.Equal(after, before[name]) {
			t.Errorf("%s roster changed:\n%s", name, after)
		}
	}

	for _, want := range []string{
		"🔁 已同步 .vault/ipa-identity.yaml 的 freeipa.admin.password",
		"🔁 已同步 .vault/nfs-roster.yaml 的 freeipa.admin.password",
		"⚠️  未同步 .vault/diverged.yaml：freeipa.admin.password 原本就跟 ipa_admin_password 不同",
		"⚠️  未同步 .vault/encrypted.yaml：ansible-vault 加密檔",
	} {
		if !strings.Contains(r.banner, want) {
			t.Errorf("banner lacks %q:\n%s", want, r.banner)
		}
	}
	if strings.Contains(r.banner, "reference.yaml") {
		t.Errorf("banner mentions the reference roster, which follows the vault on its own:\n%s", r.banner)
	}
	for _, secret := range []string{syncOldPassword, syncNewPassword, "Other-pass_3"} {
		if strings.Contains(r.banner, secret) {
			t.Fatalf("banner leaks a password:\n%s", r.banner)
		}
	}
}

// Saving the vault without changing ipa_admin_password leaves every roster
// alone, even one that already disagrees with it.
func TestEditAutomationDriverVaultOtherKeyLeavesRostersAlone(t *testing.T) {
	dir, rosters := syncWorkspace(t)
	before := map[string][]byte{}
	for name, path := range rosters {
		before[name], _ = os.ReadFile(path)
	}
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "grafana_admin_password", Value: "Grafana-pass_2"},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for name, path := range rosters {
		if after, _ := os.ReadFile(path); !bytes.Equal(after, before[name]) {
			t.Errorf("%s roster changed:\n%s", name, after)
		}
	}
	if strings.Contains(r.banner, "freeipa.admin.password") {
		t.Errorf("banner reports a roster sync:\n%s", r.banner)
	}
}

func TestWarnFreeIPARosterAdminDrift(t *testing.T) {
	dir, rosters := syncWorkspace(t)
	inv := filepath.Join(dir, "inventory.yml")
	hostVars := map[string]map[string]any{}
	for i, name := range []string{"default", "nfs", "diverged", "encrypted", "reference"} {
		hostVars["h"+string(rune('a'+i))] = map[string]any{"freeipa_roster_file": strings.TrimPrefix(rosters[name], dir+"/")}
	}
	snapshot := deployInventorySnapshot{Groups: map[string][]string{}, HostVars: hostVars}

	// The vault still matches every literal roster but the diverged one.
	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrentSnapshot(&out, inv, snapshot); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(out.String(), "warning: "); got != 1 || !strings.Contains(out.String(), rosters["diverged"]+" 的 freeipa.admin.password 跟 "+filepath.Join(dir, ".vault", "main.yaml")) {
		t.Fatalf("want one warning, for the diverged roster:\n%s", out.String())
	}

	// A vault-only rotation is what drifts the rest.
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Rotated-pass_4\"\n")
	out.Reset()
	if err := ensureFreeIPARostersCurrentSnapshot(&out, inv, snapshot); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"default", "nfs", "diverged"} {
		if !strings.Contains(out.String(), "warning: "+rosters[name]+" ") {
			t.Errorf("no warning for the %s roster:\n%s", name, out.String())
		}
	}
	for _, name := range []string{"encrypted", "reference"} {
		if strings.Contains(out.String(), rosters[name]) {
			t.Errorf("warned about the %s roster:\n%s", name, out.String())
		}
	}
	for _, secret := range []string{syncOldPassword, "Other-pass_3", "Rotated-pass_4"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("warning leaks a password:\n%s", out.String())
		}
	}

	// Without a workspace vault there is nothing to compare against.
	if err := os.Remove(filepath.Join(dir, ".vault", "main.yaml")); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := ensureFreeIPARostersCurrentSnapshot(&out, inv, snapshot); err != nil || out.Len() != 0 {
		t.Fatalf("output without a vault = %q, %v", out.String(), err)
	}
}
