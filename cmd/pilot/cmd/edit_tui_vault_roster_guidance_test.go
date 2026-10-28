package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

// guidanceWorkspace has one roster per way the sync can leave a roster to
// the operator, plus one it updates: the default roster (synced), one
// already diverged, one encrypted, one in a .vault/ subdirectory and one
// outside the workspace. (A roster another pilot process holds refuses
// the save instead: TestVaultSaveRosterSyncParity.) hosts.yml
// references them the way pilot edit writes freeipa_roster_file: as
// absolute paths.
func guidanceWorkspace(t *testing.T) (dir string, rosters map[string]string) {
	t.Helper()
	dir = t.TempDir()
	quotedOld := `"Old\"pass#1"`
	rosters = map[string]string{
		"default":   filepath.Join(dir, ".vault", "ipa-identity.yaml"),
		"diverged":  filepath.Join(dir, ".vault", "diverged.yaml"),
		"encrypted": filepath.Join(dir, ".vault", "encrypted.yaml"),
		"nested":    filepath.Join(dir, ".vault", "sub", "nested.yaml"),
		"external":  filepath.Join(t.TempDir(), "ipa-identity.yaml"),
	}
	for name, path := range rosters {
		switch name {
		case "diverged":
			writeSyncFile(t, path, syncTestRoster(`"Other-pass_3"`))
		case "encrypted":
			writeSyncFile(t, path, "$ANSIBLE_VAULT;1.1;AES256\n6162636465\n")
		default:
			writeSyncFile(t, path, syncTestRoster(quotedOld))
		}
	}
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: "+quotedOld+"\n")
	hosts := "hosts:\n"
	for i, name := range []string{"diverged", "encrypted", "nested", "external"} {
		n := string(rune('1' + i))
		hosts += "  h" + n + ":\n    ansible_host: 10.0.0." + n + "\n    roles: [freeipa-client]\n    freeipa_roster_file: " + rosters[name] + "\n"
	}
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), hosts)
	return dir, rosters
}

// Every roster the sync does not update is named with the one fix that
// works — a hand edit, ansible-vault edit for an encrypted one — and the
// report says why saving again does not help: pilot edit carries a
// password forward only on the save that changes it (PR #148 review,
// Finding B). A roster in a .vault/ subdirectory is not called "outside
// .vault/" (Finding E). The same lines, without a password, are what a
// plan or apply returns as warnings.
func TestEditAutomationDriverNamesTheHandFixForEveryUnsyncedRoster(t *testing.T) {
	dir, rosters := guidanceWorkspace(t)
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	if got := syncRosterPassword(t, rosters["default"]); got != syncNewPassword {
		t.Fatalf("default roster not synced:\n%s", r.banner)
	}
	if !strings.Contains(r.banner, "🔁 已同步 .vault/ipa-identity.yaml 的 freeipa.admin.password") {
		t.Errorf("banner does not report the synced roster:\n%s", r.banner)
	}
	for name, reason := range map[string]string{
		".vault/diverged.yaml":   "原本就跟舊的 ipa_admin_password 不同",
		".vault/encrypted.yaml":  "ansible-vault 加密（用 ansible-vault edit）",
		".vault/sub/nested.yaml": "pilot edit 只改這個 workspace .vault/ 目錄裡的 *.yml、*.yaml（不含子目錄）",
		rosters["external"]:      "pilot edit 只改這個 workspace .vault/ 目錄裡的 *.yml、*.yaml（不含子目錄）",
	} {
		line := bannerLine(r.banner, "⚠️  未同步 "+name+"：")
		if !strings.Contains(line, reason) || !strings.HasSuffix(line, "；"+rosterManualFix) {
			t.Errorf("%s: line %q lacks %q or the hand fix", name, line, reason)
		}
		if !slices.Contains(r.rosterSyncWarnings, strings.TrimPrefix(line, "⚠️  ")) {
			t.Errorf("%s is not among the warnings: %q", name, r.rosterSyncWarnings)
		}
	}
	if strings.Contains(r.banner, "不在這個 workspace 的 .vault/ 下") {
		t.Errorf("banner calls a .vault/ subdirectory outside .vault/:\n%s", r.banner)
	}
	if !strings.Contains(r.banner, rosterSyncOnlyOnChange.icon+rosterSyncOnlyOnChange.text) ||
		!slices.Contains(r.rosterSyncWarnings, rosterSyncOnlyOnChange.text) {
		t.Errorf("report does not say a later save will not sync:\n%s", r.banner)
	}
	if strings.Contains(r.banner, "再存一次即可") || slices.Contains(r.rosterSyncWarnings, "已同步 .vault/ipa-identity.yaml 的 freeipa.admin.password") {
		t.Errorf("banner promises a re-save fix or warns about a synced roster:\n%s\n%q", r.banner, r.rosterSyncWarnings)
	}
	for _, secret := range []string{syncOldPassword, syncNewPassword, "Other-pass_3"} {
		if strings.Contains(r.banner, secret) || strings.Contains(strings.Join(r.rosterSyncWarnings, "\n"), secret) {
			t.Fatal("banner or warnings leak a password")
		}
	}
}

func bannerLine(banner, prefix string) string {
	for _, line := range strings.Split(banner, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

// The recovery the runbook (§4.5), the deploy warning and the NFS gate give
// for a roster already apart from the vault is a hand edit, and it works:
// saving the vault again through pilot edit leaves the roster stale and
// the warning in place, and editing the roster's password to the vault's
// clears it (PR #148 review, Finding B).
func TestFreeIPARosterDriftRecoveryIsAHandEdit(t *testing.T) {
	dir := t.TempDir()
	roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeSyncFile(t, roster, syncTestRoster(`"Stale-pass_1"`))
	// A rotation that reached only the vault.
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Vault-pass_2\"\ngrafana_admin_password: \"Grafana-pass_1\"\n")
	preflight := func() string {
		t.Helper()
		var out bytes.Buffer
		if err := ensureFreeIPARostersCurrentSnapshot(&out, filepath.Join(dir, "inventory.yml"), deployInventorySnapshot{}); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}

	warning := preflight()
	if !strings.Contains(warning, "warning: "+roster+" ") ||
		!strings.Contains(warning, "請手動把名冊的 freeipa.admin.password 改成 vault 的 ipa_admin_password（加密名冊用 ansible-vault edit）") ||
		!strings.Contains(warning, "之後再存不會修正") || strings.Contains(warning, "會一併同步") {
		t.Fatalf("drift warning does not give the hand fix:\n%s", warning)
	}

	// Saving the vault again, with or without touching the password's key,
	// is no change to carry forward.
	stale, _ := os.ReadFile(roster)
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "grafana_admin_password", Value: "Grafana-pass_2"},
		{Action: "save_vault", File: "main.yaml"},
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: "Vault-pass_2"},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if after, _ := os.ReadFile(roster); !bytes.Equal(after, stale) {
		t.Fatalf("a save without a password change rewrote the roster:\n%s", after)
	}
	if !strings.Contains(preflight(), "warning: "+roster+" ") {
		t.Fatal("the drift warning went away without a fix")
	}

	// The documented fix: the roster's password line, by hand.
	fixed := strings.Replace(string(stale), `password: "Stale-pass_1"`, `password: "Vault-pass_2"`, 1)
	if fixed == string(stale) {
		t.Fatal("fixture has no password line to edit")
	}
	writeSyncFile(t, roster, fixed)
	if out := preflight(); out != "" {
		t.Fatalf("warning after the hand fix:\n%s", out)
	}
}

// A new ipa_admin_password Ansible would template is not silently
// accepted: the save says the rosters were not synced and why, and the
// deploy preflight says it cannot compare — neither shows the value
// (PR #148 review, Finding C).
func TestTemplatedVaultAdminPasswordIsReported(t *testing.T) {
	const template = "{{ lookup('env', 'IPA_ADMIN_PASSWORD') }}"
	dir, rosters := syncWorkspace(t)
	before := map[string][]byte{}
	for name, path := range rosters {
		before[name], _ = os.ReadFile(path)
	}
	result, err := applyEditScenario(dir, "issue-146-template", editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: template},
		{Action: "save_vault", File: "main.yaml"},
	}}, editAgentSessionOptions{})
	if err != nil || result.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v", result, err)
	}
	for name, path := range rosters {
		if after, _ := os.ReadFile(path); !bytes.Equal(after, before[name]) {
			t.Errorf("%s roster changed:\n%s", name, after)
		}
	}
	if !slices.ContainsFunc(result.Warnings, func(w string) bool {
		return strings.HasPrefix(w, "未同步名冊：新的 ipa_admin_password 含 {{、{% 或 {#")
	}) {
		t.Errorf("apply warnings do not report the templated password: %q", result.Warnings)
	}

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrentSnapshot(&out, filepath.Join(dir, "inventory.yml"), deployInventorySnapshot{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "pilot 無法比對它跟名冊的 freeipa.admin.password") || !strings.Contains(out.String(), rosters["default"]) {
		t.Errorf("preflight does not say it cannot compare:\n%s", out.String())
	}
	for _, leak := range []string{"lookup", "IPA_ADMIN_PASSWORD", syncOldPassword} {
		if strings.Contains(out.String(), leak) || strings.Contains(strings.Join(result.Warnings, "\n"), leak) {
			t.Fatalf("output shows a vault value (%q)", leak)
		}
	}
}

// A plan previews every roster write the apply makes — pilot edit stores
// freeipa_roster_file as an absolute path into the real workspace's
// .vault/, which the plan maps onto its scratch copy — and both return the
// rosters left for a manual update as warnings, so an MCP caller sees
// them (PR #148 review, Finding D).
func TestEditPlanAndApplyAgreeOnRosterWrites(t *testing.T) {
	dir, rosters := guidanceWorkspace(t)
	nfs := filepath.Join(dir, ".vault", "nfs-roster.yaml")
	writeSyncFile(t, nfs, syncTestRoster(`"Old\"pass#1"`))
	hosts, _ := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), string(hosts)+
		"  h9:\n    ansible_host: 10.0.0.9\n    roles: [freeipa-nfs-server]\n    freeipa_roster_file: "+nfs+"\n")
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	real := []string{nfs, filepath.Join(dir, ".vault", "main.yaml")}
	for _, path := range rosters {
		real = append(real, path)
	}
	before := snapshotFiles(t, real...)

	plan, err := planEditScenario(dir, rotationScenario(), editAgentSessionOptions{})
	if err != nil {
		t.Fatalf("planEditScenario() error = %v", err)
	}
	assertUnchanged(t, before)
	apply, err := applyEditScenario(dir, "issue-146-plan-apply", rotationScenario(), editAgentSessionOptions{})
	if err != nil || apply.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v", apply, err)
	}
	if got := syncRosterPassword(t, nfs); got != syncNewPassword {
		t.Fatalf("apply did not sync %s", nfs)
	}
	if !slices.Equal(plan.AffectedFiles, apply.AffectedFiles) || !slices.Contains(plan.AffectedFiles, ".vault/nfs-roster.yaml") {
		t.Errorf("plan AffectedFiles %v, apply %v; want the same, with .vault/nfs-roster.yaml", plan.AffectedFiles, apply.AffectedFiles)
	}
	if !slices.Equal(plan.Warnings, apply.Warnings) {
		t.Errorf("plan warnings %q differ from apply warnings %q", plan.Warnings, apply.Warnings)
	}
	for _, name := range []string{".vault/diverged.yaml", ".vault/encrypted.yaml", ".vault/sub/nested.yaml", rosters["external"]} {
		if !slices.ContainsFunc(apply.Warnings, func(w string) bool { return strings.HasPrefix(w, "未同步 "+name+"：") }) {
			t.Errorf("warnings do not name %s: %q", name, apply.Warnings)
		}
	}
	if slices.ContainsFunc(plan.Warnings, func(w string) bool { return strings.Contains(w, "nfs-roster.yaml") }) {
		t.Errorf("plan reports the workspace's own roster as not synced: %q", plan.Warnings)
	}
	for _, secret := range []string{syncOldPassword, syncNewPassword, "Other-pass_3"} {
		if strings.Contains(strings.Join(append(plan.Warnings, apply.Warnings...), "\n"), secret) {
			t.Fatal("warnings leak a password")
		}
	}
}

// A roster password written as an unquoted number never equals the vault's
// string in Ansible's typed comparison, so the deploy preflight warns and
// a rotation reports it with the quoting fix — both say the same, and
// neither rewrites it (PR #148 re-review, F5).
func TestNonStringRosterPasswordIsReported(t *testing.T) {
	dir := t.TempDir()
	rosters := map[string]string{
		"int":   filepath.Join(dir, ".vault", "ipa-identity.yaml"),
		"float": filepath.Join(dir, ".vault", "nfs-roster.yaml"),
	}
	writeSyncFile(t, rosters["int"], syncTestRoster(`12345678`))
	writeSyncFile(t, rosters["float"], syncTestRoster(`1234.5678`))
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"12345678\"\n")
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: .vault/nfs-roster.yaml\n")
	before := snapshotFiles(t, rosters["int"], rosters["float"])

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrentSnapshot(&out, filepath.Join(dir, "inventory.yml"), deployInventorySnapshot{
		HostVars: map[string]map[string]any{"h1": {"freeipa_roster_file": ".vault/nfs-roster.yaml"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, path := range rosters {
		if !strings.Contains(out.String(), "warning: "+path+" 的 freeipa.admin.password 沒加引號") || !strings.Contains(out.String(), "加上引號") {
			t.Errorf("preflight does not warn about %s:\n%s", path, out.String())
		}
	}

	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, shown := range []string{".vault/ipa-identity.yaml", ".vault/nfs-roster.yaml"} {
		if line := bannerLine(r.banner, "⚠️  未同步 "+shown+"："); !strings.Contains(line, rosterNotStringReason) {
			t.Errorf("banner does not report %s as not a string:\n%s", shown, r.banner)
		}
	}
	assertUnchanged(t, before)
}

// The default roster is a link to a roster outside the workspace, which
// hosts.yml also references by its real path. The apply sees one roster
// and syncs it through the link; the plan's copy holds the link as a plain
// file, and must still see one roster, not report the real path as
// unsynced (PR #148 re-review, F1).
func TestEditPlanAndApplyAgreeWhenTheDefaultRosterLinksOutside(t *testing.T) {
	dir := t.TempDir()
	external, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	shared := filepath.Join(external, "r.yaml")
	writeSyncFile(t, shared, syncTestRoster(`"Old\"pass#1"`))
	link := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Old\\\"pass#1\"\n")
	if err := os.Symlink(shared, link); err != nil {
		t.Fatal(err)
	}
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: "+shared+"\n")
	t.Setenv("PILOT_TEST_NEW_ADMIN_PASSWORD", syncNewPassword)
	before := snapshotFiles(t, shared, filepath.Join(dir, ".vault", "main.yaml"))

	plan, err := planEditScenario(dir, rotationScenario(), editAgentSessionOptions{})
	if err != nil {
		t.Fatalf("planEditScenario() error = %v", err)
	}
	assertUnchanged(t, before)
	apply, err := applyEditScenario(dir, "issue-146-linked-default", rotationScenario(), editAgentSessionOptions{})
	if err != nil || apply.RolledBack {
		t.Fatalf("applyEditScenario() = %+v, %v", apply, err)
	}
	if got := syncRosterPassword(t, shared); got != syncNewPassword {
		t.Fatalf("apply did not sync the shared roster through the link")
	}
	assertLinkTo(t, link, shared)
	if !slices.Equal(plan.AffectedFiles, apply.AffectedFiles) {
		t.Errorf("plan AffectedFiles %v, apply %v", plan.AffectedFiles, apply.AffectedFiles)
	}
	if !slices.Equal(plan.Warnings, apply.Warnings) || len(apply.Warnings) != 0 {
		t.Errorf("plan warnings %q, apply warnings %q; want none from either", plan.Warnings, apply.Warnings)
	}
}

// An unquoted vault password a YAML loader may type (190:20:30 is a number
// to Ansible's YAML 1.1 loader, 012345678 one to yaml.v3's YAML 1.2) is
// never compared and never silently left out of a rotation: the preflight
// and the save both say to quote it, and a roster password written as a
// date is reported the same way (PR #148 re-review).
func TestUnquotedVaultPasswordIsReported(t *testing.T) {
	dir := t.TempDir()
	roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	dated := filepath.Join(dir, ".vault", "dated.yaml")
	writeSyncFile(t, roster, syncTestRoster(`"190:20:30"`))
	writeSyncFile(t, dated, syncTestRoster(`2024-01-01`))
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: 190:20:30\n")
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: .vault/dated.yaml\n")
	before := snapshotFiles(t, roster, dated)

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrentSnapshot(&out, filepath.Join(dir, "inventory.yml"), deployInventorySnapshot{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "的 ipa_admin_password 沒加引號") || strings.Contains(out.String(), "190:20:30") {
		t.Fatalf("preflight does not say to quote the vault password (or shows it):\n%s", out.String())
	}

	// A rotation away from an unquoted value cannot know the old password.
	// It says so about the old value; the new one is saved quoted, so it
	// is not told to add quotes (PR #148 round 6, P3-6).
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: 012345678\n")
	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if !strings.Contains(r.banner, "⚠️  未同步名冊：原本的 ipa_admin_password 沒加引號") || !slices.ContainsFunc(r.rosterSyncWarnings, func(w string) bool {
		return strings.HasPrefix(w, "未同步名冊：原本的 ipa_admin_password 沒加引號")
	}) || strings.Contains(r.banner, "請把它加上引號") {
		t.Fatalf("rotation from an unquoted password is not reported as such:\n%s", r.banner)
	}
	if saved, _ := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml")); inventory.VaultAdminPasswordNotString(saved) || inventory.VaultAdminPassword(saved) != syncNewPassword {
		t.Fatalf("the new value was not saved as a quoted string:\n%s", saved)
	}
	assertUnchanged(t, before)

	// The roster written as a date is "quote it" on a rotation it would
	// otherwise sit out.
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: \"Old-pass_1\"\n")
	r = newEditRouterModel(dir)
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if line := bannerLine(r.banner, "⚠️  未同步 .vault/dated.yaml："); !strings.Contains(line, rosterNotStringReason) {
		t.Fatalf("the dated roster is not reported:\n%s", r.banner)
	}
}

// The NFS bootstrap reuses .vault/main.yaml's password only when it is a
// literal written as a plain string. A template, an inline !vault value or
// an unquoted value YAML may type would go into the new roster as raw
// text, so the bootstrap asks for the password instead (PR #148
// re-review, round 4).
func TestNFSBootstrapDoesNotReuseANonLiteralVaultPassword(t *testing.T) {
	for name, value := range map[string]string{
		"template":      `"{{ lookup('env', 'IPA_PW') }}"`,
		"inline !vault": "!vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162636465",
		"unquoted int":  "12345678",
		"literal":       `"Admin-pass_1"`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: "+value+"\n")
			writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  nexus:\n    ansible_host: 10.0.0.9\n    roles: []\n")
			data, _ := os.ReadFile(filepath.Join(dir, "hosts.yml"))
			hf, err := inventory.Parse(data)
			if err != nil {
				t.Fatal(err)
			}
			r := newEditRouterModel(dir)
			pushNFSRoleBootstrap(&r, dir, filepath.Join(dir, "hosts.yml"), hf, "nexus", nil)
			roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
			if name == "literal" {
				if got := syncRosterPassword(t, roster); got != "Admin-pass_1" {
					t.Fatalf("literal password not reused: %q", got)
				}
				return
			}
			if automationScreenID(&r) != nfsRosterBootstrapPasswordScreenID {
				t.Fatalf("bootstrap did not ask for the password (screen %s, banner %q)", automationScreenID(&r), r.banner)
			}
			if _, err := os.Stat(roster); !os.IsNotExist(err) {
				data, _ := os.ReadFile(roster)
				t.Fatalf("a roster was written from a %s vault value:\n%s", name, data)
			}
		})
	}
}

// An !unsafe password is a literal string to Ansible, on either side: the
// preflight compares it, and a rotation syncs it and keeps the tag. Both
// were silent before (PR #148 re-review, round 4).
func TestUnsafePasswordsAreComparedAndSynced(t *testing.T) {
	dir := t.TempDir()
	roster := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	stale := filepath.Join(dir, ".vault", "stale.yaml")
	writeSyncFile(t, roster, syncTestRoster(`!unsafe "Old-pass_1"`))
	writeSyncFile(t, stale, syncTestRoster(`!unsafe "Stale-pass_9"`))
	writeSyncFile(t, filepath.Join(dir, ".vault", "main.yaml"), "ipa_admin_password: !unsafe \"Old-pass_1\"\n")
	writeSyncFile(t, filepath.Join(dir, "hosts.yml"), "hosts:\n  h1:\n    ansible_host: 10.0.0.1\n    roles: [freeipa-client]\n    freeipa_roster_file: .vault/stale.yaml\n")

	var out bytes.Buffer
	if err := ensureFreeIPARostersCurrentSnapshot(&out, filepath.Join(dir, "inventory.yml"), deployInventorySnapshot{
		HostVars: map[string]map[string]any{"h1": {"freeipa_roster_file": ".vault/stale.yaml"}},
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "warning: "+stale+" ") || strings.Contains(out.String(), roster) {
		t.Fatalf("preflight does not compare !unsafe passwords:\n%s", out.String())
	}

	r := newEditRouterModel(dir)
	d := automationDriver{dir: dir}
	if err := d.run(&r, editScenario{Version: 1, Steps: []editAction{
		{Action: "set_vault_value", File: "main.yaml", Key: "ipa_admin_password", Value: syncNewPassword},
		{Action: "save_vault", File: "main.yaml"},
	}}); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	if !strings.Contains(r.banner, "🔁 已同步 .vault/ipa-identity.yaml 的 freeipa.admin.password") {
		t.Fatalf("the !unsafe roster was not synced:\n%s", r.banner)
	}
	if got := syncRosterPassword(t, roster); got != syncNewPassword {
		t.Fatalf("roster password = %q", got)
	}
	for _, path := range []string{roster, filepath.Join(dir, ".vault", "main.yaml")} {
		if data, _ := os.ReadFile(path); !bytes.Contains(data, []byte("!unsafe ")) {
			t.Errorf("%s lost its !unsafe tag:\n%s", filepath.Base(path), data)
		}
	}
}
