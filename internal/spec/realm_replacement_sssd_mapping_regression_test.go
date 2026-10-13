package spec

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// ipa-client-install --uninstall leaves the Kerberos snippet SSSD wrote for
// the old domain in /var/lib/sss/pubconf/krb5.include.d, and krb5.conf
// includes it. It maps the old DNS domain to the old realm, so a new server
// that kept its name in that domain was looked up in the old realm: the new
// enrollment asked the new KDC for krbtgt/IPA.PILOT.INTERNAL and failed
// (2026-10-13, a vm-target whose old and new servers share an FQDN).

const realmOldMappingTask = "Realm replacement — remove the old domain's SSSD Kerberos realm mapping"

// TestRegression_RealmReplacementRemovesTheOldDomainRealmMapping runs the
// configuration read and the removal on localhost against a temporary
// default.conf and include directory, each case twice.
func TestRegression_RealmReplacementRemovesTheOldDomainRealmMapping(t *testing.T) {
	const mapping = "[domain_realm]\n.ipa.pilot.internal = IPA.PILOT.INTERNAL\nipa.pilot.internal = IPA.PILOT.INTERNAL\n"
	cases := []struct {
		name, defaultConf string
		want              []string // files left in the include directory
	}{
		{
			name:        "the old domain's mapping goes; the other snippets stay",
			defaultConf: "[global]\nrealm = IPA.PILOT.INTERNAL\ndomain = ipa.pilot.internal\nserver = ipa1.ipa.pilot.internal\n",
			want:        []string{"domain_realm_example_com", "krb5_libdefaults", "localauth_plugin"},
		},
		{
			name:        "no domain in default.conf: nothing is removed",
			defaultConf: "[global]\nrealm = IPA.PILOT.INTERNAL\n",
			want:        []string{"domain_realm_example_com", "domain_realm_ipa_pilot_internal", "krb5_libdefaults", "localauth_plugin"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			include := filepath.Join(dir, "krb5.include.d")
			if err := os.Mkdir(include, 0o755); err != nil {
				t.Fatal(err)
			}
			for name, content := range map[string]string{
				"domain_realm_ipa_pilot_internal": mapping,
				"domain_realm_example_com":        "[domain_realm]\n.example.com = EXAMPLE.COM\n",
				"krb5_libdefaults":                "[libdefaults]\n canonicalize = true\n",
				"localauth_plugin":                "[plugins]\n",
			} {
				if err := os.WriteFile(filepath.Join(include, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			files := map[string]string{
				"/etc/ipa/default.conf":               filepath.Join(dir, "default.conf"),
				"/etc/sssd/sssd.conf":                 filepath.Join(dir, "sssd.conf"),
				"/var/lib/sss/pubconf/krb5.include.d": include,
			}
			if err := os.WriteFile(files["/etc/ipa/default.conf"], []byte(tc.defaultConf), 0o600); err != nil {
				t.Fatal(err)
			}
			tasks := []string{"Realm replacement — read the old realm's client configuration", realmOldMappingTask}
			for run := 1; run <= 2; run++ {
				rc, changed, failures := runRealmTasks(t, tasks, files, nil)
				if rc != 0 {
					t.Fatalf("run %d: rc=%d failures=%v", run, rc, failures)
				}
				if run == 2 && changed[realmOldMappingTask] {
					t.Errorf("second run: %q changed", realmOldMappingTask)
				}
				entries, err := os.ReadDir(include)
				if err != nil {
					t.Fatal(err)
				}
				var got []string
				for _, e := range entries {
					got = append(got, e.Name())
				}
				if !slices.Equal(got, tc.want) {
					t.Errorf("run %d: include directory has %q, want %q", run, got, tc.want)
				}
			}
		})
	}
}

// TestRegression_RealmReplacementRemovesTheOldMappingBeforeEnrolling: the
// mapping goes after the uninstall, which stops SSSD, and before the new
// enrollment, inside the block whose rescue restarts SSSD.
func TestRegression_RealmReplacementRemovesTheOldMappingBeforeEnrolling(t *testing.T) {
	doc, _ := loadYAML(t, "../../playbooks/apply/freeipa-realm-replacement-apply.yml").([]any)
	play := doc[0].(map[string]any)
	var order []string
	for _, item := range play["tasks"].([]any) {
		task := item.(map[string]any)
		if task["name"] != "Realm replacement — destructive switch with automatic local restore" {
			continue
		}
		block, _ := task["block"].([]any)
		for _, b := range block {
			name, _ := b.(map[string]any)["name"].(string)
			order = append(order, name)
		}
	}
	mapping := slices.Index(order, realmOldMappingTask)
	uninstall := slices.Index(order, "Realm replacement — remove old client enrollment")
	enroll := slices.Index(order, "Realm replacement — enroll client in the new realm")
	if mapping < 0 || uninstall < 0 || enroll < 0 || uninstall >= mapping || mapping >= enroll {
		t.Errorf("uninstall=%d mapping=%d enroll=%d; want uninstall, mapping removal, enroll in the destructive switch block", uninstall, mapping, enroll)
	}
}
