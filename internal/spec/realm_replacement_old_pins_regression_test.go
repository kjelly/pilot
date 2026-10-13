package spec

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The realm replacement left the old realm's server pins in /etc/hosts.
// freeipa-client-apply.yml writes them (a "PILOT FREEIPA SERVER POOL" block,
// or an older unmarked line), and ipa-client-install --uninstall does not
// remove them. On Ubuntu 24.04 the old pin, whose short name `ipa1` matched
// the new server's, made SSSD send the new host principal's AS requests to
// the old KDC; it stayed offline and the identity wait (C5) failed every
// time (2026-07-29, root-caused 2026-10-12).
//
// The new server's pin is written after them: when the new server keeps the
// old server's FQDN, its line is inside the removed pool block, and a pin
// written first went with the block (review of #53, 2026-10-13).

var realmOldPinTasks = []string{
	"Realm replacement — read the old realm's client configuration",
	"Realm replacement — list the old realm's servers",
	"Realm replacement — remove the old realm's server pool block from /etc/hosts",
	"Realm replacement — remove other /etc/hosts pins of the old realm's servers",
	"Realm replacement — pin new server FQDN before enrollment",
}

// hostsLookup returns the address glibc's files source gives name in hosts:
// the first line naming it, in any case.
func hostsLookup(hosts, name string) string {
	for line := range strings.Lines(hosts) {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		for _, f := range fields[min(1, len(fields)):] {
			if strings.EqualFold(f, name) {
				return fields[0]
			}
		}
	}
	return ""
}

// TestRegression_RealmReplacementRemovesOldServerPins runs the five tasks on
// localhost against a temporary default.conf, sssd.conf and hosts.
func TestRegression_RealmReplacementRemovesOldServerPins(t *testing.T) {
	const defaultConf = "[global]\nbasedn = dc=ipa,dc=pilot,dc=internal\nrealm = IPA.PILOT.INTERNAL\ndomain = ipa.pilot.internal\nserver = ipa1.ipa.pilot.internal\n"
	cases := []struct {
		name, sssd, hosts, newServer, want string
	}{
		{
			name: "Pilot's server pool block; the new pin and the client's own pin stay",
			sssd: "[domain/ipa.pilot.internal]\nipa_server = _srv_, ipa1.ipa.pilot.internal\n",
			hosts: "127.0.0.1 localhost\n192.0.2.3 c52-cl.ipa.pilot.internal c52-cl\n" +
				"# BEGIN PILOT FREEIPA SERVER POOL\n192.0.2.8 ipa1.ipa.pilot.internal ipa1\n# END PILOT FREEIPA SERVER POOL\n" +
				"192.0.2.12 ipa1.new.example.test ipa1\n",
			newServer: "ipa1.new.example.test",
			want:      "127.0.0.1 localhost\n192.0.2.3 c52-cl.ipa.pilot.internal c52-cl\n192.0.2.12 ipa1.new.example.test ipa1\n",
		},
		{
			name: "unmarked pins of the failover list, any case",
			sssd: "[domain/ipa.pilot.internal]\nipa_server = _srv_, IPA1.ipa.pilot.internal\nipa_backup_server = ipa2.ipa.pilot.internal\n",
			hosts: "127.0.0.1 localhost\n192.0.2.8 IPA1.ipa.pilot.internal ipa1\n192.0.2.9 ipa2.ipa.pilot.internal ipa2\n" +
				"192.0.2.12 ipa1.new.example.test ipa1\n",
			newServer: "ipa1.new.example.test",
			want:      "127.0.0.1 localhost\n192.0.2.12 ipa1.new.example.test ipa1\n",
		},
		{
			name:      "the new server keeps the old server's name",
			sssd:      "[domain/ipa.pilot.internal]\nipa_server = _srv_, ipa1.example.test\n",
			hosts:     "127.0.0.1 localhost\n192.0.2.8 ipa1.example.test ipa1\n",
			newServer: "ipa1.example.test",
			want:      "127.0.0.1 localhost\n192.0.2.12 ipa1.example.test ipa1\n",
		},
		{
			name:      "the new server keeps the old server's name, written in another case",
			sssd:      "[domain/ipa.pilot.internal]\nipa_server = _srv_, ipa1.example.test\n",
			hosts:     "127.0.0.1 localhost\n192.0.2.8 IPA1.example.test ipa1\n",
			newServer: "ipa1.example.test",
			want:      "127.0.0.1 localhost\n192.0.2.12 ipa1.example.test ipa1\n",
		},
		{
			// freeipa-client-apply.yml's block, for a server that keeps its FQDN.
			name: "the new server keeps the old server's name, inside Pilot's server pool block",
			sssd: "[domain/ipa.pilot.internal]\nipa_server = _srv_, ipa1.ipa.pilot.internal\n",
			hosts: "127.0.0.1 localhost\n192.0.2.3 c52-cl.ipa.pilot.internal c52-cl\n" +
				"# BEGIN PILOT FREEIPA SERVER POOL\n192.0.2.8 ipa1.ipa.pilot.internal ipa1\n# END PILOT FREEIPA SERVER POOL\n",
			newServer: "ipa1.ipa.pilot.internal",
			want:      "127.0.0.1 localhost\n192.0.2.3 c52-cl.ipa.pilot.internal c52-cl\n192.0.2.12 ipa1.ipa.pilot.internal ipa1\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			files := map[string]string{
				"/etc/ipa/default.conf": filepath.Join(dir, "default.conf"),
				"/etc/sssd/sssd.conf":   filepath.Join(dir, "sssd.conf"),
				"/etc/hosts":            filepath.Join(dir, "hosts"),
			}
			for real, content := range map[string]string{"/etc/ipa/default.conf": defaultConf, "/etc/sssd/sssd.conf": tc.sssd, "/etc/hosts": tc.hosts} {
				if err := os.WriteFile(files[real], []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			vars := map[string]any{
				"freeipa_realm_replacement_new_server_fqdn": tc.newServer,
				"freeipa_realm_replacement_new_server_ip":   "192.0.2.12",
			}
			rc, _, failures := runRealmTasks(t, realmOldPinTasks, files, vars)
			if rc != 0 {
				t.Fatalf("rc=%d failures=%v", rc, failures)
			}
			got, err := os.ReadFile(files["/etc/hosts"])
			if err != nil || string(got) != tc.want {
				t.Errorf("hosts = %q (err %v), want %q", got, err, tc.want)
			}
			if ip := hostsLookup(string(got), tc.newServer); ip != "192.0.2.12" {
				t.Errorf("%s resolves to %q from hosts, want the new server's 192.0.2.12", tc.newServer, ip)
			}
			rc, changed, failures := runRealmTasks(t, realmOldPinTasks, files, vars)
			if rc != 0 {
				t.Errorf("second run: rc=%d failures=%v", rc, failures)
			}
			for name, c := range changed {
				if c {
					t.Errorf("second run: %q changed", name)
				}
			}
		})
	}
}

// TestRegression_RealmReplacementRemovesOldPinsBetweenUninstallAndEnroll:
// the old configuration is read before the uninstall removes it, and the
// pins go after the uninstall (which still reaches the old server) and
// before the new enrollment, inside the block whose rescue restores
// /etc/hosts from the archive. The new server's pin follows them.
func TestRegression_RealmReplacementRemovesOldPinsBetweenUninstallAndEnroll(t *testing.T) {
	doc, _ := loadYAML(t, "../../playbooks/apply/freeipa-realm-replacement-apply.yml").([]any)
	play := doc[0].(map[string]any)
	var order []string
	var block []any
	for _, item := range play["tasks"].([]any) {
		task := item.(map[string]any)
		if task["name"] == "Realm replacement — destructive switch with automatic local restore" {
			block, _ = task["block"].([]any)
		}
	}
	if block == nil {
		t.Fatal("no destructive switch block")
	}
	for _, item := range block {
		name, _ := item.(map[string]any)["name"].(string)
		order = append(order, name)
	}
	at := func(name string) int {
		i := slices.Index(order, name)
		if i < 0 {
			t.Fatalf("%q is not in the destructive switch block", name)
		}
		return i
	}
	read, list := at(realmOldPinTasks[0]), at(realmOldPinTasks[1])
	pool, pins, newPin := at(realmOldPinTasks[2]), at(realmOldPinTasks[3]), at(realmOldPinTasks[4])
	uninstall := at("Realm replacement — remove old client enrollment")
	enroll := at("Realm replacement — enroll client in the new realm")
	if read >= list || list >= uninstall || uninstall >= pool || pool >= pins || pins >= newPin || newPin >= enroll {
		t.Errorf("order read=%d list=%d uninstall=%d pool=%d pins=%d new pin=%d enroll=%d; want read, list, uninstall, pool, pins, new pin, enroll",
			read, list, uninstall, pool, pins, newPin, enroll)
	}
}
