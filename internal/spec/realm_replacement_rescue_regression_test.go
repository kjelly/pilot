package spec

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// After a failed switch the rescue restored the archive, but the old realm
// stayed offline: ipa-client-install --uninstall had unenrolled the host
// (`ipa-join --unenroll` → host_disable), voiding the archived keytab on the
// old server, and it had also reverted authselect/PAM, the hostname, SSSD's
// and sshd's IPA settings and the CA trust, which the archive does not hold
// (2026-10-12). The switch now removes the old realm's keys from the keytab
// before the uninstall, so the unenroll cannot authenticate, and the rescue
// re-enrolls the client in the old realm with the archived keytab.

// realmRescueTasks are the rescue's tasks, without the SSSD restart.
var realmRescueTasks = []string{
	"Realm replacement — read the realm this client is enrolled in now",
	"Realm replacement — decide how to restore the old enrollment",
	"Realm replacement — remove the new realm's enrollment",
	"Realm replacement — put back the old server pins",
	"Realm replacement — create a private directory for the archived host keytab",
	"Realm replacement — extract the archived host keytab",
	"Realm replacement — re-enroll in the old realm with the archived host keys",
	"Realm replacement — remove the extracted host keytab",
	"Realm replacement — restore local pre-migration archive",
	"Realm replacement — stop with the rollback boundary",
}

const realmStubScript = `#!/usr/bin/env bash
name=$(basename "$0")
echo "$name $*" >> "$REALM_STUB_DIR/log"
case "$name $*" in
  "ipa-client-install --uninstall"*)
    n=$(( $(cat "$REALM_STUB_DIR/uninstalls" 2>/dev/null || echo 0) + 1 ))
    echo "$n" > "$REALM_STUB_DIR/uninstalls"
    if [ "$n" = 1 ] && [ -f "$REALM_STUB_DIR/after-uninstall" ]; then
      cp "$REALM_STUB_DIR/after-uninstall" "$REALM_STUB_CONF"
    else
      rm -f "$REALM_STUB_CONF"
    fi;;
  "ipa-client-install "*--keytab=*) exit "${REALM_STUB_REENROLL_RC:-0}";;
esac
exit 0
`

// TestRegression_RealmReplacementRescueReenrollsTheOldRealm runs the
// switch's preparation, key removal and uninstall and the rescue on
// localhost, with ipa-client-install, ipa-rmkeytab and tar replaced by stubs
// that log their arguments; the uninstall stub leaves default.conf as the
// case says the failed enrollment did.
func TestRegression_RealmReplacementRescueReenrollsTheOldRealm(t *testing.T) {
	const oldConf = "[global]\nbasedn = dc=ipa,dc=pilot,dc=internal\nrealm = IPA.PILOT.INTERNAL\ndomain = ipa.pilot.internal\nserver = ipa1.ipa.pilot.internal\nhost = c53-cl.ipa.pilot.internal\n"
	const newConf = "[global]\nrealm = NEW.EXAMPLE.TEST\ndomain = new.example.test\nserver = ipa1.new.example.test\nhost = c53-cl.new.example.test\n"
	const sssd = "[domain/ipa.pilot.internal]\nipa_server = _srv_, ipa1.ipa.pilot.internal\nipa_backup_server = ipa2.ipa.pilot.internal\n"
	prepare := []string{
		"Realm replacement — read the old realm's client configuration",
		"Realm replacement — record the old enrollment",
		"Realm replacement — the old enrollment can be restored",
		"Realm replacement — list the old realm's servers",
	}
	uninstall := []string{
		"Realm replacement — keep the old host enabled on the old server",
		"Realm replacement — remove old client enrollment",
	}
	reenroll := `ipa-client-install -U --keytab=(\S+)/etc/krb5\.keytab --server=ipa1\.ipa\.pilot\.internal --server=ipa2\.ipa\.pilot\.internal ` +
		`--domain=ipa\.pilot\.internal --realm=IPA\.PILOT\.INTERNAL --hostname=c53-cl\.ipa\.pilot\.internal --mkhomedir --no-ntp --no-dns-sshfp`
	cases := []struct {
		name           string
		uninstalled    bool   // the switch got as far as the uninstall
		afterUninstall string // default.conf the failed enrollment left; "" for none
		newServer      string // the new server's FQDN, if not the default
		reenrollRC     string
		want           []string // log lines, as regexes; ARCHIVE is the archive path
		wantMsg        string
	}{
		{
			name:    "failed before the uninstall: restore the archive only",
			want:    []string{`tar -xpf ARCHIVE -C /`},
			wantMsg: "still named IPA.PILOT.INTERNAL, so the client was not re-enrolled",
		},
		{
			name:           "the new realm's enrollment is in place: remove it, then re-enroll",
			uninstalled:    true,
			afterUninstall: newConf,
			want: []string{
				`ipa-rmkeytab -k /etc/krb5\.keytab -r IPA\.PILOT\.INTERNAL`,
				`ipa-client-install --uninstall -U`,
				`ipa-client-install --uninstall -U`,
				`tar -xpf ARCHIVE -C / etc/hosts`,
				`tar -xpf ARCHIVE -C (\S+) etc/krb5\.keytab`,
				reenroll,
				`tar --exclude=etc/krb5\.keytab -xpf ARCHIVE -C /`,
			},
			wantMsg: "re-enrolled in IPA.PILOT.INTERNAL as c53-cl.ipa.pilot.internal",
		},
		{
			// The new realm's uninstall still resolves the shared name to the
			// new server: it runs before the archived hosts come back.
			name:           "the new server keeps the old server's FQDN: the re-enrollment still names it",
			uninstalled:    true,
			afterUninstall: strings.ReplaceAll(newConf, "ipa1.new.example.test", "ipa1.ipa.pilot.internal"),
			newServer:      "ipa1.ipa.pilot.internal",
			want: []string{
				`ipa-rmkeytab -k /etc/krb5\.keytab -r IPA\.PILOT\.INTERNAL`,
				`ipa-client-install --uninstall -U`,
				`ipa-client-install --uninstall -U`,
				`tar -xpf ARCHIVE -C / etc/hosts`,
				`tar -xpf ARCHIVE -C (\S+) etc/krb5\.keytab`,
				reenroll,
				`tar --exclude=etc/krb5\.keytab -xpf ARCHIVE -C /`,
			},
			wantMsg: "re-enrolled in IPA.PILOT.INTERNAL as c53-cl.ipa.pilot.internal",
		},
		{
			name:        "the enrollment rolled itself back: re-enroll",
			uninstalled: true,
			want: []string{
				`ipa-rmkeytab -k /etc/krb5\.keytab -r IPA\.PILOT\.INTERNAL`,
				`ipa-client-install --uninstall -U`,
				`tar -xpf ARCHIVE -C / etc/hosts`,
				`tar -xpf ARCHIVE -C (\S+) etc/krb5\.keytab`,
				reenroll,
				`tar --exclude=etc/krb5\.keytab -xpf ARCHIVE -C /`,
			},
			wantMsg: "re-enrolled in IPA.PILOT.INTERNAL as c53-cl.ipa.pilot.internal",
		},
		{
			name:        "the re-enrollment fails: restore the whole archive, keytab included",
			uninstalled: true,
			reenrollRC:  "1",
			want: []string{
				`ipa-rmkeytab -k /etc/krb5\.keytab -r IPA\.PILOT\.INTERNAL`,
				`ipa-client-install --uninstall -U`,
				`tar -xpf ARCHIVE -C / etc/hosts`,
				`tar -xpf ARCHIVE -C (\S+) etc/krb5\.keytab`,
				reenroll,
				`tar -xpf ARCHIVE -C /`,
			},
			wantMsg: "failed too",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"ipa-client-install", "ipa-rmkeytab", "tar"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(realmStubScript), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			conf := filepath.Join(dir, "default.conf")
			for path, content := range map[string]string{conf: oldConf, filepath.Join(dir, "sssd.conf"): sssd} {
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.afterUninstall != "" {
				if err := os.WriteFile(filepath.Join(dir, "after-uninstall"), []byte(tc.afterUninstall), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			names := slices.Clone(prepare)
			if tc.uninstalled {
				names = append(names, uninstall...)
			}
			names = append(names, realmRescueTasks...)
			archive := filepath.Join(dir, "c53-cl-backup.tar.gz")
			vars := map[string]any{
				"freeipa_realm_replacement_old_realm":      "IPA.PILOT.INTERNAL",
				"freeipa_realm_replacement_backup_archive": archive,
			}
			if tc.newServer != "" {
				vars["freeipa_realm_replacement_new_server_fqdn"] = tc.newServer
			}
			env := []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"REALM_STUB_DIR=" + dir, "REALM_STUB_CONF=" + conf, "REALM_STUB_REENROLL_RC=" + tc.reenrollRC,
			}
			paths := map[string]string{"/etc/ipa/default.conf": conf, "/etc/sssd/sssd.conf": filepath.Join(dir, "sssd.conf")}
			rc, _, failures := runRealmTasksEnv(t, names, paths, vars, env)
			if rc == 0 || len(failures) != 1 || !strings.HasPrefix(failures[0], "Realm replacement — stop with the rollback boundary: ") {
				t.Fatalf("rc=%d failures=%v; want only the rollback boundary to fail", rc, failures)
			}
			if !strings.Contains(failures[0], tc.wantMsg) {
				t.Errorf("message %q does not say %q", failures[0], tc.wantMsg)
			}
			raw, err := os.ReadFile(filepath.Join(dir, "log"))
			if err != nil {
				t.Fatal(err)
			}
			log := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if len(log) != len(tc.want) {
				t.Fatalf("commands:\n%s\nwant %d:\n%s", raw, len(tc.want), strings.Join(tc.want, "\n"))
			}
			for i, w := range tc.want {
				re := regexp.MustCompile("^" + strings.ReplaceAll(w, "ARCHIVE", regexp.QuoteMeta(archive)) + "$")
				m := re.FindStringSubmatch(log[i])
				if m == nil {
					t.Errorf("command %d = %q, want %s", i+1, log[i], re)
					continue
				}
				// The keytab goes to a private directory, which is gone afterwards.
				if len(m) > 1 {
					if _, err := os.Stat(m[1]); !os.IsNotExist(err) {
						t.Errorf("command %d: %s still exists (err %v)", i+1, m[1], err)
					}
				}
			}
		})
	}
}

// TestRegression_RealmReplacementRefusesAnUnrestorableOldEnrollment: without
// the old enrollment's host the rescue could not re-enroll, so the switch
// stops before it removes anything.
func TestRegression_RealmReplacementRefusesAnUnrestorableOldEnrollment(t *testing.T) {
	dir := t.TempDir()
	paths := map[string]string{"/etc/ipa/default.conf": filepath.Join(dir, "default.conf"), "/etc/sssd/sssd.conf": filepath.Join(dir, "sssd.conf")}
	for content, path := range map[string]string{
		"[global]\nrealm = IPA.PILOT.INTERNAL\ndomain = ipa.pilot.internal\nserver = ipa1.ipa.pilot.internal\n": paths["/etc/ipa/default.conf"],
		"[domain/ipa.pilot.internal]\nipa_server = _srv_\n":                                                     paths["/etc/sssd/sssd.conf"],
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rc, _, failures := runRealmTasks(t, []string{
		"Realm replacement — read the old realm's client configuration",
		"Realm replacement — record the old enrollment",
		"Realm replacement — the old enrollment can be restored",
	}, paths, map[string]any{"freeipa_realm_replacement_old_realm": "IPA.PILOT.INTERNAL"})
	if rc == 0 || len(failures) != 1 || !strings.Contains(failures[0], "could not re-enroll this client") {
		t.Errorf("rc=%d failures=%v; want the restorability check to fail", rc, failures)
	}
}

// TestRegression_RealmReplacementRemovesOldKeysBeforeTheUninstall: the
// old realm's keys leave the keytab after the old enrollment is recorded and
// checked, and before the uninstall.
func TestRegression_RealmReplacementRemovesOldKeysBeforeTheUninstall(t *testing.T) {
	doc, _ := loadYAML(t, "../../playbooks/apply/freeipa-realm-replacement-apply.yml").([]any)
	var order []string
	walkTaskTree(doc[0].(map[string]any)["tasks"], nil, func(task map[string]any, _ []string) {
		name, _ := task["name"].(string)
		order = append(order, name)
	})
	at := func(name string) int {
		i := slices.Index(order, name)
		if i < 0 {
			t.Fatalf("%q is not in the play", name)
		}
		return i
	}
	check := at("Realm replacement — the old enrollment can be restored")
	keys := at("Realm replacement — keep the old host enabled on the old server")
	uninstall := at("Realm replacement — remove old client enrollment")
	if check >= keys || keys+1 != uninstall {
		t.Errorf("order check=%d keys=%d uninstall=%d; want the check, then the key removal right before the uninstall", check, keys, uninstall)
	}
}

// enrollmentOptions returns the ipa-client-install options in s that do not
// name a server, realm, host or credential.
func enrollmentOptions(s string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`'(--[a-z-]+)'`).FindAllStringSubmatch(s, -1) {
		switch m[1] {
		case "--uninstall":
		default:
			out = append(out, m[1])
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// TestRegression_RealmReplacementReenrollsLikeFreeipaClient: the rescue
// re-enrolls with the options freeipa-client-apply.yml enrolled with, so the
// client gets back the same configuration; --force-join has no effect with
// --keytab.
func TestRegression_RealmReplacementReenrollsLikeFreeipaClient(t *testing.T) {
	argv := func(path, name string) string {
		doc, _ := loadYAML(t, path).([]any)
		var found string
		for _, item := range doc {
			play, _ := item.(map[string]any)
			for _, section := range []string{"pre_tasks", "tasks"} {
				walkTaskTree(play[section], nil, func(task map[string]any, _ []string) {
					if task["name"] == name {
						cmd, _ := task["ansible.builtin.command"].(map[string]any)
						found, _ = cmd["argv"].(string)
					}
				})
			}
		}
		if found == "" {
			t.Fatalf("%s: no %q with a templated argv", path, name)
		}
		return found
	}
	client := enrollmentOptions(argv("../../playbooks/apply/freeipa-client-apply.yml", "FreeIPA client — run ipa-client-install (enroll into {{ ipa_realm }})"))
	client = slices.DeleteFunc(client, func(o string) bool { return o == "--force-join" })
	rescue := enrollmentOptions(argv("../../playbooks/apply/freeipa-realm-replacement-apply.yml", "Realm replacement — re-enroll in the old realm with the archived host keys"))
	rescue = slices.DeleteFunc(rescue, func(o string) bool { return o == "--keytab" })
	if !slices.Equal(client, rescue) {
		t.Errorf("rescue re-enrolls with %v, freeipa-client enrolls with %v (without --force-join)", rescue, client)
	}
}
