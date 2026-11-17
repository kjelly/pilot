package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #118, batch 2: the fixtures that set a Kerberos password with
// `kadmin.local cpw` and the 389-ds audit-log write used to put a secret into
// a shell string. The runtime test in secret_command_text_regression_test.go
// proves the bytes of a secret reach stdin unchanged; this file proves the
// two other things those migrations promised:
//
//   - kadmin.local exits 0 whatever happens (captured on FreeIPA 4.13.4, krb5
//     1.21.1, AlmaLinux 9.8: success, password mismatch, unknown principal, a
//     too short password, "Too soon to change password" and an empty stdin all
//     returned 0), so a failed password set is only visible in the output:
//     success is the stdout line `Password for "<principal>" changed.`, the
//     reason for a failure is on stderr. The tests below feed the real
//     captures (testdata/kadmin-cpw/) to the real fixture tasks and require
//     the success to change and every failure to fail with kadmin's words.
//   - the audit-log dummy write goes over ldapi with SASL EXTERNAL as root,
//     needs no password, and a failed ldapmodify (captured rc 32, 65 and 255)
//     fails the task instead of being hidden by an `echo INITIALIZED`.

// kadminCapture returns a captured kadmin.local output file with the lab
// principal swapped for user.
func kadminCapture(t *testing.T, name, user string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "kadmin-cpw", name))
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(body), "capuser@", user+"@")
}

const fakeKadminScript = `#!/bin/sh
d="$FAKE_DIR"
n=$(($(cat "$d/kadmin-count" 2>/dev/null || echo 0) + 1))
echo "$n" > "$d/kadmin-count"
cat > "$d/kadmin-stdin.$n"
printf '%s\n' "$@" > "$d/kadmin-args.$n"
[ -f "$d/kadmin.stdout" ] && cat "$d/kadmin.stdout"
[ -f "$d/kadmin.stderr" ] && cat "$d/kadmin.stderr" >&2
exit "$(cat "$d/kadmin-rc" 2>/dev/null || echo 0)"
`

const fakeProbeKinitScript = `#!/bin/sh
d="$FAKE_DIR"
cat > "$d/kinit-stdin"
printf '%s\n' "$@" > "$d/kinit-args"
exit "$(cat "$d/kinit-rc")"
`

func TestRegression_KadminCpwOutcomesAreJudgedFromItsOutput(t *testing.T) {
	requireAnsiblePlaybook(t)
	root := filepath.Join("..", "..")
	sites := []struct {
		file, user, secretVar string
		probe, cpw, gate      string
		vars                  map[string]any
	}{
		{
			file: "playbooks/test/fixtures/freeipa-audit-demo.yml", user: "audituser", secretVar: "audit_demo_user_pass",
			probe: "Fixtures — does {{ audit_demo_user }} already have the declared password?",
			cpw:   "Fixtures — set stable password for {{ audit_demo_user }} via kadmin.local (no forced change)",
			gate:  "Gate: kadmin.local changed the password of {{ audit_demo_user }}",
			vars:  map[string]any{"audit_demo_user": "audituser"},
		},
		{
			file: "playbooks/test/fixtures/freeipa-hostauthz-demo.yml", user: "hz_web", secretVar: "hz_web_pass",
			probe: "Fixtures — does hz_web already have the declared password?",
			cpw:   "Fixtures — set stable password for hz_web via kadmin.local",
			gate:  "Gate: kadmin.local changed the password of hz_web",
		},
		{
			file: "playbooks/test/fixtures/freeipa-hostauthz-demo.yml", user: "hz_db", secretVar: "hz_db_pass",
			probe: "Fixtures — does hz_db already have the declared password?",
			cpw:   "Fixtures — set stable password for hz_db via kadmin.local",
			gate:  "Gate: kadmin.local changed the password of hz_db",
		},
	}
	// A password with every character the old printf spelling rewrote.
	const password = "Pw9$HOME\\%s%d`id` end"
	for _, site := range sites {
		doc := loadYAML(t, filepath.Join(root, site.file))
		probe, cpw, gate := findNamedTask(t, doc, site.probe), findNamedTask(t, doc, site.cpw), findNamedTask(t, doc, site.gate)
		rendered := func(name string) string { return strings.ReplaceAll(name, "{{ audit_demo_user }}", "audituser") }
		for _, task := range []map[string]any{probe, cpw} {
			if task["no_log"] != true {
				t.Fatalf("%s: a task that passes the password on stdin needs no_log: true", task["name"])
			}
		}
		if gate["no_log"] == true {
			t.Fatalf("%s: the gate must keep kadmin's own message visible, it must not be no_log", gate["name"])
		}
		for _, tc := range []struct {
			name     string
			kinitRC  int
			capture  string // testdata/kadmin-cpw/<capture>.stdout and .stderr; "" prints nothing
			kadminRC int
			// wantRun: kadmin.local is called. wantOK: the run succeeds.
			wantRun, wantOK bool
			wantMsg         string
		}{
			{name: "the declared password already works", kinitRC: 0, wantRun: false, wantOK: true},
			{name: "success", kinitRC: 1, capture: "success", wantRun: true, wantOK: true},
			{name: "password mismatch", kinitRC: 1, capture: "mismatch", wantRun: true, wantMsg: "Password mismatch while reading password"},
			{name: "unknown principal", kinitRC: 1, capture: "unknown", wantRun: true, wantMsg: "Principal does not exist"},
			{name: "password too short", kinitRC: 1, capture: "too-short", wantRun: true, wantMsg: "Password is too short"},
			{name: "too soon to change", kinitRC: 1, capture: "too-soon", wantRun: true, wantMsg: "Too soon to change password"},
			{name: "stdin ended early", kinitRC: 1, capture: "empty", wantRun: true, wantMsg: "Cannot read password"},
			{name: "kadmin.local itself fails", kinitRC: 1, kadminRC: 1, wantRun: true, wantMsg: "rc=1"},
		} {
			t.Run(site.user+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				bin := filepath.Join(dir, "bin")
				if err := os.Mkdir(bin, 0o755); err != nil {
					t.Fatal(err)
				}
				write := func(name, body string) {
					if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				for name, script := range map[string]string{"kadmin.local": fakeKadminScript, "kinit": fakeProbeKinitScript} {
					if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
						t.Fatal(err)
					}
				}
				write("kinit-rc", fmt.Sprint(tc.kinitRC))
				write("kadmin-rc", fmt.Sprint(tc.kadminRC))
				if tc.capture != "" {
					write("kadmin.stdout", kadminCapture(t, tc.capture+".stdout", site.user))
					write("kadmin.stderr", kadminCapture(t, tc.capture+".stderr", site.user))
				}
				var tasks []any
				for _, task := range []map[string]any{probe, cpw, gate} {
					cp := map[string]any{}
					for k, v := range task {
						if k != "become" && k != "tags" {
							cp[k] = v
						}
					}
					tasks = append(tasks, cp)
				}
				vars := map[string]any{"ipa_realm": stdinRealm, site.secretVar: unsafeString(password)}
				for k, v := range site.vars {
					vars[k] = v
				}
				env := map[string]any{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_DIR": dir}
				res := runGatewayTasks(t, dir, []any{map[string]any{"name": "the fixture tasks", "environment": env, "block": tasks}}, vars, nil)

				if strings.Contains(res.raw, password) || strings.Contains(res.stderr, password) {
					t.Fatalf("Ansible output leaked the password:\n%s", res.raw)
				}
				probeArgs, err := os.ReadFile(filepath.Join(dir, "kinit-args"))
				if err != nil {
					t.Fatalf("the probe kinit did not run: %v", err)
				}
				if lines := strings.Split(strings.TrimSpace(string(probeArgs)), "\n"); len(lines) != 3 || lines[0] != "-c" || !strings.HasPrefix(lines[1], "MEMORY:") || lines[2] != site.user+"@"+stdinRealm {
					t.Errorf("probe kinit args = %q, want -c MEMORY:<name> %s@%s", probeArgs, site.user, stdinRealm)
				}
				if probeStdin, _ := os.ReadFile(filepath.Join(dir, "kinit-stdin")); string(probeStdin) != password+"\n" {
					t.Errorf("probe kinit stdin = %q, want the password and a newline", probeStdin)
				}

				_, calledErr := os.Stat(filepath.Join(dir, "kadmin-count"))
				if called := calledErr == nil; called != tc.wantRun {
					t.Fatalf("kadmin.local called = %v, want %v (failures %v)", called, tc.wantRun, res.failures)
				}
				if tc.wantRun {
					stdin, _ := os.ReadFile(filepath.Join(dir, "kadmin-stdin.1"))
					if string(stdin) != password+"\n"+password+"\n" {
						t.Errorf("kadmin.local stdin = %q, want the password twice, one per line", stdin)
					}
					args, _ := os.ReadFile(filepath.Join(dir, "kadmin-args.1"))
					if string(args) != "-q\ncpw "+site.user+"\n" {
						t.Errorf("kadmin.local args = %q, want -q and cpw %s only", args, site.user)
					}
				}

				cpwName := rendered(site.cpw)
				if tc.wantOK {
					if res.rc != 0 {
						t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
					}
					if changed := res.changed[cpwName]; changed != tc.wantRun {
						t.Errorf("the password task changed = %v, want %v", changed, tc.wantRun)
					}
					return
				}
				if res.rc == 0 {
					t.Fatalf("a failed password set did not fail the run\n%s", res.raw)
				}
				gateMsg := failureOf(res, rendered(site.gate))
				if gateMsg == "" {
					t.Fatalf("the gate did not fail; failures: %v", res.failures)
				}
				if !strings.Contains(gateMsg, tc.wantMsg) {
					t.Errorf("gate message %q does not carry kadmin's own words %q", gateMsg, tc.wantMsg)
				}
				if res.changed[cpwName] {
					t.Error("the password task reported changed for a failed set")
				}
			})
		}
	}
}

// ldapmodifyCapture returns a captured ldapmodify output file.
func ldapmodifyCapture(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "ldapmodify-ldapi", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

const fakeLdapmodifyScript = `#!/bin/sh
d="$FAKE_DIR"
n=$(($(cat "$d/ldap-count" 2>/dev/null || echo 0) + 1))
echo "$n" > "$d/ldap-count"
cat > "$d/ldap-stdin.$n"
printf '%s\n' "$@" > "$d/ldap-args.$n"
[ -f "$d/ldap.stdout" ] && cat "$d/ldap.stdout"
[ -f "$d/ldap.stderr" ] && cat "$d/ldap.stderr" >&2
exit "$(cat "$d/ldap-rc" 2>/dev/null || echo 0)"
`

// auditWriteTasks returns the stat and the dummy-write tasks of the 389-ds
// audit-log block in freeipa-server-apply.yml.
func auditWriteTasks(t *testing.T) (stat, write map[string]any) {
	t.Helper()
	doc := loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", "freeipa-server-apply.yml"))
	stat = findNamedTask(t, doc, "FreeIPA — 389-ds audit log: check whether the audit file already has entries")
	write = findNamedTask(t, doc, "FreeIPA — 389-ds audit log: write dummy description to trigger audit log (spec C16)")
	return stat, write
}

// TestRegression_AuditLogDummyWriteNeedsNoPassword is the structure half of
// the issue #118 fix for the 389-ds audit write: root over ldapi with SASL
// EXTERNAL (389-ds maps root to Directory Manager; the audit entry shows
// `modifiersname: cn=Directory Manager`, captured on 389-ds-base 2.9.0), no
// Directory Manager password anywhere in the task, the LDIF on stdin.
func TestRegression_AuditLogDummyWriteNeedsNoPassword(t *testing.T) {
	_, write := auditWriteTasks(t)
	_, raw := secretTaskModule(write)
	args, _ := raw.(map[string]any)
	if _, isCommand := write["ansible.builtin.command"]; !isCommand || args == nil {
		t.Fatalf("the write must be an ansible.builtin.command task, got %v", write)
	}
	argv, _ := args["argv"].([]any)
	var got []string
	for _, a := range argv {
		got = append(got, fmt.Sprint(a))
	}
	want := []string{"ldapmodify", "-Q", "-Y", "EXTERNAL", "-H", "ldapi://%2Frun%2F{{ ipa_ds_instance }}.socket"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("argv = %q, want %q", got, want)
	}
	text := valueText(write)
	for _, bad := range []string{"ipa_dm_password", "Directory Manager", " -w", "-W", "-x"} {
		if strings.Contains(text, bad) {
			t.Errorf("the dummy write must not mention %q: it authenticates by peer credentials", bad)
		}
	}
	stdin, _ := args["stdin"].(string)
	for _, line := range []string{"changetype: modify", "replace: description", "description: FreeIPA Directory Server for pilot.internal (initialized at {{ ansible_date_time.iso8601 }})"} {
		if !strings.Contains(stdin, line) {
			t.Errorf("the LDIF on stdin lacks %q:\n%s", line, stdin)
		}
	}
	if _, ok := write["when"]; !ok {
		t.Error("the write needs its when: only an empty audit file is written to (idempotent second run)")
	}
}

// TestRegression_AuditFileStatsSkipTheChecksum: both stats of the audit file
// read only its size, and the file can be 100 MB, so neither may checksum it
// (ansible.builtin.stat does by default).
func TestRegression_AuditFileStatsSkipTheChecksum(t *testing.T) {
	doc := loadYAML(t, filepath.Join("..", "..", "playbooks", "apply", "freeipa-server-apply.yml"))
	for _, name := range []string{
		"FreeIPA — 389-ds audit log: check whether the audit file already has entries",
		"FreeIPA — 389-ds audit log: read the audit file size",
	} {
		args, _ := findNamedTask(t, doc, name)["ansible.builtin.stat"].(map[string]any)
		if args == nil || args["get_checksum"] != false {
			t.Errorf("%s: stat args = %v, want get_checksum: false", name, args)
		}
	}
}

// TestRegression_HostauthzDemoPasswordDefaultsResolveOnce: the two lab users'
// declared passwords are resolved once, as play vars (like audit_demo_user_pass
// in freeipa-audit-demo.yml), and every task reads those. The play vars keep the
// old behaviour: the lab default, or hz_*_password when given.
func TestRegression_HostauthzDemoPasswordDefaultsResolveOnce(t *testing.T) {
	requireAnsiblePlaybook(t)
	const file = "../../playbooks/test/fixtures/freeipa-hostauthz-demo.yml"
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, literal := range []string{"TestWebPass123", "TestDbPass123"} {
		if n := strings.Count(string(raw), literal); n != 1 {
			t.Errorf("%s appears %d times in %s, want once (the play var default)", literal, n, file)
		}
	}
	plays, _ := loadYAML(t, file).([]any)
	if len(plays) != 1 {
		t.Fatalf("want one play, got %d", len(plays))
	}
	vars, _ := plays[0].(map[string]any)["vars"].(map[string]any)
	for _, tc := range []struct {
		name    string
		extra   map[string]any
		web, db string
	}{
		{name: "lab defaults", web: "TestWebPass123", db: "TestDbPass123"},
		{name: "overrides win", extra: map[string]any{"hz_web_password": "Web-override-9", "hz_db_password": "Db-override-9"}, web: "Web-override-9", db: "Db-override-9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(name, want string) map[string]any {
				return map[string]any{"name": name, "ansible.builtin.assert": map[string]any{"that": []any{fmt.Sprintf("%s == %q", name, want)}}}
			}
			res := runGatewayTasks(t, t.TempDir(), []any{check("hz_web_pass", tc.web), check("hz_db_pass", tc.db)}, vars, tc.extra)
			if res.rc != 0 {
				t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
			}
		})
	}
}

// TestRegression_AuditLogDummyWriteFailsLoudly runs the real stat and write
// tasks with real ansible-playbook and a fake ldapmodify. It requires the
// guard (an empty or missing audit file writes once, a non-empty one does not),
// a Directory Manager password that is not used even when present, and every
// captured ldapmodify failure (rc 32, 65, 255) failing the task with its
// stderr; the old shell echoed INITIALIZED and reported changed whatever
// ldapmodify did.
func TestRegression_AuditLogDummyWriteFailsLoudly(t *testing.T) {
	requireAnsiblePlaybook(t)
	stat, write := auditWriteTasks(t)
	const dmPassword = "Dm$HOME`id`\"'\\%s pass"
	for _, tc := range []struct {
		name        string
		audit       string // "" missing, "empty", "full"
		ldapRC      int
		stderr      string
		wantRun     bool
		wantChanged bool
		wantFailure string
	}{
		{name: "empty audit file is written to", audit: "empty", ldapRC: 0, wantRun: true, wantChanged: true},
		{name: "missing audit file is written to", audit: "", ldapRC: 0, wantRun: true, wantChanged: true},
		{name: "non-empty audit file is left alone", audit: "full", wantRun: false},
		{name: "no such object (rc 32)", audit: "empty", ldapRC: 32, stderr: "no-such-object.stderr", wantRun: true, wantFailure: "No such object (32)"},
		{name: "schema violation (rc 65)", audit: "empty", ldapRC: 65, stderr: "schema-violation.stderr", wantRun: true, wantFailure: "Object class violation (65)"},
		{name: "ldapi socket missing (rc 255)", audit: "empty", ldapRC: 255, stderr: "no-socket.stderr", wantRun: true, wantFailure: "Can't contact LDAP server"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "ldapmodify"), []byte(fakeLdapmodifyScript), 0o755); err != nil {
				t.Fatal(err)
			}
			auditFile := filepath.Join(dir, "audit")
			switch tc.audit {
			case "empty":
				if err := os.WriteFile(auditFile, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "full":
				if err := os.WriteFile(auditFile, []byte("time: 20261117000000\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "ldap-rc"), []byte(fmt.Sprint(tc.ldapRC)), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.stderr != "" {
				if err := os.WriteFile(filepath.Join(dir, "ldap.stderr"), []byte(ldapmodifyCapture(t, tc.stderr)), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// The guard reads the audit file; point it at the temp copy.
			statCopy := map[string]any{}
			for k, v := range stat {
				statCopy[k] = v
			}
			statArgs := map[string]any{}
			for k, v := range stat["ansible.builtin.stat"].(map[string]any) {
				statArgs[k] = v
			}
			statArgs["path"] = auditFile
			statCopy["ansible.builtin.stat"] = statArgs
			writeCopy := map[string]any{}
			for k, v := range write {
				if k != "tags" {
					writeCopy[k] = v
				}
			}
			vars := map[string]any{
				"ipa_ds_instance": "slapd-IPA-PILOT-INTERNAL", "ipa_domain": "ipa.pilot.internal",
				"ansible_date_time": map[string]any{"iso8601": "2026-11-17T00:00:00Z"},
				// Present, hostile and unused: the write must not need it.
				"ipa_dm_password": unsafeString(dmPassword),
			}
			env := map[string]any{"PATH": bin + string(os.PathListSeparator) + os.Getenv("PATH"), "FAKE_DIR": dir}
			res := runGatewayTasks(t, dir, []any{map[string]any{"name": "the audit tasks", "environment": env, "block": []any{statCopy, writeCopy}}}, vars, nil)
			if strings.Contains(res.raw, dmPassword) || strings.Contains(res.stderr, dmPassword) {
				t.Fatal("Ansible output leaked the Directory Manager password")
			}
			_, calledErr := os.Stat(filepath.Join(dir, "ldap-count"))
			if called := calledErr == nil; called != tc.wantRun {
				t.Fatalf("ldapmodify called = %v, want %v (failures %v)", called, tc.wantRun, res.failures)
			}
			if tc.wantRun {
				args, _ := os.ReadFile(filepath.Join(dir, "ldap-args.1"))
				if string(args) != "-Q\n-Y\nEXTERNAL\n-H\nldapi://%2Frun%2Fslapd-IPA-PILOT-INTERNAL.socket\n" {
					t.Errorf("ldapmodify args = %q", args)
				}
				stdin, _ := os.ReadFile(filepath.Join(dir, "ldap-stdin.1"))
				if !strings.HasPrefix(string(stdin), "dn: dc=ipa,dc=pilot,dc=internal\nchangetype: modify\nreplace: description\ndescription: FreeIPA Directory Server for pilot.internal (initialized at 2026-11-17T00:00:00Z)\n") {
					t.Errorf("ldapmodify stdin = %q", stdin)
				}
				if strings.Contains(string(args)+string(stdin), dmPassword) {
					t.Error("the Directory Manager password reached ldapmodify")
				}
			}
			writeName := fmt.Sprint(write["name"])
			if tc.wantFailure == "" {
				if res.rc != 0 {
					t.Fatalf("rc=%d failures=%v\n%s", res.rc, res.failures, res.raw)
				}
				if changed := res.changed[writeName]; changed != tc.wantChanged {
					t.Errorf("the write task changed = %v, want %v", changed, tc.wantChanged)
				}
				return
			}
			if res.rc == 0 {
				t.Fatalf("a failed ldapmodify did not fail the run\n%s", res.raw)
			}
			// The failure is the write task's own, and its result (not hidden
			// by no_log, which this task no longer needs) carries ldapmodify's
			// stderr.
			if failureOf(res, writeName) == "" {
				t.Errorf("the write task did not fail; failures: %v", res.failures)
			}
			if !strings.Contains(res.raw, tc.wantFailure) {
				t.Errorf("the failed run does not show ldapmodify's own %q", tc.wantFailure)
			}
		})
	}
}
