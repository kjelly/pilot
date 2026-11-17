package spec

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRegression_LogServerC11AllowsAttributesAfterRuleset(t *testing.T) {
	s, err := Parse("../../docs/verification/log-server.md")
	if err != nil {
		t.Fatal(err)
	}
	var command string
	for _, row := range s.Rows {
		if row.ID == "C11" {
			command = row.Command
		}
	}
	if command == "" {
		t.Fatal("missing C11")
	}
	path := filepath.Join(t.TempDir(), "receiver.conf")
	command = strings.ReplaceAll(command, "/etc/rsyslog.d/10-siem-receiver.conf", `"$1"`)
	for _, tc := range []struct{ input, want string }{
		{`input(type="imtcp" port="514" ruleset="siemReceiver")`, "0"},
		{`input(type="imtcp" port="514" ruleset="siemReceiver" address="127.0.0.1")`, "0"},
		{`input(type="imtcp" port="514" ruleset="wrong" address="127.0.0.1")`, "1"},
		{`input(type="imtcp" port="514" address="127.0.0.1")`, "1"},
	} {
		if err := os.WriteFile(path, []byte(tc.input+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", "-c", command, "c11", path).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != tc.want {
			t.Fatalf("C11(%s) = %q, %v; want %s", tc.input, out, err, tc.want)
		}
	}
}

// logrotateDebugUbuntuSu is `LC_ALL=C logrotate -d <policy> 2>&1` captured on a
// disposable Ubuntu 24.04.4 VM (logrotate 3.21.0, rsyslog 8.2312.0) for a copy of
// the siem-incoming policy that adds `su syslog syslog` before `sharedscripts`,
// as root, over a SIEM tree owned by syslog:syslog (uid 102, gid 102). The pid
// varies per run; the path of the policy copy and the host directory name are
// the capture host's. logrotate switches to the policy's `su` identity before
// it handles the log set and back afterwards, and says so in debug mode.
const logrotateDebugUbuntuSu = `warning: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode (-v) instead if this is not what you want.

reading config file /root/i93-su.conf
Reading state from file: /var/lib/logrotate/status
state file /var/lib/logrotate/status does not exist
Allocating hash table for state file, size 64 entries

Handling 1 logs

rotating pattern: /var/log/siem/*/*.log  after 1 days (14 rotations)
empty log files are not rotated, old logs are removed
switching euid from 0 to 102 and egid from 0 to 102 (pid 3228)
considering log /var/log/siem/i93-dev-deb/audit.log
Creating new state
  Now: 2026-11-17 07:12
  Last rotated at 2026-11-17 07:00
  log does not need rotating (log has already been rotated)
considering log /var/log/siem/i93-dev-deb/auth.log
Creating new state
  Now: 2026-11-17 07:12
  Last rotated at 2026-11-17 07:00
  log does not need rotating (log has already been rotated)
not running postrotate script, since no logs were rotated
switching euid from 102 to 0 and egid from 102 to 0 (pid 3228)
`

// logrotateSwitchTo is the first `switching` line of the capture above, used to
// build variants of it (another uid, gid, or no line) by replacing that line.
const logrotateSwitchTo = "switching euid from 0 to 102 and egid from 0 to 102 (pid 3228)\n"

// logrotateDebugUbuntuBase is a second real capture from the same Ubuntu 24.04.4
// VM (logrotate 3.21.0, rsyslog 8.2312.0): `LC_ALL=C logrotate -d
// /etc/logrotate.d/siem-incoming 2>&1` as root on the policy as it was before
// v2.1 (no `su`), rc=0. It is the policy as installed at /etc/logrotate.d, not
// the copy with `su syslog syslog` that the capture above was read from, so the
// config path differs from that one; it has no `switching` line at all.
// AlmaLinux 9.8 (logrotate 3.18.0, a root:root tree, rsyslogd as root) printed no
// `switching` line for `su root root` either, and its output was otherwise the
// same as this one; the full AlmaLinux text was not kept, so the root-owned case
// below feeds this output and passes by C12's root-owned short-circuit, not by
// anything logrotate prints.
const logrotateDebugUbuntuBase = `warning: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode (-v) instead if this is not what you want.

reading config file /etc/logrotate.d/siem-incoming
Reading state from file: /var/lib/logrotate/status
state file /var/lib/logrotate/status does not exist
Allocating hash table for state file, size 64 entries

Handling 1 logs

rotating pattern: /var/log/siem/*/*.log  after 1 days (14 rotations)
empty log files are not rotated, old logs are removed
considering log /var/log/siem/i93-dev-deb/audit.log
Creating new state
  Now: 2026-11-17 07:12
  Last rotated at 2026-11-17 07:00
  log does not need rotating (log has already been rotated)
considering log /var/log/siem/i93-dev-deb/auth.log
Creating new state
  Now: 2026-11-17 07:12
  Last rotated at 2026-11-17 07:00
  log does not need rotating (log has already been rotated)
not running postrotate script, since no logs were rotated
`

// logrotateDebugUbuntuSuNoLogs is a third real capture from the Ubuntu 24.04.4
// VM (logrotate 3.21.0, rsyslog 8.2312.0), 2026-11-17: `LC_ALL=C logrotate -d
// /etc/logrotate.d/siem-incoming 2>&1` as root, rc=0, on the candidate policy
// (`su syslog syslog`, with `missingok`) with syslog.socket and rsyslog stopped
// and every *.log under the SIEM tree moved away (count 0). The pattern is still
// "considered" (and skipped as missing), so the switch is printed with no
// landing files at all, and C12 does not depend on C7/C8 having created any.
const logrotateDebugUbuntuSuNoLogs = `warning: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode (-v) instead if this is not what you want.

reading config file /etc/logrotate.d/siem-incoming
Reading state from file: /var/lib/logrotate/status
state file /var/lib/logrotate/status does not exist
Allocating hash table for state file, size 64 entries

Handling 1 logs

rotating pattern: /var/log/siem/*/*.log  after 1 days (14 rotations)
empty log files are not rotated, old logs are removed
switching euid from 0 to 102 and egid from 0 to 102 (pid 4250)
considering log /var/log/siem/*/*.log
  log /var/log/siem/*/*.log does not exist -- skipping
Creating new state
not running postrotate script, since no logs were rotated
switching euid from 102 to 0 and egid from 102 to 0 (pid 4250)
`

// TestRegression_LogServerC12ReadsTheEffectiveRotationIdentity runs C12's
// command against a fake logrotate that prints real captures (above), with and
// without the lines logrotate prints when the policy's `su` is in effect. The
// row has to pass only for the identity that owns the landing root, and fail
// for the policy as it was before `su` was rendered.
func TestRegression_LogServerC12ReadsTheEffectiveRotationIdentity(t *testing.T) {
	s, err := Parse("../../docs/verification/log-server.md")
	if err != nil {
		t.Fatal(err)
	}
	var command string
	for _, row := range s.Rows {
		if row.ID == "C12" {
			command = row.Command
		}
	}
	if command == "" {
		t.Fatal("missing C12")
	}

	dir := t.TempDir()
	landing := filepath.Join(dir, "siem")
	if err := os.MkdirAll(filepath.Join(landing, "host-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(dir, "10-siem-receiver.conf")
	policy := filepath.Join(dir, "siem-incoming")
	writeConf := func(root string) {
		t.Helper()
		body := `template(name="SiemAuditPath" type="string" string="` + root + `/%HOSTNAME%/audit.log")` + "\n"
		if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"/etc/rsyslog.d/10-siem-receiver.conf", "/etc/logrotate.d/siem-incoming"} {
		if strings.Count(command, p) != 1 {
			t.Fatalf("C12 must name %s exactly once, got %q", p, command)
		}
	}
	command = strings.ReplaceAll(command, "/etc/rsyslog.d/10-siem-receiver.conf", conf)
	command = strings.ReplaceAll(command, "/etc/logrotate.d/siem-incoming", policy)

	// Shims: logrotate prints $FAKE_OUT and records its arguments; stat answers
	// the uid/gid of the landing root with $FAKE_UID/$FAKE_GID, so the case does
	// not depend on who runs the test.
	shims := filepath.Join(dir, "bin")
	if err := os.MkdirAll(shims, 0o755); err != nil {
		t.Fatal(err)
	}
	args := filepath.Join(dir, "logrotate.args")
	writeShim := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(shims, name), []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeShim("logrotate", `printf '%s\n' "$@" > "$FAKE_ARGS"
printf '%s' "$FAKE_OUT"
exit "${FAKE_RC:-0}"
`)
	writeShim("stat", `case "$2" in
%u) echo "$FAKE_UID" ;;
%g) echo "$FAKE_GID" ;;
*) exit 1 ;;
esac
`)

	const uid, gid = "102", "102" // the syslog user and group on the captured Ubuntu 24.04 VM
	su := logrotateDebugUbuntuSu
	if !strings.Contains(su, logrotateSwitchTo) {
		t.Fatal("the switching line the variants replace is not in the capture")
	}
	// Variants of the real capture: only the first switching line changes.
	withTo := func(line string) string { return strings.Replace(su, logrotateSwitchTo, line, 1) }
	for _, tc := range []struct {
		name, uid, gid, out string
		rc                  string
		root                string // landing root written into the receiver config; "" = landing
		want                string
		logrotateRuns       bool
	}{
		{name: "su in effect (real Ubuntu 24.04 / logrotate 3.21.0 output)", uid: uid, gid: gid, out: su, want: "0", logrotateRuns: true},
		{name: "no landing files yet, logrotate 3.21 still reports the switch (real capture)", uid: uid, gid: gid, out: logrotateDebugUbuntuSuNoLogs, want: "0", logrotateRuns: true},
		{name: "su in effect, logrotate rc=1 for an unrelated diagnostic", uid: uid, gid: gid, out: su, rc: "1", want: "0", logrotateRuns: true},
		{name: "policy without su (real output for the policy before v2.1)", uid: uid, gid: gid, out: logrotateDebugUbuntuBase, want: "1", logrotateRuns: true},
		// The only switching line left is the switch back to root afterwards.
		{name: "only the switch back to root is printed", uid: uid, gid: gid, out: withTo(""), want: "1", logrotateRuns: true},
		{name: "su names another user", uid: uid, gid: gid, out: withTo("switching euid from 0 to 103 and egid from 0 to 102 (pid 3228)\n"), want: "1", logrotateRuns: true},
		{name: "su names another group", uid: uid, gid: gid, out: withTo("switching euid from 0 to 102 and egid from 0 to 103 (pid 3228)\n"), want: "1", logrotateRuns: true},
		// Without the trailing space after the gid, `to 102` would match the longer gid 1020.
		{name: "gid only a prefix of the switched gid", uid: uid, gid: gid, out: withTo("switching euid from 0 to 102 and egid from 0 to 1020 (pid 3228)\n"), want: "1", logrotateRuns: true},
		{name: "uid only a prefix of the switched uid", uid: uid, gid: gid, out: withTo("switching euid from 0 to 1020 and egid from 0 to 102 (pid 3228)\n"), want: "1", logrotateRuns: true},
		{name: "switch made from a non-root euid", uid: uid, gid: gid, out: withTo("switching euid from 1000 to 102 and egid from 1000 to 102 (pid 3228)\n"), want: "1", logrotateRuns: true},
		{name: "logrotate prints nothing", uid: uid, gid: gid, out: "", rc: "127", want: "1", logrotateRuns: true},
		// A root-owned landing root has no identity change to prove, and logrotate
		// prints no switching line for `su root root` (AlmaLinux 9.8 capture,
		// above): the row must pass without needing logrotate at all (EL, where
		// siem_log_owner is root). The root-owned tree is a stat shim here: a
		// test process that is not root cannot create one.
		{name: "root-owned landing root (EL: su root root prints no switching line)", uid: "0", gid: "0", out: logrotateDebugUbuntuBase, want: "0"},
		{name: "root-owned user, other group", uid: "0", gid: gid, out: logrotateDebugUbuntuBase, want: "1", logrotateRuns: true},
		{name: "landing root missing", uid: uid, gid: gid, out: su, root: filepath.Join(dir, "absent"), want: "1"},
		{name: "receiver config names no landing root", uid: uid, gid: gid, out: su, root: "-", want: "1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := landing
			switch tc.root {
			case "":
			case "-":
				root = ""
			default:
				root = tc.root
			}
			if root == "" {
				if err := os.WriteFile(conf, []byte("module(load=\"imtcp\")\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				writeConf(root)
			}
			_ = os.Remove(args)
			cmd := exec.Command("sh", "-c", command)
			cmd.Env = append(os.Environ(),
				"PATH="+shims+string(os.PathListSeparator)+os.Getenv("PATH"),
				"FAKE_OUT="+tc.out, "FAKE_RC="+tc.rc, "FAKE_ARGS="+args,
				"FAKE_UID="+tc.uid, "FAKE_GID="+tc.gid)
			out, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != tc.want {
				t.Fatalf("C12 = %q, %v; want %s", out, err, tc.want)
			}
			got, readErr := os.ReadFile(args)
			if tc.logrotateRuns {
				if readErr != nil || string(got) != "-d\n"+policy+"\n" {
					t.Fatalf("logrotate was run with %q (%v); want `-d %s`", got, readErr, policy)
				}
			} else if readErr == nil {
				t.Fatalf("logrotate ran (%q) but this case must not need it", got)
			}
		})
	}

	// The real stat on the real landing directory, with no stat shim: the
	// directory is owned by whoever runs the test, so the captured output is
	// rewritten to that identity. (A root test process owns it as 0:0, which
	// takes the root-owned short-circuit instead of this path.)
	t.Run("real stat of the real landing directory", func(t *testing.T) {
		if os.Getuid() == 0 || os.Getgid() == 0 {
			t.Skip("running as root or with gid 0: the landing directory is root-owned, which C12 passes without logrotate")
		}
		realShims := filepath.Join(dir, "bin-no-stat")
		if err := os.MkdirAll(realShims, 0o755); err != nil {
			t.Fatal(err)
		}
		shim, err := os.ReadFile(filepath.Join(shims, "logrotate"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(realShims, "logrotate"), shim, 0o755); err != nil {
			t.Fatal(err)
		}
		writeConf(landing)
		me := strings.NewReplacer("102", fmt.Sprint(os.Getuid())).Replace(logrotateDebugUbuntuSu)
		meGid := strings.NewReplacer("egid from 0 to 102", "egid from 0 to "+fmt.Sprint(os.Getgid())).Replace(me)
		for _, tc := range []struct{ name, out, want string }{
			{"su in effect", meGid, "0"},
			{"policy without su", logrotateDebugUbuntuBase, "1"},
		} {
			cmd := exec.Command("sh", "-c", command)
			cmd.Env = append(os.Environ(), "PATH="+realShims+string(os.PathListSeparator)+os.Getenv("PATH"),
				"FAKE_OUT="+tc.out, "FAKE_ARGS="+args)
			out, err := cmd.CombinedOutput()
			if err != nil || strings.TrimSpace(string(out)) != tc.want {
				t.Fatalf("%s: C12 = %q, %v; want %s", tc.name, out, err, tc.want)
			}
		}
	})
}

// TestRegression_LogServerSpec locks the structure of
// docs/verification/log-server.md (v1.2 — rsyslog central SIEM receiver,
// TCP only):
//
//	C1  rsyslog package installed
//	C2  rsyslog.service active
//	C3  receiver drop-in config file exists
//	C4  imtcp module + input present in the drop-in
//	C5  the imtcp port of the receiver config (siem_receiver_tcp_port) is
//	    listening — read from the config, not a fixed 514
//	C6  the landing root of the receiver config (SiemAuditPath, i.e.
//	    siem_log_root) exists — read from the config, not a fixed
//	    /var/log/siem
//	C7/C8 a local6/authpriv message unique to this run lands under that root
//	C9  logrotate policy file exists
//	C10 logrotate policy passes a dry-run
//	C11 the imtcp input is bound to its own dedicated ruleset, not the
//	    default ruleset (v1.3 — without this, a host that is both
//	    log-server and an audit-log-forwarding client forwards its own
//	    traffic to itself, and the received copy re-enters the default
//	    ruleset's forwarding rule and re-forwards itself forever; confirmed
//	    live 2026-08-07, minimal-poc round 20, filled a 77GB disk in under
//	    an hour)
//	C12 logrotate rotates the landing files as the owner of the landing root
//	    (v2.1 — the policy's `su`; read from `logrotate -d`, which prints the
//	    euid/egid switch it will make, rather than from the policy text)
//
// v1.0/v1.1 also had a UDP receiver (imudp) and its own C4/C6 rows; v1.2
// removed UDP entirely (nothing in this repo ever forwards over UDP — see
// the spec's own §1 note) rather than keep it conditional, so this test's
// row count/IDs reflect the smaller v1.2 checklist, not the historical one.
//
// Cross-row invariants locked below:
//
//   - C1/C2/C4/C5/C10 must use positive-logic rc (`; echo $?` or a
//     native rc), never a reverse-logic grep with a numeric expected —
//     the ad-hoc `host | CHANGED | rc=0 >>` wrapper corrupts the real rc
//     to 2 when the underlying pipeline's own exit code is non-zero on
//     the healthy path (see verification-spec-template.md trap 1).
//   - C5 must use the `sh -c '... && echo 0 || echo 1'` form so the
//     outer command always exits 0 regardless of match outcome.
//   - C6–C8 read the effective root from the receiver config's
//     SiemAuditPath template and never hard-code /var/log/siem (PR #79
//     made siem_log_root an effective inventory input; a non-default root
//     failed C6–C8 while an old fixed string left in /var/log/siem could
//     make C7/C8 pass).
//   - C7/C8 send a nonce unique to this run ($$ and date +%s%N), match only
//     that message (grep -qsF "$n") and report through
//     `sh -c '… echo 0 … echo 1'` with expected `0`, so a legitimate
//     "not routed yet" FAIL renders as a clean mismatch.
//   - No row may use `~active` (matches `inactive` as a substring).
func TestRegression_LogServerSpec(t *testing.T) {
	const specPath = "../../docs/verification/log-server.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
		switch strings.ToLower(exp[r.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// Positive-logic rc rows: rc-based numeric expected, never a bare
	// reverse-logic grep feeding a "1 means healthy" expected.
	for _, id := range []string{"C1", "C2", "C4", "C10", "C11", "C12"} {
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}

	// C11 must check the imtcp input is bound to the dedicated siemReceiver
	// ruleset, not left in the default ruleset (the self-forwarding loop
	// fix).
	if !strings.Contains(cmd["C11"], "ruleset=") || !strings.Contains(cmd["C11"], "siemReceiver") {
		t.Errorf("C11 must check the imtcp input is bound to ruleset=\"siemReceiver\", got %q", cmd["C11"])
	}

	// C5: sh -c '... && echo 0 || echo 1' so the outer command always
	// exits 0 (ansible never sees a FAILED-wrapper on the unhealthy path).
	if !strings.Contains(cmd["C5"], "&& echo 0") || !strings.Contains(cmd["C5"], "|| echo 1") {
		t.Errorf("C5 must use the `... && echo 0 || echo 1` form, got %q", cmd["C5"])
	}
	// C5 must check the port the receiver config names: siem_receiver_tcp_port
	// is an inventory input, and with 2514 the receiver listened and received
	// while `grep ":514"` failed.
	for _, want := range []string{"10-siem-receiver.conf", "imtcp", "sport = :$p"} {
		if !strings.Contains(cmd["C5"], want) {
			t.Errorf("C5 must contain %q, got %q", want, cmd["C5"])
		}
	}
	if strings.Contains(cmd["C5"], ":514") {
		t.Errorf("C5 must not hard-code port 514, got %q", cmd["C5"])
	}
	if exp["C5"] != "0" {
		t.Errorf("C5 expected must be rc-based `0`, got %q", exp["C5"])
	}

	// C6–C8 and C12 must read the root siem_log_root resolves to from the
	// receiver config; C7/C8 must count only this run's nonce message.
	for _, id := range []string{"C6", "C7", "C8", "C12"} {
		for _, want := range []string{"10-siem-receiver.conf", "SiemAuditPath", "sh -c '"} {
			if !strings.Contains(cmd[id], want) {
				t.Errorf("%s must contain %q, got %q", id, want, cmd[id])
			}
		}
		if strings.Contains(cmd[id], "/var/log/siem") {
			t.Errorf("%s must not hard-code /var/log/siem, got %q", id, cmd[id])
		}
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}
	for _, id := range []string{"C7", "C8"} {
		for _, want := range []string{"date +%s%N", `grep -qsF "$n"`, "logger -p"} {
			if !strings.Contains(cmd[id], want) {
				t.Errorf("%s must send and match a nonce unique to this run (%q), got %q", id, want, cmd[id])
			}
		}
		if strings.Contains(cmd[id], "grep -r ") || strings.Contains(cmd[id], "; true") {
			t.Errorf("%s must not match a fixed selftest string, got %q", id, cmd[id])
		}
	}

	// C12: sh -c '... && echo 0 || echo 1' (outer rc always 0), and the
	// effective identity comes from what logrotate itself says it will
	// switch to, for the policy file Step 4 renders.
	if !strings.Contains(cmd["C12"], "&& echo 0") || !strings.Contains(cmd["C12"], "|| echo 1") {
		t.Errorf("C12 must use the `... && echo 0 || echo 1` form, got %q", cmd["C12"])
	}
	for _, want := range []string{"logrotate -d /etc/logrotate.d/siem-incoming", "switching euid from 0 to"} {
		if !strings.Contains(cmd["C12"], want) {
			t.Errorf("C12 must contain %q, got %q", want, cmd["C12"])
		}
	}
	for _, r := range s.Rows {
		if r.ID == "C12" && !NeedsBecome(r) {
			t.Errorf("C12 must run as root (logrotate -d switches from euid 0): NeedsBecome(C12) = false")
		}
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}
}

// TestRegression_LogServerCoexistsWithWazuhManagerTCPOnly locks a real
// production incident fix (2026-08-06, two rounds):
//
//  1. The apply playbook used to unconditionally end_play this ENTIRE host
//     whenever ANY host in inventory had wazuh-manager, on the false
//     assumption that wazuh-manager's own 514/udp docker-compose port
//     mapping made it "a syslog collector" (git log: "avoid
//     double-deployed syslog collectors"). That port is never wired into
//     anything that parses local6/auth/authpriv content — confirmed via a
//     real incident where 6 client hosts forwarded to a wazuh-manager host
//     with no TCP/514 listener at all, and via wazuh-manager.md's own §5
//     note that the port is intentionally unused.
//  2. A first fix kept UDP conditional (disabled only when co-located with
//     wazuh-manager). Since nothing in this repo ever forwards over UDP,
//     that conditional was itself unnecessary complexity — v1.2 removed
//     UDP entirely instead, which incidentally also removes any possible
//     514/udp conflict with wazuh-manager's compose.
//
// log-server must run on every host assigned to it regardless of
// wazuh-manager's presence, and must never define a UDP receiver again.
func TestRegression_LogServerCoexistsWithWazuhManagerTCPOnly(t *testing.T) {
	playbookPath := "../../playbooks/apply/log-server-apply.yml"
	b, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	s := string(b)

	if strings.Contains(s, "Skip log-server if wazuh-manager is enabled") {
		t.Error("log-server-apply.yml must not skip this host just because a wazuh-manager host exists somewhere in inventory — that port is never actually wired into anything (see wazuh-manager.md §5)")
	}
	// Forbid the actual UDP receiver constructs, not mere mentions of the
	// words (the header comment legitimately explains this history by
	// name — see docs/verification/log-server.md v1.2 changelog).
	for _, forbidden := range []string{
		`when: groups['wazuh-manager'] | default([]) | length > 0`,
		`module(load="imudp")`,
		"siem_receiver_udp_enabled:",
		"siem_receiver_udp_port:",
	} {
		if strings.Contains(s, forbidden) {
			t.Errorf("log-server-apply.yml must not contain %q — UDP support was removed entirely (v1.2), not made conditional", forbidden)
		}
	}

	if !strings.Contains(s, `module(load="imtcp")`) {
		t.Fatal("rendered rsyslog config must always include module(load=\"imtcp\")")
	}
	if !strings.Contains(s, "siem_receiver_tcp_port") {
		t.Error(`log-server-apply.yml must still define siem_receiver_tcp_port`)
	}
}

// TestRegression_LogServerReceiverUsesDedicatedRuleset locks a real
// production incident fix (2026-08-07, minimal-poc round 20):
//
// This topology always co-locates log-server with an audit-log-forwarding
// client on the same host (the central SIEM host needs its own logs
// collected too). That host's audit-log-forwarding role forwards its own
// local6/auth/authpriv traffic to itself over TCP. Before this fix, the
// imtcp input had no dedicated ruleset, so a network-received message fell
// into rsyslog's default ruleset — the SAME ruleset that carries
// audit-log-forwarding-apply.yml's own forwarding rule — and got forwarded
// again, forever. Confirmed live: one host's auth.log reached 121M+ lines
// (13GB) and filled a 77GB disk to 100% in under an hour.
//
// The fix binds the imtcp input to its own ruleset so a received message is
// written to the dynaFile exactly once and never re-enters the forwarding
// rule.
func TestRegression_LogServerReceiverUsesDedicatedRuleset(t *testing.T) {
	playbookPath := "../../playbooks/apply/log-server-apply.yml"
	b, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	s := string(b)

	if !strings.Contains(s, `ruleset(name="siemReceiver")`) {
		t.Error(`log-server-apply.yml must define ruleset(name="siemReceiver") to isolate received messages from the default ruleset`)
	}
	if !strings.Contains(s, `input(type="imtcp" port="{{ siem_receiver_tcp_port }}" ruleset="siemReceiver"`) {
		t.Error(`log-server-apply.yml's imtcp input must bind ruleset="siemReceiver" — otherwise a host that is both log-server and an audit-log-forwarding client self-forwards in an infinite loop`)
	}
	// The dynaFile actions must live inside the dedicated ruleset, not
	// dangling in the default ruleset alongside the forwarding rule.
	rulesetIdx := strings.Index(s, `ruleset(name="siemReceiver")`)
	inputIdx := strings.Index(s, `input(type="imtcp"`)
	if rulesetIdx < 0 || inputIdx < 0 || rulesetIdx > inputIdx {
		t.Fatalf("ruleset(name=\"siemReceiver\") must be defined before the imtcp input that references it")
	}
	rulesetBlock := s[rulesetIdx:inputIdx]
	for _, action := range []string{`dynaFile="SiemAuditPath"`, `dynaFile="SiemAuthPath"`} {
		if !strings.Contains(rulesetBlock, action) {
			t.Errorf("siemReceiver ruleset block must contain %q, got block:\n%s", action, rulesetBlock)
		}
	}
}
