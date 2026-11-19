package spec

import (
	"bytes"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// The receiver builds a file path from %HOSTNAME%, a value the sending host
// chooses. Without a property option rsyslog uses it as is: a HOSTNAME of
// ".." wrote /var/log/audit.log (and, for auth, the log server's own
// /var/log/auth.log), "a/../../x" walked out of the root, and "." or an
// empty name wrote into the root itself (kjelly/pilot#363, measured on Ubuntu
// 24.04.4 / rsyslog 8.2312.0). These tests pin the fix from three sides: the
// path templates themselves, every reader of the template text, and the real
// rsyslogd.

// TestRegression_LogServerPathTemplatesNeutraliseTheHostname pins the exact
// spelling of the three path templates. The repo-wide rule is
// TestRegression_RsyslogDynaFilePathsAreSecpathReplaced; this names the three
// templates and their leaves, so a template that stops being a dynaFile
// template (and so leaves the lint's reach) is still noticed.
func TestRegression_LogServerPathTemplatesNeutraliseTheHostname(t *testing.T) {
	for name, leaf := range map[string]string{
		"SiemAuditPath": "audit.log",
		"SiemAuthPath":  "auth.log",
		"SiemWazuhPath": "wazuh-alerts.log",
	} {
		got := siemReceiverTemplate(t, name, "/srv/siem")
		want := `template(name="` + name + `" type="string" string="/srv/siem/%HOSTNAME:::secpath-replace%/` + leaf + `")`
		if got != want {
			t.Errorf("%s = %s\nwant    %s", name, got, want)
		}
	}
}

// siemRootReaderRows are the spec rows that read the landing root out of the
// SiemAuditPath line with sed. They must keep reading one spelling of that
// line: AGENTS.md §5.7 (the same fact in more than one place).
var siemRootReaderRows = []struct{ spec, id string }{
	{"log-server.md", "C6"}, {"log-server.md", "C7"}, {"log-server.md", "C8"},
	{"log-server.md", "C12"}, {"log-server.md", "C13"}, {"log-shipping.md", "C3"},
}

var siemRootSed = regexp.MustCompile(`s#\.\*\\"SiemAuditPath\\".*?#\\1#p`)

// TestRegression_SiemRootReadersAgree: the five log-server rows and
// log-shipping C3 each carry the same sed, and that sed reads the root out of
// the line log-server-apply.yml renders (and out of the line it rendered
// before #363). With the old sed, which only knew `%HOSTNAME%`, the rendered
// line gives no root, and C6-C8, C12 and C3 all FAIL on a healthy host.
func TestRegression_SiemRootReadersAgree(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("sed"); err != nil {
		t.Skip(err)
	}
	seds := map[string][]string{}
	for _, r := range siemRootReaderRows {
		s, err := Parse("../../docs/verification/" + r.spec)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, row := range s.Rows {
			if row.ID != r.id {
				continue
			}
			found = true
			m := siemRootSed.FindAllString(row.Command, -1)
			if len(m) != 1 {
				t.Fatalf("%s %s must read the root with exactly one sed over SiemAuditPath, found %d in %q", r.spec, r.id, len(m), row.Command)
			}
			seds[m[0]] = append(seds[m[0]], r.spec+" "+r.id)
		}
		if !found {
			t.Fatalf("%s has no row %s", r.spec, r.id)
		}
	}
	if len(seds) != 1 {
		t.Fatalf("the rows read the landing root with %d different seds, want one:\n%v", len(seds), seds)
	}
	var expr string
	for e := range seds {
		expr = e
	}

	dir := t.TempDir()
	conf := filepath.Join(dir, "receiver.conf")
	read := func(body string) string {
		t.Helper()
		if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("sh", "-c", `sed -n "`+expr+`" "$1"`, "sed", conf).CombinedOutput()
		if err != nil {
			t.Fatalf("sed: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}
	line := func(root, host string) string {
		return `template(name="SiemAuditPath" type="string" string="` + root + `/` + host + `/audit.log")` + "\n"
	}
	for _, tc := range []struct{ name, body, want string }{
		{"the line the playbook renders now", siemReceiverTemplate(t, "SiemAuditPath", "/srv/siem") + "\n", "/srv/siem"},
		{"the line before #363", line("/srv/siem", "%HOSTNAME%"), "/srv/siem"},
		{"default root", siemReceiverTemplate(t, "SiemAuditPath", "/var/log/siem") + "\n", "/var/log/siem"},
		{"root with dots and dashes", siemReceiverTemplate(t, "SiemAuditPath", "/srv/a.b-c/siem_1") + "\n", "/srv/a.b-c/siem_1"},
		{"another property in the host position", line("/srv/siem", "%FROMHOST%"), ""},
		{"no host component", `template(name="SiemAuditPath" type="string" string="/srv/siem/audit.log")` + "\n", ""},
		{"another leaf", `template(name="SiemAuditPath" type="string" string="/srv/siem/%HOSTNAME:::secpath-replace%/auth.log")` + "\n", ""},
		{"another template name", `template(name="SiemAuthPath" type="string" string="/srv/siem/%HOSTNAME:::secpath-replace%/audit.log")` + "\n", ""},
	} {
		if got := read(tc.body); got != tc.want {
			t.Errorf("%s: sed read %q, want %q", tc.name, got, tc.want)
		}
	}
}

// hostnameFrame is one message sent to the receiver's TCP port.
type hostnameFrame struct {
	name  string
	frame string
	// match says whether a landed line is this frame's.
	match func(line string) bool
	leaf  string
	// want is the directory the message must land in below the root once the
	// hostname is neutralised; "" accepts any single directory (an RFC 3164
	// message with a tag has its hostname re-derived by rsyslog).
	want string
	// oldLandsInside is true for the frames the receiver already kept one
	// level below the root before #363: they are the legitimate sources.
	oldLandsInside bool
}

// siemHostnameFrames builds the frames. The tag makes every landed line this
// run's; messages that carry no text (a bare RFC 3164 frame has nothing after
// the hostname) are told apart by their timestamp and by lacking the app name.
func siemHostnameFrames(tag string) []hostnameFrame {
	const app = "pilot-t363"
	// The terminator keeps one nonce from being a prefix of another
	// (5424-dot, 5424-dotdot).
	nonce := func(name string) string { return tag + "-" + name + "-END" }
	rfc5424 := func(name, pri, host, leaf, want string, oldLandsInside bool) hostnameFrame {
		n := nonce(name)
		return hostnameFrame{name: name, frame: fmt.Sprintf("<%s>1 - %s %s - - - %s\n", pri, host, app, n),
			match: func(line string) bool { return strings.Contains(line, n) }, leaf: leaf, want: want, oldLandsInside: oldLandsInside}
	}
	// A bare RFC 3164 frame: nothing but a timestamp and the hostname.
	bare := func(name, clock, host, want string) hostnameFrame {
		return hostnameFrame{name: name, frame: fmt.Sprintf("<182>Jan  2 %s %s\n", clock, host),
			match: func(line string) bool { return strings.Contains(line, clock) && !strings.Contains(line, app) },
			leaf:  "audit.log", want: want}
	}
	const local6, authpriv = "182", "86"
	return []hostnameFrame{
		// The measured escapes.
		rfc5424("5424-dotdot", local6, "..", "audit.log", "_.", false),
		rfc5424("5424-dotdot-auth", authpriv, "..", "auth.log", "_.", false),
		rfc5424("5424-dot", local6, ".", "audit.log", "_", false),
		rfc5424("5424-empty", local6, "", "audit.log", "_", false),
		rfc5424("5424-traverse", local6, "a/../../x", "audit.log", "a_.._.._x", false),
		rfc5424("5424-up-two", local6, "../../log/sa363-escape", "audit.log", ".._.._log_sa363-escape", false),
		rfc5424("5424-nested", local6, "a/b", "audit.log", "a_b", false),
		rfc5424("5424-double-slash", local6, "a//b", "audit.log", "a__b", false),
		bare("3164-bare-dotdot", "03:07:11", "..", "_."),
		bare("3164-bare-dot", "03:07:12", ".", "_"),
		// Legitimate sources: the same directory before and after.
		rfc5424("5424-fqdn", local6, "host1.example.com", "audit.log", "host1.example.com", true),
		rfc5424("5424-upper", local6, "HOST2.EXAMPLE.COM", "audit.log", "HOST2.EXAMPLE.COM", true),
		rfc5424("5424-nil", local6, "-", "audit.log", "-", true),
		{name: "3164-tag-dotdot", frame: fmt.Sprintf("<182>Jan  2 03:07:13 .. %s: %s\n", app, nonce("3164-tag")),
			match: func(line string) bool { return strings.Contains(line, nonce("3164-tag")) }, leaf: "audit.log", oldLandsInside: true},
	}
}

// siemReceiverHarness is a real rsyslogd running one receiver config under
// the current user, with the landing root nested deep enough that every
// path the frames can reach stays inside base.
type siemReceiverHarness struct {
	base, root, conf string
	port             int
}

// startSiemReceiver renders the production Step 3 through Ansible, lets
// mutate change the rendered text, and starts a real rsyslogd on it. start is
// false for a receiver that is only configured, not running.
func startSiemReceiver(t *testing.T, mutate func(h *siemReceiverHarness, text string) string, start bool) *siemReceiverHarness {
	t.Helper()
	base := t.TempDir()
	h := &siemReceiverHarness{base: base, root: filepath.Join(base, "jail", "m", "siem")}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.port = ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	if err := os.MkdirAll(h.root, 0o755); err != nil {
		t.Fatal(err)
	}
	ctl := filepath.Join(base, "ctl")
	if err := os.MkdirAll(ctl, 0o755); err != nil {
		t.Fatal(err)
	}

	task := findNamedTask(t, loadFirstPlay(t, "log-server-apply.yml"), logServerReceiverTask)
	args := task["ansible.builtin.copy"].(map[string]any)
	rendered := filepath.Join(ctl, "rendered.conf")
	args["dest"] = rendered
	for _, k := range []string{"owner", "group", "backup"} {
		delete(args, k)
	}
	vars := map[string]any{"siem_receiver_relp_enabled": false, "siem_receiver_tcp_port": h.port, "siem_log_root": h.root}
	body, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "gather_facts": false, "vars": vars, "tasks": []any{task}}})
	if err != nil {
		t.Fatal(err)
	}
	play := filepath.Join(ctl, "render.yml")
	if err := os.WriteFile(play, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(ctl, "ansible.cfg")
	if err := os.WriteFile(cfg, []byte("[defaults]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", play)
	cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+cfg, "ANSIBLE_LOCAL_TEMP="+ctl)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render the production receiver config: %v\n%s", err, out)
	}
	text, err := os.ReadFile(rendered)
	if err != nil {
		t.Fatal(err)
	}
	h.conf = filepath.Join(ctl, "receiver.conf")
	if err := os.WriteFile(h.conf, []byte(mutate(h, string(text))), 0o600); err != nil {
		t.Fatal(err)
	}
	if !start {
		return h
	}

	// A private byte-identical copy of the daemon avoids the host's
	// path-attached AppArmor profile, as the Wazuh native harness does.
	bin, err := exec.LookPath("rsyslogd")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	daemon := filepath.Join(ctl, "rsyslogd")
	if err := os.WriteFile(daemon, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(daemon, "-N1", "-f", h.conf).CombinedOutput(); err != nil {
		t.Fatalf("rsyslogd -N1 rejects the receiver config: %v\n%s", err, out)
	}
	logFile, err := os.Create(filepath.Join(ctl, "rsyslogd.stderr"))
	if err != nil {
		t.Fatal(err)
	}
	d := exec.Command(daemon, "-n", "-i", filepath.Join(ctl, "rsyslogd.pid"), "-f", h.conf)
	d.Stdout, d.Stderr = logFile, logFile
	if err := d.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() { _ = d.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = d.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			_ = d.Process.Kill()
			<-exited
		}
		_ = logFile.Close()
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h.port), time.Second)
		if err == nil {
			_ = c.Close()
			return h
		}
		select {
		case <-exited:
			stderr, _ := os.ReadFile(logFile.Name())
			t.Fatalf("rsyslogd exited before listening:\n%s", stderr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("rsyslogd never listened on port %d", h.port)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// send writes each frame on its own TCP connection.
func (h *siemReceiverHarness) send(t *testing.T, frames []hostnameFrame) {
	t.Helper()
	for _, f := range frames {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", h.port), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte(f.frame)); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
}

// landed maps every frame to the file (relative to the landing root; "../.."
// when it is outside) that holds its line, for the files anywhere under base
// except the control directory.
func (h *siemReceiverHarness) landed(t *testing.T, frames []hostnameFrame) (map[string]string, []string) {
	t.Helper()
	got := map[string]string{}
	var files []string
	err := filepath.WalkDir(h.base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == filepath.Join(h.base, "ctl") {
				return filepath.SkipDir
			}
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(h.root, path)
		if err != nil {
			return err
		}
		files = append(files, rel)
		for _, line := range bytes.Split(raw, []byte("\n")) {
			for _, f := range frames {
				if _, done := got[f.name]; !done && f.match(string(line)) {
					got[f.name] = rel
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return got, files
}

// waitLanded polls until every frame has landed somewhere.
func (h *siemReceiverHarness) waitLanded(t *testing.T, frames []hostnameFrame) (map[string]string, []string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, files := h.landed(t, frames)
		var missing []string
		for _, f := range frames {
			if _, ok := got[f.name]; !ok {
				missing = append(missing, f.name)
			}
		}
		if len(missing) == 0 {
			return got, files
		}
		if time.Now().After(deadline) {
			t.Fatalf("frames never landed anywhere under %s: %v\nfiles: %v", h.base, missing, files)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// logLanding writes where each frame landed to the test log, relative to the
// landing root.
func logLanding(t *testing.T, frames []hostnameFrame, got map[string]string) {
	t.Helper()
	var b strings.Builder
	for _, f := range frames {
		fmt.Fprintf(&b, "\n  %-18s -> %s", f.name, got[f.name])
	}
	t.Logf("landed (relative to the landing root):%s", b.String())
}

// oneDirBelow reports whether rel is <one directory>/<leaf> and returns the
// directory.
func oneDirBelow(rel, leaf string) (string, bool) {
	dir, file := filepath.Split(rel)
	dir = strings.TrimSuffix(dir, string(filepath.Separator))
	if file != leaf || dir == "" || strings.Contains(dir, string(filepath.Separator)) || dir == ".." {
		return "", false
	}
	return dir, true
}

// c13Command returns log-server.md's C13 pointed at conf.
func c13Command(t *testing.T, conf string) string {
	t.Helper()
	s, err := Parse("../../docs/verification/log-server.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range s.Rows {
		if r.ID == "C13" {
			if strings.Count(r.Command, "/etc/rsyslog.d/10-siem-receiver.conf") != 1 {
				t.Fatalf("C13 must name the receiver config exactly once: %q", r.Command)
			}
			return strings.ReplaceAll(r.Command, "/etc/rsyslog.d/10-siem-receiver.conf", conf)
		}
	}
	t.Fatal("missing C13")
	return ""
}

// runC13 runs C13 the way pilot verify does (the command through sh).
func runC13(t *testing.T, conf string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", c13Command(t, conf)).CombinedOutput()
	if err != nil {
		t.Fatalf("C13 exited non-zero (a row must print its own verdict): %v\n%s", err, out)
	}
	return strings.TrimSpace(string(out))
}

func requireSiemReceiverTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"ansible-playbook", "rsyslogd", "bash", "sed", "grep", "readlink", "date"} {
		if _, err := exec.LookPath(tool); err != nil {
			// The runner image has them (TestRegression_WazuhNativeImfileDeliveryAndRotation
			// runs the same daemon there); a CI job that stopped providing one must fail,
			// not skip the only real-daemon check of the receiver's file paths.
			if os.Getenv("GITHUB_ACTIONS") == "true" {
				t.Fatalf("%s is required on the CI runner: %v", tool, err)
			}
			t.Skipf("%s not installed: %v", tool, err)
		}
	}
}

// TestRegression_LogServerReceiverKeepsHostnamePathsUnderTheRoot sends the
// frames that wrote outside the landing root before #363 to a real rsyslogd
// running the production receiver config (Step 3 rendered by Ansible), and
// reads where each line landed from the file system: every one must be
// <root>/<one directory>/<leaf>, the legitimate names must keep their own
// directory, and nothing may appear above the root. The same frames against the
// pre-#363 spelling of the templates must escape, per frame, which is what
// proves the oracle can see the defect.
func TestRegression_LogServerReceiverKeepsHostnamePathsUnderTheRoot(t *testing.T) {
	requireSiemReceiverTools(t)

	t.Run("production template", func(t *testing.T) {
		t.Parallel()
		h := startSiemReceiver(t, func(_ *siemReceiverHarness, text string) string { return text }, true)
		frames := siemHostnameFrames(fmt.Sprintf("PILOT-T363-%d", time.Now().UnixNano()))
		h.send(t, frames)
		got, files := h.waitLanded(t, frames)
		logLanding(t, frames, got)
		for _, f := range frames {
			rel := got[f.name]
			dir, ok := oneDirBelow(rel, f.leaf)
			if !ok {
				t.Errorf("%s landed in %q; want <root>/<one directory>/%s\nfiles: %v", f.name, rel, f.leaf, files)
				continue
			}
			if f.want != "" && dir != f.want {
				t.Errorf("%s landed in directory %q; want %q", f.name, dir, f.want)
			}
		}
		for _, rel := range files {
			if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Errorf("a file appeared outside the landing root: %s\nfiles: %v", rel, files)
			}
		}
		// C13 on the same running receiver.
		if got := runC13(t, h.conf); got != "0" {
			t.Errorf("C13 on the production receiver = %q, want 0", got)
		}
	})

	t.Run("pre-#363 template escapes (oracle control)", func(t *testing.T) {
		t.Parallel()
		h := startSiemReceiver(t, func(_ *siemReceiverHarness, text string) string {
			if n := strings.Count(text, "%HOSTNAME:::secpath-replace%"); n != 3 {
				t.Fatalf("the rendered receiver has %d secpath-replace hostnames, want its 3 path templates", n)
			}
			return strings.ReplaceAll(text, "%HOSTNAME:::secpath-replace%", "%HOSTNAME%")
		}, true)
		frames := siemHostnameFrames(fmt.Sprintf("PILOT-T363-%d", time.Now().UnixNano()))
		h.send(t, frames)
		got, files := h.waitLanded(t, frames)
		logLanding(t, frames, got)
		for _, f := range frames {
			rel := got[f.name]
			_, inside := oneDirBelow(rel, f.leaf)
			if f.oldLandsInside && !inside {
				t.Errorf("%s is a legitimate source and must land one directory below the root even without the option, got %q", f.name, rel)
			}
			if !f.oldLandsInside {
				if inside {
					t.Errorf("%s landed in %q under the pre-#363 template: this frame no longer reproduces #363, so it proves nothing", f.name, rel)
				}
			}
		}
		for _, name := range []string{"5424-dotdot", "5424-dotdot-auth", "5424-traverse", "5424-up-two", "3164-bare-dotdot"} {
			if rel := got[name]; !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				t.Errorf("%s must leave the landing root under the old template, landed in %q\nfiles: %v", name, rel, files)
			}
		}
		if got := runC13(t, h.conf); got != "1" {
			t.Errorf("C13 on the pre-#363 receiver = %q, want 1 (the .. line lands above the root)", got)
		}
	})

	// C13 has to see the message arrive one level below the root: a receiver
	// that wrote nothing at all would pass a check that only looks for files
	// outside the root.
	t.Run("C13 needs the line to arrive", func(t *testing.T) {
		t.Parallel()
		h := startSiemReceiver(t, func(h *siemReceiverHarness, text string) string {
			const action = `action(type="omfile" dynaFile="SiemAuditPath" createDirs="on")`
			if strings.Count(text, action) != 1 {
				t.Fatalf("the rendered receiver must hold %q once", action)
			}
			return strings.Replace(text, action, `action(type="omfile" file="`+filepath.Join(h.base, "ctl", "discard.log")+`")`, 1)
		}, true)
		if got := runC13(t, h.conf); got != "1" {
			t.Errorf("C13 on a receiver that writes nothing under the root = %q, want 1", got)
		}
		if _, err := os.Stat(filepath.Join(h.base, "ctl", "discard.log")); err != nil {
			t.Errorf("the receiver never got the C13 frame, so this case tested nothing: %v", err)
		}
	})

	t.Run("C13 with rsyslog stopped", func(t *testing.T) {
		t.Parallel()
		h := startSiemReceiver(t, func(_ *siemReceiverHarness, text string) string { return text }, false)
		if got := runC13(t, h.conf); got != "1" {
			t.Errorf("C13 with nothing listening = %q, want 1", got)
		}
	})
}
