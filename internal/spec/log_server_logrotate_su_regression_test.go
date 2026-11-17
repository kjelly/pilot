package spec

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// log-server's logrotate policy rotates siem_log_root/*/*.log. logrotate
// expands that glob as root and then renames, creates, compresses and deletes
// by full path; it refuses a symlinked or hard-linked log file, but nothing
// stops a symlinked directory component, and on Ubuntu the per-host directories
// belong to the rsyslog user (rsyslogd creates them after dropping privileges).
// That user could replace <root>/<host> with a symlink and root's daily run
// then acted inside the target. Ubuntu's global `su root adm` in
// /etc/logrotate.conf does not close this (and turns off logrotate's own
// insecure-parent check), so the policy has to state its own `su`.
//
// The identity has to be the owner and group of the tree rsyslog writes, which
// Step 2 sets to siem_log_owner:siem_log_owner: from logrotate 3.19 a rotation
// that is not running as root no longer fchown()s what it creates.
// postrotate scripts still run as root, so the HUP is unchanged.

var (
	// A `su <user> <group>` line; an operand is a bare word or a {{ }} expression.
	logrotateSuLine = regexp.MustCompile(`^su\s+(\{\{[^}]*\}\}|\S+)\s+(\{\{[^}]*\}\}|\S+)$`)

	logrotateScriptStart = map[string]bool{"postrotate": true, "prerotate": true, "firstaction": true, "lastaction": true, "preremove": true}
)

// logrotateStanza is what a single-stanza policy says outside its script blocks.
type logrotateStanza struct {
	directives []string            // trimmed, comment lines and script bodies removed
	scripts    map[string][]string // script keyword -> its body lines
}

// parseSingleStanzaPolicy reads a policy with exactly one `<paths> {` ... `}`
// stanza. Script bodies (postrotate ... endscript and the like) are kept apart
// from the directives, so a `su` inside a script is not a directive.
func parseSingleStanzaPolicy(content string) (logrotateStanza, error) {
	st := logrotateStanza{scripts: map[string][]string{}}
	stanzas, inStanza, script := 0, false, ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if script != "" {
			if line == "endscript" {
				script = ""
				continue
			}
			st.scripts[script] = append(st.scripts[script], line)
			continue
		}
		if !inStanza {
			if strings.HasSuffix(line, "{") {
				inStanza = true
				stanzas++
			}
			continue
		}
		if line == "}" {
			inStanza = false
			continue
		}
		if kw := strings.Fields(line)[0]; logrotateScriptStart[kw] {
			script = kw
			continue
		}
		st.directives = append(st.directives, line)
	}
	if script != "" {
		return st, fmt.Errorf("script block %q has no endscript", script)
	}
	if stanzas != 1 {
		return st, fmt.Errorf("want exactly one stanza, found %d", stanzas)
	}
	return st, nil
}

// suDirectives returns the operands of every `su` directive of the stanza, or
// an error for a `su` line that is not `su <user> <group>`.
func (s logrotateStanza) suDirectives() ([][2]string, error) {
	var out [][2]string
	for _, d := range s.directives {
		if f := strings.Fields(d); len(f) == 0 || f[0] != "su" {
			continue
		}
		m := logrotateSuLine.FindStringSubmatch(d)
		if m == nil {
			return nil, fmt.Errorf("%q is not `su <user> <group>`", d)
		}
		out = append(out, [2]string{m[1], m[2]})
	}
	return out, nil
}

func squashSpaces(s string) string { return strings.Join(strings.Fields(s), "") }

func TestLogrotateStanzaParsingForTheSuCheck(t *testing.T) {
	const policy = `# su from a comment is not a directive
/var/log/x/*.log {
    daily
    # su comment root root
    sharedscripts
    postrotate
        su www-data -c 'kill -HUP 1'
    endscript
}
`
	st, err := parseSingleStanzaPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if su, err := st.suDirectives(); err != nil || len(su) != 0 {
		t.Fatalf("su in a script block or a comment counted as a directive: %v, %v", su, err)
	}
	if got := st.scripts["postrotate"]; len(got) != 1 || !strings.Contains(got[0], "kill -HUP") {
		t.Fatalf("postrotate body = %q", got)
	}

	st, err = parseSingleStanzaPolicy(strings.Replace(policy, "    sharedscripts\n", "    su {{ siem_log_owner }} {{ siem_log_owner }}\n    sharedscripts\n", 1))
	if err != nil {
		t.Fatal(err)
	}
	su, err := st.suDirectives()
	if err != nil || len(su) != 1 || squashSpaces(su[0][0]) != "{{siem_log_owner}}" || squashSpaces(su[0][1]) != "{{siem_log_owner}}" {
		t.Fatalf("su = %v, %v", su, err)
	}

	for name, bad := range map[string]string{
		"one operand":     "/x/*.log {\n    su syslog\n}\n",
		"three operands":  "/x/*.log {\n    su a b c\n}\n",
		"no stanza":       "su syslog syslog\n",
		"unclosed script": "/x/*.log {\n    postrotate\n        true\n}\n",
	} {
		st, err := parseSingleStanzaPolicy(bad)
		if err == nil {
			_, err = st.suDirectives()
		}
		if err == nil {
			t.Errorf("%s: accepted %q", name, bad)
		}
	}
}

// logServerStep4 returns the siem-incoming policy task and the Step 2 task that
// creates the landing root.
func logServerStep4(t *testing.T) (step2, step4 map[string]any) {
	t.Helper()
	doc := loadYAML(t, "../../playbooks/apply/log-server-apply.yml")
	return findNamedTask(t, doc, "Step 2: Ensure {{ siem_log_root }} exists"),
		findNamedTask(t, doc, "Step 4: Render /etc/logrotate.d/siem-incoming")
}

func taskModuleArgs(t *testing.T, task map[string]any, module string) map[string]any {
	t.Helper()
	for _, key := range []string{"ansible.builtin." + module, module} {
		if args, ok := task[key].(map[string]any); ok {
			return args
		}
	}
	t.Fatalf("task %v has no %s arguments", task["name"], module)
	return nil
}

// TestRegression_LogServerPolicyRotatesAsTheLandingOwner: Step 4's stanza has
// exactly one `su`, it names the owner and group Step 2 gives the landing root,
// and the postrotate HUP that has to run as root is still there.
func TestRegression_LogServerPolicyRotatesAsTheLandingOwner(t *testing.T) {
	step2, step4 := logServerStep4(t)

	dir := taskModuleArgs(t, step2, "file")
	owner, _ := dir["owner"].(string)
	group, _ := dir["group"].(string)
	if owner == "" || group == "" {
		t.Fatalf("Step 2 must set the landing root's owner and group, got owner=%q group=%q", owner, group)
	}

	content, _ := taskModuleArgs(t, step4, "copy")["content"].(string)
	st, err := parseSingleStanzaPolicy(content)
	if err != nil {
		t.Fatalf("Step 4 policy: %v", err)
	}
	su, err := st.suDirectives()
	if err != nil {
		t.Fatalf("Step 4 policy: %v", err)
	}
	if len(su) != 1 {
		t.Fatalf("Step 4's stanza must have exactly one `su <user> <group>` line (logrotate would otherwise rotate as root through directories the rsyslog user owns), found %d in:\n%s", len(su), content)
	}
	if squashSpaces(su[0][0]) != squashSpaces(owner) || squashSpaces(su[0][1]) != squashSpaces(group) {
		t.Errorf("Step 4 rotates as `su %s %s` but Step 2 makes the landing root %s:%s; rsyslog writes that tree, and logrotate 3.19+ does not fchown when it is not root", su[0][0], su[0][1], owner, group)
	}

	hup := false
	for _, l := range st.scripts["postrotate"] {
		if strings.Contains(l, "systemctl kill -s HUP rsyslog.service") {
			hup = true
		}
	}
	if !hup {
		t.Errorf("Step 4's postrotate must still HUP rsyslog (it runs as root whatever `su` says); postrotate = %q", st.scripts["postrotate"])
	}
}

// TestRegression_LogServerPolicyIsRotatedAsItsSuByRealLogrotate renders Step 4's
// policy and gives it to the real logrotate in debug mode. logrotate prints the
// euid/egid switch it makes for the policy's `su` before it handles the log
// set, so the line is the effective state of the rendered file rather than a
// reading of its text. The user is a system account that is not the user
// running the test, so the switch is a real one (it fails with EPERM when the
// test is not root, which debug mode reports after the line; the line is what
// is asserted). A policy written by the test itself first proves that this
// logrotate reports a switch at all; when it does not, the test skips instead
// of passing.
func TestRegression_LogServerPolicyIsRotatedAsItsSuByRealLogrotate(t *testing.T) {
	if _, err := exec.LookPath("logrotate"); err != nil {
		t.Skipf("logrotate not installed: %v", err)
	}
	u, err := user.Lookup("daemon")
	if err != nil {
		t.Skipf("no daemon account to switch to: %v", err)
	}
	if u.Uid == fmt.Sprint(os.Getuid()) {
		t.Skip("running as the daemon account: switching to it is not a switch")
	}
	g, err := user.LookupGroup("daemon")
	if err != nil {
		t.Skipf("no daemon group to switch to: %v", err)
	}

	dir := t.TempDir()
	root := filepath.Join(dir, "siem")
	if err := os.MkdirAll(filepath.Join(root, "host-a"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "host-a", "audit.log"), []byte("a record\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, step4 := logServerStep4(t)
	content, _ := taskModuleArgs(t, step4, "copy")["content"].(string)
	vars := map[string]string{
		"siem_log_root":         root,
		"siem_logrotate_rotate": "14",
		"siem_logrotate_maxage": "90",
		"siem_log_owner":        "daemon",
	}
	var unknown []string
	rendered := regexp.MustCompile(`\{\{\s*(\w+)\s*\}\}`).ReplaceAllStringFunc(content, func(m string) string {
		name := regexp.MustCompile(`\w+`).FindString(m)
		v, ok := vars[name]
		if !ok {
			unknown = append(unknown, name)
		}
		return v
	})
	if len(unknown) > 0 {
		t.Fatalf("Step 4's policy reads %v, which this test does not render", unknown)
	}

	debug := func(policy string) string {
		t.Helper()
		path := filepath.Join(dir, "policy")
		if err := os.WriteFile(path, []byte(policy), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("logrotate", "-d", "-s", filepath.Join(dir, "state"), path)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, _ := cmd.CombinedOutput() // rc and EPERM text vary with who runs the test
		return string(out)
	}
	switched := regexp.MustCompile(fmt.Sprintf(`switching euid from \d+ to %s and egid from \d+ to %s `, u.Uid, g.Gid))

	probe := fmt.Sprintf("%s/*/*.log {\n    daily\n    rotate 1\n    su daemon daemon\n}\n", root)
	if out := debug(probe); !switched.MatchString(out) {
		t.Skipf("this logrotate does not report a `su` switch in debug mode:\n%s", out)
	}

	if out := debug(rendered); !switched.MatchString(out) {
		t.Errorf("logrotate does not switch to the su identity for the policy Step 4 renders; it would rotate as root:\n%s\n--- policy:\n%s", out, rendered)
	}
}
