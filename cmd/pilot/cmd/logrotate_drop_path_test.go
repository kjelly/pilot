package cmd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// awkImpl is one awk the helper has to run on: Debian ships mawk, RHEL and
// Ubuntu desktops gawk, minimal images busybox. Every one that is installed
// here runs every case; the helper must not depend on one's extensions.
type awkImpl struct {
	name string
	argv []string
}

func dropPathAwks(t *testing.T) []awkImpl {
	t.Helper()
	var impls []awkImpl
	for _, c := range []awkImpl{
		{"awk", []string{"awk"}},
		{"gawk", []string{"gawk"}},
		{"mawk", []string{"mawk"}},
		{"busybox-awk", []string{"busybox", "awk"}},
	} {
		if _, err := exec.LookPath(c.argv[0]); err != nil {
			continue
		}
		if c.argv[0] == "busybox" {
			// A busybox build without the awk applet fails here, not in a case.
			if err := exec.Command("busybox", "awk", "BEGIN{}").Run(); err != nil {
				continue
			}
		}
		impls = append(impls, c)
	}
	if len(impls) == 0 {
		t.Skip("awk not installed")
	}
	return impls
}

func dropPathScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRootForTest(t), "playbooks", "apply", "files", "logrotate-drop-path.awk")
}

// runDropPath runs the helper and returns stdout, stderr and the exit code.
func runDropPath(t *testing.T, a awkImpl, drop, policy string) (stdout, stderr string, code int) {
	t.Helper()
	in := filepath.Join(t.TempDir(), "rsyslog")
	writeFile(t, in, policy)
	args := append(append([]string{}, a.argv[1:]...), "-v", "drop="+drop, "-f", dropPathScript(t), in)
	cmd := exec.Command(a.argv[0], args...)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("%s: %v", a.name, err)
		}
		code = ee.ExitCode()
	}
	return so.String(), se.String(), code
}

// The audit-log-forwarding playbook removes its own log path from the distro's
// /etc/logrotate.d/rsyslog with this helper. Ubuntu 22.04+ ships
// "/var/log/syslog" alone before its "{": removing only that line left a stanza
// with no filename, which logrotate rejects as a whole.
func TestLogrotateDropPathHelper(t *testing.T) {
	const lone = "/var/log/syslog\n{\n\trotate 7\n\tpostrotate\n\t\t}\n\tendscript\n}\n\n/var/log/mail.log\n/var/log/kern.log\n{\n\trotate 4\n}\n"
	const loneWant = "/var/log/mail.log\n/var/log/kern.log\n{\n\trotate 4\n}\n"
	const commentedEndscript = "/var/log/other\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript # rotate done\n}\n\n/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"
	const commentedEndscriptWant = "/var/log/other\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript # rotate done\n}\n\n/var/log/mail.log\n{\n\trotate 4\n}\n"

	for _, a := range dropPathAwks(t) {
		for _, tt := range []struct{ name, in, path, want string }{
			{"lone path takes its whole stanza, blank line included", lone, "/var/log/syslog", loneWant},
			{"a lone path on the same line as the brace too", "/var/log/syslog {\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log {\n\trotate 4\n}\n"},
			{"a shared path loses only its own line", "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log\n{\n\trotate 4\n}\n"},
			{"a shared path on the brace line keeps the brace", "/var/log/mail.log\n/var/log/syslog {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log\n{\n\trotate 4\n}\n"},
			{"space separated paths", "/var/log/syslog /var/log/mail.log {\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/mail.log {\n\trotate 4\n}\n"},
			{"a path that is not there changes nothing", lone, "/var/log/messages", lone},
			// logrotate takes the first word as the directive: "endscript # why" closes the
			// script. A matcher for the bare word only left in_script set, so every later
			// stanza was copied as script body and a shared /var/log/syslog stayed.
			{"endscript with a trailing comment closes the script", commentedEndscript, "/var/log/syslog", commentedEndscriptWant},
			{"a comment after postrotate still opens the script", "/var/log/other {\n\tpostrotate # reload\n\t\t}\n\tendscript\n}\n\n/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n", "/var/log/syslog", "/var/log/other {\n\tpostrotate # reload\n\t\t}\n\tendscript\n}\n\n/var/log/mail.log\n{\n\trotate 4\n}\n"},
		} {
			t.Run(a.name+"/"+tt.name, func(t *testing.T) {
				out, stderr, code := runDropPath(t, a, tt.path, tt.in)
				if code != 0 {
					t.Fatalf("awk exit %d\n%s%s", code, out, stderr)
				}
				if out != tt.want {
					t.Fatalf("got:\n%q\nwant:\n%q", out, tt.want)
				}
			})
		}
	}
}

// onlySyslogDropped is the policy with its "/var/log/syslog" path line gone.
func onlySyslogDropped(policy string) string {
	return strings.Replace(policy, "/var/log/syslog\n", "", 1)
}

// shared is the stanza every case below ends with: it holds /var/log/syslog
// with another path, so a helper that lost its place before it leaves the path
// behind and logrotate later finds it twice.
const sharedSyslogStanza = "\n/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"

// hookStanza is a stanza whose postrotate hook ends with term.
func hookStanza(opener, term string) string {
	return "/var/log/other {\n\trotate 7\n" + opener + "\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n" + term + "\n}\n"
}

// A policy the helper must rewrite by only removing the syslog path, and that
// real logrotate (3.19, 3.21 and 3.22 agree on all of these) accepts. warns marks
// the ones logrotate accepts with an "unknown option" diagnostic (it ignores that
// line; "error:" before 3.22, "warning:" in 3.22): they are valid, but the
// playbook's own validate would not let a file with them through, which is the
// same before and after this helper.
type acceptedPolicy struct {
	name, policy, want string
	warns              bool
}

func acceptedPolicies() []acceptedPolicy {
	var cs []acceptedPolicy
	// How logrotate (3.19 to 3.22) ends a script: "endscript" at the start of a line, after
	// blanks, with no ASCII letter right behind it. Found with `logrotate -d`.
	for _, term := range []struct {
		name, text string
		warns      bool
	}{
		{"endscript", "\tendscript", false},
		{"endscript without indent", "endscript", false},
		{"endscript, spaces and a tab", "  \tendscript", false},
		{"endscript then a tab", "\tendscript\t", false},
		{"endscript;", "\tendscript;", false},
		{"endscript; # comment", "\tendscript; # rotate done", false},
		{"endscript # comment", "\tendscript # rotate done", false},
		{"endscript;# comment", "\tendscript;# rotate done", false},
		{"endscript# (the # is the dropped character)", "\tendscript#", false},
		{"endscript then a digit", "\tendscript1", false},
		{"endscript.", "\tendscript.", false},
		{"endscript CR", "\tendscript\r", false},
		{"endscript x", "\tendscript x", true},
		{"endscript_x", "\tendscript_x", true},
	} {
		in := hookStanza("\tpostrotate", term.text) + sharedSyslogStanza
		cs = append(cs, acceptedPolicy{term.name + " closes the script", in, onlySyslogDropped(in), term.warns})
	}
	// The same for the other script keywords.
	for _, kw := range []string{"prerotate", "firstaction", "lastaction", "preremove"} {
		in := hookStanza("\t"+kw, "\tendscript;") + sharedSyslogStanza
		cs = append(cs, acceptedPolicy{kw + " opens a script too", in, onlySyslogDropped(in), false})
	}
	cs = append(cs, []acceptedPolicy{
		{name: "a comment or = after the keyword still opens the script",
			policy: "/var/log/other {\n\trotate 7\n\tpostrotate # c\n\t\ttrue\n\tendscript\n\tprerotate=\n\t\ttrue\n\tendscript;\n}\n" + sharedSyslogStanza},
		{name: "a script closed on the line of its keyword",
			policy: "/var/log/other {\n\trotate 7\n\tpostrotate endscript\n}\n" + sharedSyslogStanza},
		{name: "endscript then a new script on the same line",
			policy: "/var/log/other {\n\trotate 7\n\tpostrotate\n\t\ttrue\n\tendscript postrotate\n\t\tfalse\n\tendscript\n}\n" + sharedSyslogStanza},
		{name: "endscript then a blank takes the closing brace as a statement",
			policy: "/var/log/other {\n\trotate 7\n\tpostrotate\n\t\ttrue\n\tendscript }\n" + sharedSyslogStanza},
		{name: "a brace glued to endscript is the dropped character, not a closing brace",
			policy: "/var/log/other {\n\trotate 7\n\tpostrotate\n\t\ttrue\n\tendscript}\n}\n" + sharedSyslogStanza},
		{name: "endscript in the middle of a script line is script text",
			policy: hookStanza("\tpostrotate", "\tendscript;") + "\n/var/log/more {\n\tpostrotate\n\t\techo endscript\n\tendscript\n}\n" + sharedSyslogStanza},
		{name: "endscriptx and a brace line inside a script are script text",
			policy: "/var/log/other {\n\trotate 7\n\tpostrotate\n\t\tendscriptx\n\t}\n\tendscript;\n}\n" + sharedSyslogStanza},
		{name: "a global script outside any stanza",
			policy: "postrotate\n\ttrue\nendscript;\n" + sharedSyslogStanza},
		// Not script keywords: letters behind them make them other, unknown, options.
		{name: "postrotatex is not a script keyword", warns: true,
			policy: "/var/log/other {\n\trotate 7\n\tpostrotatex\n}\n" + sharedSyslogStanza},
		{name: "POSTROTATE is not a script keyword either", warns: true,
			policy: "/var/log/other {\n\trotate 7\n\tPOSTROTATE\n\t\ttrue\n\tENDSCRIPT\n}\n" + sharedSyslogStanza},
		// Quoted paths: the quotes are not part of the name.
		{name: "a double quoted lone path",
			policy: "\"/var/log/syslog\"\n{\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n",
			want:   "/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a single quoted shared path",
			policy: "/var/log/mail.log\n'/var/log/syslog'\n{\n\trotate 4\n}\n",
			want:   "/var/log/mail.log\n{\n\trotate 4\n}\n"},
		{name: "a quoted path on the brace line",
			policy: "\"/var/log/syslog\" {\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n",
			want:   "/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a quoted shared path keeps the other quoted one verbatim",
			policy: "\"/var/log/mail.log\" \"/var/log/syslog\" {\n\trotate 4\n}\n",
			want:   "\"/var/log/mail.log\" {\n\trotate 4\n}\n"},
		// Comments in the header: they are not paths.
		{name: "a comment line between a lone path and the brace",
			policy: "/var/log/syslog\n# kept by the vendor\n{\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n",
			want:   "/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a comment line between shared paths and the brace",
			policy: "/var/log/syslog\n/var/log/mail.log\n# note\n{\n\trotate 4\n}\n",
			want:   "/var/log/mail.log\n# note\n{\n\trotate 4\n}\n"},
		{name: "a comment after the brace of a lone path",
			policy: "/var/log/syslog { # vendor\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n",
			want:   "/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a comment after the brace of a shared path keeps the brace and the comment",
			policy: "/var/log/syslog /var/log/mail.log { # vendor\n\trotate 4\n}\n",
			want:   "/var/log/mail.log { # vendor\n\trotate 4\n}\n"},
		{name: "a comment glued to the brace",
			policy: "/var/log/syslog /var/log/mail.log {# vendor\n\trotate 4\n}\n",
			want:   "/var/log/mail.log {# vendor\n\trotate 4\n}\n"},
		{name: "a brace glued to the path",
			policy: "/var/log/mail.log /var/log/syslog{\n\trotate 4\n}\n",
			want:   "/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a script keyword behind the brace",
			policy: "/var/log/syslog /var/log/mail.log { postrotate\n\ttrue\n\tendscript\n}\n",
			want:   "/var/log/mail.log { postrotate\n\ttrue\n\tendscript\n}\n"},
		// A global option is not a path, between stanzas; between a path and its brace
		// logrotate reads it as one (its `daily` becomes a log named daily), so it counts.
		{name: "a global option before a lone path",
			policy: "compress\n/var/log/syslog\n{\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n",
			want:   "compress\n/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a global option between stanzas",
			policy: "/var/log/other {\n\trotate 3\n}\ncompress\n/var/log/syslog\n{\n\trotate 7\n}\n\n/var/log/mail.log {\n\trotate 4\n}\n",
			want:   "/var/log/other {\n\trotate 3\n}\ncompress\n/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "an indented path block",
			policy: "  /var/log/syslog\n  /var/log/mail.log\n  {\n\trotate 4\n  }\n",
			want:   "  /var/log/mail.log\n  {\n\trotate 4\n  }\n"},
		{name: "tab separated paths",
			policy: "/var/log/syslog\t/var/log/mail.log\t{\n\trotate 4\n}\n",
			want:   "/var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a carriage return after a path",
			policy: "/var/log/syslog\r\n/var/log/mail.log\r\n{\n\trotate 4\n}\n",
			want:   "/var/log/mail.log\r\n{\n\trotate 4\n}\n"},
	}...)
	// The path text in a place that is not a path declaration: a script body (a
	// heredoc), a directive's value, a comment. All of it is kept as written and
	// only the shared stanza's header loses the path.
	for _, body := range []struct{ name, kw, text string }{
		{"a tab-indented path line", "postrotate", "\t/var/log/syslog"},
		{"a space-indented path line", "postrotate", "  /var/log/syslog"},
		{"an unindented path line", "prerotate", "/var/log/syslog"},
		{"a double quoted path line", "lastaction", "\t\"/var/log/syslog\""},
		{"a single quoted path line", "firstaction", "\t'/var/log/syslog'"},
		{"a path and a brace", "preremove", "\t/var/log/syslog {"},
		{"the path among other words", "postrotate", "\t/var/log/syslog /var/log/mail.log"},
		{"a brace and the path", "postrotate", "\t{ /var/log/syslog"},
	} {
		in := "/var/log/other {\n\trotate 7\n\t" + body.kw + "\n" + body.text + "\n\tendscript\n}\n" + sharedSyslogStanza
		cs = append(cs, acceptedPolicy{name: "a script body with " + body.name + " is not a declaration", policy: in, want: withoutSharedSyslogPath(in)})
		// ... and the same stanza after the one that holds the path
		in = strings.TrimPrefix(sharedSyslogStanza, "\n") + "\n/var/log/other {\n\trotate 7\n\t" + body.kw + "\n" + body.text + "\n\tendscript\n}\n"
		cs = append(cs, acceptedPolicy{name: "a script body with " + body.name + " after the shared stanza", policy: in, want: strings.Replace(in, "/var/log/syslog\n/var/log/mail.log\n{", "/var/log/mail.log\n{", 1)})
	}
	for _, c := range []struct{ name, in, want string }{
		{name: "a global script body with the path", in: "postrotate\n\t/var/log/syslog\nendscript\n" + sharedSyslogStanza},
		{name: "a directive value that is the path", in: "/var/log/other {\n\trotate 7\n\tdateformat /var/log/syslog\n}\n" + sharedSyslogStanza},
		{name: "a comment that is the path", in: "/var/log/other {\n\trotate 7\n\t# /var/log/syslog\n\t#/var/log/syslog\n}\n# /var/log/syslog\n" + sharedSyslogStanza},
		{name: "a script closed on its keyword line, then the path text as a comment", in: "/var/log/other {\n\tpostrotate endscript\n\t# /var/log/syslog\n}\n" + sharedSyslogStanza},
		// logrotate reads a flag keyword and goes on with the rest of the line, so
		// "missingok }" closes the stanza; a helper that took the rest of the line
		// for the keyword's value would still be inside it at the next header.
		{name: "a flag keyword then a closing brace", in: "/var/log/other {\n\trotate 7\n\tmissingok }\n" + sharedSyslogStanza},
		{name: "a flag keyword, another flag, then a closing brace", in: "/var/log/other {\n\tcompress delaycompress # c\n\tmissingok daily }\n" + sharedSyslogStanza},
		{name: "a flag keyword then a script that closes the stanza", in: "/var/log/other {\n\tmissingok postrotate\n\t\ttrue\n\tendscript }\n" + sharedSyslogStanza},
		{name: "a flag glued to = then a closing brace", in: "/var/log/other {\n\tmissingok= }\n" + sharedSyslogStanza},
		// A directive that takes a value takes the whole rest of the line, brace included.
		{name: "a value keyword swallows a closing brace", in: "/var/log/other {\n\tdateformat -%Y }\n}\n" + sharedSyslogStanza},
		// Between stanzas a global flag may share the line with the next header.
		{name: "a global flag on the header line of another stanza", in: "compress /var/log/other {\n\trotate 7\n}\n" + sharedSyslogStanza},
		{name: "a global flag on the header line of the shared stanza", in: "/var/log/other {\n\trotate 7\n}\ncompress /var/log/syslog /var/log/mail.log {\n\trotate 4\n}\n",
			want: "/var/log/other {\n\trotate 7\n}\ncompress /var/log/mail.log {\n\trotate 4\n}\n"},
		{name: "a global flag on the header line of the lone stanza", in: "/var/log/other {\n\trotate 7\n}\ndaily compress /var/log/syslog {\n\trotate 4\n}\n/var/log/mail.log {\n}\n",
			// the stanza goes, the global flag stays
			want: "/var/log/other {\n\trotate 7\n}\ndaily compress\n/var/log/mail.log {\n}\n"},
		// A stanza the file never closes: logrotate accepts that at the end of the file.
		{name: "an unclosed last stanza", in: "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n"},
		{name: "an unclosed lone last stanza", in: "/var/log/other {\n}\n/var/log/syslog\n{\n\trotate 4\n", want: "/var/log/other {\n}\n"},
	} {
		want := c.want
		if want == "" && strings.HasSuffix(c.in, sharedSyslogStanza) {
			want = withoutSharedSyslogPath(c.in)
		}
		cs = append(cs, acceptedPolicy{name: c.name, policy: c.in, want: want})
	}
	cs = append(cs, acceptedPolicy{name: "a flag after an unknown option stays ignored", warns: true,
		policy: "/var/log/other {\n\tbogus }\n}\n" + sharedSyslogStanza,
		want:   withoutSharedSyslogPath("/var/log/other {\n\tbogus }\n}\n" + sharedSyslogStanza)})
	// Which paths are words of the header, and which bytes of the other words stay.
	// The quoting rules are popt's (logrotate hands the text between the start of the
	// header and its first "{" to poptParseArgvString): " and ' quote, a quoted part
	// may start inside a word, outside quotes a backslash makes the next character
	// literal, inside quotes it only protects the quote character itself.
	for _, c := range []struct{ name, header, want string }{
		{"another path with an escaped double quote", `/var/log/syslog "/var/log/mail\".log" {`, `"/var/log/mail\".log" {`},
		{"another path with an escaped double quote, before the managed one", `"/var/log/mail\".log" /var/log/syslog {`, `"/var/log/mail\".log" {`},
		{"another path with an escaped single quote", `/var/log/syslog '/var/log/m\'.log' {`, `'/var/log/m\'.log' {`},
		{"another path with an escaped backslash in double quotes", `"/var/log/b\\.log" /var/log/syslog {`, `"/var/log/b\\.log" {`},
		{"another path with a backslash that protects nothing in single quotes", `'/var/log/b\x.log' /var/log/syslog {`, `'/var/log/b\x.log' {`},
		{"another path with the other quote character inside", `/var/log/syslog '/var/log/s"p.log' "/var/log/t'p.log" {`, `'/var/log/s"p.log' "/var/log/t'p.log" {`},
		{"another path with an escaped blank", `/var/log/s\ p.log /var/log/syslog {`, `/var/log/s\ p.log {`},
		{"another path with an escaped quote outside quotes", `/var/log/syslog /var/log/e\".log {`, `/var/log/e\".log {`},
		{"another path with a quoted part inside the word", `/var/log/q"a b".log /var/log/syslog {`, `/var/log/q"a b".log {`},
		{"another path with an escaped backslash outside quotes", `/var/log/syslog /var/log/\\x.log {`, `/var/log/\\x.log {`},
		{"a brace in a comment line of the header", "/var/log/syslog\n# {\n/var/log/mail.log {", "# {\n/var/log/mail.log {"},
		{"tab separated paths", "/var/log/a.log\t/var/log/syslog\t/var/log/b.log\t{", "/var/log/a.log /var/log/b.log {"},
		{"several paths on one line", "/var/log/a.log /var/log/syslog /var/log/b.log /var/log/c.log {", "/var/log/a.log /var/log/b.log /var/log/c.log {"},
		{"paths over several lines", "/var/log/a.log\n  /var/log/syslog\n/var/log/b.log\n{", "/var/log/a.log\n/var/log/b.log\n{"},
		{"a blank line and a comment in the header", "/var/log/a.log\n\n# note\n/var/log/syslog\n{", "/var/log/a.log\n\n# note\n{"},
		{"a line continuation before another path", "/var/log/syslog /var/log/a.log\\\n/var/log/b.log {", "/var/log/a.log\\\n/var/log/b.log {"},
		{"a line continuation joining two other paths", "/var/log/a.log\\\n/var/log/b.log /var/log/syslog {", "/var/log/a.log\\\n/var/log/b.log {"},
		{"a quoted path that spans lines", "\"/var/log/ml\n/x.log\" /var/log/syslog {", "\"/var/log/ml\n/x.log\" {"},
		{"a quoted path that spans lines and holds a comment-looking line", "/var/log/syslog '/var/log/ml\n  # kept\n/y.log' /var/log/b.log {", "'/var/log/ml\n  # kept\n/y.log' /var/log/b.log {"},
		{"trailing words that are data, not a comment", "/var/log/syslog /var/log/a.log # c\n{", "/var/log/a.log # c\n{"},
		{"a comment after the brace", "/var/log/syslog /var/log/a.log { # vendor", "/var/log/a.log { # vendor"},
		{"the managed path spelled with quoted parts", `/var/log/sys"log" /var/log/a.log {`, `/var/log/a.log {`},
		{"the managed path spelled with empty quotes", `""/var/log/syslog'' /var/log/a.log {`, `/var/log/a.log {`},
		{"the managed path with an escaped letter", `/var/log/sys\log /var/log/a.log {`, `/var/log/a.log {`},
		{"an empty quoted word is no path", `/var/log/a.log "" /var/log/syslog {`, `/var/log/a.log "" {`},
		{"a quote still open at the brace is closed there", `/var/log/a.log "/var/log/syslog{`, `/var/log/a.log {`},
		{"a quote still open at the brace, in another path", `/var/log/syslog "/var/log/a.log{`, `"/var/log/a.log {`},
		{"a glob keeps working", "/var/log/syslog /var/log/g*.log {", "/var/log/g*.log {"},
		{"a tilde path", "/var/log/syslog ~/lr.log {", "~/lr.log {"},
		{"multibyte names", "/var/log/日本.log \"/var/log/é x.log\" /var/log/syslog {", "/var/log/日本.log \"/var/log/é x.log\" {"},
	} {
		cs = append(cs, acceptedPolicy{name: c.name, policy: c.header + "\n\trotate 4\n}\n", want: c.want + "\n\trotate 4\n}\n"})
	}
	for i := range cs {
		if cs[i].want == "" {
			cs[i].want = onlySyslogDropped(cs[i].policy)
		}
	}
	return cs
}

// withoutSharedSyslogPath is the policy with the path line of its trailing
// shared stanza gone (the same text may appear earlier, inside a script).
func withoutSharedSyslogPath(policy string) string {
	i := strings.LastIndex(policy, sharedSyslogStanza)
	return policy[:i] + strings.Replace(sharedSyslogStanza, "/var/log/syslog\n", "", 1) + policy[i+len(sharedSyslogStanza):]
}

// The helper must end a script where logrotate does and nowhere else, keep
// everything it did not have to touch byte for byte, and drop only the path.
func TestLogrotateDropPathFollowsLogrotateStanzaSyntax(t *testing.T) {
	for _, a := range dropPathAwks(t) {
		for _, tt := range acceptedPolicies() {
			t.Run(a.name+"/"+tt.name, func(t *testing.T) {
				out, stderr, code := runDropPath(t, a, "/var/log/syslog", tt.policy)
				if code != 0 {
					t.Fatalf("awk exit %d (a policy logrotate accepts must not fail the apply)\n%s%s", code, out, stderr)
				}
				if out != tt.want {
					t.Fatalf("got:\n%q\nwant:\n%q", out, tt.want)
				}
			})
		}
	}
}

// The policy as logrotate parses it: the logs it considers, the lines it
// ignored and its errors (unreadable logs, which do not exist here, are not
// parse errors).
type logrotateView struct {
	considered []string
	ignored    []string
	errors     []string
	raw        string
}

// logrotate says "unknown option 'x' -- ignoring line" when it meets a word it
// does not know, and carries on with the rest of the policy: it skips that one
// line and still reads, and uses, every stanza. Only the prefix depends on the
// version: logrotate 3.19 and 3.21 (Ubuntu 22.04, 24.04) print "error:", 3.22
// prints "warning:". So the message is classified by its text, never by its
// prefix: it is not a rejection of the policy under either.
var logrotateIgnoredLine = regexp.MustCompile(`^(?:error|warning): \S+:\d+ unknown option .* -- ignoring line$`)

// A log that does not exist on the machine running the test; not a parse error.
var logrotateUnreadableLog = regexp.MustCompile(`(?s)^error: stat of .* failed: `)

type logrotateLineKind int

const (
	logrotateLineOther   logrotateLineKind = iota // not a diagnostic that matters here
	logrotateLineIgnored                          // a line logrotate skipped; the policy still parses
	logrotateLineError                            // the policy is rejected (or the run is aborted)
)

// classifyLogrotateLine decides what one line of `logrotate -d` output means,
// the same way for every logrotate version. Any "error:" that is not one of the
// two known harmless messages rejects the policy: "lines must begin with a
// keyword or a filename", "duplicate log entry", "unexpected }", "unexpected
// text", "without endscript", "found error in file" and whatever else a version
// prints. A "warning:" other than the ignored-line one is not an error.
func classifyLogrotateLine(l string) logrotateLineKind {
	switch {
	case logrotateIgnoredLine.MatchString(l):
		return logrotateLineIgnored
	case logrotateUnreadableLog.MatchString(l):
		return logrotateLineOther
	case strings.HasPrefix(l, "error: "):
		return logrotateLineError
	}
	return logrotateLineOther
}

// The wording below was captured from logrotate 3.19.0 and 3.21.0 (Ubuntu 22.04,
// 24.04: "error:") and 3.22.0 (the local one: "warning:").
func TestClassifyLogrotateLine(t *testing.T) {
	for _, tt := range []struct {
		line string
		want logrotateLineKind
	}{
		// Skipped lines, whichever prefix the version uses.
		{"error: rsyslog:5 unknown option 'x' -- ignoring line", logrotateLineIgnored},
		{"warning: rsyslog:5 unknown option 'x' -- ignoring line", logrotateLineIgnored},
		{"error: rsyslog:3 unknown option 'postrotatex' -- ignoring line", logrotateLineIgnored},
		{"error: rsyslog:4 unknown option 'true' -- ignoring line", logrotateLineIgnored},
		{"error: r:2 unknown option 'endscript' -- ignoring line", logrotateLineIgnored},
		// Unreadable logs are an artefact of the test, not of the policy.
		{"error: stat of /var/log/other failed: No such file or directory", logrotateLineOther},
		// Every other error rejects the policy.
		{"error: r:1 lines must begin with a keyword or a filename (possibly in double quotes)", logrotateLineError},
		{"error: found error in file r, skipping", logrotateLineError},
		{"error: r:3 duplicate log entry for /var/log/a", logrotateLineError},
		{"error: r:prerotate, postrotate or preremove without endscript", logrotateLineError},
		{"error: r:4 unexpected }", logrotateLineError},
		{"error: r:7 unexpected text", logrotateLineError},
		{"error: r:9 missing end of script", logrotateLineError},
		{"error: something no version has printed yet", logrotateLineError},
		// Close to the ignored message but not it: still rejected.
		{"error: r:3 unknown option 'x'", logrotateLineError},
		{"error: r:3 unknown option 'x' -- ignoring line, and then some", logrotateLineError},
		{"error: unknown option 'x' -- ignoring line", logrotateLineError},
		{"error: bad stat of /x", logrotateLineError},
		// Warnings other than the ignored line are not errors.
		{"warning: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode (-v) instead if this is not what you want.", logrotateLineOther},
		{"WARNING: logrotate in debug mode does nothing except printing debug messages!  Consider using verbose mode (-v) instead if this is not what you want.", logrotateLineOther},
		{"warning: r:3 duplicate log entry for /var/log/a", logrotateLineOther},
		{"considering log /var/log/syslog", logrotateLineOther},
		{"", logrotateLineOther},
	} {
		if got := classifyLogrotateLine(tt.line); got != tt.want {
			t.Errorf("classifyLogrotateLine(%q) = %d, want %d", tt.line, got, tt.want)
		}
	}
}

// A log name may hold a newline (a quoted word that spans lines), and logrotate
// prints it raw: "error: stat of /var/log/a" and "b failed: ..." are then two
// output lines for one harmless message. Join them before classifying.
func joinSplitStatErrors(lines []string) []string {
	var out []string
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if strings.HasPrefix(l, "error: stat of ") && !strings.Contains(l, " failed: ") {
			for j := i + 1; j < len(lines) && j <= i+4; j++ {
				if strings.HasPrefix(lines[j], "error: ") || strings.HasPrefix(lines[j], "warning: ") {
					break
				}
				l += "\n" + lines[j]
				if strings.Contains(lines[j], " failed: ") {
					i = j
					break
				}
			}
		}
		out = append(out, l)
	}
	return out
}

func parseWithLogrotate(t *testing.T, logrotate string, files map[string]string) logrotateView {
	t.Helper()
	dir := t.TempDir()
	confd := filepath.Join(dir, "logrotate.d")
	if err := os.Mkdir(confd, 0o755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "logrotate.conf")
	writeFile(t, main, "include "+confd+"\n")
	paths := []string{main}
	for name, body := range files {
		p := filepath.Join(confd, name)
		writeFile(t, p, body)
		paths = append(paths, p)
	}
	for _, p := range paths {
		if err := os.Chmod(p, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := exec.Command(logrotate, "-d", "-s", filepath.Join(dir, "state"), main).CombinedOutput()
	v := logrotateView{raw: string(raw)}
	for _, l := range strings.Split(v.raw, "\n") {
		if p, ok := strings.CutPrefix(l, "considering log "); ok {
			v.considered = append(v.considered, p)
		}
	}
	for _, l := range joinSplitStatErrors(strings.Split(v.raw, "\n")) {
		l = strings.TrimRight(l, "\r")
		switch classifyLogrotateLine(l) {
		case logrotateLineIgnored:
			v.ignored = append(v.ignored, l)
		case logrotateLineError:
			v.errors = append(v.errors, l)
		}
	}
	sort.Strings(v.considered)
	return v
}

const managedSyslogStanza = "/var/log/syslog {\n\tdaily\n\trotate 4\n\tmissingok\n}\n"

// The rewrite must not leave the path declared: the playbook renders its own
// /etc/logrotate.d/syslog for it, and logrotate aborts the whole run with
// "duplicate log entry" when two files declare one path, which the copy's
// validate (it parses only the one file) never sees.
func TestLogrotateDropPathLeavesNoDuplicateWithTheManagedStanza(t *testing.T) {
	logrotate, err := exec.LookPath("logrotate")
	if err != nil {
		t.Skip("logrotate not installed")
	}
	awks := dropPathAwks(t)

	for _, tt := range []struct{ name, policy string }{
		{"Ubuntu 24.04, syslog alone in its stanza", "/var/log/syslog\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript\n}\n\n/var/log/mail.log\n/var/log/kern.log\n{\n\trotate 4\n}\n"},
		{"syslog shared with other paths", "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"},
		{"a commented endscript before the shared stanza", "/var/log/other\n{\n\trotate 7\n\tpostrotate\n\t\t/usr/lib/rsyslog/rsyslog-rotate\n\tendscript # rotate done\n}\n\n/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"},
	} {
		for _, a := range awks {
			t.Run(a.name+"/"+tt.name, func(t *testing.T) {
				rewritten, stderr, code := runDropPath(t, a, "/var/log/syslog", tt.policy)
				if code != 0 {
					t.Fatalf("awk exit %d\n%s%s", code, rewritten, stderr)
				}
				v := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": rewritten, "syslog": managedSyslogStanza})
				if strings.Contains(v.raw, "duplicate log entry") {
					t.Fatalf("logrotate sees /var/log/syslog twice:\n%s\nrewritten policy:\n%s", v.raw, rewritten)
				}
			})
		}
	}
}

// The tests above only know what the helper does. This one asks logrotate: for
// every policy that logrotate itself accepts, the logs it considers after
// "rewritten policy + the managed /etc/logrotate.d/syslog" are exactly the logs
// it considered before, with no parse error and no duplicate. That is what the
// terminator, keyword and quoting rules in the helper are written to mirror.
func TestLogrotateDropPathAgreesWithRealLogrotate(t *testing.T) {
	logrotate, err := exec.LookPath("logrotate")
	if err != nil {
		t.Skip("logrotate not installed")
	}
	awks := dropPathAwks(t)

	for _, tt := range acceptedPolicies() {
		t.Run(tt.name, func(t *testing.T) {
			before := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": tt.policy})
			if len(before.errors) > 0 {
				t.Fatalf("the test policy is not one logrotate accepts: %v\n%s", before.errors, before.raw)
			}
			if tt.warns != (len(before.ignored) > 0) {
				t.Fatalf("warns=%v but logrotate ignored %v:\n%s", tt.warns, before.ignored, before.raw)
			}
			seen := 0
			for _, c := range before.considered {
				if strings.HasSuffix(c, "/var/log/syslog") {
					seen++
				}
			}
			if seen != 1 {
				t.Fatalf("logrotate does not see /var/log/syslog exactly once in the test policy (%d): %v\n%s", seen, before.considered, before.raw)
			}
			for _, a := range awks {
				rewritten, stderr, code := runDropPath(t, a, "/var/log/syslog", tt.policy)
				if code != 0 {
					t.Fatalf("%s: awk exit %d\n%s%s", a.name, code, rewritten, stderr)
				}
				after := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": rewritten, "syslog": managedSyslogStanza})
				if strings.Contains(after.raw, "duplicate log entry") || len(after.errors) > 0 {
					t.Fatalf("%s: logrotate rejects the rewritten policy: %v\n%s\nrewritten:\n%q", a.name, after.errors, after.raw, rewritten)
				}
				if strings.Join(after.considered, "\n") != strings.Join(before.considered, "\n") {
					t.Fatalf("%s: logrotate considers %v after the rewrite, %v before\nrewritten:\n%q", a.name, after.considered, before.considered, rewritten)
				}
			}
		})
	}
}

// The helper reads only header words. A script line, a directive value or a
// comment that holds the path is not a declaration: logrotate accepts the policy,
// the helper must not fail on it and must not touch the text.
func TestLogrotateDropPathKeepsScriptTextThatLooksLikeTheHeader(t *testing.T) {
	// The managed stanza is the one that follows; the lines above are script text.
	const (
		shared     = "/var/log/syslog\n/var/log/mail.log\n{\n\trotate 4\n}\n"
		sharedWant = "/var/log/mail.log\n{\n\trotate 4\n}\n"
		heredoc    = "/var/log/other {\n\trotate 7\n\tpostrotate\n\t/var/log/syslog\n\t\"/var/log/syslog\"\n\t'/var/log/syslog' /var/log/mail.log\n\t}\n\t/var/log/zzz {\n\tendscript # done\n}\n"
	)
	logrotate, _ := exec.LookPath("logrotate")
	for _, a := range dropPathAwks(t) {
		t.Run(a.name, func(t *testing.T) {
			in := heredoc + "\n" + shared
			out, stderr, code := runDropPath(t, a, "/var/log/syslog", in)
			if code != 0 {
				t.Fatalf("exit %d on a policy logrotate accepts\n%s%s", code, out, stderr)
			}
			if want := heredoc + "\n" + sharedWant; out != want {
				t.Fatalf("got:\n%q\nwant:\n%q", out, want)
			}
			if logrotate == "" {
				return
			}
			before := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": in})
			after := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": out, "syslog": managedSyslogStanza})
			if len(before.errors) > 0 || len(after.errors) > 0 || strings.Contains(after.raw, "duplicate log entry") {
				t.Fatalf("errors before %v, after %v:\n%s", before.errors, after.errors, after.raw)
			}
			if strings.Join(before.considered, "\n") != strings.Join(after.considered, "\n") {
				t.Fatalf("considered %v before, %v after", before.considered, after.considered)
			}
		})
	}
}

// logrotate versions disagree on the blanks at the very end of the header text
// (3.22 strips them, 3.19 and 3.21 keep them). For `"/var/log/syslog {` 3.19 and
// 3.21 consider the log "/var/log/syslog " (blank included) and 3.22 considers
// "/var/log/syslog" (or rejects a blank that is escaped right before the brace): the
// rewrite that is right for one drops another file on the
// other, so the helper refuses. (Captured on logrotate 3.19.0, 3.21.0, 3.22.0.)
func TestLogrotateDropPathRefusesAPathThatTheLogrotateVersionDecides(t *testing.T) {
	for _, in := range []string{
		"/var/log/other {\n}\n\"/var/log/syslog {\n}\n",
		"/var/log/other {\n}\n/var/log/a.log '/var/log/syslog \n{\n}\n",
		"/var/log/other {\n}\n/var/log/syslog\\ {\n}\n",
	} {
		for _, a := range dropPathAwks(t) {
			t.Run(a.name+"/"+strings.ReplaceAll(in, "\n", "|"), func(t *testing.T) {
				out, stderr, code := runDropPath(t, a, "/var/log/syslog", in)
				if code != 3 || !strings.Contains(stderr, "versions disagree") {
					t.Fatalf("exit %d, want 3 \"versions disagree\"\nstdout:\n%s\nstderr:\n%s", code, out, stderr)
				}
			})
		}
	}
}

// What logrotate rejects is not rewritten silently: a path-looking statement in
// a stanza body ("unexpected log filename", so a stanza this helper believes is
// open is really closed or the file is broken), a header with no "{" and one
// with an unbalanced quote. If the path is in it, the helper fails instead of
// writing a policy that keeps the path.
func TestLogrotateDropPathFailsOnPoliciesLogrotateRejects(t *testing.T) {
	logrotate, _ := exec.LookPath("logrotate")
	for _, tt := range []struct{ name, in, logrotateSays string }{
		{"a path line in a stanza body", "/var/log/other\n{\n\trotate 7\n\t/var/log/syslog\n}\n", "unexpected log filename"},
		{"a quoted path line in a stanza body", "/var/log/other\n{\n\trotate 7\n\t\"/var/log/syslog\"\n}\n", "unexpected log filename"},
		{"a path after a flag keyword in a stanza body", "/var/log/other\n{\n\tmissingok /var/log/syslog\n}\n", "unexpected log filename"},
		{"a header with no brace", "/var/log/other {\n}\n/var/log/syslog\n/var/log/mail.log\n", "missing '{'"},
		{"a header with a backslash before the brace", "/var/log/other {\n}\n/var/log/syslog\\{\n}\n", "error parsing filename"},
	} {
		for _, a := range dropPathAwks(t) {
			t.Run(a.name+"/"+tt.name, func(t *testing.T) {
				if logrotate != "" {
					v := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": tt.in})
					if !strings.Contains(v.raw, tt.logrotateSays) {
						t.Fatalf("logrotate does not say %q about this policy:\n%s", tt.logrotateSays, v.raw)
					}
				}
				out, stderr, code := runDropPath(t, a, "/var/log/syslog", tt.in)
				if code != 3 || !strings.Contains(stderr, "still declared") {
					t.Fatalf("exit %d, want 3 \"still declared\"\nstdout:\n%s\nstderr:\n%s", code, out, stderr)
				}
			})
		}
	}
}

// Words that only look like the end of a script. logrotate does not end the
// script there (it reports a script that never ends), so a helper that did
// would see the later shared stanza as a stanza, drop its path and write a
// policy that is not the original one. It has to leave the text alone and fail.
func TestLogrotateDropPathDoesNotEndAScriptOnLookalikes(t *testing.T) {
	logrotate, _ := exec.LookPath("logrotate")
	for _, term := range []string{"endscriptx", "endscriptX", "ENDSCRIPT", "Endscript", "end script", "endscrip"} {
		in := hookStanza("\tpostrotate", "\t"+term) + sharedSyslogStanza
		for _, a := range dropPathAwks(t) {
			t.Run(a.name+"/"+term, func(t *testing.T) {
				if logrotate != "" {
					v := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": in})
					if !strings.Contains(v.raw, "without endscript") {
						t.Fatalf("logrotate would accept %q as an end of script:\n%s", term, v.raw)
					}
				}
				out, stderr, code := runDropPath(t, a, "/var/log/syslog", in)
				if code != 3 || !strings.Contains(stderr, "script never ends") {
					t.Fatalf("exit %d, want 3 \"script never ends\"\nstdout:\n%s\nstderr:\n%s", code, out, stderr)
				}
			})
		}
	}
}
