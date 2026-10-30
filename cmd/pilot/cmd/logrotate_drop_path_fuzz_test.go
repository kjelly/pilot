package cmd

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A differential test: random logrotate policies, built from the syntax that
// real policies and the logrotate manual use (and the odd corners found while
// reading logrotate's config.c), each holding /var/log/syslog exactly once in
// some spelling. logrotate itself is the judge. For every policy it accepts:
//
//   - the helper must not fail,
//   - "rewritten policy + the managed /etc/logrotate.d/syslog" must make
//     logrotate consider exactly the logs it considered before, with no error
//     and no duplicate,
//   - every other path word and every script/body line must still be in the
//     output byte for byte (a rewrite may only remove the managed path word).
//
// The seed is fixed so a failure reproduces; PILOT_LOGROTATE_FUZZ_N (cases) and
// PILOT_LOGROTATE_FUZZ_SEED widen the search, PILOT_LOGROTATE_FUZZ_DUMP=<dir>
// writes every accepted policy and its rewrite for a run against other
// logrotate versions; PILOT_LOGROTATE_FUZZ_WHY=1 logs why a generated policy was
// not used.

type lrFuzz struct {
	r        *rand.Rand
	counter  int
	keep     []string // text that must survive the rewrite untouched
	managed  string
	inScript bool
}

func (g *lrFuzz) pick(opts ...string) string { return opts[g.r.Intn(len(opts))] }
func (g *lrFuzz) chance(pct int) bool        { return g.r.Intn(100) < pct }

// Spellings of /var/log/syslog that logrotate (popt) reads as that one name.
var fuzzManagedWords = []string{
	`/var/log/syslog`,
	`"/var/log/syslog"`,
	`'/var/log/syslog'`,
	`/var/log/sys"log"`,
	`/var/log/"sys"'log'`,
	`/var/log/sys\log`,
	`"/var/log/sys"log`,
	`/var/log/syslog""`,
	`""/var/log/syslog`,
	`"/var/log/syslog"''`,
	`/var/log/"syslog"`,
}

// Other log paths: every word is unique, so a duplicate is the helper's doing.
var fuzzOtherWords = []string{
	"/var/log/p%d.log",
	"\"/var/log/p%d.log\"",
	"'/var/log/p%d.log'",
	"\"/var/log/m\\\"%d.log\"", // escaped double quote inside double quotes
	"'/var/log/m\\'%d.log'",    // escaped single quote inside single quotes
	"\"/var/log/b\\\\%d.log\"", // \\ inside quotes stays two backslashes
	"'/var/log/b\\\\%d.log'",
	"\"/var/log/x\\y%d.log\"", // \y inside quotes keeps the backslash
	"\"/var/log/sp %d.log\"",
	"'/var/log/s\"p%d.log'",
	"\"/var/log/s'p%d.log\"",
	"/var/log/e\\\"%d.log", // an escaped quote outside quotes
	"/var/log/s\\ p%d.log", // an escaped blank
	"/var/log/q\"%d\".log",
	"/var/log/q'%d'.log",
	"/var/log/\"a b\"%d.log",
	"\"/var/log/h#%d\"",
	"/var/log/h#%d",
	"/var/log/syslog.%d",
	"/var/log/syslog%d",
	"\"/var/log/syslog\\\"%d\"",
	"/var/log/\\\\%d.log", // an escaped backslash outside quotes
	"\"/var/log/e\\\"\\\"%d.log\"",
	"\"\"'/var/log/e%d.log'\"\"",
	"/var/log/\u65e5\u672c%d.log", // multibyte: awks count bytes or characters
	"\"/var/log/\u00e9 %d.log\"",
	"/var/log/g%d*.log", // a glob with no match is the pattern itself
	"/var/log/g[a]%d.log",
	"~/lr%d.log",
	"\"/var/log/ml%d\n/x.log\"", // a quoted word may span lines
	"'/var/log/ml%d\n  # not a comment\n/y.log'",
}

func (g *lrFuzz) other() string {
	g.counter++
	w := fmt.Sprintf(g.pick(fuzzOtherWords...), g.counter)
	g.keep = append(g.keep, w)
	return w
}

// A header: path words, the brace, and what follows the brace. closes tells the
// caller the tail closed the stanza.
func (g *lrFuzz) header(prefix string, withManaged bool) (text string, closes, opensScript bool) {
	n := 1 + g.r.Intn(4)
	var words []string
	for i := 0; i < n; i++ {
		words = append(words, g.other())
	}
	managedAt := -1
	if withManaged {
		w := g.pick(fuzzManagedWords...)
		managedAt = g.r.Intn(len(words) + 1)
		words = append(words[:managedAt], append([]string{w}, words[managedAt:]...)...)
	}
	var b strings.Builder
	b.WriteString(prefix)
	for i, w := range words {
		if i > 0 {
			switch g.r.Intn(12) {
			case 0, 1, 2, 3, 4: // newline, as the distro files write them
				b.WriteString("\n" + g.pick("", "", "  ", "\t"))
			case 5:
				b.WriteString("\n# note " + strconv.Itoa(g.counter) + "\n")
			case 6:
				b.WriteString("\n\n")
			case 8:
				// a backslash before the newline makes the newline part of one word;
				// next to the managed path that would hide it from logrotate (and,
				// as the name holds a newline, from this test's reading of its output)
				if i == managedAt || i-1 == managedAt {
					b.WriteString("\n")
				} else {
					b.WriteString("\\\n")
				}
			case 7:
				// vertical tab and form feed are blanks to popt, not to logrotate's own parser
				b.WriteString(g.pick("\v", "\f", " \v ", "\r "))
			default:
				b.WriteString(g.pick(" ", " ", "\t", "  ", " \t "))
			}
		}
		b.WriteString(w)
	}
	switch g.r.Intn(8) {
	case 0:
		b.WriteString("\n{")
	case 1:
		b.WriteString("\n  {")
	case 2:
		b.WriteString("{")
	case 3:
		b.WriteString("\t{")
	default:
		b.WriteString(" {")
	}
	switch g.r.Intn(10) {
	case 0:
		b.WriteString(" # vendor")
	case 1:
		b.WriteString("# glued")
	case 2:
		b.WriteString(" missingok }")
		closes = true
	case 3:
		b.WriteString(" }")
		closes = true
	case 4:
		b.WriteString(" compress rotate 5")
	case 5:
		b.WriteString(g.pick(" postrotate", " prerotate # c", " postrotate echo hi"))
		opensScript = true
	}
	return b.String(), closes, opensScript
}

// The text of a script body line; many of them look like something else.
func (g *lrFuzz) scriptLine() string {
	g.counter++
	l := g.pick(
		"\t\t/usr/lib/rsyslog/rsyslog-rotate",
		"\t/var/log/syslog",
		"\t\"/var/log/syslog\"",
		"  /var/log/syslog",
		"/var/log/syslog",
		"\t'/var/log/syslog'",
		"\t/var/log/syslog {",
		"\t/var/log/syslog /var/log/mail.log",
		"\techo endscript",
		"\tendscriptx",
		"\t}",
		"\t{",
		"\t/var/log/zzz"+strconv.Itoa(g.counter)+" {",
		"",
		"   ",
		"\t# comment",
		"\tENDSCRIPT",
		"\tendscrip",
		"x endscript",
		"\tif true; then",
		"\t\ttrue",
		"\tfi",
		"\tpostrotate",
		"\trotate 4",
		"\tmissingok }",
		"{ /var/log/syslog }",
	)
	if strings.TrimSpace(l) != "" && g.chance(70) {
		// A unique tail makes the line recognisable in the output.
		l += " # s" + strconv.Itoa(g.counter)
		g.keep = append(g.keep, l)
	}
	return l
}

var fuzzScriptKeywords = []string{"prerotate", "postrotate", "firstaction", "lastaction", "preremove"}

// script writes a script: keyword line, body, terminator. closes tells the
// caller the terminator line closed the stanza.
func (g *lrFuzz) script() (lines []string, closes bool) {
	kw := g.pick(fuzzScriptKeywords...)
	first := kw + g.pick("", "", "", " # reload", "=", "\t", " ")
	lines = append(lines, "\t"+first)
	more, closes := g.scriptBody()
	return append(lines, more...), closes
}

// scriptBody writes the lines after a script keyword: body and terminator.
func (g *lrFuzz) scriptBody() (lines []string, closes bool) {
	for i, n := 0, g.r.Intn(4); i < n; i++ {
		lines = append(lines, g.scriptLine())
	}
	term := "\t" + g.pick("endscript", "endscript", "endscript;", "endscript # done", "endscript;# c", "endscript#", "endscript1", "endscript.", "  endscript", "endscript\t")
	switch g.r.Intn(8) {
	case 0:
		term = "\tendscript }"
		closes = true
	case 1:
		term = "\tendscript}"
	case 2:
		term = "\tendscript compress"
	case 3:
		// a second script starts on the line that ended the first
		term = "\tendscript " + g.pick(fuzzScriptKeywords...)
		lines = append(lines, term)
		more, c := g.scriptBody()
		return append(lines, more...), c
	}
	lines = append(lines, term)
	return lines, closes
}

func (g *lrFuzz) bodyStatements() (lines []string, closes bool) {
	for i, n := 0, g.r.Intn(6); i < n && !closes; i++ {
		switch g.r.Intn(12) {
		case 0, 1:
			var sl []string
			sl, closes = g.script()
			lines = append(lines, sl...)
		case 2:
			lines = append(lines, "\tmissingok }")
			closes = true
		case 3:
			lines = append(lines, g.pick("\tcompress missingok", "\tdaily rotate 5", "\tcompress delaycompress notifempty", "\tmissingok # note", "\tcompress # /var/log/syslog"))
		case 4:
			lines = append(lines, g.pick("# endscript", "#/var/log/syslog", "\t# postrotate", ""))
		default:
			lines = append(lines, g.pick("\trotate 4", "\tweekly", "\tsize 10k", "\tmaxage 7", "\tdateext", "\tsharedscripts", "\tmissingok", "\tcompress", "\tnotifempty", "\tdateformat /var/log/syslog", "\tmaxage 7"))
		}
	}
	return lines, closes
}

func (g *lrFuzz) stanza(prefix string, withManaged, last bool) string {
	h, closes, opens := g.header(prefix, withManaged)
	lines := []string{h}
	if opens {
		var sl []string
		sl, closes = g.scriptBody()
		lines = append(lines, sl...)
	}
	if !closes {
		var bl []string
		bl, closes = g.bodyStatements()
		lines = append(lines, bl...)
	}
	if !closes && !last {
		lines = append(lines, g.pick("}", "}", " }", "\t}", "}  ", "} "))
	}
	return strings.Join(lines, "\n") + "\n"
}

func (g *lrFuzz) policy() string {
	var b strings.Builder
	n := 1 + g.r.Intn(4)
	managedIn := g.r.Intn(n)
	for i := 0; i < n; i++ {
		switch g.r.Intn(8) {
		case 0:
			b.WriteString("\n")
		case 1:
			b.WriteString("# distro policy\n")
		case 2:
			b.WriteString(g.pick("compress\n", "delaycompress\n", "missingok\n", "daily\n"))
		case 3:
			b.WriteString("postrotate\n" + g.pick("\t/var/log/syslog\n", "\ttrue\n") + "endscript\n")
		}
		prefix := ""
		if g.chance(10) {
			prefix = g.pick("compress ", "daily compress\t", "missingok ", "compress=")
		}
		// the last stanza of a file may stay open: logrotate accepts that
		b.WriteString(g.stanza(prefix, i == managedIn, i == n-1 && g.chance(10)))
	}
	return b.String()
}

func TestLogrotateDropPathFuzzAgainstRealLogrotate(t *testing.T) {
	logrotate, err := exec.LookPath("logrotate")
	if err != nil {
		t.Skip("logrotate not installed")
	}
	awks := dropPathAwks(t)
	cases, seed := 150, int64(20261030)
	if v, err := strconv.Atoi(os.Getenv("PILOT_LOGROTATE_FUZZ_N")); err == nil && v > 0 {
		cases = v
	}
	if v, err := strconv.ParseInt(os.Getenv("PILOT_LOGROTATE_FUZZ_SEED"), 10, 64); err == nil {
		seed = v
	}
	dump := os.Getenv("PILOT_LOGROTATE_FUZZ_DUMP")
	valid := 0
	for i := 0; i < cases; i++ {
		g := &lrFuzz{r: rand.New(rand.NewSource(seed + int64(i)))}
		policy := g.policy()
		before := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": policy})
		seen := 0
		for _, c := range before.considered {
			if c == "/var/log/syslog" {
				seen++
			}
		}
		if len(before.errors) > 0 || seen != 1 {
			if os.Getenv("PILOT_LOGROTATE_FUZZ_WHY") != "" {
				t.Logf("REJECT seen=%d %q", seen, before.errors)
			}
			continue // not a policy logrotate accepts with the path once
		}
		valid++
		for _, a := range awks {
			rewritten, stderr, code := runDropPath(t, a, "/var/log/syslog", policy)
			if code != 0 {
				t.Fatalf("seed %d case %d %s: awk exit %d on a policy logrotate accepts\npolicy:\n%q\nstderr: %s", seed, i, a.name, code, policy, stderr)
			}
			after := parseWithLogrotate(t, logrotate, map[string]string{"rsyslog": rewritten, "syslog": managedSyslogStanza})
			if len(after.errors) > 0 || strings.Contains(after.raw, "duplicate log entry") {
				t.Fatalf("seed %d case %d %s: logrotate rejects the rewrite: %v\npolicy:\n%q\nrewritten:\n%q\n%s", seed, i, a.name, after.errors, policy, rewritten, after.raw)
			}
			if strings.Join(after.considered, "\n") != strings.Join(before.considered, "\n") {
				t.Fatalf("seed %d case %d %s: logrotate considers\n%q\nafter the rewrite, before:\n%q\npolicy:\n%q\nrewritten:\n%q", seed, i, a.name, after.considered, before.considered, policy, rewritten)
			}
			if len(after.ignored) != len(before.ignored) {
				t.Fatalf("seed %d case %d %s: lines logrotate ignores changed: %v -> %v\npolicy:\n%q\nrewritten:\n%q", seed, i, a.name, before.ignored, after.ignored, policy, rewritten)
			}
			for _, k := range g.keep {
				if strings.Count(rewritten, k) < strings.Count(policy, k) {
					t.Fatalf("seed %d case %d %s: %q was in the policy %d times and is in the rewrite %d times\npolicy:\n%q\nrewritten:\n%q", seed, i, a.name, k, strings.Count(policy, k), strings.Count(rewritten, k), policy, rewritten)
				}
			}
			if a.name == awks[0].name && dump != "" {
				writeFile(t, filepath.Join(dump, fmt.Sprintf("%d.orig", i)), policy)
				writeFile(t, filepath.Join(dump, fmt.Sprintf("%d.rewritten", i)), rewritten)
			}
		}
	}
	if valid < cases/3 {
		t.Fatalf("only %d of %d generated policies are ones logrotate accepts: the generator is broken", valid, cases)
	}
	t.Logf("%d of %d generated policies accepted by logrotate, all rewritten correctly on %d awks", valid, cases, len(awks))
}
