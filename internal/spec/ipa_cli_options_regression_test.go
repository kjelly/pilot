package spec

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The ipa CLI parses options with Python optparse, which accepts any
// unambiguous prefix of a long option. `ipa hbacrule-find` has no --host
// option, so the decommission query's `--host=<fqdn>` was read as
// `--hostcat=<fqdn>` and never matched (issue #104). This test checks every
// `ipa <subcommand> --option` in playbooks/ against the options that
// subcommand's `--help` lists (testdata/freeipa-cli-options.txt, captured
// from FreeIPA 4.13.4), so an abbreviation or a misspelled option fails here
// instead of silently meaning something else.

const ipaCLIOptionsFile = "testdata/freeipa-cli-options.txt"

var (
	ipaSubcommandRe   = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)+$`)
	ipaJinjaArgvRe    = regexp.MustCompile(`\[\s*'ipa'\s*,\s*'([a-z][a-z0-9-]+)'`)
	ipaJinjaOptionRe  = regexp.MustCompile(`'(--[a-z][a-z0-9-]*)`)
	ipaShellCommandRe = regexp.MustCompile(`\bipa ([a-z][a-z0-9]*(?:-[a-z0-9]+)+)([^|;&\n]*)`)
	ipaShellOptionRe  = regexp.MustCompile(`(?:^|\s)(--[a-z][a-z0-9-]*)`)
	ipaQuotedWordRe   = regexp.MustCompile(`'([a-z][a-z0-9-]*)'`)
)

// ipaOptionUse is one `--option` passed to `ipa <cmd>` somewhere in a playbook.
type ipaOptionUse struct{ cmd, option, file string }

func collectIPAOptionUses(t *testing.T) []ipaOptionUse {
	t.Helper()
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	var uses []ipaOptionUse
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			continue // rosters with Jinja-only content and similar; not task files
		}
		add := func(cmd, opt string) {
			name := strings.SplitN(opt, "=", 2)[0]
			// An option name built by Jinja (`--{{ 'a' if x else 'b' }}`)
			// is checked for every quoted candidate in the template.
			if strings.Contains(name, "{{") {
				tmpl := opt
				if end := strings.Index(opt, "}}"); end >= 0 {
					tmpl = opt[:end]
				}
				for _, w := range ipaQuotedWordRe.FindAllStringSubmatch(tmpl, -1) {
					uses = append(uses, ipaOptionUse{cmd, "--" + w[1], f})
				}
				return
			}
			uses = append(uses, ipaOptionUse{cmd, name, f})
		}
		scanString := func(s string) {
			if m := ipaJinjaArgvRe.FindStringSubmatch(s); m != nil {
				for _, o := range ipaJinjaOptionRe.FindAllStringSubmatch(s, -1) {
					add(m[1], o[1])
				}
				return
			}
			for _, m := range ipaShellCommandRe.FindAllStringSubmatch(s, -1) {
				for _, o := range ipaShellOptionRe.FindAllStringSubmatch(m[2], -1) {
					add(m[1], o[1])
				}
			}
		}
		var walk func(node any, key string)
		walk = func(node any, key string) {
			switch v := node.(type) {
			case map[string]any:
				for k, child := range v {
					walk(child, k)
				}
			case []any:
				if key == "argv" && len(v) > 1 && v[0] == "ipa" {
					if cmd, ok := v[1].(string); ok && ipaSubcommandRe.MatchString(cmd) {
						for _, item := range v[2:] {
							if s, ok := item.(string); ok && strings.HasPrefix(s, "--") {
								add(cmd, s)
							}
						}
					}
					return
				}
				for _, child := range v {
					walk(child, key)
				}
			case string:
				switch key {
				case "argv", "cmd", "_raw_params", "shell", "command", "ansible.builtin.shell", "ansible.builtin.command":
					scanString(v)
				}
			}
		}
		walk(doc, "")
	}
	return uses
}

func loadIPACLIOptions(t *testing.T) map[string]map[string]bool {
	t.Helper()
	f, err := os.Open(ipaCLIOptionsFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	known := map[string]map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		opts := map[string]bool{}
		for _, o := range fields[1:] {
			opts[o] = true
		}
		known[fields[0]] = opts
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return known
}

func TestRegression_PlaybookIPAOptionsExistInIPAHelp(t *testing.T) {
	known := loadIPACLIOptions(t)
	uses := collectIPAOptionUses(t)
	if len(uses) < 100 {
		t.Fatalf("found only %d ipa option uses under playbooks/; the extraction is broken", len(uses))
	}
	var problems []string
	seen := map[string]bool{}
	for _, u := range uses {
		key := u.cmd + " " + u.option + " " + u.file
		if seen[key] {
			continue
		}
		seen[key] = true
		opts, ok := known[u.cmd]
		switch {
		case !ok:
			problems = append(problems, u.file+": `ipa "+u.cmd+"` is not in "+ipaCLIOptionsFile+"; run `ipa "+u.cmd+" --help` on a FreeIPA server and add its options")
		case !opts[u.option]:
			problems = append(problems, u.file+": `ipa "+u.cmd+"` has no option "+u.option+" (optparse would read an unambiguous prefix of another option silently)")
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// The check must reject the abbreviation that caused issue #104.
func TestRegression_PlaybookIPAOptionsRejectsAbbreviation(t *testing.T) {
	known := loadIPACLIOptions(t)
	if !known["hbacrule-find"]["--hostcat"] || known["hbacrule-find"]["--host"] {
		t.Fatalf("captured hbacrule-find options are not what issue #104 relies on: %v", known["hbacrule-find"])
	}
	m := ipaShellCommandRe.FindStringSubmatch("ipa hbacrule-find --host=web1.ipa.pilot.internal")
	if m == nil || m[1] != "hbacrule-find" {
		t.Fatalf("shell form not parsed: %v", m)
	}
}
