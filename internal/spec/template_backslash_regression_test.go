package spec

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// templateBackslashAllowlist lists templates that still use "\\" with the
// reason they are left as they are. Keys are "<path>:<line>".
var templateBackslashAllowlist = map[string]string{
	// regex_findall('(?im)^[ \\t]*dnsttl: (.+)$') is the class "space,
	// backslash or t", not "space or tab". `ipa dnsrecord-show` indents
	// with spaces only, so it still finds the TTL; changing it needs its
	// own freeipa-dns vm-target run.
	"../../playbooks/apply/freeipa-dns-apply.yml:480": "harmless with real ipa output; fix with a freeipa-dns run",
}

var jinjaTemplateBlock = regexp.MustCompile(`(?s)\{\{.*?\}\}|\{%.*?%\}`)

// TestRegression_JinjaTemplatesUseSingleBackslashes is a repo-wide lint
// over every playbooks/**/*.yml. ansible-core 2.19 does not unescape "\\"
// in a string literal inside a {{ }} or {% %} template (a bare when:/that:
// expression does), so in a YAML scalar that is not double-quoted
// regex_replace('/\\.', ”) looks for a backslash and never matches.
// AG82's ".." refusal message and its path normalization used '\\.' and
// '\\1': the message listed no path and "/./" was never collapsed, while
// the tests passed through other checks (PR #19). Write one backslash, or
// put the value in a double-quoted YAML string, where YAML removes one.
func TestRegression_JinjaTemplatesUseSingleBackslashes(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	checked := 0
	used := map[string]bool{}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", path, err)
		}
		walkScalars(&doc, func(n *yaml.Node) {
			if n.Style&yaml.DoubleQuotedStyle != 0 {
				return
			}
			for _, block := range jinjaTemplateBlock.FindAllString(n.Value, -1) {
				checked++
				if !strings.Contains(block, `\\`) {
					continue
				}
				key := path + ":" + strconv.Itoa(n.Line)
				if _, ok := templateBackslashAllowlist[key]; ok {
					used[key] = true
					continue
				}
				t.Errorf("%s:%d: %q has \"\\\\\" inside a Jinja template; ansible-core 2.19 keeps both backslashes there, write one", path, n.Line, firstLine(block))
			}
		})
	}
	for key := range templateBackslashAllowlist {
		if !used[key] {
			t.Errorf("allowlist entry %s matched nothing; remove it", key)
		}
	}
	// playbooks/** has thousands of templates; a small count means the
	// walker is broken.
	if checked < 1000 {
		t.Fatalf("only %d templates found; the walker is broken", checked)
	}
}

// TestJinjaTemplateBackslashSemantics checks the premise of the lint above
// on the installed ansible-core: inside a {{ }} template one backslash
// reaches the regex and two stay two, while a bare when: expression takes
// either.
func TestJinjaTemplateBackslashSemantics(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skipf("ansible-playbook not installed: %v", err)
	}
	dir := t.TempDir()
	play := `- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    p: /etc/pilot/./a
  tasks:
    - name: template
      debug:
        msg: >-
          single={{ p | regex_replace('/\.(?=/|$)', '') }}
          double={{ p | regex_replace('/\\.(?=/|$)', '') }}
    - name: bare conditional with two backslashes
      debug:
        msg: matched
      when: p is search('/\\./')
`
	pb := filepath.Join(dir, "play.yml")
	if err := os.WriteFile(pb, []byte(play), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", pb)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "ANSIBLE_NOCOLOR=1", "ANSIBLE_LOCALHOST_WARNING=False")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ansible-playbook: %v\n%s", err, out)
	}
	got := string(out)
	if !strings.Contains(got, "single=/etc/pilot/a double=/etc/pilot/./a") {
		t.Errorf("template backslash handling differs from ansible-core 2.19; revisit TestRegression_JinjaTemplatesUseSingleBackslashes:\n%s", got)
	}
	if !strings.Contains(got, `"msg": "matched"`) {
		t.Errorf("a bare when: no longer unescapes \"\\\\\":\n%s", got)
	}
}

func walkScalars(n *yaml.Node, fn func(*yaml.Node)) {
	if n.Kind == yaml.ScalarNode {
		fn(n)
	}
	for _, c := range n.Content {
		walkScalars(c, fn)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}
