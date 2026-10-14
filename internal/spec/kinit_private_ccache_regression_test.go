package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Issue #69: playbooks ran `kinit admin` into the host's default credential
// cache and never destroyed it, so a FreeIPA admin TGT stayed on the host
// after the run (a freshly deployed FreeIPA server had admin@REALM in root's
// KCM:0), and any later program using the default cache acted as admin
// without knowing it. Every kinit must write to a private cache instead:
// tasks/freeipa-private-ccache-open.yml + -close.yml around a block whose
// environment sets KRB5CCNAME, or an explicit KRB5CCNAME / `kinit -c` the
// task cleans up itself.
//
// kinitDefaultCacheAllowlist is a ratchet: these sites still use the default
// cache, but already run kdestroy afterwards, so they do not leave a ticket
// behind after a successful run. Migrating them needs live runs on
// topologies this change did not set up (the pilot-access, identity, NFS and
// client-failover ones, and the demo/simulation fixtures). Remove an entry when its file is migrated; the test fails
// if an entry no longer matches anything, and for any new default-cache
// kinit.
var kinitDefaultCacheAllowlist = map[string]int{
	"playbooks/apply/freeipa-identity-apply.yml":                  1,
	"playbooks/apply/freeipa-nfs-server-apply.yml":                1,
	"playbooks/apply/pilot-access-directory-apply.yml":            2,
	"playbooks/apply/pilot-access-gateway-apply.yml":              1,
	"playbooks/apply/pilot-access-target-policy-apply.yml":        2,
	"playbooks/apply/pilot-session-store-apply.yml":               1,
	"playbooks/apply/tasks/freeipa-client-server-failover.yml":    1,
	"playbooks/test/fixtures/freeipa-audit-demo.yml":              1,
	"playbooks/test/fixtures/freeipa-audit-sim.yml":               1,
	"playbooks/test/fixtures/freeipa-client-fixtures.yml":         1,
	"playbooks/test/fixtures/freeipa-hostauthz-demo.yml":          3,
	"playbooks/test/fixtures/freeipa-hostauthz-sim.yml":           1,
	"playbooks/test/fixtures/pilot-access-transport-fixtures.yml": 2,
}

var (
	kinitWordRe     = regexp.MustCompile(`(^|[\s;|&(])kinit(\s|$)`)
	inlineCcacheRe  = regexp.MustCompile(`KRB5CCNAME=`)
	kinitCacheOptRe = regexp.MustCompile(`(^|[\s;|&(])kinit\s[^\n]*\s-c\s`)
)

type kinitSite struct {
	file    string
	task    string
	private bool
}

// commandText returns the command a shell/command/raw task runs, with shell
// comment lines removed, or "" when the task runs none of those modules.
func kinitCommandText(task map[string]any) string {
	for _, module := range []string{"ansible.builtin.shell", "shell", "ansible.builtin.command", "command", "ansible.builtin.raw", "raw"} {
		raw, ok := task[module]
		if !ok {
			continue
		}
		var text string
		switch v := raw.(type) {
		case string:
			text = v
		case map[string]any:
			if cmd, ok := v["cmd"].(string); ok {
				text = cmd
			}
			if argv, ok := v["argv"].([]any); ok {
				parts := make([]string, 0, len(argv))
				for _, a := range argv {
					parts = append(parts, fmt.Sprint(a))
				}
				text = strings.Join(parts, " ")
			}
		}
		var kept []string
		for _, line := range strings.Split(text, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "#") {
				kept = append(kept, line)
			}
		}
		return strings.Join(kept, "\n")
	}
	return ""
}

func envSetsCcache(task map[string]any) bool {
	env, ok := task["environment"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = env["KRB5CCNAME"]
	return ok
}

func kinitIncludesFile(task map[string]any, suffix string) bool {
	for _, key := range []string{"ansible.builtin.include_tasks", "include_tasks", "ansible.builtin.import_tasks", "import_tasks"} {
		switch v := task[key].(type) {
		case string:
			if strings.HasSuffix(v, suffix) {
				return true
			}
		case map[string]any:
			if f, _ := v["file"].(string); strings.HasSuffix(f, suffix) {
				return true
			}
		}
	}
	return false
}

func kinitTaskList(raw any) []map[string]any {
	list, _ := raw.([]any)
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// walkKinit visits every task, carrying whether an enclosing block (or the
// play) sets KRB5CCNAME, and records each kinit and each block that opens
// a pilot_krb5ccname cache without the shared open/close tasks.
func walkKinit(file string, tasks []map[string]any, inherited bool, sites *[]kinitSite, problems *[]string) {
	for _, task := range tasks {
		name, _ := task["name"].(string)
		private := inherited || envSetsCcache(task)
		if _, isBlock := task["block"]; isBlock {
			if env, ok := task["environment"].(map[string]any); ok {
				if v, _ := env["KRB5CCNAME"].(string); strings.Contains(v, "pilot_krb5ccname") {
					block := kinitTaskList(task["block"])
					if len(block) == 0 || !kinitIncludesFile(block[0], "freeipa-private-ccache-open.yml") {
						*problems = append(*problems, fmt.Sprintf("%s: block %q sets KRB5CCNAME from pilot_krb5ccname but does not include tasks/freeipa-private-ccache-open.yml first", file, name))
					}
					closed := false
					for _, t := range kinitTaskList(task["always"]) {
						if kinitIncludesFile(t, "freeipa-private-ccache-close.yml") {
							closed = true
						}
					}
					if !closed {
						*problems = append(*problems, fmt.Sprintf("%s: block %q opens a private Kerberos cache but its always: does not include tasks/freeipa-private-ccache-close.yml", file, name))
					}
				}
			}
			for _, section := range []string{"block", "rescue", "always"} {
				walkKinit(file, kinitTaskList(task[section]), private, sites, problems)
			}
			continue
		}
		text := kinitCommandText(task)
		if !kinitWordRe.MatchString(text) {
			continue
		}
		*sites = append(*sites, kinitSite{
			file:    file,
			task:    name,
			private: private || inlineCcacheRe.MatchString(text) || kinitCacheOptRe.MatchString(text),
		})
	}
}

func scanKinit(t *testing.T) ([]kinitSite, []string) {
	t.Helper()
	var sites []kinitSite
	var problems []string
	err := filepath.WalkDir("../../playbooks", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		for _, item := range kinitTaskList(doc) {
			if _, isPlay := item["hosts"]; isPlay {
				playPrivate := envSetsCcache(item)
				for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
					walkKinit(rel, kinitTaskList(item[section]), playPrivate, &sites, &problems)
				}
				continue
			}
			walkKinit(rel, []map[string]any{item}, false, &sites, &problems)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sites, problems
}

func TestRegression_KinitUsesAPrivateCredentialCache(t *testing.T) {
	sites, problems := scanKinit(t)
	if len(sites) < 20 {
		t.Fatalf("found only %d kinit sites under playbooks/; the scan is broken", len(sites))
	}
	for _, p := range problems {
		t.Error(p)
	}
	defaultCache := map[string][]string{}
	for _, s := range sites {
		if !s.private {
			defaultCache[s.file] = append(defaultCache[s.file], s.task)
		}
	}
	var files []string
	for f := range defaultCache {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		want, allowed := kinitDefaultCacheAllowlist[f]
		switch {
		case !allowed:
			t.Errorf("%s: kinit into the default credential cache in %q; wrap the tasks that use the ticket in a block with tasks/freeipa-private-ccache-open.yml and -close.yml (issue #69)", f, defaultCache[f])
		case len(defaultCache[f]) > want:
			t.Errorf("%s: %d default-cache kinit tasks %q, the allowlist permits %d; new ones must use a private cache (issue #69)", f, len(defaultCache[f]), defaultCache[f], want)
		case len(defaultCache[f]) < want:
			t.Errorf("%s: %d default-cache kinit tasks, the allowlist still says %d; lower it", f, len(defaultCache[f]), want)
		}
	}
	for f, want := range kinitDefaultCacheAllowlist {
		if len(defaultCache[f]) == 0 && want > 0 {
			t.Errorf("%s is allowlisted for %d default-cache kinit tasks but has none; remove the entry", f, want)
		}
	}
}

// The scan itself: what counts as a private cache, what is reported, and
// that a comment mentioning kinit is not a kinit.
func TestKinitScanClassifiesSites(t *testing.T) {
	src := `
- name: default cache
  ansible.builtin.shell: printf %s x | kinit admin
- name: inline cache
  ansible.builtin.shell: |
    # kinit admin would be wrong here
    printf %s x | KRB5CCNAME="{{ cc }}" kinit admin
- name: explicit -c
  ansible.builtin.command:
    argv: [kinit, -k, -c, "{{ cc }}", host/x]
- name: comment only
  ansible.builtin.shell: |
    # kinit admin
    true
- name: task env
  ansible.builtin.command: kinit admin
  environment:
    KRB5CCNAME: "{{ cc }}"
- name: good block
  environment:
    KRB5CCNAME: "{{ pilot_krb5ccname | default('FILE:/nonexistent/x') }}"
  block:
    - ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-open.yml}
    - name: inherits
      ansible.builtin.command: kinit admin
  always:
    - ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-close.yml}
- name: no close
  environment:
    KRB5CCNAME: "{{ pilot_krb5ccname }}"
  block:
    - ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-open.yml}
- name: no open first
  environment:
    KRB5CCNAME: "{{ pilot_krb5ccname }}"
  block:
    - name: kinit first
      ansible.builtin.command: kinit admin
  always:
    - ansible.builtin.include_tasks: {file: tasks/freeipa-private-ccache-close.yml}
`
	var doc []map[string]any
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	var sites []kinitSite
	var problems []string
	walkKinit("x.yml", doc, false, &sites, &problems)
	got := map[string]bool{}
	for _, s := range sites {
		got[s.task] = s.private
	}
	want := map[string]bool{"default cache": false, "inline cache": true, "explicit -c": true, "task env": true, "inherits": true, "kinit first": true}
	for task, private := range want {
		if p, found := got[task]; !found || p != private {
			t.Errorf("%q: found=%v private=%v, want private=%v", task, found, p, private)
		}
	}
	if _, found := got["comment only"]; found {
		t.Error("a comment mentioning kinit was counted as a kinit")
	}
	joined := strings.Join(problems, "\n")
	if len(problems) != 2 || !strings.Contains(joined, `"no close"`) || !strings.Contains(joined, `"no open first"`) {
		t.Errorf("problems = %v, want the block without close and the one without open first", problems)
	}
}
