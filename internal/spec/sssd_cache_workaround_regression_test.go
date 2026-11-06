package spec

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// sssdCacheClearAllowlist names the only files under playbooks/ that may clear
// SSSD's cache, each with the reason it is not a workaround. Keys are paths
// relative to playbooks/, with forward slashes.
//
// AGENTS.md §5.9 item 5: a result that needs a cache clear (or a restart, or a
// wait) to come out right is a symptom of a bug, not something to document or
// script around. #214 (sudo rules still stale after `sss_cache -E`) is the
// example: the fix was to find out what actually refreshes the rules, wait for
// it with a bound, and report PARTIAL, not to add another flush. #291 tracks
// the open questions about how long SSSD may take to show a change. Until it
// is decided, a new `sss_cache` call in a playbook would quietly pre-empt that
// decision, so it has to be registered here and justified.
//
// Restarting SSSD is not checked: restarting it after editing sssd.conf is how
// configuration takes effect and appears in many playbooks.
var sssdCacheClearAllowlist = map[string]string{
	"apply/files/freeipa-sssd-sudo-refresh.py":       "#214 helper: expires the client's rules, restarts SSSD and waits, bounded, for the client's own sudoLastFullRefreshTime to move; clients that do not finish are reported as PARTIAL",
	"apply/files/freeipa-ssh-key-cache.py":           "SSH-key propagation helper: `sss_cache -u` followed by a bounded check that sss_ssh_authorizedkeys serves exactly the expected key set, tracked in a durable journal",
	"apply/tasks/freeipa-client-server-failover.yml": "client configuration reconcile: expires the cache after the ipa_server line and the krb5 realm file were rewritten, which is a configuration change, not a stale read of FreeIPA data",
}

var (
	// reSSSCache matches the sss_cache tool as a word, in any argv or shell form.
	reSSSCache = regexp.MustCompile(`\bsss_cache\b`)
	// reRemoveSSSState matches shell commands that delete SSSD's databases or
	// memory-mapped caches. Reading them (ldbsearch) is not a mutation.
	reRemoveSSSState = regexp.MustCompile(`\b(rm|unlink|truncate|shred)\b[^\n]*/var/lib/sss/(db|mc)\b`)
	// reSSSStatePath matches the paths whose removal through the file module is
	// the same thing.
	reSSSStatePath = regexp.MustCompile(`^/var/lib/sss/(db|mc)(/|$)`)
)

// TestRegression_SSSDCacheClearsOnlyInVettedHelpers is a repo-wide lint over
// playbooks/**. It fails when a file that is not in sssdCacheClearAllowlist
// clears SSSD's cache, and when an allowlist entry no longer does (so the
// list cannot rot into a blanket exemption).
func TestRegression_SSSDCacheClearsOnlyInVettedHelpers(t *testing.T) {
	root := filepath.Join("..", "..", "playbooks")
	found, err := scanSSSDCacheClears(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(found) == 0 {
		t.Fatal("scan found no SSSD cache clears at all; the vetted helpers should be detected, so the detector is broken")
	}
	var files []string
	for f := range found {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		if _, ok := sssdCacheClearAllowlist[f]; ok {
			continue
		}
		t.Errorf("%s clears SSSD's cache (%s). A result that needs a cache clear to be correct is a bug "+
			"(AGENTS.md §5.9 item 5; open design questions in #291), so do not script the clear around it. "+
			"Find what refreshes the data and wait for that with a bound, as freeipa-sssd-sudo-refresh.py does. "+
			"If this really is a vetted helper, add it to sssdCacheClearAllowlist with the reason and its evidence.",
			f, strings.Join(found[f], "; "))
	}
	var listed []string
	for f := range sssdCacheClearAllowlist {
		listed = append(listed, f)
	}
	sort.Strings(listed)
	for _, f := range listed {
		if _, ok := found[f]; !ok {
			t.Errorf("sssdCacheClearAllowlist entry %s no longer clears SSSD's cache (or the file is gone); remove the entry", f)
		}
	}
}

func TestSSSDCacheClearDetector(t *testing.T) {
	cases := []struct {
		name string
		file string
		body string
		want int
	}{
		{"command module with argv", "a.yml", "- name: t\n  ansible.builtin.command:\n    argv: [sss_cache, -E]\n", 1},
		{"free-form command", "a.yml", "- name: t\n  ansible.builtin.command: sss_cache -u alice\n", 1},
		{"shell with pipeline", "a.yml", "- name: t\n  ansible.builtin.shell: |\n    sss_cache -E && systemctl restart sssd\n", 1},
		{"python helper", "files/h.py", "import subprocess\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"rm of the sssd databases", "a.yml", "- name: t\n  ansible.builtin.shell: rm -f /var/lib/sss/db/*.ldb\n", 1},
		{"file module removing the memory cache", "a.yml", "- name: t\n  ansible.builtin.file:\n    path: /var/lib/sss/mc/passwd\n    state: absent\n", 1},
		{"yaml comment is not a clear", "a.yml", "# sss_cache -E would not help here\n- name: t\n  ansible.builtin.debug:\n    msg: ok\n", 0},
		{"python comment is not a clear", "files/h.py", "# do not call sss_cache here\nprint('x')\n", 0},
		{"reading the sssd database is not a clear", "a.yml", "- name: t\n  ansible.builtin.command: ldbsearch -H /var/lib/sss/db/cache_x.ldb -b cn=sysdb\n", 0},
		{"file module only touching the database is not a clear", "a.yml", "- name: t\n  ansible.builtin.file:\n    path: /var/lib/sss/db/cache_x.ldb\n    mode: '0600'\n", 0},
		{"restarting sssd after a config edit is not a clear", "a.yml", "- name: t\n  ansible.builtin.systemd:\n    name: sssd\n    state: restarted\n", 0},
		{"a longer identifier is not the tool", "a.yml", "- name: t\n  ansible.builtin.debug:\n    msg: \"{{ not_sss_cache_flag }}\"\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sssdCacheClears(tc.file, []byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != tc.want {
				t.Fatalf("got %d hits %v, want %d", len(got), got, tc.want)
			}
		})
	}
}

// TestScanSSSDCacheClearsWalksATree proves the walk reports a clear in a file
// it has never heard of, and reports nothing for a clean tree, so the repo-wide
// test above cannot pass just because the walk finds no files.
func TestScanSSSDCacheClearsWalksATree(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("apply/clean.yml", "- name: t\n  ansible.builtin.debug:\n    msg: ok\n")
	write("README.md", "run sss_cache -E by hand\n")
	got, err := scanSSSDCacheClears(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("clean tree reported %v", got)
	}
	write("apply/new-workaround.yml", "- name: flush\n  ansible.builtin.command: sss_cache -E\n")
	got, err = scanSSSDCacheClears(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got["apply/new-workaround.yml"]; !ok || len(got) != 1 {
		t.Fatalf("expected exactly apply/new-workaround.yml, got %v", got)
	}
}

// scanSSSDCacheClears returns, per file under root (key relative to root, with
// forward slashes), what clears SSSD's cache there. Markdown and binary files
// are skipped: prose may name the tool.
func scanSSSDCacheClears(root string) (map[string][]string, error) {
	found := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ext := filepath.Ext(path); ext == ".md" || ext == ".asc" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		hits, err := sssdCacheClears(rel, raw)
		if err != nil {
			return fmt.Errorf("%s: %w", rel, err)
		}
		if len(hits) > 0 {
			found[rel] = hits
		}
		return nil
	})
	return found, err
}

// sssdCacheClears returns one message per place in raw that clears SSSD's
// cache: a non-comment line naming sss_cache or removing SSSD's state, and, for
// YAML, a file-module task that removes it.
func sssdCacheClears(name string, raw []byte) ([]string, error) {
	var out []string
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		switch {
		case reSSSCache.MatchString(line):
			out = append(out, fmt.Sprintf("line %d runs sss_cache", i+1))
		case reRemoveSSSState.MatchString(line):
			out = append(out, fmt.Sprintf("line %d deletes SSSD state under /var/lib/sss", i+1))
		}
	}
	if ext := filepath.Ext(name); ext == ".yml" || ext == ".yaml" {
		var doc yaml.Node
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		var walk func(n *yaml.Node)
		walk = func(n *yaml.Node) {
			if n == nil {
				return
			}
			if n.Kind == yaml.MappingNode {
				p, s := mappingValue(n, "path"), mappingValue(n, "state")
				if p != nil && s != nil && s.Value == "absent" && reSSSStatePath.MatchString(p.Value) {
					out = append(out, fmt.Sprintf("line %d removes %s with state: absent", n.Line, p.Value))
				}
			}
			for _, c := range n.Content {
				walk(c)
			}
		}
		walk(&doc)
	}
	return out, nil
}
