package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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
//
// What the lint can and cannot see. It reads text: a non-comment line that names
// sss_cache or sssctl cache-expire/cache-remove (as a command line or inside a
// one-line argv list), a shell rm/unlink/truncate/shred of /var/lib/sss/{db,mc},
// and a file-module task with path + state: absent on those directories. Prose
// does not count: a Python docstring (a triple-quoted string that is a statement
// by itself, see pythonProseLines) and a YAML task name: are skipped, so an
// allowlisted file whose real call is gone is reported as stale even when its
// documentation still mentions the tool. A triple-quoted string that is assigned,
// passed to a call or formatted is code, and so is every line of it. It does not
// see find -delete, mv, os.remove/shutil.rmtree, an argv split across lines or
// list items, dest:/name: aliases, a path built from a variable or loop item, or
// the second document of a multi-document YAML file. Those need a reviewer
// (.agents/skills/pilot-code-review/references/pilot-history-checks.md).
var sssdCacheClearAllowlist = map[string]string{
	"apply/files/freeipa-sssd-sudo-refresh.py":       "#214 helper: expires the client's rules, restarts SSSD and waits, bounded, for the client's own sudoLastFullRefreshTime to move; clients that do not finish are reported as PARTIAL",
	"apply/files/freeipa-ssh-key-cache.py":           "SSH-key propagation helper: `sss_cache -u` followed by a bounded check that sss_ssh_authorizedkeys serves exactly the expected key set, tracked in a durable journal",
	"apply/tasks/freeipa-client-server-failover.yml": "client configuration reconcile: expires the cache after the ipa_server line and the krb5 realm file were rewritten, which is a configuration change, not a stale read of FreeIPA data",
}

var (
	// reSSSCache matches the sss_cache tool as a word, in any argv or shell form.
	reSSSCache = regexp.MustCompile(`\bsss_cache\b`)
	// reSSSCtlCache matches sssctl's equivalents of sss_cache -E and of deleting
	// the cache databases, as a command line (`sssctl cache-expire -E`) and as the
	// first items of a one-line argv list (`[sssctl, cache-expire]`,
	// `["sssctl", "cache-expire"]`). An argv split across lines is not matched.
	reSSSCtlCache = regexp.MustCompile(`\bsssctl[\s,"'\[\]]+cache-(expire|remove)\b`)
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
	for _, problem := range sssdAllowlistProblems(found, sssdCacheClearAllowlist) {
		t.Error(problem)
	}
}

// sssdAllowlistProblems compares what the scan found with an allowlist and returns
// one message per file that clears SSSD's cache without being listed and one per
// listed file that no longer clears it. It is separate from the repo scan so a
// test can prove both branches fire.
func sssdAllowlistProblems(found map[string][]string, allowlist map[string]string) []string {
	var problems []string
	var files []string
	for f := range found {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		if _, ok := allowlist[f]; ok {
			continue
		}
		problems = append(problems, fmt.Sprintf("%s clears SSSD's cache (%s). A result that needs a cache clear to be correct is a bug "+
			"(AGENTS.md §5.9 item 5; open design questions in #291), so do not script the clear around it. "+
			"Find what refreshes the data and wait for that with a bound, as freeipa-sssd-sudo-refresh.py does. "+
			"If this really is a vetted helper, add it to sssdCacheClearAllowlist with the reason and its evidence.",
			f, strings.Join(found[f], "; ")))
	}
	var listed []string
	for f := range allowlist {
		listed = append(listed, f)
	}
	sort.Strings(listed)
	for _, f := range listed {
		if _, ok := found[f]; !ok {
			problems = append(problems, fmt.Sprintf("sssdCacheClearAllowlist entry %s no longer clears SSSD's cache (or the file is gone); remove the entry", f))
		}
	}
	return problems
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
		{"sssctl cache-expire", "a.yml", "- name: t\n  ansible.builtin.command: sssctl cache-expire -E\n", 1},
		{"sssctl cache-remove", "a.yml", "- name: t\n  ansible.builtin.shell: sssctl cache-remove -o -p\n", 1},
		{"sssctl status is not a clear", "a.yml", "- name: t\n  ansible.builtin.command: sssctl domain-status ipa.example\n", 0},
		{"sssctl cache-expire as a yaml argv list", "a.yml", "- name: t\n  ansible.builtin.command:\n    argv: [sssctl, cache-expire, -E]\n", 1},
		{"sssctl cache-remove as a yaml argv list", "a.yml", "- name: t\n  ansible.builtin.command:\n    argv: [\"sssctl\", \"cache-remove\", \"-o\"]\n", 1},
		{"sssctl cache-expire as a python argv list", "files/h.py", "import subprocess\nsubprocess.run([\"sssctl\", \"cache-expire\", \"-E\"])\n", 1},
		{"sssctl config-check as a yaml argv list is not a clear", "a.yml", "- name: t\n  ansible.builtin.command:\n    argv: [sssctl, config-check]\n", 0},
		{"sssctl domain-status as a python argv list is not a clear", "files/h.py", "import subprocess\nsubprocess.run([\"sssctl\", \"domain-status\", \"ipa.example\"])\n", 0},
		{"yaml task name that mentions the tool is prose", "a.yml", "- name: \"flush with sss_cache -E after reconciliation\"\n  ansible.builtin.debug:\n    msg: ok\n", 0},
		{"yaml task name does not hide the real call", "a.yml", "- name: \"flush with sss_cache -E\"\n  ansible.builtin.command:\n    argv: [sss_cache, -E]\n", 1},
		{"python module docstring is prose", "files/h.py", "\"\"\"Runs sss_cache -E on the host.\n\nsss_cache only expires held rules.\n\"\"\"\nprint('x')\n", 0},
		{"python one-line docstring is prose", "files/h.py", "def f():\n    \"\"\"Say what happened after sss_cache failed.\"\"\"\n    return 1\n", 0},
		{"python docstring does not hide the real call", "files/h.py", "\"\"\"Mentions sss_cache.\"\"\"\nimport subprocess\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"python triple-quoted shell script is code", "files/h.py", "import subprocess\nsubprocess.run(\"\"\"\nsss_cache -E\n\"\"\", shell=True)\n", 1},
		{"python assigned triple-quoted string is code", "files/h.py", "CMD = \"\"\"sss_cache -E\n\"\"\"\n", 1},

		// The delimiter that closes a string that is not a docstring must not look
		// like the start of one: it used to hide every line up to the next
		// triple quote, so a real call after it was never scanned.
		{"call after an assigned multi-line string", "files/h.py", "X = \"\"\"\nhello\n\"\"\"\nimport subprocess\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"call after an assigned multi-line string, single quotes", "files/h.py", "X = '''\nhello\n'''\nimport subprocess\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"call after a multi-line string argument closed by shell=True", "files/h.py", "import subprocess\nsubprocess.run(\"\"\"\necho hi\n\"\"\", shell=True)\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"call after a multi-line string argument closed by shell=True, single quotes", "files/h.py", "import subprocess\nsubprocess.run('''\necho hi\n''', shell=True)\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"call after a multi-line string with a method call", "files/h.py", "import subprocess\nTEXT = \"\"\"\nhello {}\n\"\"\".format(1)\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"string argument on its own continuation line is code", "files/h.py", "import subprocess\nsubprocess.run(\n    \"\"\"sss_cache -E\"\"\",\n    shell=True,\n)\n", 1},
		{"string argument on its own continuation line is code, single quotes", "files/h.py", "import subprocess\nsubprocess.run(\n    '''sss_cache -E''',\n    shell=True,\n)\n", 1},
		{"string argument on its own continuation line, nothing after it, is code", "files/h.py", "import subprocess\nsubprocess.run(\n    \"\"\"sss_cache -E\"\"\"\n)\n", 1},
		{"string in a list literal is code", "files/h.py", "CMDS = [\n    \"\"\"sss_cache -E\"\"\",\n]\n", 1},
		{"string in a list literal, nothing after it, is code", "files/h.py", "CMDS = [\n    \"\"\"sss_cache -E\"\"\"\n]\n", 1},
		{"string joined to the previous line by a backslash is code", "files/h.py", "CMD = \"echo \" + \\\n    \"\"\"sss_cache -E\"\"\"\n", 1},
		{"f-string statement is code", "files/h.py", "f\"\"\"sss_cache {1}\"\"\"\n", 1},
		{"triple quotes inside a single-quoted string do not open a docstring", "files/h.py", "X = '\"\"\"'\nimport subprocess\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"a docstring followed by more code", "files/h.py", "\"\"\"Mentions\nsss_cache here.\n\"\"\"\nimport subprocess\nsubprocess.run([\"sss_cache\", \"-E\"])\n", 1},
		{"a function docstring that mentions the tool, then the real call", "files/h.py", "import subprocess\n\ndef flush():\n    \"\"\"Expire everything with sss_cache -E.\n\n    sss_cache only expires held rules.\n    \"\"\"\n    subprocess.run([\"sss_cache\", \"-E\"], check=False)\n", 1},
		{"a docstring with an apostrophe and a trailing comment is prose", "files/h.py", "def f():\n    '''Don't call sss_cache.'''  # sss_cache\n    return 1\n", 0},
		{"a raw docstring is prose", "files/h.py", "def f():\n    r\"\"\"Uses sss_cache \\n literally.\"\"\"\n    return 1\n", 0},
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

// TestSSSDPythonProseLines pins which lines the scanner calls prose. The detector
// cases above only see it through a hit count; this one also fails on a line that
// is marked, or left unmarked, for the wrong reason.
func TestSSSDPythonProseLines(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []int
	}{
		{"module docstring", "\"\"\"a\nb\n\"\"\"\nx = 1\n", []int{1, 2, 3}},
		{"one-line docstring in a function", "def f():\n    \"\"\"a\"\"\"\n    return 1\n", []int{2}},
		{"assigned string: interior and closing line are code", "X = '''\na\n'''\nx = 1\n", nil},
		{"string argument closed on its own line", "f('''\na\n''', 1)\nx = 1\n", nil},
		{"docstring, then an assigned string", "\"\"\"a\"\"\"\nX = \"\"\"\nb\n\"\"\"\n", []int{1}},
		{"code after the closing quotes", "\"\"\"a\"\"\"; x = 1\n", nil},
		{"a method call on the string", "\"\"\"a\"\"\".strip()\n", nil},
		{"a comment after the closing quotes", "\"\"\"a\n\"\"\"  # c\n", []int{1, 2}},
		{"an escaped triple quote does not close the docstring", "\"\"\"a \\\"\"\" b\n\"\"\"\n", []int{1, 2}},
		{"an apostrophe in a comment or a string opens nothing", "# don't\ns = \"it's\"\n\"\"\"a\"\"\"\n", []int{3}},
		{"triple quotes inside a single-quoted string", "x = '\"\"\"'\n\"\"\"a\"\"\"\n", []int{2}},
		{"a backslash joins the string to the previous line", "x = 1 + \\\n\"\"\"a\"\"\"\n", nil},
		{"a backslash continues a single-quoted string", "x = 'a\\\nb'\n\"\"\"c\"\"\"\n", []int{3}},
		{"a statement after a bracketed expression starts fresh", "x = [\n    1,\n]\n\"\"\"a\"\"\"\n", []int{4}},
		{"an unterminated triple-quoted string is code", "\"\"\"a\nb\n", nil},
		{"carriage returns and a byte order mark", "\xef\xbb\xbf\"\"\"a\r\nb\"\"\"\r\nx = 1\r\n", []int{1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []int
			for l := range pythonProseLines([]byte(tc.src)) {
				got = append(got, l)
			}
			sort.Ints(got)
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Fatalf("prose lines %v, want %v\n%s", got, tc.want, tc.src)
			}
		})
	}
}

// pyASTScript prints, for every file named on its command line, the line ranges
// Python's own parser assigns to docstrings ([first, last, 1 when the literal is
// triple-quoted]) and to every other multi-line string literal ([first, last]).
const pyASTScript = `import ast, json, sys
out = {}
for path in sys.argv[1:]:
    with open(path, 'rb') as f:
        data = f.read()
    text = data.decode('utf-8-sig')
    tree = ast.parse(data, path)
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docs.add(id(first.value))
    entry = {'docstrings': [], 'strings': []}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in docs:
            literal = (ast.get_source_segment(text, node) or '').lstrip('rRuUbBfF')
            entry['docstrings'].append([node.lineno, node.end_lineno, int(literal[:3] in ('"""', "'''"))])
        elif node.end_lineno > node.lineno:
            entry['strings'].append([node.lineno, node.end_lineno])
    out[path] = entry
json.dump(out, sys.stdout)
`

// TestSSSDPythonProseLinesMatchPythonAST runs the scanner over every .py under
// playbooks/ and compares it with Python's own parser: a line the scanner skips
// must belong to a docstring, so code is never hidden (the failure that
// wazuh-transaction.py exposed), and every line of a triple-quoted docstring must
// be skipped, so the stale-entry check is not kept alive by documentation. The
// corpus must contain multi-line strings that are not docstrings, or the
// comparison could not tell the scanner from the line-prefix rule it replaced.
func TestSSSDPythonProseLinesMatchPythonAST(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 is not on PATH, so pythonProseLines is not cross-checked against Python's own ast here: %v", err)
	}
	var files []string
	err = filepath.WalkDir(filepath.Join("..", "..", "playbooks"), func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && filepath.Ext(path) == ".py" {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no .py file under playbooks/")
	}
	sort.Strings(files)
	cmd := exec.Command(python, append([]string{"-I", "-c", pyASTScript}, files...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("python3 could not parse the playbook helpers: %v\n%s", err, stderr.String())
	}
	var pyAST map[string]struct {
		Docstrings [][3]int `json:"docstrings"`
		Strings    [][2]int `json:"strings"`
	}
	if err := json.Unmarshal(out, &pyAST); err != nil {
		t.Fatalf("unreadable ast output: %v\n%s", err, out)
	}
	docstringLines, codeStrings := 0, 0
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		skipped := pythonProseLines(raw)
		inDocstring, inTripleDocstring := map[int]bool{}, map[int]bool{}
		for _, d := range pyAST[file].Docstrings {
			for l := d[0]; l <= d[1]; l++ {
				inDocstring[l] = true
				if d[2] == 1 {
					inTripleDocstring[l] = true
				}
			}
		}
		docstringLines += len(inTripleDocstring)
		codeStrings += len(pyAST[file].Strings)
		for l := 1; l <= len(lines); l++ {
			switch {
			case skipped[l] && !inDocstring[l]:
				t.Errorf("%s:%d is skipped as prose but Python does not see a docstring there, so code is hidden from the SSSD lint: %q", file, l, lines[l-1])
			case inTripleDocstring[l] && !skipped[l]:
				t.Errorf("%s:%d is in a triple-quoted docstring but is scanned as code: %q", file, l, lines[l-1])
			}
		}
	}
	if docstringLines == 0 || codeStrings == 0 {
		t.Fatalf("the corpus has %d triple-quoted docstring lines and %d multi-line strings that are not docstrings; the cross-check needs both to prove anything", docstringLines, codeStrings)
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
	ext := filepath.Ext(name)
	var prose map[int]bool
	if ext == ".py" {
		prose = pythonProseLines(raw)
	}
	for i, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if prose[i+1] {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if (ext == ".yml" || ext == ".yaml") && isYAMLNameLine(trimmed) {
			continue
		}
		switch {
		case reSSSCache.MatchString(line):
			out = append(out, fmt.Sprintf("line %d runs sss_cache", i+1))
		case reSSSCtlCache.MatchString(line):
			out = append(out, fmt.Sprintf("line %d runs sssctl cache-expire/cache-remove", i+1))
		case reRemoveSSSState.MatchString(line):
			out = append(out, fmt.Sprintf("line %d deletes SSSD state under /var/lib/sss", i+1))
		}
	}
	if ext == ".yml" || ext == ".yaml" {
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

// pythonProseLines returns the 1-based numbers of the lines of a Python source
// that are prose: every line of a triple-quoted string that is a statement by
// itself, which is a docstring or a string used as a block comment. Nothing else
// is in the result. In particular the interior and the closing line of a
// triple-quoted string that is assigned, passed to a call (a shell script handed
// to subprocess), formatted or put in a list stay code, and so does every line
// after them.
//
// The first version decided from the prefix of each line, so the closing quotes
// of `X = """..."""` looked like the opening of a docstring and hid the rest of
// the file (apply/files/wazuh-transaction.py: 700 lines of code). This scans the
// whole text instead and tracks what Python's tokenizer tracks: single-line
// strings with escapes and string prefixes, triple-quoted strings, # comments,
// bracket depth and backslash continuations. Whether a string is prose is
// decided once, at its opening delimiter: it is the first token of its logical
// line (depth 0, not a continuation) and only whitespace or a comment follows
// its closing delimiter. Strings inside brackets, after another token, followed
// by `.format(...)`, `%` or a `;`, and f-strings (their replacement fields run
// code) are code.
//
// It is a scanner, not a parser, and it errs toward scanning. Limits: a string
// that shares its line with the header it belongs to (`def f(): """doc"""`) is
// code; adjacent string literals are not joined across lines (that needs
// brackets or a backslash, so they are code anyway); an f-string replacement
// field that reuses the enclosing quote (PEP 701) ends the string early; an
// unterminated triple-quoted string is code. TestSSSDPythonProseLinesMatchPythonAST
// checks the result against Python's own ast for every .py under playbooks/.
func pythonProseLines(raw []byte) map[int]bool {
	src := strings.ReplaceAll(strings.TrimPrefix(string(raw), "\xef\xbb\xbf"), "\r\n", "\n")
	prose := map[int]bool{}
	line, depth := 1, 0
	atStmt := true     // the next token is the first one of its logical line
	continued := false // this physical line ended with a backslash
	for i := 0; i < len(src); {
		switch c := src[i]; {
		case c == '\n':
			if depth == 0 && !continued {
				atStmt = true
			}
			continued = false
			line++
			i++
		case c == ' ' || c == '\t' || c == '\f' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == '\\':
			continued = i+1 < len(src) && src[i+1] == '\n'
			i++
		case c == '(' || c == '[' || c == '{':
			depth++
			atStmt = false
			i++
		case c == ')' || c == ']' || c == '}':
			if depth > 0 {
				depth--
			}
			atStmt = false
			i++
		case isPyWordByte(c) || c == '\'' || c == '"':
			start := i
			for i < len(src) && isPyWordByte(src[i]) {
				i++
			}
			if i == len(src) || (src[i] != '\'' && src[i] != '"') || !isPyStringPrefix(src[start:i]) {
				atStmt = false // a name or a number
				continue
			}
			standalone := atStmt && !strings.ContainsAny(src[start:i], "fF")
			atStmt = false
			opening, triple := line, isPyTripleQuote(src, i)
			end, newlines, closed := scanPyString(src, i)
			i, line = end, line+newlines
			if !standalone || !triple || !closed {
				continue
			}
			tail, _, _ := strings.Cut(src[i:], "\n")
			if tail = strings.TrimSpace(tail); tail == "" || strings.HasPrefix(tail, "#") {
				for l := opening; l <= line; l++ {
					prose[l] = true
				}
			}
		default:
			atStmt = false
			i++
		}
	}
	return prose
}

// scanPyString scans the string literal whose opening quote is src[i]. It
// returns the index after the literal, how many newlines it spans, and whether
// it was terminated. A single-quoted string ends at an unescaped newline; a
// backslash escapes the next byte, a newline included, in raw strings too.
func scanPyString(src string, i int) (end, newlines int, closed bool) {
	delim := src[i : i+1]
	triple := isPyTripleQuote(src, i)
	if triple {
		delim = src[i : i+3]
	}
	for i += len(delim); i < len(src); i++ {
		switch {
		case src[i] == '\\' && i+1 < len(src):
			i++
			if src[i] == '\n' {
				newlines++
			}
		case src[i] == '\n':
			if !triple {
				return i, newlines, false
			}
			newlines++
		case strings.HasPrefix(src[i:], delim):
			return i + len(delim), newlines, true
		}
	}
	return len(src), newlines, false
}

// isPyTripleQuote reports whether the quote at src[i] opens a triple-quoted string.
func isPyTripleQuote(src string, i int) bool {
	return strings.HasPrefix(src[i:], strings.Repeat(src[i:i+1], 3))
}

// isPyWordByte reports whether c can be part of a name, a number or a string prefix.
func isPyWordByte(c byte) bool {
	return c == '_' || c >= 0x80 || (c >= '0' && c <= '9') || ((c|0x20) >= 'a' && (c|0x20) <= 'z')
}

// isPyStringPrefix reports whether word is a legal prefix of a string literal
// (the empty prefix included).
func isPyStringPrefix(word string) bool {
	switch strings.ToLower(word) {
	case "", "r", "u", "b", "f", "br", "rb", "fr", "rf":
		return true
	}
	return false
}

// isYAMLNameLine reports whether a (trimmed) YAML line is a task or play name:,
// which is prose.
func isYAMLNameLine(trimmed string) bool {
	return strings.HasPrefix(trimmed, "name:") || strings.HasPrefix(trimmed, "- name:")
}

// TestSSSDAllowlistProblemsFireBothWays proves the comparison reports a file that
// clears the cache without being listed, and a listed file that no longer does,
// and stays quiet when the two agree.
func TestSSSDAllowlistProblemsFireBothWays(t *testing.T) {
	allow := map[string]string{"a.yml": "reason"}
	if got := sssdAllowlistProblems(map[string][]string{"a.yml": {"line 1 runs sss_cache"}}, allow); len(got) != 0 {
		t.Fatalf("agreeing found and allowlist reported %v", got)
	}
	got := sssdAllowlistProblems(map[string][]string{"a.yml": {"x"}, "b.yml": {"line 3 runs sss_cache"}}, allow)
	if len(got) != 1 || !strings.Contains(got[0], "b.yml clears SSSD's cache") || !strings.Contains(got[0], "line 3 runs sss_cache") {
		t.Fatalf("an unlisted clear must be reported by name with its line, got %v", got)
	}
	got = sssdAllowlistProblems(map[string][]string{}, allow)
	if len(got) != 1 || !strings.Contains(got[0], "a.yml no longer clears SSSD's cache") {
		t.Fatalf("a stale allowlist entry must be reported, got %v", got)
	}
}

// TestSSSDStaleEntryFiresWhenTheRealCallIsRemoved takes the allowlisted files as
// they are, removes only the real call and keeps the documentation that names the
// tool, then requires the scan to find nothing. Before prose was skipped, those
// mentions kept the entry alive and the stale check never fired.
func TestSSSDStaleEntryFiresWhenTheRealCallIsRemoved(t *testing.T) {
	cases := []struct{ file, real, replacement string }{
		{"apply/files/freeipa-sssd-sudo-refresh.py", `["sss_cache", "-E"]`, `["true"]`},
		{"apply/files/freeipa-ssh-key-cache.py", `["sss_cache", "-d", domain, "-u", user]`, `["true"]`},
		{"apply/tasks/freeipa-client-server-failover.yml", `argv: [sss_cache, -E]`, `argv: [true]`},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "playbooks", filepath.FromSlash(tc.file)))
			if err != nil {
				t.Fatal(err)
			}
			before, err := sssdCacheClears(tc.file, raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(before) == 0 {
				t.Fatalf("%s has no detected clear to begin with", tc.file)
			}
			if !strings.Contains(string(raw), tc.real) {
				t.Fatalf("%s no longer contains %q; update this test with the helper", tc.file, tc.real)
			}
			mutated := strings.ReplaceAll(string(raw), tc.real, tc.replacement)
			after, err := sssdCacheClears(tc.file, []byte(mutated))
			if err != nil {
				t.Fatal(err)
			}
			if len(after) != 0 {
				t.Fatalf("the real call is gone but the scan still reports %v, so the stale-entry check cannot fire", after)
			}
		})
	}
}
