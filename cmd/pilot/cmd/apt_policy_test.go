package cmd

// TestAptUpdateCacheAllowlist, TestAptNoInsecureFlags, and
// TestAptClassifyFailureScript machine-enforce docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md §21.2
// / §21.3: ordinary apply playbooks must install Debian/Ubuntu packages
// through playbooks/apply/tasks/apt-package-install.yml instead of a bare
// `ansible.builtin.apt` + `update_cache: true`, so an unrelated broken
// third-party repository can never fail a capability that never needed
// it (the x64-deliver-bbq / freeipa-client incident these tests guard
// against — docs/verification/apt-repository-tolerance.md).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// bareAptPackageInstallInclude matches a plain-string
// `ansible.builtin.include_tasks: tasks/apt-package-install.yml` (or the
// nested-block equivalent) with no `file:`/`apply:` form. Found live
// (2026-09-14, vm-target apt-tolerance-test): a dynamic include_tasks's
// own `tags:` gates only the include statement itself — it is NOT
// inherited by the tasks it pulls in (unlike a static import_tasks),
// which import_tasks itself can't be used for here since several task
// `name:` fields template a variable set earlier in the same file
// (`_pilot_apt_policy`), which import_tasks tries to resolve at parse
// time, before any task has run. Running `pilot vm-target run ... --tags
// C1` (a normal per-row dev workflow, AGENTS.md §4) against
// freeipa-client-apply.yml silently completed with ok=0 failures and
// installed nothing — no error, just a no-op — until every call site
// was converted to the `file: ... / apply: {tags: [...]}` form.
var bareAptPackageInstallInclude = regexp.MustCompile(`include_tasks:\s*tasks/apt-package-install\.yml\s*$`)

func TestAptPackageInstallCallSitesUseApplyTags(t *testing.T) {
	root := "../../.."
	paths, err := filepath.Glob(filepath.Join(root, "playbooks", "apply", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		for i, line := range strings.Split(string(data), "\n") {
			if bareAptPackageInstallInclude.MatchString(line) {
				t.Errorf("%s:%d: bare `include_tasks: tasks/apt-package-install.yml` with no apply.tags — "+
					"a caller-scoped --tags filter (e.g. --tags C1) will silently skip every task inside it "+
					"and install nothing, with no error. Use the `file: .../ apply: {tags: [...]}` form "+
					"(see any existing call site, e.g. playbooks/apply/docker-apply.yml) with apply.tags "+
					"matching this task's own tags.", rel, i+1)
			}
		}
	}
}

// aptUpdateCacheAllowlist is a ratchet, not an escape hatch: every entry
// must still exist on disk AND still contain a bare `update_cache: true`
// — a stale entry (the file was migrated but the allowance never
// dropped) fails just as loudly as an unlisted new one. Migrating a file
// off this list is the expected way it shrinks (docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md §16
// Phase 2-4); adding to it requires a reason, same as
// specTagMap/tagCheckExemptSpecs above.
var aptUpdateCacheAllowlist = map[string]string{
	"playbooks/apply/os-patch-sla-apply.yml": "OS patch semantics require the entire configured package universe to be trustworthy, not just one required source (spec.md §17, Non-Goal 7) — never migrate to tolerant",
}

var updateCacheTruePattern = regexp.MustCompile(`update_cache:\s*true\b`)

func TestAptUpdateCacheAllowlist(t *testing.T) {
	root := "../../.."
	var paths []string
	for _, pattern := range []string{
		filepath.Join(root, "playbooks", "apply", "*.yml"),
		filepath.Join(root, "playbooks", "apply", "tasks", "*.yml"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}

	found := map[string]bool{}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		hit := false
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			if updateCacheTruePattern.MatchString(line) {
				hit = true
				break
			}
		}
		if hit {
			found[rel] = true
			if _, ok := aptUpdateCacheAllowlist[rel]; !ok {
				t.Errorf("playbook %s has a bare `update_cache: true` install — route it through playbooks/apply/tasks/apt-package-install.yml instead (docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md §21.3), or add it to aptUpdateCacheAllowlist here with a reason", rel)
			}
		}
	}
	for rel, reason := range aptUpdateCacheAllowlist {
		if !found[rel] {
			t.Errorf("aptUpdateCacheAllowlist entry %q (%s) no longer has update_cache: true — drop the stale allowance", rel, reason)
		}
	}
}

var insecureAptPatterns = []string{
	"trusted=yes",
	"allow_unauthenticated",
	"--allow-unauthenticated",
	"--force-yes",
	"Acquire::AllowInsecureRepositories",
}

// TestAptNoInsecureFlags scans non-comment lines only: several of the new
// apt-*.yml task files' own header comments document these strings as
// forbidden (so a maintainer reading the file sees the rule), which would
// otherwise false-positive a naive whole-file grep.
func TestAptNoInsecureFlags(t *testing.T) {
	root := "../../.."
	var paths []string
	for _, pattern := range []string{
		filepath.Join(root, "playbooks", "apply", "*.yml"),
		filepath.Join(root, "playbooks", "apply", "tasks", "*.yml"),
	} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, m...)
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, pat := range insecureAptPatterns {
				if strings.Contains(line, pat) {
					t.Errorf("%s:%d uses forbidden insecure APT flag %q (docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md §25 MUST NOT) — never disable APT signature verification", rel, i+1, pat)
				}
			}
		}
	}
}

// loadClassifyScript extracts the embedded Python classifier from
// apt-classify-failure.yml so this test always exercises the real,
// shipped script rather than a copy that could silently drift.
func loadClassifyScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "playbooks", "apply", "tasks", "apt-classify-failure.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(data, &tasks); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, task := range tasks {
		varsRaw, ok := task["vars"]
		if !ok {
			continue
		}
		varsMap, ok := varsRaw.(map[string]any)
		if !ok {
			continue
		}
		if script, ok := varsMap["_pilot_apt_classify_py"].(string); ok {
			return script
		}
	}
	t.Fatalf("could not find _pilot_apt_classify_py in %s", path)
	return ""
}

type classifyResult struct {
	Errors []struct {
		Source           string `json:"source"`
		Type             string `json:"type"`
		KeyID            string `json:"key_id"`
		Required         bool   `json:"required"`
		RequiredSourceID string `json:"required_source_id"`
		Raw              string `json:"raw"`
	} `json:"errors"`
	HasUnknown bool `json:"has_unknown"`
}

func runClassify(t *testing.T, script, stdout, stderr string, requiredSources []map[string]string) classifyResult {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not found on PATH — skipping (the framework requires it on managed hosts, not on the machine running go test)")
	}
	if requiredSources == nil {
		requiredSources = []map[string]string{}
	}
	reqJSON, err := json.Marshal(requiredSources)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", "-c", script)
	cmd.Env = append(os.Environ(),
		"PILOT_APT_REQUIRED_SOURCES="+string(reqJSON),
		"PILOT_APT_STDOUT="+stdout,
		"PILOT_APT_STDERR="+stderr,
	)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("classify script failed: %v\nstderr shown separately if captured by exec.Error", err)
	}
	var result classifyResult
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("classify script produced invalid JSON: %v\noutput: %s", err, out)
	}
	return result
}

// TestAptClassifyFailureScriptRealCaptures feeds the classifier apt-get
// output CAPTURED FOR REAL on a live Ubuntu 24.04 host (this dev
// machine), not hand-typed guesses — AGENTS.md §5.6 / the
// pilot-external-cli-fixture-must-be-real-capture lesson. Capturing these
// found two real bugs before they shipped: apt's actual 404 wording is
// "File not found" (not "Not Found"), on an unprefixed continuation line
// the original per-line "W:/E:/Err:" prefix filter silently dropped; and
// a non-root apt-get failure says "Could not open lock file", not only
// "Could not get lock".
func TestAptClassifyFailureScriptRealCaptures(t *testing.T) {
	script := loadClassifyScript(t)

	t.Run("real_404_on_release_file", func(t *testing.T) {
		// Captured via: a local python3 http.server serving an empty
		// directory, apt-get -o Dir::Etc::sourcelist=... update against
		// it with Dir::State::lists/Dir::Cache redirected to a scratch
		// dir (Ubuntu 24.04, apt-get from noble).
		stderr := "Ign:1 http://127.0.0.1:18924/repo noble InRelease\n" +
			"Err:2 http://127.0.0.1:18924/repo noble Release\n" +
			"  404  File not found [IP: 127.0.0.1 18924]\n" +
			"Reading package lists...\n" +
			"E: The repository 'http://127.0.0.1:18924/repo noble Release' does not have a Release file."
		result := runClassify(t, script, "", stderr, nil)
		if result.HasUnknown {
			t.Errorf("expected no unknown classifications, got has_unknown=true: %+v", result.Errors)
		}
		var types []string
		for _, e := range result.Errors {
			types = append(types, e.Type)
		}
		wantAny := map[string]bool{"http_404": false, "release_missing": false}
		for _, ty := range types {
			if _, ok := wantAny[ty]; ok {
				wantAny[ty] = true
			}
		}
		for ty, seen := range wantAny {
			if !seen {
				t.Errorf("expected classification %q among %v", ty, types)
			}
		}
		for _, e := range result.Errors {
			if e.Source != "127.0.0.1:18924" {
				t.Errorf("entry %+v: expected source 127.0.0.1:18924 (inherited from the Err:/Ign: header line), got %q", e, e.Source)
			}
		}
	})

	t.Run("real_non_root_apt_lock_failure", func(t *testing.T) {
		// Captured via: running `apt-get update` as a non-root user on
		// this real Ubuntu 24.04 host (genuine permission-denied lock
		// failure, not simulated).
		stderr := "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\n" +
			"E: Unable to lock directory /var/lib/apt/lists/\n" +
			"W: Problem unlinking the file /var/cache/apt/pkgcache.bin - RemoveCaches (13: Permission denied)"
		result := runClassify(t, script, "", stderr, nil)
		if result.HasUnknown {
			t.Errorf("expected no unknown classifications, got has_unknown=true: %+v", result.Errors)
		}
		if len(result.Errors) != 2 {
			t.Fatalf("expected exactly 2 classified errors (the two E: lines), got %d: %+v", len(result.Errors), result.Errors)
		}
		for _, e := range result.Errors {
			if e.Type != "apt_lock" {
				t.Errorf("entry %+v: expected type apt_lock", e)
			}
		}
	})
}

// TestAptClassifyFailureScriptGPGNoPubkey uses the exact incident text
// from docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md (host x64-deliver-bbq, HashiCorp repository,
// key FC9CA96ACA026560) — real reported evidence, not a guess — wrapped
// in the well-known, version-stable apt-get "GPG error" line shape.
func TestAptClassifyFailureScriptGPGNoPubkey(t *testing.T) {
	script := loadClassifyScript(t)
	stderr := "W: GPG error: https://apt.releases.hashicorp.com stable InRelease: " +
		"The following signatures couldn't be verified because the public key is not available: NO_PUBKEY FC9CA96ACA026560\n" +
		"E: The repository 'https://apt.releases.hashicorp.com stable InRelease' is not signed."
	result := runClassify(t, script, "", stderr, nil)
	foundNoPubkey := false
	for _, e := range result.Errors {
		if e.Type == "gpg_no_pubkey" {
			foundNoPubkey = true
			if e.KeyID != "FC9CA96ACA026560" {
				t.Errorf("expected key_id FC9CA96ACA026560, got %q", e.KeyID)
			}
			if e.Source != "apt.releases.hashicorp.com" {
				t.Errorf("expected source apt.releases.hashicorp.com, got %q", e.Source)
			}
			if e.Required {
				t.Errorf("HashiCorp source must not be classified as required with no required_sources declared")
			}
		}
	}
	if !foundNoPubkey {
		t.Fatalf("expected a gpg_no_pubkey classification, got %+v", result.Errors)
	}
}

// TestAptClassifyFailureScriptRequiredSourceMatching verifies the
// "pilot"-class required-source matching (hostnames read from the
// caller-declared source_file, never guessed) — the only fully hermetic
// way to test required-source attribution, since the "os" class reads
// this machine's real /etc/apt/sources.list.
func TestAptClassifyFailureScriptRequiredSourceMatching(t *testing.T) {
	script := loadClassifyScript(t)
	dir := t.TempDir()
	sourceFile := filepath.Join(dir, "pilot-wazuh.sources")
	if err := os.WriteFile(sourceFile, []byte("deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	requiredSources := []map[string]string{
		{"id": "pilot-wazuh", "class": "pilot", "source_file": sourceFile},
	}

	t.Run("required_source_failure_is_flagged", func(t *testing.T) {
		stderr := "W: GPG error: https://packages.wazuh.com/4.x/apt/ stable InRelease: " +
			"The following signatures couldn't be verified because the public key is not available: NO_PUBKEY 0DCFCA5547B19D2A\n" +
			"E: The repository 'https://packages.wazuh.com/4.x/apt/ stable InRelease' is not signed."
		result := runClassify(t, script, "", stderr, requiredSources)
		found := false
		for _, e := range result.Errors {
			if e.Type == "gpg_no_pubkey" {
				found = true
				if !e.Required {
					t.Errorf("packages.wazuh.com error must be required=true given the declared pilot-wazuh source_file")
				}
				if e.RequiredSourceID != "pilot-wazuh" {
					t.Errorf("expected required_source_id=pilot-wazuh, got %q", e.RequiredSourceID)
				}
			}
		}
		if !found {
			t.Fatalf("expected a gpg_no_pubkey classification, got %+v", result.Errors)
		}
	})

	t.Run("unrelated_source_failure_is_not_flagged", func(t *testing.T) {
		stderr := "W: GPG error: https://apt.releases.hashicorp.com stable InRelease: " +
			"The following signatures couldn't be verified because the public key is not available: NO_PUBKEY FC9CA96ACA026560\n" +
			"E: The repository 'https://apt.releases.hashicorp.com stable InRelease' is not signed."
		result := runClassify(t, script, "", stderr, requiredSources)
		for _, e := range result.Errors {
			if e.Type == "gpg_no_pubkey" && e.Required {
				t.Errorf("HashiCorp error must not be required=true when only pilot-wazuh is declared required: %+v", e)
			}
		}
	})
}

// TestAptClassifyFailureScriptUnknown ensures a genuinely unrecognized
// hard apt error is surfaced as "unknown" rather than silently dropped
// (docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md §10: "Classification 不得把未知 package install
// error 靜默降級").
func TestAptClassifyFailureScriptUnknown(t *testing.T) {
	script := loadClassifyScript(t)
	stderr := "E: Some genuinely novel apt failure mode nobody has classified yet"
	result := runClassify(t, script, "", stderr, nil)
	if !result.HasUnknown {
		t.Fatalf("expected has_unknown=true, got %+v", result)
	}
	found := false
	for _, e := range result.Errors {
		if e.Type == "unknown" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an 'unknown' classified entry, got %+v", result.Errors)
	}
}

// TestAptInstallRetriesOnlyAfterStaleIndexFetch locks the install's
// rescue path: a fetch failure from stale cached indexes (captured live
// on a fresh cloud image behind an apt proxy) refreshes once and retries;
// every other failure, and any failure under the offline policy, stays
// FATAL (spec.md §5 tolerant flow, §25 "unknown install failure
// conservative fatal", T10).
func TestAptInstallRetriesOnlyAfterStaleIndexFetch(t *testing.T) {
	data, err := os.ReadFile("../../../playbooks/apply/tasks/apt-package-install.yml")
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(data, &tasks); err != nil {
		t.Fatal(err)
	}
	var install map[string]any
	var find func([]map[string]any)
	find = func(ts []map[string]any) {
		for _, task := range ts {
			if name, _ := task["name"].(string); strings.Contains(name, "install, refreshing once if the cached indexes are stale") {
				install = task
			}
			for _, key := range []string{"block", "rescue"} {
				if nested, ok := task[key].([]any); ok {
					find(toTaskList(nested))
				}
			}
		}
	}
	find(tasks)
	if install == nil {
		t.Fatal("the final install block with its stale-index rescue is missing")
	}
	block := toTaskList(install["block"].([]any))
	rescue := toTaskList(install["rescue"].([]any))
	if len(block) != 1 || block[0]["ansible.builtin.apt"] == nil {
		t.Fatalf("the block must hold only the single install, got %v", block)
	}
	for _, task := range append(append([]map[string]any{}, block...), rescue...) {
		if _, ok := task["ignore_errors"]; ok {
			t.Errorf("task %q must not use ignore_errors (spec.md §25)", task["name"])
		}
	}
	if len(rescue) != 5 {
		t.Fatalf("rescue must be: fatal gate, refresh, health gate, one retry, mode fact; got %d tasks", len(rescue))
	}
	gate, _ := rescue[0]["when"].(string)
	if rescue[0]["ansible.builtin.fail"] == nil || !strings.Contains(gate, "_pilot_apt_policy == 'offline' or") {
		t.Fatalf("the rescue must first re-raise every non-stale failure and every offline failure, got when=%q", gate)
	}
	if inc, _ := rescue[1]["ansible.builtin.include_tasks"].(string); inc != "apt-cache-refresh.yml" {
		t.Errorf("the rescue must refresh through apt-cache-refresh.yml, got %v", rescue[1])
	}
	if when, _ := rescue[2]["when"].(string); rescue[2]["ansible.builtin.fail"] == nil || when != "not pilot_apt_refresh_result.required_sources_healthy" {
		t.Errorf("a refresh that leaves a required source unhealthy must be FATAL, got %v", rescue[2])
	}
	if rescue[3]["ansible.builtin.apt"] == nil {
		t.Errorf("the rescue must retry the install once, got %v", rescue[3])
	}

	m := regexp.MustCompile(`is search\('([^']+)'\)`).FindStringSubmatch(gate)
	if m == nil {
		t.Fatalf("no search() pattern in the gate %q", gate)
	}
	stale := regexp.MustCompile(m[1])
	raw, err := os.ReadFile("testdata/apt-install-stale-index-404.txt")
	if err != nil {
		t.Fatal(err)
	}
	var captured []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "#") {
			captured = append(captured, line)
		}
	}
	if !stale.MatchString(strings.Join(captured, "\n")) {
		t.Errorf("pattern %q must match the captured stale-index failure", m[1])
	}
	// Real captures of failures a refresh does not fix (Ubuntu 24.04).
	for _, msg := range []string{
		"E: Unable to locate package nosuchpkg-xyz",
		"E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\nE: Unable to lock directory /var/lib/apt/lists/",
	} {
		if stale.MatchString(msg) {
			t.Errorf("pattern %q must not retry %q", m[1], msg)
		}
	}
}

func toTaskList(items []any) []map[string]any {
	var out []map[string]any
	for _, item := range items {
		if task, ok := item.(map[string]any); ok {
			out = append(out, task)
		}
	}
	return out
}

// TestAptUpdateIsBounded: every apt-get update the shared framework runs is
// capped by timeout(1) and apt's own per-request timeout, and a timed-out
// attempt (rc 124) is retried. An unbounded refresh hung a fresh-host
// topology run for over 38 minutes (2026-09-24).
func TestAptUpdateIsBounded(t *testing.T) {
	for _, name := range []string{"apt-cache-refresh.yml", "apt-scoped-refresh.yml"} {
		data, err := os.ReadFile(filepath.Join("../../../playbooks/apply/tasks", name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, want := range []string{
			"pilot_apt_update_timeout_seconds | default(300)",
			"Acquire::http::Timeout={{ pilot_apt_http_timeout_seconds | default(30) }}",
			"Acquire::https::Timeout={{ pilot_apt_http_timeout_seconds | default(30) }}",
			"Acquire::Retries={{ pilot_apt_acquire_retries | default(3) }}",
			"| default(1)) == 124)",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: apt-get update must be bounded; missing %q", name, want)
			}
		}
	}
}
