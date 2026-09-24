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
	"fmt"
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

// aptDirectInstallAllowlist is a ratchet like aptUpdateCacheAllowlist, for
// the other way around the framework: installing a package on the Debian
// path with plain ansible.builtin.apt / ansible.builtin.package and no
// update_cache at all. That installs from whatever apt index the host
// already has, so a stale index 404s and fails the apply (2026-09-24:
// tasks/freeipa-dns-client-resolver.yml's dnsutils install on the vm-target
// golden image, docs/evidence/freeipa-dns-client/2026-09-24-583df40.md).
// The entries below were found by the same sweep and not migrated yet:
// moving each one changes which apt path its playbook runs and needs its
// own vm-target run. Keys are "<file>|<package list>".
var aptDirectInstallAllowlist = map[string]string{
	"playbooks/apply/dcgm-exporter-apply.yml|apache2-utils":                                                                                     "not yet migrated (2026-09-24 sweep)",
	"playbooks/apply/freeipa-client-apply.yml|{{ ipa_audit_packages_debian":                                                                     "not yet migrated (2026-09-24 sweep); package name is chosen per OS family",
	"playbooks/apply/freeipa-nfs-client-apply.yml|{{ ['nfs-utils', 'autofs'] if ansible_os_family == 'RedHat' else ['nfs-common', 'autofs'] }}": "not yet migrated (2026-09-24 sweep); package name is chosen per OS family",
	"playbooks/apply/freeipa-nfs-server-apply.yml|{{ nfs_server_packages }}":                                                                    "not yet migrated (2026-09-24 sweep)",
}

// TestAptDirectInstallAllowlist fails on any Debian-reachable package
// install in playbooks/apply that bypasses tasks/apt-package-install.yml
// and is not in aptDirectInstallAllowlist, and on allowlist entries that
// no longer match anything. A task counts as EL-only, and is skipped, when
// its `when:` mentions RedHat.
func TestAptDirectInstallAllowlist(t *testing.T) {
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
		rel, err := filepath.Rel(root, p)
		if err != nil {
			t.Fatal(err)
		}
		rel = filepath.ToSlash(rel)
		if rel == "playbooks/apply/tasks/apt-package-install.yml" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		for _, pkgs := range directDebianInstalls(doc) {
			key := rel + "|" + pkgs
			// Allowlist keys may be a prefix of a long templated name.
			matched := ""
			for allowed := range aptDirectInstallAllowlist {
				if key == allowed || strings.HasPrefix(key, allowed) {
					matched = allowed
				}
			}
			if matched == "" {
				t.Errorf("%s installs %q with plain ansible.builtin.apt/package on the Debian path — route it through playbooks/apply/tasks/apt-package-install.yml (a stale apt index otherwise 404s and fails the apply), or add %q to aptDirectInstallAllowlist with a reason", rel, pkgs, key)
				continue
			}
			found[matched] = true
		}
	}
	for allowed := range aptDirectInstallAllowlist {
		if !found[allowed] {
			t.Errorf("aptDirectInstallAllowlist entry %q no longer matches any install — drop the stale allowance", allowed)
		}
	}
}

// directDebianInstalls returns the package spec (as written) of every task
// in doc that installs with ansible.builtin.apt or ansible.builtin.package
// and is not limited to RedHat by its `when:`.
func directDebianInstalls(doc any) []string {
	var out []string
	var walk func(n any)
	walk = func(n any) {
		switch v := n.(type) {
		case []any:
			for _, c := range v {
				walk(c)
			}
		case map[string]any:
			for _, key := range []string{"ansible.builtin.apt", "apt", "ansible.builtin.package", "package"} {
				args, ok := v[key].(map[string]any)
				if !ok {
					continue
				}
				name, ok := args["name"]
				if !ok {
					continue
				}
				if strings.Contains(fmt.Sprint(v["when"]), "RedHat") {
					continue
				}
				if list, ok := name.([]any); ok {
					parts := make([]string, len(list))
					for i, item := range list {
						parts[i] = fmt.Sprint(item)
					}
					out = append(out, strings.Join(parts, ","))
				} else {
					out = append(out, strings.TrimSpace(fmt.Sprint(name)))
				}
			}
			for _, c := range v {
				walk(c)
			}
		}
	}
	walk(doc)
	return out
}

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
