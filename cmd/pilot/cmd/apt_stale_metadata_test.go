package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// aptStaleProbeSearchRe extracts the regex apt-download-probe.yml passes
// to its stale-metadata `is search(...)` test, so the Go test below
// exercises the exact pattern the playbook ships — not a copy of it.
var aptStaleProbeSearchRe = regexp.MustCompile(`_pilot_apt_download_probe\.stderr \| default\(''\)\) is search\('([^']+)', multiline=True\)`)

// realStaleIndexDownloadStderr is a verbatim excerpt of `apt-get -y -o
// DPkg::Lock::Timeout=60 install --download-only freeipa-client` (rc=100)
// captured 2026-09-23 on a fresh ubuntu-24.04 vm-target whose golden-image
// apt lists predated the mirror's current krb5/sssd/tzdata-legacy
// versions, through the dev-lite apt-cacher-ng proxy (AGENTS.md §5.6: real
// capture, not a guess). The index still listed a Candidate, so the old
// cache-first check never refreshed and the install died on these 404s.
const realStaleIndexDownloadStderr = "E: Failed to fetch http://security.ubuntu.com/ubuntu/pool/main/t/tzdata/tzdata-legacy_2026a-0ubuntu0.24.04.1_all.deb  404  Not Found [IP: 192.168.122.1 3142]\n" +
	"E: Failed to fetch http://security.ubuntu.com/ubuntu/pool/main/k/krb5/libgssrpc4t64_1.20.1-6ubuntu2.6_amd64.deb  404  Not Found [IP: 192.168.122.1 3142]\n" +
	"E: Failed to fetch http://security.ubuntu.com/ubuntu/pool/main/s/sssd/sssd_2.9.4-1.1ubuntu6.5_amd64.deb  404  Not Found [IP: 192.168.122.1 3142]\n" +
	"E: Some files failed to download\n"

// TestAptPackageInstallStaleMetadataProbe locks the fix for spec.md §5's
// "install 顯示 metadata stale → global refresh → retry install" branch
// (docs/superpowers/specs/2026-09-14-apt-repository-fault-tolerance-spec.md):
// a cache hit is probed with --download-only before the single real
// install, and a package-download 404 flips the flow onto the existing
// refresh path. It also re-asserts the invariants the probe must not
// break: exactly one ansible.builtin.apt task, and no refresh for a probe
// failure that is not a 404.
func TestAptPackageInstallStaleMetadataProbe(t *testing.T) {
	text := readAptTask(t, "apt-package-install.yml")
	probe := readAptTask(t, "apt-download-probe.yml")

	for _, required := range []string{
		"include_tasks: apt-download-probe.yml",
		"pilot_apt_probe_stage: cache_hit",
		"_pilot_apt_stale_metadata: true",
		"package_download_404",
		"_pilot_apt_policy != 'offline'",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("apt-package-install.yml missing %q", required)
		}
	}
	if !strings.Contains(probe, "- --download-only") {
		t.Errorf("apt-download-probe.yml no longer runs apt-get install --download-only")
	}
	if n := strings.Count(text, "ansible.builtin.apt:"); n != 1 {
		t.Errorf("apt-package-install.yml has %d ansible.builtin.apt tasks, want exactly 1 (the single sanctioned mutation point)", n)
	}
	if strings.Contains(probe, "ansible.builtin.apt:") {
		t.Errorf("apt-download-probe.yml must never install: it has an ansible.builtin.apt task")
	}

	m := aptStaleProbeSearchRe.FindStringSubmatch(probe)
	if m == nil {
		t.Fatalf("could not find the stale-metadata `is search(...)` pattern in apt-download-probe.yml")
	}
	re, err := regexp.Compile("(?m)" + m[1])
	if err != nil {
		t.Fatalf("stale-metadata pattern %q does not compile: %v", m[1], err)
	}
	if !re.MatchString(realStaleIndexDownloadStderr) {
		t.Errorf("stale-metadata pattern %q does not match the real stale-index capture", m[1])
	}
	// Non-404 failures must stay on the old path (the real install reports
	// them). Both are real captures: "connection refused" from the same
	// 2026-09-23 vm-target with Acquire::http::Proxy pointed at a closed
	// port; the lock failure is TestAptClassifyFailureScriptRealCaptures's
	// own captured non-root apt lock error.
	for name, stderr := range map[string]string{
		"connection refused": "E: Failed to fetch http://archive.ubuntu.com/ubuntu/pool/universe/s/sl/sl_5.02-1_amd64.deb  Could not connect to 127.0.0.1:9 (127.0.0.1). - connect (111: Connection refused)\n" +
			"E: Some files failed to download\n",
		"lock": "E: Could not open lock file /var/lib/apt/lists/lock - open (13: Permission denied)\n" +
			"E: Unable to lock directory /var/lib/apt/lists/\n",
		"success": "",
	} {
		if re.MatchString(stderr) {
			t.Errorf("stale-metadata pattern must not match %s output %q", name, stderr)
		}
	}
}

func readAptTask(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "..", "playbooks", "apply", "tasks", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

// TestAptNetworkStepsHaveWallClock locks the 2026-09-23 fix for a hung
// refresh: apt-get update sat on a half-closed connection to a caching
// proxy with no end, blocking the whole play. Every apt-get network step in
// the shared framework must run under coreutils `timeout` with its
// documented default, and a timeout (rc 124/-9) must never read as a
// healthy refresh.
func TestAptNetworkStepsHaveWallClock(t *testing.T) {
	for _, tc := range []struct {
		file, bound string
	}{
		{"apt-cache-refresh.yml", "pilot_apt_update_timeout_seconds | default(300)"},
		{"apt-scoped-refresh.yml", "pilot_apt_update_timeout_seconds | default(300)"},
		{"apt-download-probe.yml", "pilot_apt_download_timeout_seconds | default(900)"},
	} {
		text := readAptTask(t, tc.file)
		for _, required := range []string{"timeout", "--kill-after=30", tc.bound, "in [124, 137, -9]"} {
			if !strings.Contains(text, required) {
				t.Errorf("%s missing %q", tc.file, required)
			}
		}
		// No apt-get invocation may bypass the wall clock: every command
		// that runs apt-get must be the argv form that starts with timeout.
		if regexp.MustCompile(`(?m)^\s*cmd:\s*(>-\s*)?\n?\s*apt-get`).MatchString(text) {
			t.Errorf("%s runs apt-get through cmd: without the timeout wrapper", tc.file)
		}
	}
	for _, file := range []string{"apt-cache-refresh.yml", "apt-scoped-refresh.yml"} {
		if !strings.Contains(readAptTask(t, file), "'type': 'refresh_timeout'") {
			t.Errorf("%s does not record a refresh_timeout error", file)
		}
	}
	if !strings.Contains(readAptTask(t, "apt-cache-refresh.yml"), "and not (_pilot_apt_global_timed_out | bool)") {
		t.Errorf("apt-cache-refresh.yml: a timed-out global refresh must not count as required_sources_healthy")
	}
	if !strings.Contains(readAptTask(t, "apt-download-probe.yml"), "reason=apt_download_timeout") {
		t.Errorf("apt-download-probe.yml: a timed-out probe must FATAL with reason=apt_download_timeout")
	}
}

// TestAptTimeoutExitCodes checks the rc values the playbooks treat as a
// timeout against the real coreutils `timeout` on this machine, run through
// Python's subprocess the way Ansible's command module runs it (AGENTS.md
// §5.6: real behavior, not a remembered convention): 124 when TERM ends the
// command, -9 when --kill-after has to KILL it — `timeout` KILLs its whole
// process group, itself included, so there is no exit status 137 to see.
func TestAptTimeoutExitCodes(t *testing.T) {
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("coreutils timeout not installed")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not installed")
	}
	const script = `import subprocess
for s in ["sleep 5", "trap '' TERM; sleep 5"]:
    print(subprocess.run(["timeout", "--kill-after=1", "1", "sh", "-c", s]).returncode)
`
	out, err := exec.Command("python3", "-c", script).Output()
	if err != nil {
		t.Fatalf("python3: %v", err)
	}
	if got := strings.Fields(string(out)); len(got) != 2 || got[0] != "124" || got[1] != "-9" {
		t.Fatalf("timeout rc as Python sees it = %q, want [124 -9]", got)
	}
	for _, file := range []string{"apt-cache-refresh.yml", "apt-scoped-refresh.yml", "apt-download-probe.yml"} {
		if !strings.Contains(readAptTask(t, file), "in [124, 137, -9]") {
			t.Errorf("%s must treat rc 124 and -9 (and 137 via a shell) as a timeout", file)
		}
	}
}

// TestAptStaleMetadataNeedsWorkingRefresh locks the second half of the
// 2026-09-23 fix: after a stale-metadata refresh, the old index still lists
// the old candidate, so "candidate exists" proves nothing. The install may
// proceed only after a refresh that was healthy for the required sources
// AND a re-probe without 404s; otherwise it must FATAL with
// reason=stale_metadata_unrecovered.
func TestAptStaleMetadataNeedsWorkingRefresh(t *testing.T) {
	text := readAptTask(t, "apt-package-install.yml")
	for _, required := range []string{
		"not (pilot_apt_refresh_result.required_sources_healthy | bool)",
		"pilot_apt_probe_stage: after_global_refresh",
		"pilot_apt_probe_stage: after_scoped_refresh",
		"stale_metadata_unrecovered",
		// per-include reset: freeipa-client includes this file twice
		"_pilot_apt_stale_metadata: false",
		"pilot_apt_download_probe_result: {}",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("apt-package-install.yml missing %q", required)
		}
	}
	// Both re-probes must come before the single install, and the
	// after-global re-probe must sit inside the refresh block, after the
	// global refresh include.
	install := strings.Index(text, "ansible.builtin.apt:")
	global := strings.Index(text, "include_tasks: apt-cache-refresh.yml")
	for _, stage := range []string{"after_global_refresh", "after_scoped_refresh"} {
		i := strings.Index(text, "pilot_apt_probe_stage: "+stage)
		if i < global || i > install {
			t.Errorf("re-probe %s must run after the global refresh and before the install", stage)
		}
	}
	// A block's `when:` is re-evaluated per task: gating the refresh blocks
	// on _pilot_apt_has_candidate itself skipped the stale checks the moment
	// the post-refresh re-check flipped it to true (found live 2026-09-23).
	for _, gate := range []string{"when: _pilot_apt_needs_refresh | bool", "when: _pilot_apt_needs_scoped_refresh | bool"} {
		if !strings.Contains(text, gate) {
			t.Errorf("apt-package-install.yml: refresh block must be gated by a fixed fact (%q)", gate)
		}
	}
	if regexp.MustCompile(`(?m)^\s*when: not _pilot_apt_has_candidate\s*\n\s*block:`).MatchString(text) {
		t.Errorf("apt-package-install.yml: a block gated on `not _pilot_apt_has_candidate` skips its own later tasks once the candidate re-check succeeds")
	}
	if n := strings.Count(text, "reason={{ 'stale_metadata_unrecovered' if _pilot_apt_stale_unrecovered else 'required_source_unhealthy' }}"); n != 3 {
		t.Errorf("want all 3 no-candidate FATALs to report stale_metadata_unrecovered on the stale path, found %d", n)
	}
}
