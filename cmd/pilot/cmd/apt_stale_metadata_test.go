package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// aptStaleProbeSearchRe extracts the regex apt-package-install.yml passes
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
	path := filepath.Join("..", "..", "..", "playbooks", "apply", "tasks", "apt-package-install.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	text := string(data)

	for _, required := range []string{
		"'install', '--download-only'",
		"_pilot_apt_stale_metadata: true",
		"package_download_404",
		"_pilot_apt_policy != 'offline'",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("apt-package-install.yml missing %q", required)
		}
	}
	if n := strings.Count(text, "ansible.builtin.apt:"); n != 1 {
		t.Errorf("apt-package-install.yml has %d ansible.builtin.apt tasks, want exactly 1 (the single sanctioned mutation point)", n)
	}

	m := aptStaleProbeSearchRe.FindStringSubmatch(text)
	if m == nil {
		t.Fatalf("could not find the stale-metadata `is search(...)` pattern in %s", path)
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
