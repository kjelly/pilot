package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_HostMonitoringSpec locks the structure of
// docs/verification/host-monitoring.md (v1.1 — node_exporter agent,
// installed from a pinned upstream release binary on both Ubuntu/Debian and
// AlmaLinux/EL, never from either distro's package manager, with mandatory
// HTTP Basic Auth):
//
//	C1     node_exporter binary present at /usr/local/bin/node_exporter
//	C2     installed version matches the pinned release
//	C3     dedicated system user exists with a nologin shell
//	C4     systemd unit file present
//	C5     systemd unit runs as the dedicated user, not root
//	C6     systemd unit has NoNewPrivileges=true
//	C7     node_exporter.service is active
//	C8     9100/tcp is listening
//	C9     an UNauthenticated request to /metrics (9100) is rejected (401) —
//	       proves auth is actually enforced, not just configured
//	C10    web-config.yml declares basic_auth_users for the configured user
//
// Cross-row invariants locked below:
//
//   - No row may use ~active (matches inactive as a substring).
//   - C5/C6 must use the `; echo $?` positive-logic rc idiom per
//     verification-spec-template.md trap 1.
//   - C9 must assert on 401 specifically (not just "curl fails") — a config
//     that's present but not enforced is a real, distinct failure mode from
//     "config file doesn't exist", and only testing the unauthenticated path
//     can catch it (see spec-driven-feature-workflow skill §5 on checks that
//     have only run against a true-positive state).
//   - host-monitoring-apply.yml must install node_exporter via a pinned,
//     checksummed upstream release binary (get_url + checksum:), NOT via
//     apt/dnf — Ubuntu's package lags upstream and EL9 has no package at
//     all (see spec §1.5); the playbook must support both Debian and
//     RedHat os_family via the same binary path, and must have a pinned
//     checksum for both amd64 and arm64.
//   - The systemd unit must run as the dedicated non-root user, set
//     NoNewPrivileges=true (matches C5/C6), and pass --web.config.file so
//     auth is actually wired into the running process, not just present on
//     disk unused.
//   - The dedicated user must be a system account with no interactive
//     shell (matches C3).
//   - The basic-auth password must be a hard-required gate (no escape
//     hatch) — node_exporter must never serve metrics without a credential.
//   - The bcrypt hash must be generated via htpasswd (apache2-utils/
//     httpd-tools), gated on a change-detection fingerprint of the
//     plaintext (not the password itself) — bcrypt salts are
//     non-deterministic per call, so re-hashing an unchanged password on
//     every apply would thrash idempotency and the service restart.
//   - The plaintext password must never be logged (no_log on every task
//     that touches it).
//   - `state: restarted` must be idempotency-gated on the binary, unit, or
//     credential actually changing, never run unconditionally on every
//     apply (see spec-driven-feature-workflow skill §3).
func TestRegression_HostMonitoringSpec(t *testing.T) {
	const specPath = "../../docs/verification/host-monitoring.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
		switch strings.ToLower(exp[r.ID]) {
		case "ok", "normal", "reasonable", "sufficient", "合理", "正常", "足夠":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// No row anywhere may use ~active (false-positives on "inactive").
	for _, r := range s.Rows {
		if strings.EqualFold(strings.TrimSpace(r.Expected), "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}

	// C5/C6 must use the `; echo $?` positive-logic form (trap 1).
	for _, id := range []string{"C5", "C6"} {
		if !strings.Contains(cmd[id], "; echo $?") {
			t.Errorf("%s must use the `; echo $?` positive-logic rc idiom, got %q", id, cmd[id])
		}
		if exp[id] != "0" {
			t.Errorf("%s expected must be rc-based `0`, got %q", id, exp[id])
		}
	}

	// C7 service-active check must use systemctl is-active with rc-based
	// expected, not ~active (false-positives on inactive).
	if !strings.Contains(cmd["C7"], "systemctl is-active node_exporter") {
		t.Errorf("C7 must check systemctl is-active node_exporter, got %q", cmd["C7"])
	}
	if exp["C7"] != "0" {
		t.Errorf("C7 expected must be rc-based `0`, got %q", exp["C7"])
	}

	// C9 must assert on 401 specifically (auth actually enforced), hitting
	// the real metrics endpoint on the contract's port, WITHOUT credentials.
	if !strings.Contains(cmd["C9"], ":9100/metrics") {
		t.Errorf("C9 must hit :9100/metrics, got %q", cmd["C9"])
	}
	if strings.Contains(cmd["C9"], "-u ") || strings.Contains(cmd["C9"], "://prometheus:") {
		t.Errorf("C9 must be an UNauthenticated request (no credentials) — it proves auth rejects anonymous access, got %q", cmd["C9"])
	}
	if exp["C9"] != "~401" {
		t.Errorf("C9 expected must be ~401, got %q", exp["C9"])
	}

	// C10 must assert the web-config.yml declares basic_auth_users for the
	// configured user.
	if !strings.Contains(cmd["C10"], "web-config.yml") || !strings.Contains(cmd["C10"], "prometheus:") {
		t.Errorf("C10 must check web-config.yml for the configured basic-auth user, got %q", cmd["C10"])
	}
	if exp["C10"] != "0" {
		t.Errorf("C10 expected must be rc-based `0`, got %q", exp["C10"])
	}

	// No credentials belong in a spec (AGENTS.md) — this spec's whole point
	// is auth, so it's especially easy to slip a real password in by habit.
	for _, r := range s.Rows {
		lower := strings.ToLower(r.Command)
		for _, forbidden := range []string{"password=", "-u prometheus:", "secret_key"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s must not reference %q (no credentials in spec); got %q", r.ID, forbidden, r.Command)
			}
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}

	playbookRaw, err := os.ReadFile("../../playbooks/apply/host-monitoring-apply.yml")
	if err != nil {
		t.Fatalf("read host-monitoring-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)

	// Must install via a pinned, checksummed upstream release — never a
	// distro package manager (the whole design rationale in spec §1.5).
	if !strings.Contains(applyRaw, "ansible.builtin.get_url") {
		t.Errorf("host-monitoring-apply.yml must install node_exporter via get_url (pinned upstream release), not a package manager")
	}
	if !strings.Contains(applyRaw, "checksum:") {
		t.Errorf("host-monitoring-apply.yml's get_url task must verify a checksum")
	}
	if strings.Contains(applyRaw, "name: node_exporter\n") {
		t.Errorf("host-monitoring-apply.yml must not install a package literally named node_exporter (no such EL9 package exists; see spec §1.5)")
	}

	// Must support both OS families via the same binary-install path.
	if !strings.Contains(applyRaw, "ansible_os_family in ['Debian', 'RedHat']") {
		t.Errorf("host-monitoring-apply.yml must gate on ansible_os_family in ['Debian', 'RedHat']")
	}

	// Must have a pinned checksum for both amd64 and arm64.
	for _, arch := range []string{"amd64:", "arm64:"} {
		if !strings.Contains(applyRaw, arch) {
			t.Errorf("host-monitoring-apply.yml's node_exporter_checksums must have an entry for %q", strings.TrimSuffix(arch, ":"))
		}
	}

	// The dedicated user must be a system account with no interactive shell.
	if !strings.Contains(applyRaw, "system: true") {
		t.Errorf("host-monitoring-apply.yml must create the dedicated user with system: true")
	}
	if !strings.Contains(applyRaw, "shell: /usr/sbin/nologin") {
		t.Errorf("host-monitoring-apply.yml must set a nologin shell on the dedicated user (matches spec C3)")
	}

	// The systemd unit must run as the dedicated user, set
	// NoNewPrivileges=true (matches C5/C6), and actually wire up auth via
	// --web.config.file (not just render the file and never reference it).
	if !strings.Contains(applyRaw, "User={{ node_exporter_user }}") {
		t.Errorf("host-monitoring-apply.yml's systemd unit must run as User={{ node_exporter_user }} (matches spec C5)")
	}
	if !strings.Contains(applyRaw, "NoNewPrivileges=true") {
		t.Errorf("host-monitoring-apply.yml's systemd unit must set NoNewPrivileges=true (matches spec C6)")
	}
	if !strings.Contains(applyRaw, "--web.config.file=") {
		t.Errorf("host-monitoring-apply.yml's systemd unit ExecStart must pass --web.config.file (auth must actually be wired in, not just rendered to disk unused)")
	}

	// The basic-auth password must be a hard-required gate, no escape hatch.
	if !strings.Contains(applyRaw, "node_exporter_basic_auth_password is defined") {
		t.Errorf("host-monitoring-apply.yml must gate on node_exporter_basic_auth_password being defined — auth is mandatory, not optional")
	}

	// The bcrypt hash must come from htpasswd (apache2-utils/httpd-tools),
	// gated on a change-detection fingerprint, not regenerated every apply.
	if !strings.Contains(applyRaw, "apache2-utils") || !strings.Contains(applyRaw, "httpd-tools") {
		t.Errorf("host-monitoring-apply.yml must install htpasswd via apache2-utils (Debian) and httpd-tools (EL)")
	}
	if !strings.Contains(applyRaw, "htpasswd -nbBC") {
		t.Errorf("host-monitoring-apply.yml must generate the bcrypt hash via htpasswd -nbBC")
	}
	if !strings.Contains(applyRaw, "hash('sha256')") {
		t.Errorf("host-monitoring-apply.yml must use a fingerprint (hash of the plaintext) to detect credential changes — bcrypt itself is non-deterministic per call")
	}
	if !strings.Contains(applyRaw, "node_exporter_basic_auth_changed") {
		t.Errorf("host-monitoring-apply.yml must gate hash regeneration/file rewrite on a computed \"credential changed\" fact")
	}

	// The plaintext password is referenced directly in a handful of
	// expected places (the htpasswd command line, the fingerprint
	// computation, the required-password gate) — what matters is that
	// every task touching it is no_log.
	if strings.Count(applyRaw, "no_log: true") < 4 {
		t.Errorf("host-monitoring-apply.yml must no_log every task that handles the plaintext password or its hash (expected at least 4 such tasks), got %d", strings.Count(applyRaw, "no_log: true"))
	}

	// `state: restarted` must never run unconditionally (idempotency trap).
	if !strings.Contains(applyRaw, "state: restarted") {
		t.Fatalf("host-monitoring-apply.yml must restart the service when the binary/unit/credential changes")
	}
	if !strings.Contains(applyRaw, "node_exporter_binary_result is changed") ||
		!strings.Contains(applyRaw, "node_exporter_unit_result is changed") ||
		!strings.Contains(applyRaw, "node_exporter_webconfig_result is changed") {
		t.Errorf("host-monitoring-apply.yml's restart task must be gated on the binary, unit, or web-config credential actually changing, not run unconditionally")
	}
}
