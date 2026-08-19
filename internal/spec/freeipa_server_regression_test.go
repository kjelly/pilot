package spec

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestRegression_FreeipaServerSpec locks the structural contract of
// docs/verification/freeipa-server.md: 20 rows C1..C20 (C14–C16 = 389-ds
// directory-service audit log, added in v1.1; C19 = kpasswd 464/tcp, added
// in v1.5; C20 = allow-recursion/allow-query-cache opened to any client,
// added in v1.6), lint-clean, and a generated verify playbook that covers
// every row.
//
// Inventory alignment: like freeipa-client.md, §1 declares group
// `freeipa-server` while the vm-target reference environment puts the host in
// `all` (run/verify with `-e target_group=all`). Per AGENTS.md §3 we therefore
// do NOT assert SpecAndInventoryAgree — the alignment lives in the
// `-e target_group=` override, not a fixed group name.
func TestRegression_FreeipaServerSpec(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-server.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	if len(s.Rows) != 20 {
		t.Fatalf("rows=%d want=20 (spec must cover C1..C20 inclusive)", len(s.Rows))
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15", "C16", "C17", "C18", "C19", "C20"}
	gotIDs := make([]string, 0, len(s.Rows))
	seen := map[string]bool{}
	for _, r := range s.Rows {
		if seen[r.ID] {
			t.Errorf("duplicate row ID %q", r.ID)
		}
		seen[r.ID] = true
		gotIDs = append(gotIDs, r.ID)
	}
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Errorf("row IDs = %v, want %v", gotIDs, wantIDs)
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", fsToString(fs))
	}
	for _, r := range s.Rows {
		if strings.TrimSpace(r.Expected) == "" {
			t.Errorf("row %s has empty Expected", r.ID)
		}
		if strings.TrimSpace(r.Command) == "" {
			t.Errorf("row %s has empty Command", r.ID)
		}
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out := pb.RenderYAML()
	var plays []map[string]any
	if err := yaml.Unmarshal([]byte(out), &plays); err != nil {
		t.Fatalf("generated playbook does not parse as YAML: %v\n--- output ---\n%s", err, out)
	}
	if len(plays) != 1 {
		t.Fatalf("generated playbook plays=%d, want 1", len(plays))
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
}

// TestRegression_FreeipaServerSpec_MatcherChoices locks the two hard-won
// matcher decisions the spec documents (all were verify false-negatives in
// practice): C2 must use POSITIVE logic (`sudo ipactl status`, not a
// reverse-logic `| grep STOPPED`), while C3 and C12 must derive the effective
// configured FQDN instead of hard-coding the default ipa1 hostname.
func TestRegression_FreeipaServerSpec_MatcherChoices(t *testing.T) {
	const specPath = "../../docs/verification/freeipa-server.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	cmd := map[string]string{}
	exp := map[string]string{}
	for _, r := range s.Rows {
		cmd[r.ID] = r.Command
		exp[r.ID] = strings.TrimSpace(r.Expected)
	}

	// C2: positive-logic service health, rc-based.
	if !strings.Contains(cmd["C2"], "ipactl status") {
		t.Errorf("C2 must check `ipactl status`, got %q", cmd["C2"])
	}
	if strings.Contains(cmd["C2"], "grep") {
		t.Errorf("C2 must NOT use reverse-logic grep (ad-hoc reports rc=2 on the healthy path); got %q", cmd["C2"])
	}
	if exp["C2"] != "0" {
		t.Errorf("C2 expected must be rc-based `0`, got %q", exp["C2"])
	}

	// C3: compare hostname -f to FreeIPA's effective host setting exactly.
	if exp["C3"] != "0" {
		t.Errorf("C3 expected must be rc-based `0`, got %q", exp["C3"])
	}
	if !strings.Contains(cmd["C3"], "hostname -f") || !strings.Contains(cmd["C3"], "/etc/ipa/default.conf") {
		t.Errorf("C3 must compare hostname -f with FreeIPA's effective host setting, got %q", cmd["C3"])
	}
	if strings.Contains(cmd["C3"], "ipa1.ipa.pilot.internal") {
		t.Errorf("C3 must not hard-code the default FreeIPA FQDN, got %q", cmd["C3"])
	}

	// C12: probe the CA endpoint via this host's configured FQDN.
	if !strings.Contains(cmd["C12"], "$(hostname -f)") {
		t.Errorf("C12 must derive the CA endpoint FQDN from hostname -f, got %q", cmd["C12"])
	}
	if strings.Contains(cmd["C12"], "ipa1.ipa.pilot.internal") {
		t.Errorf("C12 must not hard-code the default FreeIPA FQDN, got %q", cmd["C12"])
	}

	// C14/C15: 389-ds audit-log config read via dsconf (needs root over ldapi),
	// matched with ~contains on the exact `attr: on` line. Positive logic — we
	// assert the flag is ON, never a reverse grep for `off`.
	for _, id := range []string{"C14", "C15"} {
		if !strings.Contains(cmd[id], "dsconf") || !strings.Contains(cmd[id], "config get") {
			t.Errorf("%s must read the 389-ds audit flag via `dsconf ... config get`, got %q", id, cmd[id])
		}
		if !strings.HasPrefix(exp[id], "~") || !strings.Contains(exp[id], ": on") {
			t.Errorf("%s expected should be a ~contains match on `<attr>: on`, got %q", id, exp[id])
		}
	}

	// C16: audit file present AND non-empty via `test -s` (rc-based), never a
	// reverse-logic pipe. Expected must be rc `0`.
	if !strings.Contains(cmd["C16"], "test -s") {
		t.Errorf("C16 must use `test -s <auditfile>` (exists && non-empty), got %q", cmd["C16"])
	}
	if exp["C16"] != "0" {
		t.Errorf("C16 expected must be rc-based `0`, got %q", exp["C16"])
	}

	// The whole spec must be lint-warning-free for the matcher traps: no
	// ^-anchored expected and no ~active anywhere.
	for _, r := range s.Rows {
		e := strings.TrimSpace(r.Expected)
		if strings.HasPrefix(e, "^") {
			t.Errorf("row %s uses a ^-anchored expected %q — broken under ad-hoc", r.ID, e)
		}
		if strings.EqualFold(e, "~active") {
			t.Errorf("row %s uses ~active (matches inactive); use rc-based systemctl is-active", r.ID)
		}
	}
}

// TestRegression_FreeipaServerApplyPlaybook_HasCloudInitEtcHostsGuard locks
// the 2026-08-18 fix for cloud-init-freeipa-incident-report.md: the same
// class of bug found on the client side (cloud-init's manage_etc_hosts
// wiping a /etc/hosts pin on reboot) applies equally to the server's own
// FQDN pin. freeipa-server-apply.yml must include the shared
// cloud-init-etc-hosts-guard.yml task BEFORE its own /etc/hosts pin.
func TestRegression_FreeipaServerApplyPlaybook_HasCloudInitEtcHostsGuard(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-server-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	guardIdx := strings.Index(playbook, "tasks/cloud-init-etc-hosts-guard.yml")
	if guardIdx < 0 {
		t.Fatalf("playbook must include tasks/cloud-init-etc-hosts-guard.yml")
	}
	pinIdx := strings.Index(playbook, `regexp: '\s{{ ipa_server_fqdn | regex_escape }}(\s|$)'`)
	if pinIdx < 0 {
		t.Fatalf("playbook must still pin the server FQDN in /etc/hosts")
	}
	if guardIdx > pinIdx {
		t.Errorf("cloud-init-etc-hosts-guard.yml must be included BEFORE the /etc/hosts FQDN pin")
	}
}

// TestRegression_FreeipaServerApplyPlaybook_OpensRecursionToAnyClient locks
// the 2026-08-18 fix for "let the FreeIPA DNS server forward arbitrary
// clients' requests to an external DNS server". Confirmed live (see
// docs/verification/freeipa-server.md §8) that a stock `ipa-server-install
// --setup-dns` sets NEITHER allow-recursion NOR allow-query-cache at all —
// /etc/named.conf is FreeIPA-owned ("DO NOT MODIFY! Any modification will be
// overwritten by upgrades") and only `include`s
// /etc/named/ipa-options-ext.conf, which ships with just a commented-out
// EXAMPLE of a restrictive ACL (e.g. `trusted_clients`) for the operator to
// fill in. Whether that ACL was never set or was added later by a hardening
// pass, either way recursive/forwarded lookups get REFUSED for any client
// outside it even though ipa_domain's own authoritative answers keep working
// for anyone — so the playbook must set both directives to `any` in
// ipa-options-ext.conf specifically (NEVER edit named.conf itself), default
// on, operator-overridable via freeipa_dns_allow_any_recursion, and reload
// named via a handler rather than a bare command task so a config error
// can't take down an already-running server (same convention as
// reverse-proxy-apply.yml's nginx handlers).
func TestRegression_FreeipaServerApplyPlaybook_OpensRecursionToAnyClient(t *testing.T) {
	const playbookPath = "../../playbooks/apply/freeipa-server-apply.yml"
	raw, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	playbook := string(raw)

	for _, want := range []string{
		"ipa_dns_allow_any_recursion",
		"allow-recursion",
		"allow-query-cache",
		"/etc/named/ipa-options-ext.conf",
		"notify: reload named for open recursion",
	} {
		if !strings.Contains(playbook, want) {
			t.Errorf("playbook must contain %q", want)
		}
	}

	// The fix must target ipa-options-ext.conf (FreeIPA's documented
	// "user customization, survives upgrades" file), never named.conf
	// itself — named.conf is only ever referenced for read-only validation
	// (named-checkconf), never as an ansible.builtin.lineinfile/replace/copy
	// path= target.
	for _, mod := range []string{"ansible.builtin.lineinfile", "ansible.builtin.replace", "ansible.builtin.copy", "ansible.builtin.blockinfile"} {
		idx := 0
		for {
			i := strings.Index(playbook[idx:], mod)
			if i < 0 {
				break
			}
			i += idx
			// Look at the next ~200 chars for a path:/dest: pointing at
			// named.conf directly (not the ipa-options-ext.conf include).
			window := playbook[i:min(i+400, len(playbook))]
			if strings.Contains(window, "/etc/named.conf") && !strings.Contains(window, "ipa-options-ext.conf") {
				t.Errorf("%s must never target /etc/named.conf directly (FreeIPA: \"DO NOT MODIFY! Any modification will be overwritten by upgrades\") — found near offset %d", mod, i)
			}
			idx = i + len(mod)
		}
	}

	if !strings.Contains(playbook, "named-checkconf") {
		t.Errorf("playbook must validate named.conf (named-checkconf) before reloading — a bad substitution must never take down an already-running server")
	}
	if !strings.Contains(playbook, "rndc reconfig") {
		t.Errorf("playbook must reload via `rndc reconfig` (live config reload), not a full service restart")
	}

	// The reload must be handler-driven (listen: reload named for open
	// recursion), not a bare command task gated on .changed — ansible-lint's
	// no-handler rule flags exactly that pattern, and reverse-proxy-apply.yml
	// already established the validate-then-reload handler convention.
	if !strings.Contains(playbook, "listen: reload named for open recursion") {
		t.Errorf("named reload must be handler-driven (listen: reload named for open recursion), not an inline command task")
	}
}
