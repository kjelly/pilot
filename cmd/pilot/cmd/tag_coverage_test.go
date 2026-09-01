package cmd

// TestSpecPlaybookTagAlignment machine-enforces AGENTS.md §4's tag rule:
// apply-playbook tasks that implement a spec row carry that row's ID as a
// tag (bare `C3` for single-spec playbooks, `<role>-C3` for multi-spec
// ones). Before 2026-07-18 the rule was checked by hand with
// `--list-tags`; this test makes both drift directions fail CI:
//
//   - orphan tag: a row-shaped tag in the playbook that no spec row
//     defines (spec renumbered/removed but the playbook kept the old ID);
//   - uncovered row: a spec row with no correspondingly-tagged task and
//     no entry in the mapping's exempt list (new row added to the spec
//     but the playbook was never taught about it).
//
// Exemptions are a ratchet, not an escape hatch: every exempt row must
// still exist in the spec AND stay uncovered — a stale exemption fails
// the test so the table tracks reality.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/spec"
)

// specTagMapping pairs one verification spec with the apply playbook that
// implements it, plus how that playbook namespaces its row tags.
type specTagMapping struct {
	spec     string   // filename under docs/verification/
	playbook string   // filename under playbooks/apply/
	prefixes []string // tag namespaces (`db` => db-C3); empty = bare row IDs
	// exemptRows lists rows deliberately implemented without a dedicated
	// tagged task (satisfied as a side effect of another row's task, or
	// verify-only conditions like "port answers"). Keep the reason short.
	exemptRows map[string]string
	// noRowTags marks playbooks that deliberately do not tag by row ID at
	// all (say why). The orphan check still applies.
	noRowTags string
	// stageTags lists row-shaped tags that are deliberately NOT row IDs
	// (e.g. freeipa-server-replica's R1/R2 promote stages). Each must
	// still exist in the playbook, so the allowance can't go stale.
	stageTags map[string]string
}

var specTagMap = []specTagMapping{
	{spec: "alertmanager.md", playbook: "alertmanager-apply.yml"},
	{spec: "audit-log-forwarding.md", playbook: "audit-log-forwarding-apply.yml",
		exemptRows: map[string]string{
			"C11": "functional probe (run sudo, assert audit.log recorded it) — verify-only outcome of the C1..C10 auditd config",
		}},
	{spec: "core-infra-provider.md", playbook: "core-infra-provider-apply.yml",
		prefixes: []string{"dns", "ntp"},
		exemptRows: map[string]string{
			"C7": "optional DNS probe gated on $DNS_PROBE_NAME — verify-only",
		}},
	{spec: "core-infra-provider-db.md", playbook: "keycloak-db-apply.yml",
		prefixes: []string{"db"},
		exemptRows: map[string]string{
			"C4":  "keycloak database is created by the postgres container's POSTGRES_DB env on first boot (the docker_container task, tagged db-C1..db-C3) — no separate mutation task",
			"C5":  "keycloak role is created by POSTGRES_USER on first boot — same task as C4",
			"C6":  "database ownership follows POSTGRES_DB+POSTGRES_USER on first boot — same task as C4",
			"C11": "capacity guard (DB size < 10 GiB) — verify-only",
		}},
	{spec: "dashboard.md", playbook: "dashboard-apply.yml"},
	{spec: "detection-engine.md", playbook: "detection-engine-apply.yml",
		prefixes: []string{"detection-engine"},
		exemptRows: map[string]string{
			"C6":  "status.json/textfile carrying no secret is a Go-code-level guarantee (internal/detection/status.go, metrics.go never define a secret field) — no apply task produces or could break this",
			"C10": "cold-start no-false-anomaly is an internal/detection algorithm property (baseline_test.go's 120-bucket gate) — no apply task implements it",
			"C11": "lifecycle/escalation/resolution/outbox-ordering SCENARIO evidence comes from the fake-protocol topology lane (spec §49), not a single already-applied host — this row is verifyOnly",
		}},
	{spec: "agent-controller.md", playbook: "agent-controller-apply.yml",
		prefixes: []string{"agent-controller"},
		exemptRows: map[string]string{
			"C3":  "HMAC signature verification is a Go-code-level guarantee (internal/agentcontroller/http.go's verifySignature) — no apply task implements the auth check itself, only provisions the shared secret",
			"C7":  "replay/escalation dedup SCENARIO evidence comes from the disposable-lane topology test, not a single already-applied host — this row is verifyOnly",
			"C8":  "the observe-only MCP capability boundary is proven by pilot's own MCP test suite plus the disposable-lane evidence — this row is verifyOnly",
			"C9":  "valid-diagnosis-persists SCENARIO evidence requires submitting a signed webhook and inspecting the resulting row — this row is verifyOnly",
			"C10": "malformed-output-never-persists is a Go-code-level guarantee (internal/agentcontroller/model.go's DiagnosisResult.Validate, queue.go's dispatchOne) — no apply task implements it",
			"C11": "restart-preserves-state SCENARIO evidence comes from the disposable-lane topology test — this row is verifyOnly",
			"C13": "idempotent-reapply changed=0 is proven by `pilot vm-target test`'s own apply-twice comparison — this row is verifyOnly",
		}},
	{spec: "detection-engine-model-provider.md", playbook: "detection-engine-apply.yml",
		noRowTags: "Stage B provider verification: M1 shares the same config-validate task as C3 (detection-engine-C3); M2-M5 are pure diagnostic CLI checks (provider probe/status field reads) with no dedicated mutating task to tag — spec §60"},
	{spec: "docker.md", playbook: "docker-apply.yml", prefixes: []string{"docker"},
		exemptRows: map[string]string{
			"C3": "docker --version probe — side effect of the engine install (docker-C1)",
			"C5": "hello-world pull+run probe — verify-only whole-chain check",
			"C6": "default networks (bridge/host/none) are created by the engine itself (docker-C1)",
			"C7": "compose v2 plugin version probe — installed by the same package set (docker-C1)",
			"C8": "cgroup driver probe — property of the engine install (docker-C1)",
		}},
	{spec: "freeipa-dns.md", playbook: "freeipa-dns-apply.yml",
		exemptRows: map[string]string{
			"C12": "idempotent-rerun is a multi-run property, not a single tagged task — same reasoning as freeipa-identity.md's own §7 dynamic SOPs",
		}},
	{spec: "freeipa-dns-client.md", playbook: "freeipa-dns-client-apply.yml",
		exemptRows: map[string]string{
			"C2": "resolver-managing service health (Debian systemd-resolved / EL NetworkManager already active) is a precondition this playbook consumes, not a service it starts/stops itself — verify-only",
		}},
	{spec: "freeipa-ca-trust.md", playbook: "freeipa-ca-trust-apply.yml",
		exemptRows: map[string]string{
			"C1": "self-signed/root property observed on the same CA file C2 installs — no separate mutation",
			"C3": "effective Debian/Ubuntu trust-store behavior derived from C2's install",
			"C4": "effective RedHat-family trust-store behavior derived from C2's install",
			"C5": "same installed state as C2, independent of FreeIPA (AAA) enrollment",
			"C6": "idempotent-rerun is a multi-run property, not a single tagged task — evidenced by vm-target topology test, same reasoning as freeipa-dns.md's own C12",
		}},
	{spec: "reverse-proxy.md", playbook: "reverse-proxy-apply.yml",
		exemptRows: map[string]string{
			"C3": "nginx -t is an effective outcome of C1/C2's valid base install, not a separate mutation",
			"C6": "idempotent-rerun is a multi-run property, not a single tagged task — evidenced by vm-target topology test, same reasoning as freeipa-ca-trust.md's own C6",
		}},
	{spec: "internal-endpoint.md", playbook: "internal-endpoint-apply.yml",
		exemptRows: map[string]string{
			"C1":  "pure Go manifest-validator behavior — no Ansible task",
			"C2":  "pure Go manifest-validator behavior — no Ansible task",
			"C3":  "pure Go manifest-validator behavior — no Ansible task",
			"C11": "certificate-owner derivation is a Go-side computation consumed by the C13 service-principal task, not a separate mutation",
			"C14": "cert SAN is a property of the C15 certmonger request, not a separate mutation",
			"C16": "architectural invariant of C15 — certmonger runs on the owner host and never distributes the private key",
			"C17": "end-to-end effective behavior of the C27 nginx render task",
			"C18": "end-to-end effective behavior of the C27 nginx render task",
			"C19": "end-to-end effective behavior of the C4 direct-route DNS write plus C15's certificate",
			"C20": "client-usage convention check (fqdn:port), not a separate mutation",
			"C25": "same DNS-write task as C4 — this row asserts the record still matches after an inventory_host IP change, not a distinct mutation (see contracts/internal-endpoint.yaml's derived exemption)",
			"C26": "idempotent-rerun is a multi-run property, not a single tagged task — evidenced by vm-target topology test, same reasoning as freeipa-dns.md's own C12",
			"C28": "effective TLS behavior (proxy_ssl_verify on) of the same C27 nginx render task",
			"C29": "effective TLS behavior (proxy_ssl_verify off) of the same C27 nginx render task",
			"C30": "pure Go manifest-validator behavior — no Ansible task",
			"C31": "effective behavior proving the C27 nginx render task did not silently downgrade to plaintext",
			"C32": "effective proxy_ssl_name behavior of the same C27 nginx render task",
		}},
	{spec: "freeipa-client.md", playbook: "freeipa-client-apply.yml",
		exemptRows: map[string]string{
			"C4":  "host keytab is produced by ipa-client-install (C1..C3) — no separate mutation task",
			"C5":  "SSSD account resolution is wired by ipa-client-install — same as C4",
			"C6":  "sssd.conf access_provider=ipa is written by ipa-client-install — same as C4",
			"C10": "kernel auditing probe (auditctl -s) — verify-only outcome of the audit tasks",
		}},
	{spec: "freeipa-realm-replacement.md", playbook: "freeipa-realm-replacement-apply.yml"},
	{spec: "host-monitoring.md", playbook: "host-monitoring-apply.yml",
		exemptRows: map[string]string{
			"C8": "port-listening probe — verify-only outcome of the service actually running (C7)",
			"C9": "unauthenticated-request-rejected probe — verify-only outcome of the web-config.yml render (C10) actually being enforced by the running service (C7)",
		}},
	{spec: "dcgm-exporter.md", playbook: "dcgm-exporter-apply.yml",
		exemptRows: map[string]string{
			"C8": "unauthenticated-request-rejected probe — verify-only outcome of the container running (C3) and the web-config.yml render (C9) actually being enforced",
		}},
	{spec: "freeipa-identity.md", playbook: "freeipa-identity-apply.yml",
		exemptRows: map[string]string{
			"C1": "legacy data-driven membership row predates row tags",
			"C2": "legacy data-driven revocation row predates row tags",
			"C3": "legacy HBAC category row predates row tags",
			"C4": "legacy HBAC membership row predates row tags",
			"C5": "legacy sudo category row predates row tags",
			"C6": "legacy sudo membership row predates row tags",
			"C7": "legacy hostgroup attribute row predates row tags",
			"C8": "legacy user attribute row predates row tags",
		}},
	{spec: "freeipa-nfs-server.md", playbook: "freeipa-nfs-server-apply.yml"},
	{spec: "freeipa-nfs-client.md", playbook: "freeipa-nfs-client-apply.yml",
		exemptRows: map[string]string{
			"C6": "verify-only invariant proving the client playbook never writes NFS mounts to /etc/fstab",
		}},
	{spec: "freeipa-server.md", playbook: "freeipa-server-apply.yml",
		noRowTags: "installer-shaped playbook: one ipa-server-install task satisfies most rows; feature tags (freeipa-install/-service/-audit) instead"},
	{spec: "freeipa-server-replica.md", playbook: "freeipa-server-replica-apply.yml",
		noRowTags: "two-stage promote playbook: stage tags R1 (client install) / R2 (replica promote); the spec's own §7 table documents the row→stage mapping",
		stageTags: map[string]string{
			"R1": "stage 1: hostname/hosts pin + ipa-client-install",
			"R2": "stage 2: ipa-replica-install + service bring-up",
		}},
	{spec: "keycloak.md", playbook: "keycloak-apply.yml", prefixes: []string{"keycloak"}},
	{spec: "log-server.md", playbook: "log-server-apply.yml"},
	{spec: "log-shipping.md", playbook: "log-shipping-apply.yml"},
	{spec: "os-patch-sla.md", playbook: "os-patch-sla-apply.yml",
		noRowTags: "stage-gated patch pipeline: rows assert SLA policy outcomes, not per-task mutations"},
	{spec: "pam-oidc-sshd.md", playbook: "pam-oidc-sshd-apply.yml"},
	{spec: "prometheus.md", playbook: "prometheus-apply.yml",
		exemptRows: map[string]string{
			"C14": "up{job=\"node\"}==1 probe — verify-only outcome of the node-exporter scrape job rendered for C13 actually authenticating and succeeding",
		}},
	{spec: "prometheus-external-targets.md", playbook: "prometheus-apply.yml",
		prefixes: []string{"ext-target"},
		exemptRows: map[string]string{
			"C4": "Prometheus targets-API visibility is a verify-only outcome of the ext-target-C3 scrape-config render actually being loaded",
			"C5": "successful scrape (up==1) is a verify-only outcome of the ext-target-C3 job reaching a real reachable target",
			"C6": "promtool check config is a post-apply, read-only pilot verify check (spec.md §22 correction) — no apply-time task invokes promtool",
			"C7": "directory permission is a property of the ext-target-C1 directory-creation task's explicit mode: 0755",
			"C8": "no-plaintext-password is an architectural invariant of the scrape-job compiler always emitting password_file, never password — no dedicated task",
		}},
	{spec: "restic-backup.md", playbook: "restic-backup-apply.yml",
		exemptRows: map[string]string{
			"C4": "repository connectivity probe — v1.4 deliberately stopped triggering a synchronous first backup during apply (avoids apply-time lock contention across hosts sharing one repository); satisfied by the timer's own randomized-delay schedule, not an apply task",
			"C5": "at-least-one-snapshot probe — same v1.4 deferred-snapshot design as C4; expected to fail until the timer's next scheduled window, not an apply bug",
			"C6": "restic check integrity probe — verify-only outcome of a snapshot existing (C5), which itself only arrives via the timer's own schedule under the v1.4 deferred-snapshot design",
		}},
	{spec: "seaweedfs-s3.md", playbook: "seaweedfs-s3-apply.yml", prefixes: []string{"s3"},
		exemptRows: map[string]string{
			"C8": "anonymous DELETE + GET-404 probe — verify-only outcome of the gateway config (s3-C1..C7)",
		}},
	{spec: "snmp-exporter.md", playbook: "snmp-exporter-apply.yml",
		exemptRows: map[string]string{
			"C11": "idempotent-reapply probe — verify-only outcome of the real second-apply changed=0 evidence recorded in the spec, not a single tagged task",
			"C12": "prod version-policy scenario probe — verify-only outcome of the pre_tasks assert gate (Go-level: no dedicated apply task, checked via --check with prod/exception scenarios in the spec's actual-run evidence)",
		}},
	{spec: "thanos-query.md", playbook: "thanos-query-apply.yml"},
	{spec: "wazuh-fim.md", playbook: "wazuh-fim-apply.yml"},
	{spec: "wazuh-manager.md", playbook: "wazuh-manager-apply.yml",
		exemptRows: map[string]string{
			"C7": "in-effect ossec.conf probe — asserts the /wazuh-config-mount injection (C4..C6 compose tasks) actually took",
			"C8": "disk headroom guard (≥ 5GB free) — verify-only capacity check",
			"C9": "wazuh-logtest rule-engine probe — verify-only functional check",
		}},
}

// Specs with no apply playbook in playbooks/apply/ at all.
var tagCheckExemptSpecs = map[string]string{
	"hello-localhost.md":             "smoke-test spec; its playbook lives in playbooks/test/",
	"core-infra.md":                  "composite host-baseline spec: satisfied by dns/ntp/keycloak playbooks together, no single apply playbook",
	"sso-composition-example.md":     "documentation example of the spec-supplier pattern, never applied",
	"snmp-monitoring-integration.md": "cross-cutting spec spanning internal/monitoring, internal/detection, internal/agentcontroller, internal/repair, internal/diagnose — verified by each package's own Go tests (see the spec's Checks probes), no single apply playbook",
}

// rowShapedTag matches IDs like C1, R2, C2.5.1 — the shapes spec row IDs
// take — while skipping feature tags (always, dns, freeipa-install, …).
var rowShapedTag = regexp.MustCompile(`^[A-Z]\d+(\.\d+)*$`)

func TestSpecPlaybookTagAlignment(t *testing.T) {
	root := "../../.."
	specDir := filepath.Join(root, "docs", "verification")
	pbDir := filepath.Join(root, "playbooks", "apply")

	// --- mapping completeness: every spec and playbook on disk is either
	// mapped or explicitly exempted, so new files can't dodge the check.
	mappedSpecs := map[string]bool{}
	mappedPBs := map[string]bool{}
	for _, m := range specTagMap {
		mappedSpecs[m.spec] = true
		mappedPBs[m.playbook] = true
	}
	specFiles, err := filepath.Glob(filepath.Join(specDir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range specFiles {
		base := filepath.Base(p)
		if !mappedSpecs[base] && tagCheckExemptSpecs[base] == "" {
			t.Errorf("spec %s is neither in specTagMap nor tagCheckExemptSpecs — map it to its apply playbook (or exempt it with a reason)", base)
		}
	}
	pbFiles, err := filepath.Glob(filepath.Join(pbDir, "*-apply.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pbFiles {
		base := filepath.Base(p)
		if !mappedPBs[base] {
			t.Errorf("playbook %s is not in specTagMap — every apply playbook needs a spec (AGENTS.md §3)", base)
		}
	}

	// --- per-mapping alignment.
	for _, m := range specTagMap {
		t.Run(strings.TrimSuffix(m.spec, ".md"), func(t *testing.T) {
			parsed, err := spec.Parse(filepath.Join(specDir, m.spec))
			if err != nil {
				t.Fatalf("parse spec: %v", err)
			}
			rowIDs := map[string]bool{}
			for _, r := range parsed.Rows {
				rowIDs[r.ID] = true
			}
			if len(rowIDs) == 0 {
				t.Fatalf("spec %s has no checklist rows — wrong file in the map?", m.spec)
			}

			tags, err := playbookTags(filepath.Join(pbDir, m.playbook))
			if err != nil {
				t.Fatalf("read playbook tags: %v", err)
			}

			// Orphan check: row-shaped tags must be live spec rows
			// (unless declared as deliberate stage tags).
			for tag := range tags {
				if _, isStage := m.stageTags[tag]; isStage {
					continue
				}
				id, shaped := stripRowTag(tag, m.prefixes)
				if !shaped {
					continue
				}
				if !rowIDs[id] {
					t.Errorf("playbook %s has tag %q but spec %s has no row %q (renumbered or removed row? update the playbook)", m.playbook, tag, m.spec, id)
				}
			}
			// Stage-tag allowances must stay real.
			for tag, why := range m.stageTags {
				if !tags[tag] {
					t.Errorf("stageTags allows %q (%s) but %s no longer has that tag — drop the stale allowance", tag, why, m.playbook)
				}
			}

			if m.noRowTags != "" {
				return
			}

			// Coverage check: every row is tagged somewhere, or exempted.
			for id := range rowIDs {
				covered := false
				for _, cand := range rowTagCandidates(id, m.prefixes) {
					if tags[cand] {
						covered = true
						break
					}
				}
				reason, exempt := m.exemptRows[id]
				switch {
				case !covered && !exempt:
					t.Errorf("spec %s row %s has no tagged task in %s — tag the implementing task (AGENTS.md §4) or exempt it here with a reason", m.spec, id, m.playbook)
				case covered && exempt:
					t.Errorf("spec %s row %s is exempted (%q) but %s now has a tagged task — drop the stale exemption", m.spec, id, reason, m.playbook)
				}
			}
			// Stale-exemption check: exempted rows must still exist.
			for id := range m.exemptRows {
				if !rowIDs[id] {
					t.Errorf("exemptRows lists %s but spec %s has no such row — drop it", id, m.spec)
				}
			}
		})
	}
}

// rowTagCandidates returns the tag spellings that would mark a task as
// implementing the given spec row under the mapping's namespaces.
func rowTagCandidates(id string, prefixes []string) []string {
	if len(prefixes) == 0 {
		return []string{id}
	}
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p + "-" + id
	}
	return out
}

// stripRowTag reports whether tag is row-shaped under the mapping's
// namespaces, returning the bare row ID. Bare mappings accept `C3`;
// prefixed mappings accept `<prefix>-C3` (a bare `C3` in a multi-spec
// playbook is NOT row-shaped for that mapping — the cross-spec collision
// is exactly what the prefixes exist to avoid).
func stripRowTag(tag string, prefixes []string) (id string, ok bool) {
	if len(prefixes) == 0 {
		if rowShapedTag.MatchString(tag) {
			return tag, true
		}
		return "", false
	}
	for _, p := range prefixes {
		if rest, found := strings.CutPrefix(tag, p+"-"); found && rowShapedTag.MatchString(rest) {
			return rest, true
		}
	}
	return "", false
}

// playbookTags collects every string that appears under a `tags:` key
// anywhere in the playbook YAML (task, block, or play level; scalar or
// list form). ansible-playbook --list-tags would be authoritative, but a
// structural walk needs no ansible install and covers the same ground for
// presence checks.
func playbookTags(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	tags := map[string]bool{}
	collectYAMLTags(&doc, tags)
	return tags, nil
}

func collectYAMLTags(n *yaml.Node, out map[string]bool) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Kind == yaml.ScalarNode && k.Value == "tags" {
				switch v.Kind {
				case yaml.ScalarNode:
					out[v.Value] = true
				case yaml.SequenceNode:
					for _, item := range v.Content {
						if item.Kind == yaml.ScalarNode {
							out[item.Value] = true
						}
					}
				}
			}
			collectYAMLTags(v, out)
		}
		return
	}
	for _, c := range n.Content {
		collectYAMLTags(c, out)
	}
}
