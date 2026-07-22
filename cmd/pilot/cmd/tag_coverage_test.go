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
	{spec: "docker.md", playbook: "docker-apply.yml", prefixes: []string{"docker"},
		exemptRows: map[string]string{
			"C3": "docker --version probe — side effect of the engine install (docker-C1)",
			"C5": "hello-world pull+run probe — verify-only whole-chain check",
			"C6": "default networks (bridge/host/none) are created by the engine itself (docker-C1)",
			"C7": "compose v2 plugin version probe — installed by the same package set (docker-C1)",
			"C8": "cgroup driver probe — property of the engine install (docker-C1)",
		}},
	{spec: "freeipa-client.md", playbook: "freeipa-client-apply.yml",
		exemptRows: map[string]string{
			"C4":  "host keytab is produced by ipa-client-install (C1..C3) — no separate mutation task",
			"C5":  "SSSD account resolution is wired by ipa-client-install — same as C4",
			"C6":  "sssd.conf access_provider=ipa is written by ipa-client-install — same as C4",
			"C10": "kernel auditing probe (auditctl -s) — verify-only outcome of the audit tasks",
		}},
	{spec: "freeipa-identity.md", playbook: "freeipa-identity-apply.yml",
		noRowTags: "data-driven reconciler: tasks loop over the vault roster, no 1:1 row↔task mapping; feature tags (users/groups/hbac/sudo) instead"},
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
	{spec: "prometheus.md", playbook: "prometheus-apply.yml"},
	{spec: "restic-backup.md", playbook: "restic-backup-apply.yml"},
	{spec: "seaweedfs-s3.md", playbook: "seaweedfs-s3-apply.yml", prefixes: []string{"s3"},
		exemptRows: map[string]string{
			"C8": "anonymous DELETE + GET-404 probe — verify-only outcome of the gateway config (s3-C1..C7)",
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
	"hello-localhost.md":         "smoke-test spec; its playbook lives in playbooks/test/",
	"core-infra.md":              "composite host-baseline spec: satisfied by dns/ntp/keycloak playbooks together, no single apply playbook",
	"sso-composition-example.md": "documentation example of the spec-supplier pattern, never applied",
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
