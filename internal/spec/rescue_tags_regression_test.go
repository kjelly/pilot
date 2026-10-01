package spec

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// rescueTagGapAllowlist lists playbooks whose rescues a tag-scoped run can
// still skip. Each needs its rollback's prerequisites made to run under
// tags too, and its own tag-scoped failure test on a target, in a
// follow-up to the 2026-10-01 change that fixed the first eight. An entry
// fails the test once the playbook has no gaps left.
var rescueTagGapAllowlist = map[string]string{
	"playbooks/apply/audit-log-forwarding-apply.yml":       "follow-up: audit rules and SIEM forward rollback",
	"playbooks/apply/dcgm-exporter-apply.yml":              "follow-up: container removal",
	"playbooks/apply/freeipa-nfs-server-apply.yml":         "follow-up: exports fragment snapshot and restore",
	"playbooks/apply/freeipa-realm-replacement-apply.yml":  "follow-up: pre-migration archive restore",
	"playbooks/apply/freeipa-server-apply.yml":             "follow-up: rescue tagged freeipa/freeipa-verify, block has freeipa-dns-recursion",
	"playbooks/apply/host-monitoring-apply.yml":            "follow-up: node_exporter stop",
	"playbooks/apply/log-server-apply.yml":                 "follow-up: rsyslog drop-in removal",
	"playbooks/apply/log-shipping-apply.yml":               "follow-up: failure message only",
	"playbooks/apply/pilot-access-target-policy-apply.yml": "follow-up: sshd drop-in snapshot and restore",
	"playbooks/apply/snmp-exporter-apply.yml":              "follow-up: auths.yml removal",
	"playbooks/apply/wazuh-fim-apply.yml":                  "follow-up: FIM block and /etc/hosts pin removal",
	"playbooks/apply/wazuh-manager-apply.yml":              "follow-up: SIEM forward block and /etc/hosts pin removal",
}

// TestRegression_RescueRunsWheneverItsBlockDoes is a repo-wide lint over
// playbooks/**. --tags filters a block's rescue like any other task list:
// when a selected task in the block fails, only the rescue tasks that the
// same --tags selects run (checked on ansible-core 2.19.2). Until
// 2026-10-01, eight apply playbooks (agent-controller, alertmanager,
// dashboard, detection-engine, pam-oidc-sshd, prometheus, restic-backup,
// thanos-query) had untagged rescues around row-tagged steps, so a failed
// `--tags <row>` run did not roll back. Tagging only the rollback is worse:
// the untagged `fail` at the end of the rescue is skipped, the rescue
// succeeds, and the run ends rc=0 with `rescued=1`. A rescue task must be tagged
// `always`, or carry every tag of every task in its block (and be untagged
// when one of them is), so that it runs under every selection that runs
// any of them. A block's `always:` section is filtered the same way and
// gets the same check (none of the eight in playbooks/** had a gap). A
// rescue that reads a snapshot or fact set earlier needs that setter to
// run as well; for `always` rescues
// TestRegression_AlwaysTaggedTasksHaveAllPrerequisitesAlways checks this.
func TestRegression_RescueRunsWheneverItsBlockDoes(t *testing.T) {
	blocks := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(path, "../../")
		problems, n := rescueTagGaps(loadYAML(t, path))
		blocks += n
		if _, allowed := rescueTagGapAllowlist[rel]; allowed {
			if len(problems) == 0 {
				t.Errorf("%s: no rescue gaps left; remove it from rescueTagGapAllowlist", rel)
			}
			continue
		}
		for _, p := range problems {
			t.Errorf("%s: %s", rel, p)
		}
	}
	for rel := range rescueTagGapAllowlist {
		if _, err := os.Stat("../../" + rel); err != nil {
			t.Errorf("rescueTagGapAllowlist: %s: %v", rel, err)
		}
	}
	// playbooks/** has dozens of block/rescue pairs; none found means the
	// detection broke.
	if blocks < 20 {
		t.Fatalf("found only %d blocks with a rescue; the detection is broken", blocks)
	}
}

func TestRescueTagGaps(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"untagged rescue around a row-tagged step (the 2026-10-01 bug)", `
- hosts: all
  tasks:
    - block:
        - name: snapshot
          copy: {src: a, dest: a.bak}
        - name: mutate
          tags: [C3]
          copy: {src: b, dest: a}
      rescue:
        - name: restore
          copy: {src: a.bak, dest: a}
        - name: surface
          fail: {msg: x}
`, []string{`"restore"`, `"surface"`}},
		{"always rescue", `
- hosts: all
  tasks:
    - block:
        - name: mutate
          tags: [C3]
          copy: {src: b, dest: a}
      rescue:
        - name: restore
          tags: [always]
          copy: {src: a.bak, dest: a}
`, nil},
		{"only the rollback is always: the untagged fail is skipped and the run ends rc=0", `
- hosts: all
  tasks:
    - block:
        - name: mutate
          tags: [C3]
          copy: {src: b, dest: a}
      rescue:
        - name: restore
          tags: [always]
          copy: {src: a.bak, dest: a}
        - name: surface
          fail: {msg: x}
`, []string{`"surface"`}},
		{"rescue inherits the block's tags", `
- hosts: all
  tasks:
    - tags: [C1]
      block:
        - name: mutate
          copy: {src: b, dest: a}
      rescue:
        - name: restore
          copy: {src: a.bak, dest: a}
`, nil},
		{"all untagged", `
- hosts: all
  tasks:
    - block:
        - name: mutate
          copy: {src: b, dest: a}
      rescue:
        - name: restore
          copy: {src: a.bak, dest: a}
`, nil},
		{"rescue tagged but block has an untagged step", `
- hosts: all
  tasks:
    - block:
        - name: mutate
          copy: {src: b, dest: a}
        - name: check
          tags: [C2]
          command: x
      rescue:
        - name: restore
          tags: [C2]
          copy: {src: a.bak, dest: a}
`, []string{`"restore"`}},
		{"rescue misses one row tag", `
- hosts: all
  tasks:
    - block:
        - {name: a, tags: [C1], command: x}
        - {name: b, tags: [C2], command: y}
      rescue:
        - {name: restore, tags: [C1], command: z}
`, []string{`"restore"`}},
		{"always step needs an always rescue", `
- hosts: all
  tasks:
    - block:
        - {name: a, tags: [always], command: x}
      rescue:
        - {name: restore, command: z}
`, []string{`"restore"`}},
		{"nested block in the rescue", `
- hosts: all
  tasks:
    - block:
        - {name: a, tags: [C1], command: x}
      rescue:
        - tags: [always]
          block:
            - {name: restore, command: z}
`, nil},
		{"block always: section is filtered the same way", `
- hosts: all
  tasks:
    - block:
        - {name: a, tags: [C1], command: x}
      rescue:
        - {name: restore, tags: [always], command: z}
      always:
        - {name: cleanup, command: rm}
`, []string{`always task "cleanup"`}},
		{"task file", `
- block:
    - {name: a, tags: [C1], command: x}
  rescue:
    - {name: restore, command: z}
`, []string{`"restore"`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, n := rescueTagGaps(doc)
			if n == 0 {
				t.Fatal("block with rescue not detected")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d problems %v, want %d", len(got), got, len(tc.want))
			}
			for i, w := range tc.want {
				if !strings.Contains(got[i], w) {
					t.Errorf("problem %d = %q, want it to name %s", i, got[i], w)
				}
			}
		})
	}
}

// rescueTagGaps returns one message per rescue or block `always:` task in
// doc that some --tags selection skips while it runs a task of its block,
// and the number of blocks with a rescue found.
func rescueTagGaps(doc any) ([]string, int) {
	items, _ := doc.([]any)
	var lists []struct {
		list any
		tags []string
	}
	add := func(list any, tags []string) {
		lists = append(lists, struct {
			list any
			tags []string
		}{list, tags})
	}
	if len(items) > 0 {
		if first, _ := items[0].(map[string]any); first != nil {
			if _, isPlay := first["hosts"]; !isPlay {
				add(items, nil) // a task file
			}
		}
	}
	for _, p := range items {
		play, _ := p.(map[string]any)
		if _, ok := play["hosts"]; !ok {
			continue
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			add(play[section], yamlTags(play))
		}
	}

	var out []string
	blocks := 0
	for _, l := range lists {
		walkTaskTree(l.list, l.tags, func(task map[string]any, tags []string) {
			if task["block"] == nil || (task["rescue"] == nil && task["always"] == nil) {
				return
			}
			if task["rescue"] != nil {
				blocks++
			}
			var body [][]string
			walkTaskTree(task["block"], tags, func(t map[string]any, tt []string) {
				if t["block"] == nil {
					body = append(body, tt)
				}
			})
			for _, section := range []string{"rescue", "always"} {
				walkTaskTree(task[section], tags, func(r map[string]any, rt []string) {
					if r["block"] != nil || slices.Contains(rt, "always") {
						return
					}
					for _, bt := range body {
						if reason := rescueSkippedReason(bt, rt); reason != "" {
							name, _ := r["name"].(string)
							out = append(out, fmt.Sprintf("%s task %q (tags %v) does not run under %s, which runs a task of its block; tag it always", section, name, rt, reason))
							return
						}
					}
				})
			}
		})
	}
	return out, blocks
}

// rescueSkippedReason returns a --tags selection that runs a task tagged
// bodyTags but not a rescue task tagged rescueTags (neither has `always`
// unless bodyTags does), or "" when there is none.
func rescueSkippedReason(bodyTags, rescueTags []string) string {
	if slices.Contains(bodyTags, "always") {
		return "every --tags"
	}
	if len(bodyTags) == 0 {
		if len(rescueTags) > 0 {
			return "--tags untagged"
		}
		return ""
	}
	for _, tag := range bodyTags {
		if !slices.Contains(rescueTags, tag) {
			return "--tags " + tag
		}
	}
	return ""
}
