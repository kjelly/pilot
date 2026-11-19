package spec

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// preTaskGateNotAlwaysAllowlist lists pre_tasks checks that a tag-scoped
// run may skip in a play whose includes pass tags down with `apply`. It is
// empty: the stage gates became `always` on 2026-09-25 and the input checks
// (core-infra-provider's infra_role, restic-backup's secrets and
// destination) on 2026-10-01. An entry needs a reason. Keys are
// "<playbook>|<task name>"; entries may only be removed.
var preTaskGateNotAlwaysAllowlist = map[string]bool{}

// TestRegression_PreTaskGatesRunUnderApplyTags is a repo-wide lint over
// playbooks/**. In a play with an include_tasks that passes tags down with
// `apply`, every assert/fail in pre_tasks must run whenever those included
// tasks can: it must be tagged `always`, or carry every tag the play's
// includes apply. Otherwise `--tags <row>` skips the gate and still runs
// the included mutation. PR #10's review found two such bypasses the
// include migration had opened: freeipa-ca-trust's stage gates
// (`--tags C2 -e stage=prod` installed the CA without confirm_prod) and
// internal-endpoint's C7/C8 DNS gates (see
// TestRegression_InternalEndpointGatesCoverTaggedMutations for the
// tasks-section half, which needs the row mapping).
func TestRegression_PreTaskGatesRunUnderApplyTags(t *testing.T) {
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	seen := map[string]bool{}
	checkedPlays := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: parse: %v", rel, err)
		}
		gates, plays := skippablePreTaskGates(doc)
		checkedPlays += plays
		for _, name := range gates {
			key := rel + "|" + name
			if preTaskGateNotAlwaysAllowlist[key] {
				seen[key] = true
				continue
			}
			t.Errorf("%s: pre_tasks gate %q is not `always` (and lacks the tags the play's includes apply), so --tags skips it while the included tasks still run", rel, name)
		}
	}
	// The migrated playbooks alone have more than ten such plays; a much
	// smaller count means the walker stopped finding them.
	if checkedPlays < 10 {
		t.Fatalf("only %d plays with apply-tagged includes found; the walker is broken", checkedPlays)
	}
	for key := range preTaskGateNotAlwaysAllowlist {
		if !seen[key] {
			t.Errorf("preTaskGateNotAlwaysAllowlist entry %q no longer matches — drop it", key)
		}
	}
}

func TestSkippablePreTaskGates(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"untagged gate before apply include (freeipa-ca-trust before the fix)", `
- hosts: all
  pre_tasks:
    - name: g
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, []string{"g"}},
		{"always gate", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [always]
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
		{"gate carries every applied tag", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [C1, C2]
      fail: {msg: x}
  tasks:
    - name: i
      tags: [C1]
      include_tasks: {file: tasks/a.yml, apply: {tags: [C1]}}
    - name: j
      tags: [C2]
      include_tasks: {file: tasks/b.yml, apply: {tags: [C2]}}
`, nil},
		{"gate misses one applied tag", `
- hosts: all
  pre_tasks:
    - name: g
      tags: [C1]
      ansible.builtin.fail: {msg: x}
  tasks:
    - name: i
      tags: [C1, C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C1, C2]}}
`, []string{"g"}},
		{"always inherited from a block", `
- hosts: all
  pre_tasks:
    - tags: [always]
      block:
        - name: g
          ansible.builtin.assert: {that: [true]}
  tasks:
    - block:
        - name: i
          tags: [C2]
          ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
		{"no apply include in the play", `
- hosts: all
  pre_tasks:
    - name: g
      ansible.builtin.assert: {that: [true]}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: tasks/a.yml
`, nil},
		{"non-gate pre_task is ignored", `
- hosts: all
  pre_tasks:
    - name: s
      ansible.builtin.set_fact: {x: 1}
  tasks:
    - name: i
      tags: [C2]
      ansible.builtin.include_tasks: {file: tasks/a.yml, apply: {tags: [C2]}}
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, _ := skippablePreTaskGates(doc)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

var gateModules = []string{"ansible.builtin.assert", "assert", "ansible.builtin.fail", "fail"}

// skippablePreTaskGates returns, for every play in doc that has an
// include_tasks with apply.tags, the names of its assert/fail pre_tasks
// whose effective tags (own plus inherited from the play and enclosing
// blocks) have neither `always` nor every tag those includes apply. The
// second result is the number of such plays checked.
func skippablePreTaskGates(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		playTags := yamlTags(play)
		applied := map[string]bool{}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], playTags, func(task map[string]any, _ []string) {
				for _, key := range []string{"ansible.builtin.include_tasks", "include_tasks"} {
					inc, _ := task[key].(map[string]any)
					apply, _ := inc["apply"].(map[string]any)
					for _, tag := range yamlTags(apply) {
						applied[tag] = true
					}
				}
			})
		}
		if len(applied) == 0 {
			continue
		}
		checked++
		walkTaskTree(play["pre_tasks"], playTags, func(task map[string]any, tags []string) {
			if !slices.ContainsFunc(gateModules, func(m string) bool { _, ok := task[m]; return ok }) {
				return
			}
			if slices.Contains(tags, "always") {
				return
			}
			for tag := range applied {
				if !slices.Contains(tags, tag) {
					name, _ := task["name"].(string)
					out = append(out, name)
					return
				}
			}
		})
	}
	return out, checked
}

// walkTaskTree calls fn for every task in a task list, recursing into
// block/rescue/always, with each task's effective tags.
func walkTaskTree(list any, inherited []string, fn func(task map[string]any, tags []string)) {
	tasks, _ := list.([]any)
	for _, item := range tasks {
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		tags := append(slices.Clone(inherited), yamlTags(task)...)
		fn(task, tags)
		for _, key := range []string{"block", "rescue", "always"} {
			walkTaskTree(task[key], tags, fn)
		}
	}
}

// yamlTags returns a task's or play's `tags:` as a list, accepting both the
// list and the single-string form.
func yamlTags(m map[string]any) []string {
	switch v := m["tags"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, tag := range v {
			if s, ok := tag.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// TestRegression_InternalEndpointGatesCoverTaggedMutations locks which
// tasks-section gates of internal-endpoint-apply.yml must run under the
// row tags of the mutations they protect. The route DNS reconcile runs
// under C4-C6 and has no zone or collision check of its own, so the C7 and
// C8 gates carry C4-C6; the service-principal (C13) and certificate (C15)
// tasks rely on the C12 enrollment preflight. Before this, `--tags C4`
// could `ipa dnsrecord-mod` a record freeipa-dns.yaml owns. It also locks
// the stage gates on the fleet-wide baseline play (C9 resolver, C10 CA
// trust), which had none.
func TestRegression_InternalEndpointGatesCoverTaggedMutations(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/internal-endpoint-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	var doc []any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc) < 2 {
		t.Fatalf("expected the baseline play and the reconcile play, got %d plays", len(doc))
	}
	find := func(play any, section, prefix string) (map[string]any, []string) {
		var task map[string]any
		var tags []string
		p, _ := play.(map[string]any)
		walkTaskTree(p[section], nil, func(tk map[string]any, tg []string) {
			if name, _ := tk["name"].(string); strings.HasPrefix(name, prefix) {
				task, tags = tk, tg
			}
		})
		if task == nil {
			t.Fatalf("no %s task named %q", section, prefix)
		}
		return task, tags
	}

	for _, gate := range []string{
		"Gate: staging or prod requires explicit confirm",
		"Gate: prod requires recent staging attestation",
	} {
		if _, tags := find(doc[0], "pre_tasks", gate); !slices.Contains(tags, "always") {
			t.Errorf("baseline play: %q must be tagged always, got %v", gate, tags)
		}
	}

	for _, tc := range []struct{ prefix, section string }{
		{"Gate: endpoint's DNS zone exists in freeipa-dns manifest", "tasks"},
		{"Gate: no DNS ownership collision with an explicit freeipa-dns.yaml record", "tasks"},
	} {
		_, tags := find(doc[1], tc.section, tc.prefix)
		for _, row := range []string{"C4", "C5", "C6"} {
			if !slices.Contains(tags, row) {
				t.Errorf("%q must carry %s (the route DNS reconcile runs under it), got %v", tc.prefix, row, tags)
			}
		}
	}

	// The environment-group cross-check is skipped only for the
	// host-decommission provider's read-only query. ansible_run_tags is a
	// tuple on ansible-core 2.19, so the comparison needs `| list`; without
	// it the condition is always true and the query failed on every host in
	// a staging or prod group (found on a vm-target, 2026-09-25).
	for i, play := range doc[:2] {
		task, tags := find(play, "pre_tasks", "Gate: stage must match this host's inventory environment group")
		if !slices.Contains(tags, "always") {
			t.Errorf("play %d: cross-check must be tagged always, got %v", i, tags)
		}
		if when, _ := task["when"].(string); when != "(ansible_run_tags | list) != ['iep_decommission_verify']" {
			t.Errorf("play %d: cross-check when = %q, want the decommission-query exemption with `| list`", i, when)
		}
	}

	preflight, tags := find(doc[1], "tasks", "Preflight: TLS certificate owner host has live FreeIPA enrollment")
	inc, _ := preflight["ansible.builtin.include_tasks"].(map[string]any)
	apply, _ := inc["apply"].(map[string]any)
	for _, row := range []string{"C12", "C13", "C15"} {
		if !slices.Contains(tags, row) || !slices.Contains(yamlTags(apply), row) {
			t.Errorf("C12 preflight must carry %s on the include and in apply.tags, got tags=%v apply=%v", row, tags, yamlTags(apply))
		}
	}
}

// TestRegression_InternalEndpointDeleteDelegateToNeverEmpty locks the
// empty-delegate_to fix in the delete sequence. A literal-address route has
// route_owner "" and a tls.mode: disabled endpoint has certificate_owner "".
// delegate_to is templated before `when`, so either one bare is a hard
// error ("Empty hostname produced from delegate_to"), not a skip. Every
// delegate_to in the file needs a fallback that its `when:` never acts on.
func TestRegression_InternalEndpointDeleteDelegateToNeverEmpty(t *testing.T) {
	raw, err := os.ReadFile("../../playbooks/apply/tasks/internal-endpoint-delete.yml")
	if err != nil {
		t.Fatal(err)
	}
	var tasks []any
	if err := yaml.Unmarshal(raw, &tasks); err != nil {
		t.Fatal(err)
	}
	delegated := 0
	walkTaskTree(tasks, nil, func(task map[string]any, _ []string) {
		target, ok := task["delegate_to"].(string)
		if !ok {
			return
		}
		delegated++
		if !strings.Contains(target, "or inventory_hostname") {
			t.Errorf("task %q: delegate_to %q has no fallback for an empty owner", task["name"], target)
		}
	})
	if delegated < 7 {
		t.Fatalf("found only %d delegated tasks; expected the nginx and certificate steps", delegated)
	}
}

// stageGateNotAlwaysAllowlist lists stage gates that may carry a row or
// action tag instead of `always`, with the reason. Keys are
// "<playbook>|<task name>". Entries may only be removed.
var stageGateNotAlwaysAllowlist = map[string]string{
	"playbooks/decommission/wazuh-manager-agent-deregister.yml|Gate: staging or prod requires explicit confirm (deregister action only)": "tagged agent_deregister, the one mutating action, so the read-only agent_query action (the provider's pre-check) is not blocked by it",
	"playbooks/decommission/wazuh-manager-agent-deregister.yml|Gate: prod requires recent staging attestation (deregister action only)":  "same as the confirm gate",
}

// stageGateText matches the stage variables and confirm/attestation inputs
// a stage gate reads.
var stageGateText = regexp.MustCompile(`\b(patch_)?stage\b|confirm_(staging|prod)|staging_attested_within_hours`)

// TestRegression_StageGatesAlwaysRunInTaggedPlays is a repo-wide lint over
// playbooks/**. In any play with a task tagged other than `always`, every
// assert that reads the stage (confirm, environment-group cross-check,
// prod attestation and other prod-only checks) must run under every
// --tags selection, so it must be tagged `always`. Six apply playbooks
// (core-infra-provider, docker, keycloak, keycloak-db, reverse-proxy,
// seaweedfs-s3) had these gates untagged until 2026-09-25. pilot deploy's
// single-component wizard passes its "只跑某幾個檢查項目" answer straight to
// --tags, so a host in the prod group deployed at the default stage
// (sandbox) with a row tag skipped the cross-check and was changed with
// sandbox rules and no confirmation.
func TestRegression_StageGatesAlwaysRunInTaggedPlays(t *testing.T) {
	seen := map[string]bool{}
	plays := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		doc := loadYAML(t, path)
		gates, checked := stageGatesNotAlways(doc)
		plays += checked
		for _, name := range gates {
			key := rel + "|" + name
			if _, ok := stageGateNotAlwaysAllowlist[key]; ok {
				seen[key] = true
				continue
			}
			t.Errorf("%s: stage gate %q is not tagged always, so --tags skips it while tagged tasks still run", rel, name)
		}
	}
	if plays < 50 {
		t.Fatalf("only %d plays with tagged tasks found; the walker is broken", plays)
	}
	for key := range stageGateNotAlwaysAllowlist {
		if !seen[key] {
			t.Errorf("stageGateNotAlwaysAllowlist entry %q no longer matches — drop it", key)
		}
	}
}

// TestRegression_ApplyPlaysWithConfirmGateHaveCrossCheck locks AGENTS.md
// §4.3: every apply play that gates on confirm_staging/confirm_prod also
// asserts that the stage matches the host's staging/prod inventory group.
// freeipa-ca-trust, internal-endpoint (both plays) and reverse-proxy had no
// such check until 2026-09-25, although §4.3 said every playbook had it.
func TestRegression_ApplyPlaysWithConfirmGateHaveCrossCheck(t *testing.T) {
	checked := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		if !strings.HasPrefix(rel, "playbooks/apply/") {
			continue
		}
		missing, n := playsMissingCrossCheck(loadYAML(t, path))
		checked += n
		for _, play := range missing {
			t.Errorf("%s: play %q has a confirm gate but no stage/inventory-group cross-check (AGENTS.md §4.3)", rel, play)
		}
	}
	if checked < 35 {
		t.Fatalf("only %d apply plays with a confirm gate found; the walker is broken", checked)
	}
}

// everyApplyPlayStageGateAllowlist lists the apply plays exempt from
// TestRegression_EveryApplyPlayHasAStageGate: a purely read-only play that
// mutates nothing, whose file header says why it needs no gate (AGENTS.md
// §4.3 point 4). Keys are "<playbook>|<play name>" (a name that appears twice
// in one file cannot be listed), values the reason. It is empty: every play
// in playbooks/apply/ carries the gates. An entry that matches no play, or
// whose play has since gained a gate, fails the test, so entries can only be
// removed.
var everyApplyPlayStageGateAllowlist = map[string]string{}

// TestRegression_EveryApplyPlayHasAStageGate locks the AGENTS.md §4.3 set
// rule: every play in playbooks/apply/*.yml has the staging/prod confirm gate
// and the prod attestation gate. That covers component playbooks, the §4.0
// internal entries (<component>-<purpose>.yml) and hotfixes, and a file with
// several plays is checked per play. The environment-group cross-check stays
// with TestRegression_ApplyPlaysWithConfirmGateHaveCrossCheck, which checks
// every play that has a confirm gate; together the two cover all three.
//
// §4.3 used to say "all 41 apply playbooks have the gate" and list them. The
// 41 was kept by hand from the deploy catalog, so the two internal entries
// without a catalog item (freeipa-identity-auth-cache.yml and
// wazuh-fim-agent-skew-hotfix.yml) were never counted, and no test required
// the gate: a new apply playbook with none, or one that lost only its prod
// attestation, passed every lint (kjelly/pilot#315).
//
// Scope and limits. Top-level playbooks/apply/*.yml and *.yaml; tasks/ is not
// read, and a document that is not a list (the data manifests) is skipped. A
// play is a list item with `hosts`. An import_playbook that resolves outside
// playbooks/apply/ fails, because its plays would not be seen. The gates are
// found by text in `that:` (playGates): `when:` is not evaluated, a gate
// written as `fail` does not count, and where the gate sits relative to the
// first mutation is not checked (the always-tag lints cover the tags).
func TestRegression_EveryApplyPlayHasAStageGate(t *testing.T) {
	var files []string
	for _, pattern := range []string{"../../playbooks/apply/*.yml", "../../playbooks/apply/*.yaml"} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, matches...)
	}
	sort.Strings(files)
	hit := map[string]bool{}
	plays := 0
	for _, path := range files {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		problems, n := stageGateProblems(rel, loadYAML(t, path), everyApplyPlayStageGateAllowlist, hit)
		plays += n
		for _, problem := range problems {
			t.Error(problem)
		}
	}
	if plays < 40 {
		t.Fatalf("only %d apply plays found in %d files; the walker is broken", plays, len(files))
	}
	for _, key := range unmatchedStageGateAllowlist(everyApplyPlayStageGateAllowlist, hit) {
		t.Errorf("everyApplyPlayStageGateAllowlist entry %q matches no play — drop it", key)
	}
}

// TestRegression_DecommissionQueryCrossCheckExemptions locks the two
// read-only host-decommission queries that skip the environment-group
// cross-check: they run without a stage (the freeipa-identity one already
// during `plan`, which takes no confirmation), and the skip must apply to
// that tag alone. `| list` because ansible_run_tags is a tuple on
// ansible-core 2.19; a bare list comparison is always unequal.
func TestRegression_DecommissionQueryCrossCheckExemptions(t *testing.T) {
	for playbook, tag := range map[string]string{
		"../../playbooks/apply/freeipa-identity-apply.yml":  "freeipa_host_absent_inspect",
		"../../playbooks/apply/internal-endpoint-apply.yml": "iep_decommission_verify",
	} {
		want := "(ansible_run_tags | list) != ['" + tag + "']"
		found := 0
		plays, _ := loadYAML(t, playbook).([]any)
		for _, p := range plays {
			play, _ := p.(map[string]any)
			walkTaskTree(play["pre_tasks"], nil, func(task map[string]any, _ []string) {
				if name, _ := task["name"].(string); name != "Gate: stage must match this host's inventory environment group" {
					return
				}
				found++
				if when, _ := task["when"].(string); when != want {
					t.Errorf("%s: cross-check when = %q, want %q", playbook, when, want)
				}
			})
		}
		if found == 0 {
			t.Errorf("%s: no environment-group cross-check found", playbook)
		}
	}
}

func TestStageGateDetection(t *testing.T) {
	const src = `
- name: untagged gates in a tagged play
  hosts: all
  pre_tasks:
    - name: confirm
      ansible.builtin.assert: {that: ["(stage == 'sandbox') or (stage == 'prod' and confirm_prod | bool)"]}
    - name: xcheck
      tags: [always]
      ansible.builtin.assert: {that: ["not ('prod' in group_names and stage != 'prod')"]}
    - name: prod only
      ansible.builtin.assert: {that: ["path | length > 0"]}
      when: stage == 'prod'
    - name: unrelated input check
      ansible.builtin.assert: {that: ["foo is defined"]}
  tasks:
    - name: row task
      tags: [C1]
      ansible.builtin.debug: {msg: x}
- name: confirm gate, no cross-check
  hosts: all
  pre_tasks:
    - name: confirm
      tags: [always]
      ansible.builtin.assert: {that: ["stage == 'sandbox' or confirm_staging | bool"]}
- name: nothing tagged
  hosts: all
  pre_tasks:
    - name: confirm
      ansible.builtin.assert: {that: ["confirm_prod | bool"]}
  tasks:
    - ansible.builtin.debug: {msg: x}
`
	var doc any
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	gates, plays := stageGatesNotAlways(doc)
	if strings.Join(gates, ",") != "confirm,prod only" || plays != 1 {
		t.Errorf("stageGatesNotAlways = %v over %d plays, want [confirm prod only] over 1", gates, plays)
	}
	missing, n := playsMissingCrossCheck(doc)
	if strings.Join(missing, ",") != "confirm gate, no cross-check,nothing tagged" || n != 3 {
		t.Errorf("playsMissingCrossCheck = %v of %d, want the second and third play of 3", missing, n)
	}
}

// TestEveryApplyPlayStageGateDetection runs the per-play lint on synthetic
// playbooks: each shape it must accept, and each way a play can fail it.
func TestEveryApplyPlayStageGateDetection(t *testing.T) {
	const (
		confirm = `    - name: confirm
      ansible.builtin.assert: {that: ["stage == 'sandbox' or confirm_staging | bool"]}
`
		cross = `    - name: xcheck
      ansible.builtin.assert: {that: ["not ('prod' in group_names and stage != 'prod')"]}
`
		attest = `    - name: attest
      ansible.builtin.assert: {that: ["(staging_attested_within_hours | int) <= 168"]}
      when: stage == 'prod'
`
		rel = "playbooks/apply/x.yml"
	)
	play := func(name, sections string) string {
		return "- name: " + name + "\n  hosts: all\n" + sections
	}
	pre := func(tasks ...string) string { return "  pre_tasks:\n" + strings.Join(tasks, "") }
	post := func(tasks ...string) string { return "  post_tasks:\n" + strings.Join(tasks, "") }
	const noGateTask = `    - name: noop
      ansible.builtin.debug: {msg: x}
`

	cases := []struct {
		name  string
		src   string
		allow map[string]string
		want  []string // exact problem strings, in order
		plays int
		hit   []string // allowlist keys that must have matched a play
	}{
		{
			name:  "gates in pre_tasks",
			src:   play("pre", pre(confirm, cross, attest)),
			plays: 1,
		},
		{
			name: "gates nested in a block in tasks",
			src: play("nested", `  tasks:
    - name: wrapper
      block:
        - ansible.builtin.assert: {that: ["confirm_prod | bool"]}
        - ansible.builtin.assert: {that: ["(staging_attested_within_hours | int) <= 168"]}
`),
			plays: 1,
		},
		{
			// the cross-check is another lint's job: a play with both
			// other gates and no cross-check passes this one
			name:  "no cross-check is left to the cross-check lint",
			src:   play("nocross", pre(confirm, attest)),
			plays: 1,
		},
		{
			name:  "a data manifest map is skipped",
			src:   "freeipa:\n  hosts: {a: b}\n  users: []\n",
			plays: 0,
		},
		{
			name: "no gate at all",
			src:  play("bare", pre(noGateTask)),
			want: []string{
				`playbooks/apply/x.yml: play #0 "bare" has no staging/prod confirm gate (AGENTS.md §4.3)`,
				`playbooks/apply/x.yml: play #0 "bare" has no prod attestation gate (AGENTS.md §4.3)`,
			},
			plays: 1,
		},
		{
			name: "the second play of a file is the one named",
			src:  play("gated", pre(confirm, cross, attest)) + play("fleet", pre(cross, attest)),
			want: []string{
				`playbooks/apply/x.yml: play #1 "fleet" has no staging/prod confirm gate (AGENTS.md §4.3)`,
			},
			plays: 2,
		},
		{
			name: "confirm only in a when:",
			src: play("whenonly", `  tasks:
    - name: guarded
      ansible.builtin.debug: {msg: x}
      when: confirm_prod | bool and staging_attested_within_hours | int <= 168
`),
			want: []string{
				`playbooks/apply/x.yml: play #0 "whenonly" has no staging/prod confirm gate (AGENTS.md §4.3)`,
				`playbooks/apply/x.yml: play #0 "whenonly" has no prod attestation gate (AGENTS.md §4.3)`,
			},
			plays: 1,
		},
		{
			name: "gates only in post_tasks",
			src:  play("late", post(confirm, attest)),
			want: []string{
				`playbooks/apply/x.yml: play #0 "late" has no staging/prod confirm gate (AGENTS.md §4.3)`,
				`playbooks/apply/x.yml: play #0 "late" has no prod attestation gate (AGENTS.md §4.3)`,
			},
			plays: 1,
		},
		{
			name: "gates written as fail instead of assert",
			src: play("failgate", pre(`    - name: confirm
      ansible.builtin.fail: {msg: need confirm}
      when: stage == 'prod' and not confirm_prod | bool
`, `    - name: attest
      ansible.builtin.fail: {msg: stale}
      when: stage == 'prod' and (staging_attested_within_hours | int) > 168
`)),
			want: []string{
				`playbooks/apply/x.yml: play #0 "failgate" has no staging/prod confirm gate (AGENTS.md §4.3)`,
				`playbooks/apply/x.yml: play #0 "failgate" has no prod attestation gate (AGENTS.md §4.3)`,
			},
			plays: 1,
		},
		{
			name: "confirm without the prod attestation",
			src:  play("noattest", pre(confirm, cross)),
			want: []string{
				`playbooks/apply/x.yml: play #0 "noattest" has no prod attestation gate (AGENTS.md §4.3)`,
			},
			plays: 1,
		},
		{
			name: "import outside playbooks/apply",
			src:  "- import_playbook: ../test/fixtures/x-fixtures.yml\n" + play("pre", pre(confirm, cross, attest)),
			want: []string{
				`playbooks/apply/x.yml: import_playbook "../test/fixtures/x-fixtures.yml" resolves to playbooks/test/fixtures/x-fixtures.yml, outside playbooks/apply/, so this lint cannot see its plays`,
			},
			plays: 1,
		},
		{
			name: "import from tasks/ is not a playbook of this directory",
			src:  "- ansible.builtin.import_playbook: tasks/x.yml\n",
			want: []string{
				`playbooks/apply/x.yml: import_playbook "tasks/x.yml" resolves to playbooks/apply/tasks/x.yml, outside playbooks/apply/, so this lint cannot see its plays`,
			},
		},
		{
			name: "import of a sibling in playbooks/apply is checked as its own file",
			src:  "- import_playbook: y-apply.yml\n",
		},
		{
			name:  "an allowlisted gate-less play is exempt and counted as matched",
			src:   play("inspect", pre(noGateTask)),
			allow: map[string]string{rel + "|inspect": "read-only"},
			plays: 1,
			hit:   []string{rel + "|inspect"},
		},
		{
			name:  "stale allowlist entry: the play now has the gates",
			src:   play("inspect", pre(confirm, cross, attest)),
			allow: map[string]string{rel + "|inspect": "read-only"},
			want: []string{
				`allowlist entry "playbooks/apply/x.yml|inspect": the play now has a stage gate — drop the entry`,
			},
			plays: 1,
			hit:   []string{rel + "|inspect"},
		},
		{
			name:  "stale allowlist entry: the play has started to gate",
			src:   play("inspect", pre(confirm)),
			allow: map[string]string{rel + "|inspect": "read-only"},
			want: []string{
				`allowlist entry "playbooks/apply/x.yml|inspect": the play now has a stage gate — drop the entry`,
			},
			plays: 1,
			hit:   []string{rel + "|inspect"},
		},
		{
			// an allowlist entry names a play, so it must not also exempt a
			// gate-less copy that kept the name
			name:  "allowlisted name used by two plays",
			src:   play("inspect", pre(noGateTask)) + play("inspect", pre(noGateTask)),
			allow: map[string]string{rel + "|inspect": "read-only"},
			want: []string{
				`allowlist entry "playbooks/apply/x.yml|inspect" matches 2 plays; give each play its own name`,
				`allowlist entry "playbooks/apply/x.yml|inspect" matches 2 plays; give each play its own name`,
			},
			plays: 2,
			hit:   []string{rel + "|inspect"},
		},
		{
			name:  "an allowlist entry for another play does not exempt this one",
			src:   play("bare", pre(noGateTask)),
			allow: map[string]string{rel + "|other": "read-only"},
			want: []string{
				`playbooks/apply/x.yml: play #0 "bare" has no staging/prod confirm gate (AGENTS.md §4.3)`,
				`playbooks/apply/x.yml: play #0 "bare" has no prod attestation gate (AGENTS.md §4.3)`,
			},
			plays: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.src), &doc); err != nil {
				t.Fatal(err)
			}
			hit := map[string]bool{}
			got, n := stageGateProblems(rel, doc, tc.allow, hit)
			if !slices.Equal(got, tc.want) || n != tc.plays {
				t.Errorf("stageGateProblems = %q over %d plays, want %q over %d", got, n, tc.want, tc.plays)
			}
			for _, key := range tc.hit {
				if !hit[key] {
					t.Errorf("allowlist key %q was not recorded as matched", key)
				}
			}
			if tc.hit == nil && len(hit) != 0 {
				t.Errorf("matched allowlist keys %v, want none", hit)
			}
		})
	}

	t.Run("unmatched allowlist entries are reported", func(t *testing.T) {
		allow := map[string]string{"playbooks/apply/gone.yml|inspect": "r", rel + "|inspect": "r"}
		got := unmatchedStageGateAllowlist(allow, map[string]bool{rel + "|inspect": true})
		if want := []string{"playbooks/apply/gone.yml|inspect"}; !slices.Equal(got, want) {
			t.Errorf("unmatchedStageGateAllowlist = %q, want %q", got, want)
		}
		if got := unmatchedStageGateAllowlist(nil, nil); len(got) != 0 {
			t.Errorf("empty allowlist reported %q", got)
		}
	})
}

// applyPlay is one play of an apply playbook and which of the §4.3 stage
// gates playGates found in it.
type applyPlay struct {
	index                  int // position among the file's plays, from 0
	name                   string
	confirm, cross, attest bool
}

// applyPlaysOf returns the plays of one parsed apply playbook (list items with
// `hosts`) and the targets of its import_playbook items. A document that is
// not a list, such as a data manifest, has neither.
func applyPlaysOf(doc any) (plays []applyPlay, imports []string) {
	items, _ := doc.([]any)
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"import_playbook", "ansible.builtin.import_playbook"} {
			if v, ok := m[key]; ok {
				imports = append(imports, fmt.Sprint(v))
			}
		}
		if _, ok := m["hosts"]; !ok {
			continue
		}
		name, _ := m["name"].(string)
		confirm, cross, attest := playGates(m)
		plays = append(plays, applyPlay{index: len(plays), name: name, confirm: confirm, cross: cross, attest: attest})
	}
	return plays, imports
}

// stageGateProblems returns one message per violation of the apply-play stage
// gate rule in the playbook rel (repo-relative, slash-separated) and the
// number of plays it checked. hit collects the allowlist keys that matched a
// play, for unmatchedStageGateAllowlist.
func stageGateProblems(rel string, doc any, allow map[string]string, hit map[string]bool) ([]string, int) {
	plays, imports := applyPlaysOf(doc)
	var out []string
	for _, imp := range imports {
		target := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(rel), imp)))
		if filepath.ToSlash(filepath.Dir(target)) != "playbooks/apply" {
			out = append(out, fmt.Sprintf("%s: import_playbook %q resolves to %s, outside playbooks/apply/, so this lint cannot see its plays", rel, imp, target))
		}
	}
	perKey := map[string]int{}
	for _, pl := range plays {
		perKey[rel+"|"+pl.name]++
	}
	for _, pl := range plays {
		key := rel + "|" + pl.name
		if _, ok := allow[key]; ok {
			hit[key] = true
			switch {
			case perKey[key] > 1:
				out = append(out, fmt.Sprintf("allowlist entry %q matches %d plays; give each play its own name", key, perKey[key]))
			case pl.confirm || pl.attest:
				out = append(out, fmt.Sprintf("allowlist entry %q: the play now has a stage gate — drop the entry", key))
			}
			continue
		}
		if !pl.confirm {
			out = append(out, fmt.Sprintf("%s: play #%d %q has no staging/prod confirm gate (AGENTS.md §4.3)", rel, pl.index, pl.name))
		}
		if !pl.attest {
			out = append(out, fmt.Sprintf("%s: play #%d %q has no prod attestation gate (AGENTS.md §4.3)", rel, pl.index, pl.name))
		}
	}
	return out, len(plays)
}

// unmatchedStageGateAllowlist returns the allowlist keys no play matched, in
// order.
func unmatchedStageGateAllowlist(allow map[string]string, hit map[string]bool) []string {
	var out []string
	for key := range allow {
		if !hit[key] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// stageGatesNotAlways returns, for every play in doc with a task tagged
// other than `always`, the names of the asserts that read the stage but
// are not tagged `always` (own or inherited), and how many such plays it
// checked.
func stageGatesNotAlways(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		playTags := yamlTags(play)
		tagged := false
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], playTags, func(_ map[string]any, tags []string) {
				if slices.ContainsFunc(tags, func(tag string) bool { return tag != "always" }) {
					tagged = true
				}
			})
		}
		if !tagged {
			continue
		}
		checked++
		for _, section := range []string{"pre_tasks", "tasks"} {
			walkTaskTree(play[section], playTags, func(task map[string]any, tags []string) {
				if isStageGate(task) && !slices.Contains(tags, "always") {
					name, _ := task["name"].(string)
					out = append(out, name)
				}
			})
		}
	}
	return out, checked
}

// crossCheckStageText matches the stage variable a cross-check compares with
// group_names.
var crossCheckStageText = regexp.MustCompile(`\b(patch_)?stage\b`)

// playGates reports which of the three AGENTS.md §4.3 stage gates a play has.
// This is the one definition of them; every lint that asks "does this play
// have the confirm gate" calls it. Only asserts in pre_tasks and tasks
// (including blocks) count, read from `that:` as text:
//   - confirm: that: names confirm_staging or confirm_prod;
//   - cross: that: names group_names and the stage variable (the
//     environment-group cross-check);
//   - attest: that: names staging_attested_within_hours (the prod
//     attestation gate).
//
// A `when:` that mentions these names, a `fail` task, and anything in
// post_tasks or rescue-only paths are not a gate. The text is not evaluated.
func playGates(play map[string]any) (confirm, cross, attest bool) {
	for _, section := range []string{"pre_tasks", "tasks"} {
		walkTaskTree(play[section], nil, func(task map[string]any, _ []string) {
			that := assertThat(task)
			if strings.Contains(that, "confirm_staging") || strings.Contains(that, "confirm_prod") {
				confirm = true
			}
			if strings.Contains(that, "group_names") && crossCheckStageText.MatchString(that) {
				cross = true
			}
			if strings.Contains(that, "staging_attested_within_hours") {
				attest = true
			}
		})
	}
	return confirm, cross, attest
}

// playsMissingCrossCheck returns the names of the plays in doc that have a
// confirm_staging/confirm_prod assert but no assert comparing the stage
// with group_names, and how many plays with a confirm assert it checked.
func playsMissingCrossCheck(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		confirm, cross, _ := playGates(play)
		if !confirm {
			continue
		}
		checked++
		if !cross {
			name, _ := play["name"].(string)
			out = append(out, name)
		}
	}
	return out, checked
}

// isStageGate reports whether task is an assert whose that: or when: reads
// the stage or its confirm/attestation inputs.
func isStageGate(task map[string]any) bool {
	if _, ok := task["ansible.builtin.assert"]; !ok {
		if _, ok := task["assert"]; !ok {
			return false
		}
	}
	return stageGateText.MatchString(assertThat(task) + " " + fmt.Sprint(task["when"]))
}

// assertThat returns an assert task's that: as one string ("" for any other
// task).
func assertThat(task map[string]any) string {
	for _, module := range []string{"ansible.builtin.assert", "assert"} {
		if args, ok := task[module].(map[string]any); ok {
			return fmt.Sprint(args["that"])
		}
	}
	return ""
}

func playbookFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir("../../playbooks", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

func loadYAML(t *testing.T, path string) any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: parse: %v", path, err)
	}
	return doc
}

// TestRegression_NoUntaggedChecksInTaggedPlays is a repo-wide lint over
// playbooks/**. In a play with tasks tagged other than `always`, an
// assert or fail with no tag of its own or from an enclosing block is
// skipped by every --tags run while the tagged tasks still run, so its
// check silently stops applying. Until 2026-10-01, nine apply playbooks
// had such input checks (required variables, secrets, a resolvable S3
// destination, alertmanager's non-empty config, detection-engine's
// feature profile) and detection-engine and agent-controller two mid-flow
// asserts each. A check in pre_tasks, or next to tagged steps in the same
// task list, must be `always` or carry the row tags of the steps it
// guards. An untagged check among untagged steps is consistent: both run
// only in a full run (the decommission playbooks, whose only tagged tasks
// are the read-only `inspect` ones, verify their untagged removal that
// way). Rescue and block `always:` sections are checked by
// TestRegression_RescueRunsWheneverItsBlockDoes.
func TestRegression_NoUntaggedChecksInTaggedPlays(t *testing.T) {
	plays := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")
		names, n := untaggedChecksInTaggedPlays(loadYAML(t, path))
		plays += n
		for _, name := range names {
			t.Errorf("%s: check %q has no tag, so any --tags run skips it while the play's tagged tasks run", rel, name)
		}
	}
	if plays < 50 {
		t.Fatalf("only %d plays with tagged tasks found; the walker is broken", plays)
	}
}

func TestUntaggedChecksInTaggedPlays(t *testing.T) {
	const src = `
- hosts: all
  pre_tasks:
    - name: untagged input check
      ansible.builtin.assert: {that: [x is defined]}
    - name: always input check
      tags: [always]
      assert: {that: [x is defined]}
  tasks:
    - name: row task
      tags: [C1]
      ansible.builtin.debug: {msg: x}
    - tags: [C2]
      block:
        - name: inherits C2 from the block
          ansible.builtin.fail: {msg: x}
    - block:
        - name: tagged step
          tags: [C3]
          ansible.builtin.command: step
        - name: untagged mid-flow assert
          ansible.builtin.assert: {that: [y]}
      rescue:
        - name: rescue fail is out of scope here
          ansible.builtin.fail: {msg: rollback}
- hosts: all
  tasks:
    - name: untagged play has nothing to skip
      ansible.builtin.assert: {that: [z]}
- hosts: all
  pre_tasks:
    - name: read-only inspect
      tags: [inspect]
      ansible.builtin.debug: {msg: x}
  tasks:
    - block:
        - name: untagged removal
          ansible.builtin.command: rm x
        - name: verify removal (decommission shape, consistent)
          ansible.builtin.assert: {that: [gone]}
`
	var doc any
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	names, plays := untaggedChecksInTaggedPlays(doc)
	if strings.Join(names, ",") != "untagged input check,untagged mid-flow assert" || plays != 2 {
		t.Fatalf("got %v over %d plays", names, plays)
	}
}

// untaggedChecksInTaggedPlays returns the names of the assert/fail tasks
// with no effective tag, outside rescue and block `always:` sections, that
// sit in pre_tasks or in a task list where another task (or a task nested
// under it) is tagged other than `always`, in every play of doc that has
// such a tagged task; and the number of those plays.
func untaggedChecksInTaggedPlays(doc any) ([]string, int) {
	plays, _ := doc.([]any)
	var out []string
	checked := 0
	for _, p := range plays {
		play, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := play["hosts"]; !ok {
			continue
		}
		playTags := yamlTags(play)
		tagged := false
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], playTags, func(_ map[string]any, tags []string) {
				if slices.ContainsFunc(tags, func(tag string) bool { return tag != "always" }) {
					tagged = true
				}
			})
		}
		if !tagged {
			continue
		}
		checked++
		rowTagged := func(task map[string]any, inherited []string) bool {
			found := false
			walkTaskTree([]any{task}, inherited, func(_ map[string]any, tags []string) {
				if slices.ContainsFunc(tags, func(tag string) bool { return tag != "always" }) {
					found = true
				}
			})
			return found
		}
		var walk func(list any, inherited []string, inPreTasks bool)
		walk = func(list any, inherited []string, inPreTasks bool) {
			tasks, _ := list.([]any)
			for i, item := range tasks {
				task, ok := item.(map[string]any)
				if !ok {
					continue
				}
				tags := append(slices.Clone(inherited), yamlTags(task)...)
				if slices.ContainsFunc(gateModules, func(m string) bool { _, ok := task[m]; return ok }) && len(tags) == 0 {
					amongTagged := false
					for j, other := range tasks {
						if o, ok := other.(map[string]any); ok && j != i && rowTagged(o, inherited) {
							amongTagged = true
							break
						}
					}
					if inPreTasks || amongTagged {
						name, _ := task["name"].(string)
						out = append(out, name)
					}
				}
				walk(task["block"], tags, false)
			}
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walk(play[section], playTags, section == "pre_tasks")
		}
	}
	return out, checked
}
