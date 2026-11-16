package spec

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The kernel audit rule list is one shared object: every component that keeps rules in it (Wazuh's who-data
// keeps `wazuh_fim` watches there) loses them when another component runs `augenrules --load` (its
// audit.rules starts with `-D`, and the script calls `auditctl -R` even when it reports "No change"), runs
// `auditctl -R` or `-D`, or restarts auditd (Ubuntu 24.04's unit loads the rules in ExecStartPost). Until
// issue #324 audit-log-forwarding-apply.yml did that in Step 3 on every apply, in Step 8a and in its rescue,
// and nothing gave the watches back: every row of every spec stayed green while who-data was off.
//
// TestRegression_KernelAuditListDisturbersGuardAndGiveBack is the repo-wide lint for the class (AGENTS.md
// section 5.10): a task of playbooks/** that can empty or replace the kernel audit list must
//
//   - carry a `when` that is not constantly true (a disturbance is never unconditional);
//   - be preceded, in the same play, by the include of tasks/audit-whodata-guard.yml under exactly the same
//     `when` (refuse before touching anything while a Wazuh writer is active or the Wazuh state cannot be
//     read); a rescue is exempt from this one, it has nothing left to refuse;
//   - be followed, in the normal flow after it, by the include of tasks/audit-whodata-rearm.yml (give the
//     watches back, or fail with a typed reason); and, when it sits in a block that has a rescue, the rescue
//     must include the re-arm too; a disturbance inside a rescue must be followed by it in that rescue.
//
// A site that cannot or should not do this is listed in kernelAuditListDisturberAllowlist with the reason; an
// entry that no longer matches a disturbing task fails, so the list cannot go stale.
var kernelAuditListDisturberAllowlist = map[string]string{
	"playbooks/decommission/audit-log-forwarding-decommission.yml::Reload the kernel audit rule list (custom rules removed)":                                          "host retirement: the decommission removes the whole host's Wazuh agent with it, and runs only for a host being retired",
	"playbooks/apply/audit-log-forwarding-apply.yml::Step 8b: Reload auditd if the syslog plugin config changed or isn't actually running (spec C21) — RedHat family": "measured not to be a disturbance: on AlmaLinux 9.8 (Wazuh agent 4.14.x, 2026-11-12) with who-data live, 6 consecutive SIGHUPs to auditd 8 s apart left the wazuh_fim watches (2), the kernel list size (8), the audisp-af_unix PID, its established connection and its listener unchanged and logged no `Audit rules removed`, and the real playbook's HUP path with a drifted syslog plugin config did the same without touching the agent; measured only for plugin-config-change and plain HUPs on EL 9.8 (docs/verification/audit-log-forwarding.md section 5)",
}

const (
	guardInclude = "audit-whodata-guard.yml"
	rearmInclude = "audit-whodata-rearm.yml"
)

var (
	// A command that empties or replaces the kernel audit list: augenrules --load, auditctl -R/-D/--reload-rules,
	// a SIGHUP of auditd, and a service-manager restart or reload of auditd, whatever options come before the
	// verb (`systemctl -q restart auditd`, `--quiet`, `auditd.service`). A unit whose name only begins with
	// auditd is another unit.
	disturbingCommand = regexp.MustCompile(`(?:` +
		`\baugenrules\b[^\n|;&]*--load\b` +
		`|\bauditctl\b[^\n|;&]*(?:\s-[RD]\b|\s--reload-rules\b)` +
		`|\b(?:pkill|kill)\b[^\n|;&]*-(?:HUP|1|SIGHUP)\b[^\n|;&]*\bauditd\b` +
		`|\bservice\s+auditd\s+(?:restart|reload|force-reload)\b` +
		`|\bsystemctl\b(?:\s+-{1,2}[A-Za-z][\w=-]*)*\s+(?:restart|reload|try-restart|reload-or-restart|try-reload-or-restart|force-reload)\s+auditd(?:\.service)?(?:[\s;&|]|$)` +
		`)`)
	auditdUnit = regexp.MustCompile(`^auditd(?:\.service)?$`)
)

type auditTaskRef struct {
	task     map[string]any
	name     string
	rescueOf []auditBlockCtx // enclosing blocks, outermost first
	inRescue bool            // inside any rescue/always section
}

type auditBlockCtx struct {
	rescue  []any
	section string // block | rescue | always
}

func flattenAuditTasks(tasks []any, ctx []auditBlockCtx, inRescue bool, out *[]auditTaskRef) {
	for _, raw := range tasks {
		task, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := task["name"].(string)
		*out = append(*out, auditTaskRef{task: task, name: name, rescueOf: ctx, inRescue: inRescue})
		block, hasBlock := task["block"].([]any)
		rescue, _ := task["rescue"].([]any)
		always, _ := task["always"].([]any)
		if hasBlock {
			flattenAuditTasks(block, append(append([]auditBlockCtx{}, ctx...), auditBlockCtx{rescue: rescue, section: "block"}), inRescue, out)
			if rescue != nil {
				flattenAuditTasks(rescue, append(append([]auditBlockCtx{}, ctx...), auditBlockCtx{rescue: rescue, section: "rescue"}), true, out)
			}
			if always != nil {
				flattenAuditTasks(always, append(append([]auditBlockCtx{}, ctx...), auditBlockCtx{rescue: rescue, section: "always"}), true, out)
			}
		}
	}
}

// auditTaskLists returns each independently ordered task list of a YAML document: one per play (pre_tasks,
// tasks, post_tasks in play order, which is the order Ansible runs them), or the file itself for a bare task file.
func auditTaskLists(document any) [][]any {
	list, ok := document.([]any)
	if !ok {
		return nil
	}
	isPlay := false
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			if _, has := m["hosts"]; has {
				isPlay = true
			}
		}
	}
	if !isPlay {
		return [][]any{list}
	}
	var lists [][]any
	for _, item := range list {
		play, ok := item.(map[string]any)
		if !ok {
			continue
		}
		var tasks []any
		for _, key := range []string{"pre_tasks", "tasks", "post_tasks"} {
			if part, ok := play[key].([]any); ok {
				tasks = append(tasks, part...)
			}
		}
		lists = append(lists, tasks)
	}
	return lists
}

func auditCommandText(task map[string]any) string {
	var parts []string
	for key, value := range task {
		switch key {
		case "ansible.builtin.command", "command", "ansible.builtin.shell", "shell", "ansible.builtin.raw", "raw", "ansible.builtin.script", "script":
			switch v := value.(type) {
			case string:
				parts = append(parts, v)
			case map[string]any:
				if cmd, ok := v["cmd"].(string); ok {
					parts = append(parts, cmd)
				}
				if argv, ok := v["argv"].([]any); ok {
					words := make([]string, len(argv))
					for i, w := range argv {
						words[i] = fmt.Sprint(w)
					}
					parts = append(parts, strings.Join(words, " "))
				}
			}
		}
	}
	return strings.Join(parts, "\n")
}

// describeDisturber names what a task does: its command text, or the auditd service operation.
func describeDisturber(task map[string]any) string {
	if text := strings.Join(strings.Fields(auditCommandText(task)), " "); text != "" {
		return text
	}
	return "an auditd restart or reload through a service module"
}

func disturbsKernelAuditList(task map[string]any) bool {
	if disturbingCommand.MatchString(auditCommandText(task)) {
		return true
	}
	for _, module := range []string{"ansible.builtin.systemd", "systemd", "ansible.builtin.systemd_service", "ansible.builtin.service", "service"} {
		if args, ok := task[module].(map[string]any); ok {
			name := fmt.Sprint(args["name"])
			state := fmt.Sprint(args["state"])
			if auditdUnit.MatchString(name) && (state == "restarted" || state == "reloaded") {
				return true
			}
		}
	}
	return false
}

func nonTrivialWhen(task map[string]any) bool {
	when, ok := task["when"]
	if !ok {
		return false
	}
	switch v := when.(type) {
	case bool:
		return !v
	case string:
		text := strings.TrimSpace(v)
		return text != "" && !regexp.MustCompile(`^(?:true|True|yes|\{\{\s*true\s*\}\})$`).MatchString(text)
	case []any:
		for _, item := range v {
			if t, ok := item.(string); ok && strings.TrimSpace(t) != "" && !regexp.MustCompile(`^(?:true|True|yes)$`).MatchString(strings.TrimSpace(t)) {
				return true
			}
		}
		return false
	}
	return false
}

// whenKey is the `when` of a task as one comparable text.
func whenKey(task map[string]any) string {
	return fmt.Sprintf("%#v", task["when"])
}

func includesFile(task map[string]any, file string) bool {
	for _, key := range []string{"ansible.builtin.include_tasks", "include_tasks", "ansible.builtin.import_tasks", "import_tasks"} {
		switch v := task[key].(type) {
		case string:
			if strings.HasSuffix(v, file) {
				return true
			}
		case map[string]any:
			if f, ok := v["file"].(string); ok && strings.HasSuffix(f, file) {
				return true
			}
		}
	}
	return false
}

func anyIncludes(tasks []any, file string) bool {
	var flat []auditTaskRef
	flattenAuditTasks(tasks, nil, false, &flat)
	for _, ref := range flat {
		if includesFile(ref.task, file) {
			return true
		}
	}
	return false
}

// auditDisturbanceProblems lists, for one document, every disturbing task that lacks a piece of the contract.
// `site` is "<path>::<task name>", the allowlist key.
func auditDisturbanceProblems(path string, document any) (problems []string, sites []string) {
	for _, tasks := range auditTaskLists(document) {
		var flat []auditTaskRef
		flattenAuditTasks(tasks, nil, false, &flat)
		for i, ref := range flat {
			if !disturbsKernelAuditList(ref.task) {
				continue
			}
			site := path + "::" + ref.name
			sites = append(sites, site)
			var missing []string
			if !nonTrivialWhen(ref.task) {
				missing = append(missing, "a `when` that is not constantly true")
			}
			// The guard must refuse under exactly the condition under which this task disturbs the list, so a
			// guard for another disturbance in the same play (a Debian restart, say) does not cover this one.
			// A rescue has nothing left to refuse: it only has to give the watches back.
			if !ref.inRescue {
				guarded := false
				for _, before := range flat[:i] {
					if includesFile(before.task, guardInclude) && whenKey(before.task) == whenKey(ref.task) {
						guarded = true
					}
				}
				if !guarded {
					missing = append(missing, "an earlier include of tasks/"+guardInclude+" under the same `when`")
				}
			}
			if !ref.inRescue {
				followed := false
				for _, after := range flat[i+1:] {
					if !after.inRescue && includesFile(after.task, rearmInclude) {
						followed = true
					}
				}
				if !followed {
					missing = append(missing, "a later include of tasks/"+rearmInclude+" in the normal flow")
				}
				for _, ctx := range ref.rescueOf {
					if ctx.section == "block" && ctx.rescue != nil && !anyIncludes(ctx.rescue, rearmInclude) {
						missing = append(missing, "an include of tasks/"+rearmInclude+" in the rescue of its block")
					}
				}
			} else {
				followed := false
				for _, after := range flat[i+1:] {
					if after.inRescue && includesFile(after.task, rearmInclude) {
						followed = true
					}
				}
				if !followed {
					missing = append(missing, "a later include of tasks/"+rearmInclude+" in the same rescue")
				}
			}
			if len(missing) > 0 {
				problems = append(problems, fmt.Sprintf("%s: runs `%s` (empties or replaces the kernel audit list, with the Wazuh agent's who-data in it) without %s",
					site, describeDisturber(ref.task), strings.Join(missing, ", ")))
			}
		}
	}
	return problems, sites
}

func TestRegression_KernelAuditListDisturbersGuardAndGiveBack(t *testing.T) {
	flagged := map[string]bool{} // sites that lack a piece of the contract
	seen := map[string]bool{}    // every disturbing site
	scanned := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(path, "../../")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := yaml.Unmarshal(raw, &document); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		scanned++
		problems, sites := auditDisturbanceProblems(rel, document)
		for _, site := range sites {
			seen[site] = true
		}
		for _, p := range problems {
			site := p[:strings.Index(p, ": runs `")]
			flagged[site] = true
			if _, allowed := kernelAuditListDisturberAllowlist[site]; !allowed {
				t.Error(p)
			}
		}
	}
	if scanned < 50 {
		t.Fatalf("scanned only %d playbook files: the walk is broken", scanned)
	}
	var sites []string
	for site := range kernelAuditListDisturberAllowlist {
		sites = append(sites, site)
	}
	sort.Strings(sites)
	for _, site := range sites {
		switch {
		case !seen[site]:
			t.Errorf("kernelAuditListDisturberAllowlist: %s matches no disturbing task any more; remove the entry", site)
		case !flagged[site]:
			// The list is for sites that cannot be made safe, not for sites that already are.
			t.Errorf("kernelAuditListDisturberAllowlist: %s now has the guard and the re-arm; remove the entry", site)
		}
	}
}

func TestAuditDisturbanceLintCases(t *testing.T) {
	const guard = `{name: guard, ansible.builtin.include_tasks: {file: tasks/audit-whodata-guard.yml}, when: need}`
	const rearm = `{name: rearm, ansible.builtin.include_tasks: {file: tasks/audit-whodata-rearm.yml}}`
	cases := []struct {
		name string
		yaml string
		want int
	}{
		{"unconditional load, nothing else (the base Step 3)", `
- hosts: all
  tasks:
    - block:
        - {name: load, ansible.builtin.command: augenrules --load}
      rescue:
        - {name: reload, ansible.builtin.command: augenrules --load}
`, 2},
		{"conditional, guarded, followed, rescue re-arms", `
- hosts: all
  tasks:
    - block:
        - ` + guard + `
        - {name: load, ansible.builtin.command: augenrules --load, when: need}
      rescue:
        - {name: reload, ansible.builtin.command: augenrules --load, when: reload_needed}
        - ` + rearm + `
    - ` + rearm + `
`, 0},
		{"no guard before it", `
- hosts: all
  tasks:
    - {name: load, ansible.builtin.command: augenrules --load, when: need}
    - ` + rearm + `
`, 1},
		{"a guard under another condition does not cover it (a Debian-only guard before an EL SIGHUP)", `
- hosts: all
  tasks:
    - {name: guard, ansible.builtin.include_tasks: {file: tasks/audit-whodata-guard.yml}, when: debian}
    - {name: hup, ansible.builtin.command: pkill -HUP -x auditd, when: redhat}
    - ` + rearm + `
`, 1},
		{"a disturbance in a rescue needs no guard, only the re-arm after it", `
- hosts: all
  tasks:
    - block:
        - {name: step, ansible.builtin.debug: {msg: x}}
      rescue:
        - {name: reload, ansible.builtin.command: augenrules --load, when: reload_needed}
        - ` + rearm + `
`, 0},
		{"no re-arm after it", `
- hosts: all
  tasks:
    - ` + guard + `
    - {name: load, ansible.builtin.command: augenrules --load, when: need}
`, 1},
		{"re-arm in the rescue only: the normal flow never gives the watches back", `
- hosts: all
  tasks:
    - block:
        - ` + guard + `
        - {name: load, ansible.builtin.command: augenrules --load, when: need}
      rescue:
        - ` + rearm + `
`, 1},
		{"re-arm after the block but not in the rescue", `
- hosts: all
  tasks:
    - block:
        - ` + guard + `
        - {name: load, ansible.builtin.command: augenrules --load, when: need}
      rescue:
        - {name: fail, ansible.builtin.fail: {msg: x}}
    - ` + rearm + `
`, 1},
		{"constant when is not a condition", `
- hosts: all
  tasks:
    - ` + guard + `
    - {name: load, ansible.builtin.command: augenrules --load, when: true}
    - ` + rearm + `
`, 1},
		{"auditctl -D", `
- hosts: all
  tasks:
    - {name: flush, ansible.builtin.shell: "auditctl -D", when: x}
`, 1},
		{"auditctl -R", `
- hosts: all
  tasks:
    - {name: load, ansible.builtin.command: {argv: [auditctl, -R, /etc/audit/audit.rules]}, when: x}
`, 1},
		{"auditd restart through systemd", `
- hosts: all
  tasks:
    - {name: restart, ansible.builtin.systemd: {name: auditd, state: restarted}, when: x}
`, 1},
		{"auditd SIGHUP", `
- hosts: all
  tasks:
    - {name: hup, ansible.builtin.command: pkill -HUP -x auditd, when: x}
`, 1},
		{"systemctl with an option before the verb", `
- hosts: all
  tasks:
    - {name: quiet, ansible.builtin.command: systemctl -q restart auditd, when: x}
    - {name: long, ansible.builtin.shell: "systemctl --quiet --no-block restart auditd.service", when: x}
    - {name: argv, ansible.builtin.command: {argv: [systemctl, -q, reload-or-restart, auditd]}, when: x}
`, 3},
		{"auditctl --reload-rules and kill -HUP of the pid", `
- hosts: all
  tasks:
    - {name: reload, ansible.builtin.command: auditctl --reload-rules, when: x}
    - {name: hup, ansible.builtin.shell: "kill -HUP $(pidof auditd)", when: x}
`, 2},
		{"auditd-like unit names and read-only systemctl and auditctl are not disturbances", `
- hosts: all
  tasks:
    - {name: other unit, ansible.builtin.command: systemctl restart auditd-remote.service}
    - {name: status, ansible.builtin.command: systemctl -q status auditd}
    - {name: active, ansible.builtin.command: systemctl --quiet is-active auditd}
    - {name: start, ansible.builtin.command: systemctl -q start auditd}
    - {name: version, ansible.builtin.command: auditctl --version}
    - {name: enabled, ansible.builtin.command: auditctl -e 1}
`, 0},
		{"auditd started is not a restart", `
- hosts: all
  tasks:
    - {name: start, ansible.builtin.systemd: {name: auditd, state: started, enabled: true}}
`, 0},
		{"other services and read-only audit commands", `
- hosts: all
  tasks:
    - {name: rsyslog, ansible.builtin.systemd: {name: rsyslog, state: restarted}}
    - {name: list, ansible.builtin.command: auditctl -l}
    - {name: status, ansible.builtin.command: auditctl -s}
    - {name: check, ansible.builtin.command: augenrules --check}
`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var document any
			if err := yaml.Unmarshal([]byte(tc.yaml), &document); err != nil {
				t.Fatal(err)
			}
			if got, _ := auditDisturbanceProblems("case.yml", document); len(got) != tc.want {
				t.Fatalf("got %d problems, want %d: %v", len(got), tc.want, got)
			}
		})
	}
}

// The guard, the "attempted" record and the disturbance itself share one condition, written three times in the
// playbook: a Debian-only restart cannot be guarded by a task that runs on another family, and a record set
// when nothing was disturbed would make the rescue reload a list nobody emptied.
func TestRegression_AuditDisturbanceGuardsShareTheDisturbancesCondition(t *testing.T) {
	play := loadFirstPlay(t, "audit-log-forwarding-apply.yml")
	when := func(name string) string {
		t.Helper()
		task := findTaskDeep(play, name)
		if task == nil {
			t.Fatalf("task %q not found", name)
		}
		return whenKey(task)
	}
	for _, group := range [][]string{
		{
			"Step 3c: Refuse to flush the kernel audit list while Wazuh is mid-operation or unreadable (spec C23)",
			"Step 3d: Record that the kernel audit list is about to be loaded (spec C23)",
			"Step 3: Load the custom rules into the running kernel audit list (spec C10)",
		},
		{
			"Step 8d: Refuse to restart auditd while Wazuh is mid-operation or unreadable (spec C23) — Debian family",
			"Step 8e: Record that auditd is about to be restarted (spec C23) — Debian family",
			"Step 8a: Reload auditd if the syslog plugin config changed or isn't actually running (spec C21) — Debian family",
		},
	} {
		for _, name := range group[1:] {
			if when(name) != when(group[0]) {
				t.Errorf("%q and %q must run under the same condition:\n%s\n%s", group[0], name, when(group[0]), when(name))
			}
		}
	}
}
