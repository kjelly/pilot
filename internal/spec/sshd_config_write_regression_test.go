package spec

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// sshdConfigWriteAllowlist lists sshd configuration writes that do not
// follow TestRegression_SshdConfigWritesAreValidatedAndReverted yet, keyed
// "<playbook>: <path>". It is empty: freeipa-client's password-auth drop-in
// (apply and decommission) and pilot-access-target-policy's absent path were
// the last three, fixed on 2026-10-12. An entry needs a reason, and fails
// the test once the write follows the rule.
var sshdConfigWriteAllowlist = map[string]string{}

// TestRegression_SshdConfigWritesAreValidatedAndReverted is a lint over the
// real playbooks (playbooks/apply and playbooks/decommission; test
// fixtures only run on disposable VMs). Until 2026-10-12 the gateway and Directory wrote their
// ForceCommand drop-ins, ran `sshd -t` and reloaded sshd only when the
// write reported a change. A failed `sshd -t` left the new drop-in on disk;
// the next run found it unchanged, skipped `sshd -t` and the reload and
// passed, while sshd still ran without it, and sshd's next restart would
// load a configuration nothing had validated (PR #38 review). So every
// task that writes or removes /etc/ssh/sshd_config or a .conf file under
// /etc/ssh/sshd_config.d must:
//   - when it writes content, validate the file on its own first
//     (`validate: /usr/sbin/sshd -t -f %s`);
//   - sit in a block with a rescue, which puts back what the run found;
//   - be followed in its task list by a whole-configuration `sshd -t`,
//     before any systemd/service task (the reload).
//
// Writes inside a rescue are those put-backs and are exempt.
// pilot-access-target-policy-apply.yml's install already worked this way.
func TestRegression_SshdConfigWritesAreValidatedAndReverted(t *testing.T) {
	problems := map[string][]string{}
	writes := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(path, "../../")
		if !strings.HasPrefix(rel, "playbooks/apply/") && !strings.HasPrefix(rel, "playbooks/decommission/") {
			continue
		}
		for _, w := range sshdConfigWrites(loadYAML(t, path)) {
			writes++
			key := rel + ": " + w.path
			problems[key] = append(problems[key], w.problems...)
		}
	}
	keys := make([]string, 0, len(problems))
	for key := range problems {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, allowed := sshdConfigWriteAllowlist[key]; allowed {
			if len(problems[key]) == 0 {
				t.Errorf("%s: follows the rule now; remove it from sshdConfigWriteAllowlist", key)
			}
			continue
		}
		for _, p := range problems[key] {
			t.Errorf("%s: %s", key, p)
		}
	}
	for key := range sshdConfigWriteAllowlist {
		if _, ok := problems[key]; !ok {
			t.Errorf("sshdConfigWriteAllowlist: %s: no such write in playbooks/**", key)
		}
	}
	// Install and removal for the gateway, the Directory and target-policy,
	// and the two freeipa-client ones.
	if writes < 8 {
		t.Fatalf("found only %d sshd configuration writes; the detection is broken", writes)
	}
}

// sshdConfigWrite is one task that writes or removes sshd configuration.
type sshdConfigWrite struct {
	name, path string
	problems   []string
}

var (
	sshdWriteModules = []string{
		"copy", "template", "lineinfile", "blockinfile", "replace", "file",
	}
	sshdServiceModules = []string{"systemd", "systemd_service", "service"}
	sshdCommandModules = []string{"command", "shell"}
	singleVarRE        = regexp.MustCompile(`^\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$`)
)

// taskModule returns the args of the first of mods a task uses, accepting
// the short and the ansible.builtin. name.
func taskModule(task map[string]any, mods []string) (string, any, bool) {
	for _, mod := range mods {
		for _, key := range []string{mod, "ansible.builtin." + mod} {
			if args, ok := task[key]; ok {
				return mod, args, true
			}
		}
	}
	return "", nil, false
}

// isSshdConfigPath: sshd reads /etc/ssh/sshd_config and, through its
// Include, /etc/ssh/sshd_config.d/*.conf; snapshots such as *.bak there are
// not configuration.
func isSshdConfigPath(path string) bool {
	return path == "/etc/ssh/sshd_config" ||
		(strings.HasPrefix(path, "/etc/ssh/sshd_config.d/") && strings.HasSuffix(path, ".conf"))
}

// runsSshdCheck reports whether a task runs `sshd -t` on the whole
// configuration (no -f).
func runsSshdCheck(task map[string]any) bool {
	_, args, ok := taskModule(task, sshdCommandModules)
	if !ok {
		return false
	}
	var words []string
	switch a := args.(type) {
	case string:
		words = strings.Fields(a)
	case map[string]any:
		if argv, ok := a["argv"].([]any); ok {
			for _, w := range argv {
				words = append(words, fmt.Sprint(w))
			}
		} else if cmd, ok := a["cmd"].(string); ok {
			words = strings.Fields(cmd)
		}
	}
	if len(words) == 0 || !strings.HasSuffix(words[0], "sshd") {
		return false
	}
	return slices.Contains(words, "-t") && !slices.Contains(words, "-f")
}

// sshdConfigWrites finds the sshd configuration writes in a playbook or a
// task file and what each lacks.
func sshdConfigWrites(doc any) []sshdConfigWrite {
	var out []sshdConfigWrite
	items, _ := doc.([]any)
	isPlaybook := false
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			if _, ok := m["hosts"]; ok {
				isPlaybook = true
			}
		}
	}
	if !isPlaybook {
		walkSshdWrites(items, nil, false, false, &out)
		return out
	}
	for _, item := range items {
		play, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vars, _ := play["vars"].(map[string]any)
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			list, _ := play[section].([]any)
			walkSshdWrites(list, vars, false, false, &out)
		}
	}
	return out
}

// sshdConfigWriteOf returns the module, the sshd configuration file and the
// module args of a task that writes or removes that file, with a path that
// is a single play var resolved; path is "" for any other task.
func sshdConfigWriteOf(task map[string]any, vars map[string]any) (mod, path string, args map[string]any) {
	mod, raw, ok := taskModule(task, sshdWriteModules)
	if !ok {
		return "", "", nil
	}
	args, _ = raw.(map[string]any)
	path, _ = args["dest"].(string)
	if path == "" {
		path, _ = args["path"].(string)
	}
	if m := singleVarRE.FindStringSubmatch(path); m != nil {
		path, _ = vars[m[1]].(string)
	}
	if !isSshdConfigPath(path) || (mod == "file" && args["state"] != "absent") {
		return "", "", nil
	}
	return mod, path, args
}

func walkSshdWrites(list []any, vars map[string]any, inRescue, rescued bool, out *[]sshdConfigWrite) {
	for i, item := range list {
		task, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if block, ok := task["block"].([]any); ok {
			rescue, _ := task["rescue"].([]any)
			walkSshdWrites(block, vars, inRescue, rescued || len(rescue) > 0, out)
			walkSshdWrites(rescue, vars, true, rescued, out)
			always, _ := task["always"].([]any)
			walkSshdWrites(always, vars, inRescue, rescued, out)
			continue
		}
		mod, path, args := sshdConfigWriteOf(task, vars)
		if path == "" || inRescue {
			continue
		}
		w := sshdConfigWrite{name: fmt.Sprint(task["name"]), path: path}
		if mod != "file" {
			if v, _ := args["validate"].(string); !strings.Contains(v, "sshd -t -f %s") {
				w.problems = append(w.problems, fmt.Sprintf("%q writes it without `validate: /usr/sbin/sshd -t -f %%s`", w.name))
			}
		}
		if !rescued {
			w.problems = append(w.problems, fmt.Sprintf("%q is not in a block with a rescue that puts back what the run found", w.name))
		}
		checked := false
		for _, next := range list[i+1:] {
			nt, ok := next.(map[string]any)
			if !ok {
				continue
			}
			if runsSshdCheck(nt) {
				checked = true
				break
			}
			if _, _, isService := taskModule(nt, sshdServiceModules); isService {
				w.problems = append(w.problems, fmt.Sprintf("%q is followed by %q before any whole-configuration `sshd -t`", w.name, nt["name"]))
				checked = true
				break
			}
		}
		if !checked {
			w.problems = append(w.problems, fmt.Sprintf("%q is not followed in its task list by a whole-configuration `sshd -t`", w.name))
		}
		*out = append(*out, w)
	}
}

func TestSshdConfigWrites(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string // substrings, one per expected problem
	}{
		{"the 2026-10-12 bug: no validate, no rescue", `
- hosts: all
  tasks:
    - name: install
      copy: {dest: /etc/ssh/sshd_config.d/90-x.conf, content: x}
      register: r
    - name: check
      command: {argv: [sshd, -t]}
      when: r.changed
    - name: reload
      systemd: {name: ssh, state: reloaded}
      when: r.changed
`, []string{"without `validate", "not in a block with a rescue"}},
		{"validated, reverted, checked before the reload", `
- hosts: all
  tasks:
    - block:
        - name: install
          ansible.builtin.copy: {dest: /etc/ssh/sshd_config.d/90-x.conf, content: x, validate: /usr/sbin/sshd -t -f %s}
        - name: check
          ansible.builtin.command: {argv: [sshd, -t]}
        - name: reload
          ansible.builtin.systemd: {name: ssh, state: reloaded}
      rescue:
        - name: put back
          ansible.builtin.copy: {dest: /etc/ssh/sshd_config.d/90-x.conf, content: y}
`, nil},
		{"restart before any sshd -t (freeipa-client decommission)", `
- hosts: all
  tasks:
    - block:
        - name: remove
          file: {path: /etc/ssh/sshd_config.d/05-x.conf, state: absent}
        - name: restart
          systemd: {name: ssh, state: restarted}
      rescue:
        - name: diagnostics
          fail: {msg: x}
`, []string{"is followed by \"restart\""}},
		{"no sshd -t at all", `
- hosts: all
  tasks:
    - block:
        - name: install
          template: {dest: /etc/ssh/sshd_config, src: a.j2, validate: "sshd -t -f %s"}
      rescue:
        - name: put back
          copy: {dest: /etc/ssh/sshd_config, content: y}
`, []string{"not followed in its task list"}},
		{"sshd -t -f checks one file, not the whole configuration", `
- hosts: all
  tasks:
    - block:
        - name: install
          copy: {dest: /etc/ssh/sshd_config.d/90-x.conf, content: x, validate: /usr/sbin/sshd -t -f %s}
        - name: check one file
          command: sshd -t -f /etc/ssh/sshd_config.d/90-x.conf
        - name: reload
          service: {name: ssh, state: reloaded}
      rescue:
        - name: put back
          copy: {dest: /etc/ssh/sshd_config.d/90-x.conf, content: y}
`, []string{"is followed by \"reload\""}},
		{"dest from play vars; a .bak snapshot is not configuration", `
- hosts: all
  vars:
    dropin: /etc/ssh/sshd_config.d/06-x.conf
    backup: /etc/ssh/sshd_config.d/06-x.conf.pre-x.bak
  tasks:
    - name: snapshot
      copy: {dest: "{{ backup }}", content: x}
    - name: install
      copy: {dest: "{{ dropin }}", content: x}
`, []string{"without `validate", "not in a block with a rescue", "not followed in its task list"}},
		{"ssh client configuration is not sshd's", `
- hosts: all
  tasks:
    - name: client
      copy: {dest: /etc/ssh/ssh_config.d/05-x.conf, content: x}
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, w := range sshdConfigWrites(doc) {
				got = append(got, w.problems...)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("problems = %q, want %d matching %q", got, len(tc.want), tc.want)
			}
			for i, want := range tc.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("problem %d = %q, want it to mention %q", i, got[i], want)
				}
			}
		})
	}
}

func TestRegression_SshdConfigWriteAllowlistPathsExist(t *testing.T) {
	for key := range sshdConfigWriteAllowlist {
		rel, _, _ := strings.Cut(key, ": ")
		if _, err := os.Stat("../../" + rel); err != nil {
			t.Errorf("sshdConfigWriteAllowlist: %s: %v", rel, err)
		}
	}
}

// containsTask reports whether item, or a task in its block, rescue or
// always sections at any depth, satisfies pred.
func containsTask(item any, pred func(map[string]any) bool) bool {
	task, ok := item.(map[string]any)
	if !ok {
		return false
	}
	if pred(task) {
		return true
	}
	for _, key := range []string{"block", "rescue", "always"} {
		list, _ := task[key].([]any)
		if slices.ContainsFunc(list, func(sub any) bool { return containsTask(sub, pred) }) {
			return true
		}
	}
	return false
}

// sshdStepsAfterReload finds, in each block whose rescue puts sshd
// configuration back, the tasks that run after the one that reloads or
// restarts a service. It returns them and the number of such blocks.
func sshdStepsAfterReload(doc any) (problems []string, blocks int) {
	var walk func(list []any, vars map[string]any)
	walk = func(list []any, vars map[string]any) {
		for _, item := range list {
			task, ok := item.(map[string]any)
			if !ok {
				continue
			}
			block, _ := task["block"].([]any)
			rescue, _ := task["rescue"].([]any)
			putsBack := slices.ContainsFunc(rescue, func(sub any) bool {
				return containsTask(sub, func(t map[string]any) bool {
					_, path, _ := sshdConfigWriteOf(t, vars)
					return path != ""
				})
			})
			if putsBack {
				blocks++
				reload := slices.IndexFunc(block, func(sub any) bool {
					return containsTask(sub, func(t map[string]any) bool {
						_, _, ok := taskModule(t, sshdServiceModules)
						return ok
					})
				})
				if reload >= 0 {
					for _, after := range block[reload+1:] {
						a, _ := after.(map[string]any)
						r, _ := block[reload].(map[string]any)
						problems = append(problems, fmt.Sprintf("%q runs after %q in %q, whose rescue puts sshd's configuration back although sshd has already loaded the new one",
							fcName(a), fcName(r), fmt.Sprint(task["name"])))
					}
				}
			}
			for _, key := range []string{"block", "rescue", "always"} {
				sub, _ := task[key].([]any)
				walk(sub, vars)
			}
		}
	}
	items, _ := doc.([]any)
	isPlaybook := slices.ContainsFunc(items, func(item any) bool {
		m, _ := item.(map[string]any)
		_, ok := m["hosts"]
		return ok
	})
	if !isPlaybook {
		walk(items, nil)
		return problems, blocks
	}
	for _, item := range items {
		play, ok := item.(map[string]any)
		if !ok {
			continue
		}
		vars, _ := play["vars"].(map[string]any)
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			list, _ := play[section].([]any)
			walk(list, vars)
		}
	}
	return problems, blocks
}

// TestRegression_SshdReloadEndsItsRollbackBlock: pilot-access-target-policy's
// absent path removed its pre-change snapshot after the reload, in the block
// whose rescue puts the drop-in back. When that removal failed, sshd already
// ran without the policy, the rescue put the drop-in back on disk without a
// reload, and the run said "sshd was not reloaded"; sshd's next restart
// would load the policy again (PR #50 review). The present path's
// post-reload `sshd -t` sat in its block the same way. In a block whose
// rescue puts sshd configuration back, the reload must be the last step.
func TestRegression_SshdReloadEndsItsRollbackBlock(t *testing.T) {
	blocks := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(path, "../../")
		if !strings.HasPrefix(rel, "playbooks/apply/") && !strings.HasPrefix(rel, "playbooks/decommission/") {
			continue
		}
		problems, n := sshdStepsAfterReload(loadYAML(t, path))
		blocks += n
		for _, p := range problems {
			t.Errorf("%s: %s", rel, p)
		}
	}
	// Install and removal for the gateway, the Directory and target-policy,
	// and the two freeipa-client ones.
	if blocks < 8 {
		t.Fatalf("found only %d blocks that put sshd configuration back; the detection is broken", blocks)
	}
}

func TestSshdStepsAfterReload(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string // substrings, one per expected problem
	}{
		{"the PR #50 review: snapshot removal after the reload", `
- hosts: all
  vars:
    dropin: /etc/ssh/sshd_config.d/06-x.conf
  tasks:
    - name: remove the policy
      block:
        - name: remove
          file: {path: "{{ dropin }}", state: absent}
        - name: check
          command: {argv: [sshd, -t]}
        - name: reload
          systemd: {name: ssh, state: reloaded}
        - name: remove the snapshot
          file: {path: /etc/ssh/sshd_config.d/06-x.conf.bak, state: absent}
      rescue:
        - name: put back
          copy: {dest: "{{ dropin }}", content: x}
`, []string{`"remove the snapshot" runs after "reload"`}},
		{"a check after the reload, even when the rescue reloads", `
- hosts: all
  tasks:
    - name: install
      block:
        - name: write
          ansible.builtin.copy: {dest: /etc/ssh/sshd_config.d/06-x.conf, content: x, validate: /usr/sbin/sshd -t -f %s}
        - name: check
          ansible.builtin.command: {argv: [sshd, -t]}
        - name: reload
          ansible.builtin.systemd: {name: ssh, state: reloaded}
        - name: check again
          ansible.builtin.command: {argv: [sshd, -t]}
      rescue:
        - name: put back
          ansible.builtin.file: {path: /etc/ssh/sshd_config.d/06-x.conf, state: absent}
        - name: reload
          ansible.builtin.systemd: {name: ssh, state: reloaded}
`, []string{`"check again" runs after "reload"`}},
		{"the reload in a nested block, then a step", `
- hosts: all
  tasks:
    - name: outer
      block:
        - name: write
          copy: {dest: /etc/ssh/sshd_config, content: x, validate: /usr/sbin/sshd -t -f %s}
        - name: inner
          block:
            - name: check
              command: {argv: [sshd, -t]}
            - name: restart
              service: {name: sshd, state: restarted}
        - name: later
          debug: {msg: x}
      rescue:
        - block:
            - name: put back
              copy: {dest: /etc/ssh/sshd_config, content: y}
`, []string{`"later" runs after "inner"`}},
		{"the reload last; later steps outside the block", `
- hosts: all
  tasks:
    - name: install
      block:
        - name: write
          copy: {dest: /etc/ssh/sshd_config.d/06-x.conf, content: x, validate: /usr/sbin/sshd -t -f %s}
        - name: check
          command: {argv: [sshd, -t]}
        - name: reload
          systemd: {name: ssh, state: reloaded}
      rescue:
        - name: put back
          copy: {dest: /etc/ssh/sshd_config.d/06-x.conf, content: y}
    - name: remove the snapshot
      file: {path: /etc/ssh/sshd_config.d/06-x.conf.bak, state: absent}
`, nil},
		{"a rescue that does not touch sshd configuration", `
- hosts: all
  tasks:
    - name: decommission
      block:
        - name: reload
          systemd: {name: ssh, state: reloaded}
        - name: later
          debug: {msg: x}
      rescue:
        - name: diagnostics
          fail: {msg: x}
`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var doc any
			if err := yaml.Unmarshal([]byte(tc.yaml), &doc); err != nil {
				t.Fatal(err)
			}
			got, _ := sshdStepsAfterReload(doc)
			if len(got) != len(tc.want) {
				t.Fatalf("problems = %q, want %d matching %q", got, len(tc.want), tc.want)
			}
			for i, want := range tc.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("problem %d = %q, want it to mention %q", i, got[i], want)
				}
			}
		})
	}
}

// ipaInstallerAllowlist lists FreeIPA installer runs that do not check sshd's
// configuration first yet, keyed "<playbook>: <task name>". Each belongs to
// a component with its own vm-target run; an entry fails the test once it
// is fixed.
var ipaInstallerAllowlist = map[string]string{
	"playbooks/apply/freeipa-server-apply.yml: FreeIPA — run ipa-server-install (native; first run is 8–12 min)":                      "needs a fresh freeipa-server run",
	"playbooks/apply/freeipa-server-replica-apply.yml: FreeIPA replica — step 1/2: ipa-client-install (enroll into {{ ipa_realm }})":  "needs a replica topology run",
	"playbooks/apply/freeipa-server-replica-apply.yml: FreeIPA replica — step 2/2: ipa-replica-install (promote; first run 8-12 min)": "needs a replica topology run",
	"playbooks/apply/freeipa-realm-replacement-apply.yml: Realm replacement — remove old client enrollment":                           "needs a realm-replacement run",
	"playbooks/apply/freeipa-realm-replacement-apply.yml: Realm replacement — enroll client in the new realm":                         "needs a realm-replacement run",
}

var ipaInstallers = []string{"ipa-client-install", "ipa-server-install", "ipa-replica-install"}

// runsIpaInstaller reports whether a task runs one of the FreeIPA installers,
// named in its command or in the task vars its argv is built from.
func runsIpaInstaller(task map[string]any) bool {
	_, args, ok := taskModule(task, sshdCommandModules)
	if !ok {
		return false
	}
	var text string
	switch a := args.(type) {
	case string:
		text = a
	case map[string]any:
		text = fmt.Sprint(a["argv"], " ", a["cmd"])
	}
	text += " " + fmt.Sprint(task["vars"])
	for _, name := range ipaInstallers {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// ipaInstallersWithoutSshdCheck returns the names of installer tasks with no
// whole-configuration `sshd -t` before them in their task list.
func ipaInstallersWithoutSshdCheck(doc any) []string {
	var out []string
	var walk func(list []any)
	walk = func(list []any) {
		checked := false
		for _, item := range list {
			task, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if runsSshdCheck(task) {
				checked = true
			}
			if runsIpaInstaller(task) && !checked {
				out = append(out, fmt.Sprint(task["name"]))
			}
			for _, key := range []string{"block", "rescue", "always"} {
				sub, _ := task[key].([]any)
				walk(sub)
			}
		}
	}
	items, _ := doc.([]any)
	for _, item := range items {
		play, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
			list, _ := play[section].([]any)
			walk(list)
		}
	}
	return out
}

// TestRegression_IpaInstallersRunAfterAnSshdCheck: ipa-client-install,
// ipa-server-install and ipa-replica-install configure sshd and restart it.
// With a broken file in sshd_config.d that restart fails and sshd stays
// down; ipa-client-install --uninstall then stopped half done (SSSD's
// configuration removed, /etc/ipa/default.conf still there) on AlmaLinux 9
// (2026-10-12). Every installer run in playbooks/apply and
// playbooks/decommission needs a whole-configuration `sshd -t` earlier in
// its task list.
func TestRegression_IpaInstallersRunAfterAnSshdCheck(t *testing.T) {
	found := map[string]bool{}
	installers := 0
	for _, path := range playbookFiles(t) {
		rel := strings.TrimPrefix(path, "../../")
		if !strings.HasPrefix(rel, "playbooks/apply/") && !strings.HasPrefix(rel, "playbooks/decommission/") {
			continue
		}
		doc := loadYAML(t, path)
		var all []string
		items, _ := doc.([]any)
		for _, item := range items {
			play, _ := item.(map[string]any)
			for _, section := range []string{"pre_tasks", "tasks", "post_tasks", "handlers"} {
				walkTaskTree(play[section], nil, func(task map[string]any, _ []string) {
					if runsIpaInstaller(task) {
						all = append(all, fmt.Sprint(task["name"]))
					}
				})
			}
		}
		installers += len(all)
		for _, name := range ipaInstallersWithoutSshdCheck(doc) {
			key := rel + ": " + name
			found[key] = true
			if _, ok := ipaInstallerAllowlist[key]; !ok {
				t.Errorf("%s: runs a FreeIPA installer, which restarts sshd, with no `sshd -t` before it in its task list", key)
			}
		}
	}
	for key := range ipaInstallerAllowlist {
		if !found[key] {
			t.Errorf("ipaInstallerAllowlist: %s checks sshd first now (or no longer exists); remove it", key)
		}
	}
	// freeipa-client, its decommission, the server, the replica (2) and the
	// realm replacement (2).
	if installers < 7 {
		t.Fatalf("found only %d FreeIPA installer runs; the detection is broken", installers)
	}
}
