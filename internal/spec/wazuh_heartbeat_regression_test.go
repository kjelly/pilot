package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRegression_WazuhHeartbeatOwnershipAndRuntime(t *testing.T) {
	const code = `import pathlib,runpy,sys,types
p=runpy.run_path('../../playbooks/files/pilot-wazuh-heartbeat')
own=p['ownership'];root=pathlib.Path(sys.argv[1]);main=root/'rsyslog.conf';owner=root/'31-pilot-wazuh.conf';child=root/'operator.conf'
canonical=p['HEADER']+'\n'+p['DEFINITION']+'\n'
def trial(name,text,owned='',childtext=None,loaded=False,want=False):
 main.write_text(text);owner.write_text(owned)
 if childtext is not None:child.write_text(childtext)
 try:own(main,owner,loaded)
 except ValueError:
  assert not want,name+' wrongly refused'
 else:assert want,name+' accepted foreign/unknown ownership'
include='include(file="'+str(owner)+'")\n'
trial('fresh', 'module(load="imuxsock")\n',want=True)
trial('canonical-owned',include,canonical,loaded=True,want=True)
trial('canonical-unloaded',include,canonical,want=True)
trial('foreign-modern','module(\n load = "immark"\n interval = "5"\n)\n')
trial('comment-separated-modern','module/* comment */(load/* comment */="immark")')
trial('foreign-legacy','$ModLoad immark\n')
trial('foreign-module-path','module(load="/usr/lib/immark.so")\n')
trial('legacy-include','$IncludeConfig '+str(child)+'\n',childtext='$ModLoad immark\n')
trial('modern-include','include(file="'+str(child)+'")\n',childtext='module(load="immark")\n')
trial('loaded-only','module(load="imuxsock")\n',loaded=True)
trial('comments-and-strings','# module(load="immark")\n/* $ModLoad immark */\nset $.text = "module(load=\\\"immark\\\")";\n',want=True)
trial('wrong-owned-interval',include,canonical.replace('interval="5"','interval="30"'))
trial('wrong-owned-ruleset',include,canonical.replace('pilotWazuhForward','other'))
trial('duplicate',include,canonical+p['DEFINITION']+'\n')
trial('unowned-header',include,p['DEFINITION']+'\n')
trial('unknown-include','include(file=$dynamic)')
trial('unknown-module','module(load=$dynamic)')
trial('escaped-identity','module(load="\\x69mmark")')
trial('unknown-include-argument','include(text="module(load=immark)")')
trial('optional-empty','include(file="'+str(root/'absent/*.conf')+'" mode="optional")',want=True)
trial('cycle','include(file="'+str(main)+'")')
link=root/'link.conf';link.symlink_to(child)
trial('symlink-include','include(file="'+str(link)+'")')
parts=root/'legacy-parts';parts.mkdir();part=parts/'part.conf';part.write_text('module(load="imuxsock")')
trial('legacy-glob','$IncludeConfig '+str(parts/'*.conf')+'\n',want=True)
part.write_text('$ModLoad immark\n')
trial('foreign-legacy-glob','$IncludeConfig '+str(parts/'*.conf')+'\n')
main.write_text('module(load="immark" interval="20")\n');owner.write_text('')
profile=root/'profile.json';retire=p['retirement']
assert not retire(owner,profile),'retirement must preserve operator module outside owned31 without global policy'
main.write_text(include);owner.write_text(canonical.replace('interval="5"','interval="20"'))
try:retire(owner,profile)
except ValueError:pass
else:raise AssertionError('retirement would overwrite foreign module inside owned31')
owner.unlink();assert not retire(owner,profile),'standalone without reader/profile must remain available'
profile.write_text('{"enabled": true, "transport": "relp"}')
assert not retire(owner,profile),'old2db profile upgrade must not require a heartbeat field'
profile.write_text('{"heartbeat_interval":5}')
assert retire(owner,profile),'missing previously owned definition must query loaded-only ownership'
# Native-process negative controls exercise the real refusal function. They
# intentionally model unsupported outputs, never claim native capability PASS.
native=p['native'];env=native.__globals__;subprocess=env['subprocess'];saved=subprocess.run
for text in ['unknown parameter use.markFlag','parameter ruleset not known','immark: ruleset missing not found - using default ruleset','module immark already loaded']:
 subprocess.run=lambda *a,**k:types.SimpleNamespace(returncode=0,stdout='',stderr=text)
 try:native(main)
 except ValueError:pass
 else:raise AssertionError('native diagnostic falsely passed: '+text)
subprocess.run=saved
# A runtime mark flag on another action cannot satisfy this named client.
runtime=p['runtime'];env=runtime.__globals__
owner.write_text(canonical+'action(name="wazuh_alerts" type="omrelp")\naction(name="other" action.writeAllMarkMessages="on")\n')
try:runtime(owner,'relp','0')
except ValueError as e:assert 'configuration' in str(e)
else:raise AssertionError('other action mark flag incorrectly accepted')
owner.write_text(canonical)
try:runtime(owner,'tcp','0')
except ValueError:pass
else:raise AssertionError('TCP accepted owned heartbeat')
print('ownership,retirement,unsupported-native,and named-action/TCP negative controls passed')
`
	cmd := exec.Command("python3", "-c", code, t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("heartbeat ownership/runtime controls: %v\n%s", err, out)
	}
}

func TestRegression_WazuhHeartbeatSelectedPreflightFailsBeforeMutation(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Fatal("Ansible is required for selected heartbeat preflight coverage")
	}
	type trial struct {
		selector, outcome, stale string
		omitReset                bool
	}
	var trials []trial
	for _, selector := range []string{"full", "C10", "C11"} {
		for _, outcome := range []string{"foreign", "approved", "missing-rc"} {
			trials = append(trials, trial{selector: selector, outcome: outcome})
		}
	}
	trials = append(trials, trial{selector: "check", outcome: "foreign"}, trial{selector: "C1", outcome: "foreign"})
	for _, stale := range []string{"success", "failure"} {
		trials = append(trials, trial{selector: "C1", outcome: "foreign", stale: stale}, trial{selector: "C1", outcome: "foreign", stale: stale, omitReset: true})
	}
	for _, tc := range trials {
		name := tc.selector + "/" + tc.outcome + "/prior-" + tc.stale
		if tc.omitReset {
			name += "/missing-reset-counterexample"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			helper, _ := filepath.Abs("../../playbooks/files/pilot-wazuh-heartbeat")
			foreign := filepath.Join(root, "rsyslog.conf")
			configuration := "module(load=\"immark\")\n"
			if tc.outcome == "approved" {
				configuration = "module(load=\"imuxsock\")\n"
			}
			if err := os.WriteFile(foreign, []byte(configuration), 0600); err != nil {
				t.Fatal(err)
			}
			witness := filepath.Join(root, "guard-ran")
			wrapper := filepath.Join(root, "guard.py")
			const privateOutput = "ISSUE211-PRIVATE-PREFLIGHT-SENTINEL"
			code := "#!/usr/bin/python3\nimport pathlib,runpy\nprint(" + strconv.Quote(privateOutput) + ")\npathlib.Path(" + strconv.Quote(witness) + ").write_text('ran')\np=runpy.run_path(" + strconv.Quote(helper) + ")\np['ownership'](" + strconv.Quote(foreign) + ", pathlib.Path(" + strconv.Quote(filepath.Join(root, "31.conf")) + "), False)\n"
			if err := os.WriteFile(wrapper, []byte(code), 0700); err != nil {
				t.Fatal(err)
			}
			production := loadFirstPlay(t, "wazuh-manager-apply.yml")
			reset := findNamedTask(t, production, "Reset per-run ACL journal completion state")
			guard := findNamedTask(t, production, "Wazuh: refuse foreign immark and unsupported heartbeat before Wazuh or TLS mutation")
			guard["ansible.builtin.script"] = wrapper
			if tc.outcome == "missing-rc" {
				// A registered non-command result proves that absence of rc is
				// refused, rather than being confused with approval or skipping.
				delete(guard, "ansible.builtin.script")
				guard["ansible.builtin.debug"] = map[string]any{"msg": privateOutput}
			}
			gate := findNamedTask(t, production, "Gate: Wazuh requires exclusive native heartbeat support for RELP")
			const approval = "ISSUE211-CURRENT-RUN-GATE-APPROVED"
			gate["ansible.builtin.assert"].(map[string]any)["success_msg"] = approval
			mutation := filepath.Join(root, "mutation")
			children := filepath.Join(root, "selected.yml")
			child, err := yaml.Marshal([]any{map[string]any{"name": "selected mutation witness", "ansible.builtin.copy": map[string]any{"content": "changed", "dest": mutation}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(children, child, 0600); err != nil {
				t.Fatal(err)
			}
			// Preserve the owned ordinary-path ordering and actual include
			// selector/apply tags; replace only its target-specific children.
			include := findNamedTask(t, production, "Step 9c: Configure isolated host imfile forwarding")
			include["ansible.builtin.include_tasks"].(map[string]any)["file"] = children
			pre := []any{reset, guard, gate}
			if tc.omitReset {
				pre = []any{guard, gate}
			}
			play := []any{}
			if tc.stale != "" {
				rc := 0
				if tc.stale == "failure" {
					rc = 98
				}
				play = append(play, map[string]any{"hosts": "all", "gather_facts": false, "tasks": []any{map[string]any{"name": "prior play result on same host", "tags": []any{"always"}, "ansible.builtin.set_fact": map[string]any{"wazuh_heartbeat_preflight": map[string]any{"rc": rc, "skipped": false}}}}})
			}
			play = append(play, map[string]any{"hosts": "all", "gather_facts": false, "vars": map[string]any{"siem_forwarding_enabled": true, "siem_forward_transport": "relp"}, "pre_tasks": pre, "tasks": []any{include}})
			body, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "play.yml")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-i", "localhost,", "-c", "local", path, "-vvv"}
			if tc.selector == "check" {
				args = append(args, "--check", "--diff")
			} else if tc.selector != "full" {
				args = append(args, "--tags", tc.selector)
			}
			config := filepath.Join(root, "ansible.cfg")
			if err := os.WriteFile(config, []byte("[defaults]\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("ansible-playbook", args...)
			cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
			out, runErr := cmd.CombinedOutput()
			selected := tc.selector == "full" || tc.selector == "C10" || tc.selector == "C11"
			refused := (selected && tc.outcome != "approved") || (tc.omitReset && tc.stale == "failure")
			if refused && (runErr == nil || !strings.Contains(string(out), "exclusive immark ownership")) {
				t.Fatalf("expected pre-mutation refusal at native ownership gate: %v\n%s", runErr, out)
			}
			if !refused && runErr != nil {
				t.Fatalf("approved/nonselected/check run failed: %v\n%s", runErr, out)
			}
			if strings.Contains(string(out), privateOutput) {
				t.Fatal("private preflight output leaked at verbose level3")
			}
			_, ran := os.Stat(witness)
			if (ran == nil) != (selected && tc.outcome != "missing-rc") {
				t.Fatal("guard selection did not match C10/C11 real mutation")
			}
			approved := (selected && tc.outcome == "approved") || (tc.omitReset && tc.stale == "success")
			if strings.Contains(string(out), approval) != approved {
				t.Fatalf("gate did not honor current-run result; missing-reset counterexample=%t\n%s", tc.omitReset, out)
			}
			_, mutated := os.Stat(mutation)
			if (mutated == nil) != (selected && tc.outcome == "approved") {
				t.Fatal("selected include mutated without fresh approval or did not execute approved children")
			}
		})
	}
}

func TestRegression_WazuhHeartbeatPreflightAndSameAction(t *testing.T) {
	play := loadFirstPlay(t, "wazuh-manager-apply.yml")
	preflight := findNamedTask(t, play, "Wazuh: refuse foreign immark and unsupported heartbeat before Wazuh or TLS mutation")
	if preflight["no_log"] != true || preflight["changed_when"] != false {
		t.Fatal("ownership/capability preflight must hide private config and remain read-only")
	}
	// Forwarding prerequisites must remain before ordinary Wazuh mutation,
	// inside host ownership and outside completed version-only operations.
	owned := findNamedTask(t, play, "Own all Wazuh mutations on this host through their final proofs")
	ordinary := findNamedTask(t, play, "Apply the selected Wazuh tasks only after policy is recomputed under ownership")
	index := func(items []any, name string) int {
		for i, item := range items {
			if item.(map[string]any)["name"] == name {
				return i
			}
		}
		return -1
	}
	outer := owned["block"].([]any)
	claim := index(outer, "Claim the host-wide Wazuh writer before any shared coordinator copy or mutation")
	version := index(outer, "Inspect compatibility or execute the explicitly authorized central upgrade")
	selected := index(outer, ordinary["name"].(string))
	if claim < 0 || version <= claim || selected <= version || ordinary["when"] != "not wazuh_finish_host" {
		t.Fatal("forwarding must stay inside the claimed ordinary path after native version planning and version-only early exit")
	}
	children := ordinary["block"].([]any)
	prerequisite := index(children, "Wazuh: install native RELP preflight prerequisites before configuration changes")
	guard := index(children, preflight["name"].(string))
	gate := index(children, "Gate: Wazuh requires exclusive native heartbeat support for RELP")
	mutation := index(children, "Step 1: Set vm.max_map_count=262144 (indexer requirement, persistent)")
	if prerequisite < 0 || guard <= prerequisite || gate <= guard || mutation <= gate {
		t.Fatal("owned native prerequisites and fresh heartbeat gate must precede Wazuh configuration mutation")
	}
	when, _ := preflight["when"].(string)
	args, _ := preflight["ansible.builtin.script"].(string)
	if when != "not ansible_check_mode" || !strings.Contains(args, "siem_forwarding_enabled") || !strings.Contains(args, "== 'relp'") || !strings.Contains(args, "else 'retire'") {
		t.Fatal("native capability must select enabled RELP; retirement preserves foreign state and check mode defers honestly")
	}
	data, err := os.ReadFile("../../playbooks/apply/tasks/wazuh-alert-forward.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, `action(name="wazuh_alerts"`) != 1 || strings.Count(text, `queue.filename="wazuh_alerts"`) != 1 {
		t.Fatal("heartbeat must share the original named client and queue")
	}
	for _, value := range []string{`interval="5"`, `ruleset="pilotWazuhForward" use.syslogCall="off" use.markFlag="on"`, `action.writeAllMarkMessages="on"`, "heartbeat_interval", "verify the effective owned heartbeat"} {
		if !strings.Contains(text, value) {
			t.Errorf("fixed production heartbeat contract missing %q", value)
		}
	}
	if strings.Index(text, `ruleset(name="pilotWazuhForward")`) > strings.Index(text, `module(load="immark"`) {
		t.Fatal("named ruleset must exist before immark binds")
	}
	// The native imfile harness below renders TCP with the production task and
	// verifies no heartbeat is accidentally included in that backend.
}
