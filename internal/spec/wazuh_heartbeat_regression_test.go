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
	for _, selector := range []string{"full", "C10", "C11", "C1", "check"} {
		t.Run(selector, func(t *testing.T) {
			root := t.TempDir()
			helper, _ := filepath.Abs("../../playbooks/files/pilot-wazuh-heartbeat")
			foreign := filepath.Join(root, "foreign.conf")
			if err := os.WriteFile(foreign, []byte("module(load=\"immark\")\n"), 0600); err != nil {
				t.Fatal(err)
			}
			witness := filepath.Join(root, "guard-ran")
			wrapper := filepath.Join(root, "guard.py")
			code := "#!/usr/bin/python3\nimport pathlib,runpy\npathlib.Path(" + strconv.Quote(witness) + ").write_text('ran')\np=runpy.run_path(" + strconv.Quote(helper) + ")\np['ownership'](" + strconv.Quote(foreign) + ", pathlib.Path(" + strconv.Quote(filepath.Join(root, "31.conf")) + "), False)\n"
			if err := os.WriteFile(wrapper, []byte(code), 0700); err != nil {
				t.Fatal(err)
			}
			production := loadFirstPlay(t, "wazuh-manager-apply.yml")
			guard := findNamedTask(t, production, "Wazuh: refuse foreign immark and unsupported heartbeat before Wazuh or TLS mutation")
			guard["ansible.builtin.script"] = wrapper
			gate := findNamedTask(t, production, "Gate: Wazuh requires exclusive native heartbeat support for RELP")
			mutation := filepath.Join(root, "mutation")
			play := []any{map[string]any{"hosts": "all", "gather_facts": false, "vars": map[string]any{"siem_forwarding_enabled": true, "siem_forward_transport": "relp"}, "tasks": []any{guard, gate, map[string]any{"name": "mutation must follow accepted preflight", "tags": []any{"C10", "C11"}, "ansible.builtin.copy": map[string]any{"content": "changed", "dest": mutation}}}}}
			body, err := yaml.Marshal(play)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "play.yml")
			if err := os.WriteFile(path, body, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-i", "localhost,", "-c", "local", path, "-vvv"}
			if selector == "check" {
				args = append(args, "--check", "--diff")
			} else if selector != "full" {
				args = append(args, "--tags", selector)
			}
			config := filepath.Join(root, "ansible.cfg")
			_ = os.WriteFile(config, []byte("[defaults]\n"), 0600)
			cmd := exec.Command("ansible-playbook", args...)
			cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
			out, runErr := cmd.CombinedOutput()
			selected := selector == "full" || selector == "C10" || selector == "C11"
			if selected && (runErr == nil || !strings.Contains(string(out), "exclusive immark ownership")) {
				t.Fatalf("expected safe pre-mutation refusal: %v\n%s", runErr, out)
			}
			if !selected && runErr != nil {
				t.Fatalf("nonselected/check run must defer the native gate: %v\n%s", runErr, out)
			}
			_, ran := os.Stat(witness)
			if (ran == nil) != selected {
				t.Fatal("guard selection did not match C10/C11 real mutation")
			}
			if _, err := os.Stat(mutation); !os.IsNotExist(err) {
				t.Fatal("configuration mutation ran before ownership approval")
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
	pre := play["pre_tasks"].([]any)
	found := false
	for _, task := range pre {
		if task.(map[string]any)["name"] == preflight["name"] {
			found = true
		}
	}
	if !found {
		t.Fatal("ownership/native capability must precede all Wazuh configuration mutation")
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
