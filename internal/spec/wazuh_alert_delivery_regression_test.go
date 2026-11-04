package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Exercise the production oracle against actual files. Only challenge ownership
// and the clock are substituted: the test is unprivileged and must not wait 45s
// for every deliberate missing-delivery control. VM evidence covers native root.
func TestRegression_WazuhDeliveryOracleRejectsStaleBlockedAndReplay(t *testing.T) {
	const code = `import json,pathlib,runpy,sys,time,types
p=runpy.run_path('../../playbooks/files/pilot-wazuh-delivery')
check=p['check_delivery']; env=check.__globals__; root=pathlib.Path(sys.argv[1])
challenge=root/'challenge.json'; output=root/'wazuh-alerts.log'
env['CHALLENGE']=challenge
original_stat=pathlib.Path.stat
def stat(path,*args,**kwargs):
 result=original_stat(path,*args,**kwargs)
 if '.checking-' in path.name:return types.SimpleNamespace(st_uid=0,st_mode=result.st_mode)
 return result
pathlib.Path.stat=stat
nonce='PILOT-WAZUH-'+'a'*32
record=json.loads(pathlib.Path('testdata/wazuh-alert-delivery/real-alert.json').read_text())
assert nonce in record['full_log']
def trial(records,created=None,want=False):
 output.write_text(''.join(json.dumps(r)+'\n' for r in records))
 challenge.write_text(json.dumps({'nonce':nonce,'created':created if created is not None else time.time(),'output':str(output)}));challenge.chmod(0o600)
 ticks=iter(range(0,1000,10)); env['time']=types.SimpleNamespace(time=time.time,monotonic=lambda:next(ticks),sleep=lambda _:None)
 try:check();actual=True
 except ValueError:actual=False
 assert actual==want,(records,created,actual,want)
 assert not challenge.exists() and not list(root.glob('*.checking-*')),'challenge not consumed'
trial([record],want=True)
try:check();raise AssertionError('replay passed')
except FileNotFoundError:pass
trial([],want=False) # healthy local config cannot substitute for a landed alert
trial([dict(record,full_log='old nonce')],want=False)
trial([dict(record,rule={})],want=False)
trial([record],created=time.time()-181,want=False)
trial([record],created=time.time()+10,want=False)
print('delivered=PASS; blocked, wrong nonce, missing fields, stale, future and replay=FAIL')
`
	if output, err := exec.Command("python3", "-c", code, t.TempDir()).CombinedOutput(); err != nil {
		t.Fatalf("real-file delivery oracle: %v\n%s", err, output)
	}
}

func TestRegression_WazuhDeliveryTraceability(t *testing.T) {
	s, err := Parse("../../docs/verification/wazuh-alert-delivery.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rows) != 1 || s.Rows[0].ID != "C1" || s.Rows[0].Expected != "0" ||
		!strings.Contains(s.Rows[0].Command, "pilot-wazuh-delivery delivery") {
		t.Fatal("delivery row must run the receiver oracle with a numeric verdict")
	}
	if HasErrors(Lint(s)) {
		t.Fatal("delivery spec lint errors")
	}
	data, err := os.ReadFile("../../playbooks/apply/tasks/wazuh-alert-forward.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, invariant := range []string{`ruleset(name="pilotWazuhForward")`, `ruleset="pilotWazuhForward"`,
		`Tag="pilot-wazuh-alert:" Facility="local5"`, `queue.filename="wazuh_alerts"`,
		`PersistStateInterval="1"`, `freshStartTail="off"`, `pilot-wazuh-acl`} {
		if !strings.Contains(text, invariant) {
			t.Errorf("missing isolated ingestion/rotation invariant %s", invariant)
		}
	}
}

func TestRegression_WazuhSELinuxBoundaryDoesNotDependOnPythonFacts(t *testing.T) {
	if _, err := exec.LookPath("ansible-playbook"); err != nil {
		t.Skip(err)
	}
	for _, tc := range []struct {
		name                  string
		marker, enabled, fail bool
	}{
		{name: "Ubuntu without SELinux", enabled: true},
		{name: "enabled filesystem with missing Python facts", marker: true, enabled: true, fail: true},
		{name: "standalone remains available", marker: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			marker := filepath.Join(root, "enforce")
			if tc.marker {
				if err := os.WriteFile(marker, []byte("1\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			play := loadFirstPlay(t, "wazuh-manager-apply.yml")
			probe := findNamedTask(t, play, "Gate: detect SELinux independently of optional Python bindings")
			probe["ansible.builtin.stat"].(map[string]any)["path"] = marker
			gate := findNamedTask(t, play, "Gate: Wazuh forwarding uses a supported host reader")
			body, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "gather_facts": false,
				"vars":  map[string]any{"ansible_distribution": "Ubuntu", "ansible_selinux": map[string]any{}, "siem_forwarding_enabled": tc.enabled},
				"tasks": []any{probe, gate}}})
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, "play.yml")
			if err := os.WriteFile(file, body, 0600); err != nil {
				t.Fatal(err)
			}
			config := filepath.Join(root, "ansible.cfg")
			if err := os.WriteFile(config, []byte("[defaults]\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", file)
			cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tc.fail {
				t.Fatalf("rejected=%v want=%v: %s", err != nil, tc.fail, out)
			}
			if tc.fail && !strings.Contains(string(out), "without SELinux") {
				t.Fatalf("failed before the intended SELinux gate: %s", out)
			}
		})
	}
}

// Render production fragments through Ansible/Jinja, then run real rsyslog
// daemons under the current user. This is a native imfile/TCP/omfile harness;
// systemd confinement, Docker permissions and Wazuh emission require VM evidence.
func TestRegression_WazuhNativeImfileDeliveryAndRotation(t *testing.T) {
	for _, tool := range []string{"ansible-playbook", "rsyslogd", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(err)
		}
	}
	root := t.TempDir()
	data, err := os.ReadFile("../../playbooks/apply/tasks/wazuh-alert-forward.yml")
	if err != nil {
		t.Fatal(err)
	}
	var tasks []map[string]any
	if err := yaml.Unmarshal(data, &tasks); err != nil {
		t.Fatal(err)
	}
	var sender map[string]any
	for _, task := range tasks {
		if task["name"] == "Wazuh: render the isolated imfile reader and forward action" {
			sender = task
		}
	}
	if sender == nil {
		t.Fatal("missing production imfile render")
	}
	delete(sender, "when")
	copyTask := sender["ansible.builtin.copy"].(map[string]any)
	copyTask["dest"] = filepath.Join(root, "sender.conf")
	delete(copyTask, "owner")
	delete(copyTask, "group")
	text := copyTask["content"].(string)
	text = strings.ReplaceAll(text, "/var/spool/rsyslog/pilot-wazuh", filepath.Join(root, "spool"))
	// The real host uses the pinned alias; this unprivileged harness uses loopback.
	copyTask["content"] = strings.ReplaceAll(text, `target="siem-log-server"`, `target="127.0.0.1"`)
	receiver := findNamedTask(t, loadFirstPlay(t, "log-server-apply.yml"), "Step 3: Render 10-siem-receiver.conf (imtcp + %HOSTNAME% dynaFile routing)")
	rc := receiver["ansible.builtin.copy"].(map[string]any)
	rc["dest"] = filepath.Join(root, "receiver.conf")
	delete(rc, "owner")
	delete(rc, "group")
	portScript := "import socket; s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1])"
	port, err := exec.Command("python3", "-c", portScript).Output()
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]any{"siem_forward_transport": "tcp", "siem_forward_port": strings.TrimSpace(string(port)),
		"siem_forward_queue_engine": "auto", "wazuh_logs_source": filepath.Join(root, "source"),
		"siem_receiver_relp_enabled": false, "siem_receiver_tcp_port": strings.TrimSpace(string(port)),
		"siem_log_root": filepath.Join(root, "out")}
	body, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "gather_facts": false, "vars": vars, "tasks": []any{sender, receiver}}})
	if err != nil {
		t.Fatal(err)
	}
	play := filepath.Join(root, "render.yml")
	if err := os.WriteFile(play, body, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", play)
	config := filepath.Join(root, "ansible.cfg")
	if err := os.WriteFile(config, []byte("[defaults]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("production render: %v\n%s", err, out)
	}
	// A private byte-identical copy avoids the host's path-attached AppArmor
	// profile; VM tests separately exercise the installed confined service.
	binary, err := exec.LookPath("rsyslogd")
	if err != nil {
		t.Fatal(err)
	}
	binaryBytes, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "rsyslogd"), binaryBytes, 0755); err != nil {
		t.Fatal(err)
	}
	const harness = `import json,os,pathlib,runpy,socket,subprocess,sys,time,uuid
root=pathlib.Path(sys.argv[1]); (root/'source/alerts').mkdir(parents=True);(root/'spool/state').mkdir(parents=True)
source=root/'source/alerts/alerts.json';month=source.parent/'2026/Nov';month.mkdir(parents=True)
daily=month/'ossec-alerts-03.json';daily.write_text('');daily.chmod(0o640);os.link(daily,source)
check_input=runpy.run_path('../../playbooks/files/pilot-wazuh-delivery')['check_input']
rendered=(root/'sender.conf').read_text()
assert 'module(load="immark"' not in rendered and 'action.writeAllMarkMessages' not in rendered,'TCP unexpectedly enabled heartbeat'
# A test-only fallthrough witness makes removal/broadening of the production
# whole-body drop observable, even though syslog normally has no file route.
receiver=root/'receiver.conf';text=receiver.read_text();needle='    stop\n}\n\ninput('
assert text.count(needle)==1
text=text.replace(needle,'    action(type="omfile" file="'+str(root/'fallthrough.log')+'" template="RSYSLOG_SyslogProtocol23Format")\n'+needle,1)
receiver.write_text(text)
check_input(rendered,str(root/'source'))
for before,after in [('File="'+str(source)+'"','File="/nonexistent/alerts.json"'),
                     ('Facility="local5"','Facility="local6"'),
                     ('ruleset="pilotWazuhForward"','ruleset="RSYSLOG_DefaultRuleset"')]:
 assert before in rendered
 try:check_input(rendered.replace(before,after),str(root/'source'))
 except ValueError:pass
 else:raise AssertionError('local input drift was accepted: '+before)
processes=[]; logs=[]
def start(name):
 config=root/(name+'.conf'); valid=subprocess.run([str(root/'rsyslogd'),'-N1','-f',str(config)],capture_output=True)
 assert valid.returncode==0,valid.stderr.decode()
 log=(root/(name+'.stderr')).open('wb');logs.append(log)
 proc=subprocess.Popen([str(root/'rsyslogd'),'-n','-i',str(root/(name+'.pid')),'-f',str(config)],stderr=log,stdout=log);processes.append(proc);return proc
def wait(nonce):
 deadline=time.monotonic()+10
 while time.monotonic()<deadline:
  files=list((root/'out').glob('*/wazuh-alerts.log'))
  if files and nonce in files[0].read_text():return
  assert all(p.poll() is None for p in processes),'daemon exited'
  time.sleep(.1)
 raise AssertionError('nonce did not land: '+nonce)
def emit():
 nonce='PILOT-WAZUH-'+uuid.uuid4().hex
 record=json.loads(pathlib.Path('testdata/wazuh-alert-delivery/real-alert.json').read_text())
 record['full_log']=record['full_log'].replace('PILOT-WAZUH-'+'a'*32,nonce)
 record['full_log']+=' PILOT-WAZUH-TRANSPORT-HEARTBEAT-v1'
 with source.open('a') as f:f.write(json.dumps(record)+'\n')
 return nonce
try:
 start('receiver');time.sleep(.3);start('sender');time.sleep(.5)
 marker='PILOT-WAZUH-TRANSPORT-HEARTBEAT-v1'
 with socket.create_connection(('127.0.0.1',int(sys.argv[2]))) as stream:
  for message in [marker,'prefix-'+marker]:
   stream.sendall(('<46>1 2026-11-03T00:00:00Z fixture-host rsyslogd - - - '+message+'\n').encode())
 deadline=time.monotonic()+5
 while time.monotonic()<deadline:
  witness=root/'fallthrough.log'
  if witness.exists() and 'prefix-'+marker in witness.read_text():break
  time.sleep(.1)
 assert witness.exists() and witness.read_text().count(marker)==1,'exact marker drop failed or contains-match consumed nonreserved message'
 first=emit();wait(first)
 assert marker in list((root/'out').glob('*/wazuh-alerts.log'))[0].read_text(),'valid JSON containing marker was dropped'
 old_inode=source.stat().st_ino;source.unlink();daily.rename(daily.with_suffix('.old'))
 daily.write_text('');daily.chmod(0o640);os.link(daily,source)
 assert source.stat().st_ino!=old_inode and source.stat().st_nlink==2
 second=emit();wait(second)
 # The independent receiver ruleset must never write this source to audit/auth.
 assert not list((root/'out').glob('*/audit.log')) and not list((root/'out').glob('*/auth.log'))
 print('real imfile/TCP/omfile delivery and fresh daily hardlink inode rotation passed')
finally:
 for p in reversed(processes):
  p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 for f in logs:f.close()
 for path in root.glob('*.stderr'):
  text=path.read_text()
  if 'error during parsing' in text:print(text,file=sys.stderr)
`
	if out, err := exec.Command("python3", "-c", harness, root, strings.TrimSpace(string(port))).CombinedOutput(); err != nil {
		t.Fatalf("native reader/receiver: %v\n%s", err, out)
	}
}
