package spec

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Compose the actual caller baseline, shared migration, caller render and ALL
// caller rescue tasks in source order. External service/kernel commands use
// bounded canaries. The local host need not have omrelp: this proves final bytes,
// metadata, absence and module-declaration dependency, not native parser/service
// approval. The dedicated VM arm supplies the matching native-module proof.
func TestRegression_AuditForwardBaselinePrecedesSharedMigration(t *testing.T) {
	for _, tool := range []string{"python3", "ansible-playbook"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatal(err)
		}
	}
	const code = `import copy,json,os,pathlib,shutil,subprocess,sys,tempfile
documents=json.load(sys.stdin)
original=documents['caller']
def find(node,name):
 if isinstance(node,dict):
  if node.get('name')==name:return node
  for value in node.values():
   result=find(value,name)
   if result:return result
 if isinstance(node,list):
  for value in node:
   result=find(value,name)
   if result:return result
 return None
outer=next(t for t in original['tasks'] if 'rescue' in t and find(t['rescue'],'ROLLBACK — restore the previous siem forward config'))
baseline_names=['Step 7: Snapshot the existing forward config','Step 7: Require a regular managed forward config','Step 7: Capture current-run forward config bytes','Step 7: Keep the existing forward config for rollback','Step 7: Record a complete current-run forward baseline']
tls_name='Step 7: Provision the sender TLS profile and snapshot its material'
render_name='Step 7: Render 99-siem-forward.conf (local6.* + auth,authpriv.* -> siem-log-server)'
validate_name='Step 7: Validate the effective rsyslog configuration before restart'
helper=documents['tls']
helper_names=[t['name'] for t in helper if t.get('name') in [
 'RELP: inspect the role\'s TLS files and desired profile','RELP: refuse symlinks and non-regular certificate files',
 'RELP: snapshot existing TLS files for rollback','RELP: record this snapshot\'s role',
 'RELP: snapshot module declarations before sender migration','RELP: retain sender module declarations for rollback',
 'RELP: migrate the legacy audit-owned output module declaration','RELP: load the shared output module exactly once']]
assert len(helper_names)==8,helper_names
assert find(outer,validate_name), 'production validation task missing'
cases=[
 dict(name='legacy-C16',tag='C16',exists=True,shared=False,stale=True),
 dict(name='legacy-C17',tag='C17',exists=True,shared=False),
 dict(name='shared-full',tag='',exists=True,shared=True),
 dict(name='absent99-stale-backup',tag='C16',exists=False,shared=False,stale=True),
 dict(name='backup-failure-stale-backup',tag='C16',exists=True,shared=False,stale=True,fault='backup'),
 dict(name='before-capture-stale-facts',tag='C16',exists=True,shared=False,stale=True,fault='before'),
 dict(name='before-migration',tag='C17',exists=True,shared=False,fault='pre-migration'),
 dict(name='partial-migration',tag='C17',exists=True,shared=False,fault='partial'),
 dict(name='nonselected-C19-stale-facts',tag='C19',exists=True,shared=False,stale=True),
 dict(name='excluded-reader',tag='C16',skip=True,exists=True,shared=False,stale=True),
 dict(name='TCP-current-caller-restore',tag='C16',exists=True,shared=False,tcp=True),
 dict(name='counterexample-post-migration-baseline',tag='C16',exists=True,shared=False,stale=True,wrong=True)]
for case in cases:
 root=pathlib.Path(tempfile.mkdtemp(prefix='audit-caller-order-'))
 try:
  private=root/'private';private.mkdir();tls=private/'pilot-relp-sender';tls.mkdir()
  conf=private/'99-siem-forward.conf';module=private/'09-pilot-omrelp.conf';backup=pathlib.Path(str(conf)+'.pre-audit-forwarding.bak')
  def adapt(node):
   node=json.loads(json.dumps(copy.deepcopy(node)).replace('/etc/rsyslog.d',str(private)))
   def owners(n):
    if isinstance(n,dict):
     args=n.get('ansible.builtin.copy',{})
     for key in ['owner','group']:
      if args.get(key)=='root':args.pop(key)
     for value in n.values():owners(value)
    elif isinstance(n,list):
     for value in n:owners(value)
   owners(node);return node
  variables=dict(siem_forward_conf=str(conf),siem_forwarding_enabled=True,
   siem_forward_transport='tcp' if case.get('tcp') else 'relp',siem_forward_alias='siem-log-server',
   siem_forward_port=514,siem_relp_port=20514,siem_relp_server_name='logs.example.test',
   siem_queue_spool=str(root/'spool'),siem_forward_queue_engine='disk',audit_syslog_group='root',audit_rules_dest=str(root/'audit.rules'))
  (root/'ansible.cfg').write_text('[defaults]\n')
  env=os.environ.copy();env.update(ANSIBLE_CONFIG=str(root/'ansible.cfg'),ANSIBLE_LOCAL_TEMP=str(root/'local'),ANSIBLE_REMOTE_TEMP=str(root/'remote'),ANSIBLE_FORKS='1')
  def execute(tasks,name,tag=''):
   play=root/(name+'.yml');play.write_text(json.dumps([dict(hosts='all',gather_facts=False,vars=variables,tasks=tasks)]))
   args=['ansible-playbook','-i','localhost,','-c','local','-vvv','--diff',str(play)]
   if tag:args+=['--tags',tag]
   if case.get('skip') and name=='run':args+=['--skip-tags','C16,C17']
   result=subprocess.run(args,env=env,capture_output=True,text=True)
   (root/(name+'.stdout')).write_text(result.stdout);(root/(name+'.stderr')).write_text(result.stderr)
   return result
  render=adapt(find(outer,render_name));setup=execute([dict(render,tags=['always'])],'setup')
  assert setup.returncode==0,'setup render failed'
  initial='# original legacy baseline\n'+conf.read_text()
  if not case.get('tcp') and not case['shared']:initial='module(load="omrelp" tls.tlsLib="gnutls")\n'+initial
  if case['exists']:conf.write_text(initial);conf.chmod(0o600)
  else:conf.unlink()
  module_initial='# original shared declaration\nmodule(load="omrelp" tls.tlsLib="gnutls")\n'
  if case['shared']:module.write_text(module_initial);module.chmod(0o640)
  if case.get('stale'):backup.write_text('STALE DATA MUST NEVER BECOME CURRENT\n');backup.chmod(0o600)
  for name in ['ca.pem','cert.pem','key.pem','profile.json']:
   (tls/name).write_text('original private '+name);(tls/name).chmod(0o600)
   (root/name).write_text('unrelated '+name)
  initial_meta=conf.stat() if conf.exists() else None
  helpers=[]
  for task in helper:
   if task.get('name') not in helper_names:continue
   if task['name']=='RELP: migrate the legacy audit-owned output module declaration' and case.get('fault')=='pre-migration':helpers.append({'ansible.builtin.fail':{'msg':'CONTROLLED_BEFORE_MIGRATION'}})
   helpers.append(adapt(task))
   if task['name']=='RELP: migrate the legacy audit-owned output module declaration' and case.get('fault')=='partial':helpers.append({'ansible.builtin.fail':{'msg':'CONTROLLED_PARTIAL_MIGRATION'}})
  (root/'helper.yml').write_text(json.dumps(helpers))
  (root/'restore.yml').write_text(json.dumps(adapt(documents['restore'])))
  block=[];late=[]
  if case.get('fault')=='before':block.append({'tags':['always'],'ansible.builtin.fail':{'msg':'CONTROLLED_BEFORE_CAPTURE'}})
  for task in outer['block']:
   name=task.get('name')
   if name in baseline_names:
    task=adapt(task)
    if name=='Step 7: Keep the existing forward config for rollback' and case.get('fault')=='backup':task['ansible.builtin.copy']['dest']=str(root/'missing-parent/backup')
    (late if case.get('wrong') else block).append(task)
   elif name==tls_name:
    task=adapt(task);task['ansible.builtin.include_tasks']['file']=str(root/'helper.yml');block.append(task)
    if case.get('wrong'):block+=late;late=[]
   elif name==render_name:
    block.append(render)
    block.append({'tags':['C16','C17'],'ansible.builtin.copy':{'dest':str(root/'rendered'),'content':'render completed','mode':'0600'}})
   elif name==validate_name:
    task=adapt(task);task['ansible.builtin.command']={'argv':['python3','-c','import pathlib,sys;pathlib.Path(sys.argv[1]).write_text("fault reached");sys.exit(1)',str(root/'fault')]};block.append(task)
  assert not late,'counterexample failed to place backup after helper'
  block.append({'tags':['always'],'ansible.builtin.fail':{'msg':'CONTROLLED_END_OF_SELECTED_CALLER'}})
  rescue=adapt(outer['rescue'])
  checker=root/'check-combined.py'
  checker.write_text('import pathlib,sys\np=pathlib.Path(sys.argv[1]);text="\\n".join(x.read_text() for x in p.glob("*.conf"));ok=("type=\\"omrelp\\"" not in text or text.count("module(load=\\"omrelp\\"")==1);(p.parent/"validated").write_text(str(ok));sys.exit(0 if ok else 1)\n')
  for task in rescue:
   name=task.get('name','')
   if name=='ROLLBACK — restore sender TLS material before restoring the service':task['ansible.builtin.include_tasks']['file']=str(root/'restore.yml')
   elif name=='ROLLBACK — reload kernel audit rules back to the restored state':task['ansible.builtin.command']='/bin/true'
   elif name=='ROLLBACK — validate the restored rsyslog configuration':task['ansible.builtin.command']={'argv':['python3',str(checker),str(private)]}
   elif name=='ROLLBACK — restart rsyslog with the restored configuration':
    task.pop('ansible.builtin.systemd');task['ansible.builtin.command']={'argv':['python3','-c','import pathlib,sys;p=pathlib.Path(sys.argv[1]);assert (p/"validated").read_text()=="True";(p/"restarted").write_text("1")',str(root)]}
  tasks=[{'tags':['always'],'no_log':True,'ansible.builtin.set_fact':{'siem_forward_baseline_complete':True,'siem_forward_content_snapshot':{'content':'U1RBTEU='},'siem_forward_conf_result':{'changed':True},'siem_tls_snapshot_role':'sender','siem_tls_restore_result':{'changed':True}}},
   adapt(find(original,'Reset this run\'s audit and rsyslog recovery results')),
   adapt(documents['inputs'][0]),
   {'block':block,'rescue':rescue}]
  result=execute(tasks,'run',case['tag'])
  assert result.returncode!=0 and 'audit-log-forwarding apply failed' in result.stdout,'original caller failure was not retained'
  selected=case['tag']!='C19' and not case.get('skip') and not case.get('fault')
  assert (root/'rendered').exists()==selected,'failure occurred before intended selected render'
  if case.get('wrong'):
   assert conf.exists() and conf.read_text()!=initial and 'module(load="omrelp"' not in conf.read_text() and not module.exists(),'wrong-order control did not corrupt the intended final module dependency'
   assert (root/'validated').read_text()=='False' and not (root/'restarted').exists(),'invalid combined dependency restarted service'
  else:
   assert conf.exists()==case['exists'],'original absence/existence not restored'
   if case['exists']:
    now=conf.stat();assert conf.read_text()==initial and (now.st_mode&0o777,now.st_uid,now.st_gid)==(initial_meta.st_mode&0o777,initial_meta.st_uid,initial_meta.st_gid),'caller baseline bytes/metadata not restored'
   assert module.exists()==case['shared'],'09 initial absence/existence not restored'
   if case['shared']:assert module.read_text()==module_initial and module.stat().st_mode&0o777==0o640,'09 bytes/mode not restored'
  for name in ['ca.pem','cert.pem','key.pem','profile.json']:
   assert (tls/name).read_text()=='original private '+name and (tls/name).stat().st_mode&0o777==0o600,'private material changed'
   assert (root/name).read_text()=='unrelated '+name,'unrelated basename changed'
  print(case['name']+' PASS',flush=True)
  artifacts=os.environ.get('PILOT_AUDIT_CALLER_TEST_ARTIFACT_DIR')
  if artifacts:
   dest=pathlib.Path(artifacts)/case['name'];dest.mkdir(parents=True,exist_ok=True)
   for name in ['run.yml','run.stdout','run.stderr','helper.yml','restore.yml','check-combined.py']:
    if (root/name).exists():shutil.copy2(root/name,dest/name)
 finally:shutil.rmtree(root)
`
	// Go owns YAML decoding, as in the rest of the spec tests. JSON is valid
	// Ansible input and lets the controller run with Python's standard library
	// only, even when CI's PATH Python differs from Ansible's environment.
	documents := map[string]any{"caller": loadFirstPlay(t, "audit-log-forwarding-apply.yml")}
	for key, name := range map[string]string{"tls": "rsyslog-relp-tls.yml", "restore": "rsyslog-relp-restore.yml", "inputs": "rsyslog-relp-inputs.yml"} {
		raw, err := os.ReadFile(filepath.Join("../../playbooks/apply/tasks", name))
		if err != nil {
			t.Fatal(err)
		}
		var tasks []any
		if err := yaml.Unmarshal(raw, &tasks); err != nil {
			t.Fatal(err)
		}
		documents[key] = tasks
	}
	payload, err := json.Marshal(documents)
	if err != nil {
		t.Fatal(err)
	}
	// -I -S deliberately excludes site packages, proving PyYAML is not an
	// incidental requirement of this actual twelve-case Ansible harness.
	cmd := exec.Command("python3", "-I", "-S", "-c", code)
	cmd.Stdin = bytes.NewReader(payload)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("full audit caller recovery order: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
