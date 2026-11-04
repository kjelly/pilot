'''Actual Ansible script action + local shell; harmless receiver only.

The real manager selection/default tasks and exact central cmd are copied,
replacing only its first source-file token. No product CLI, package, service
or Docker action runs. Check+recover calls the real pre-mutation helper gate
with a runner that forbids native commands. No fake argv/action plugin.
'''
import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
import yaml

REPO=Path(__file__).resolve().parents[3]
MANAGER=REPO/'playbooks/apply/wazuh-manager-apply.yml'
OWNER='0123456789abcdef0123456789abcdef'
RECEIVER=r'''
import argparse,importlib.util,json,os,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('action')
for name in ('version','legacy','owner','component','mode','family','manager','agent-id','agent-name','reader-desired-json','reader-checker-sha256'):p.add_argument('--'+name,default='')
for name in ('upgrade','preview','recover','confirm-previous-stopped','ack-rsyslog-downtime-and-replay'):p.add_argument('--'+name,action='store_true')
a=p.parse_args();record={'argv':sys.argv[1:],'guard':None,'native_calls':0};status=0
if a.preview and a.recover:
 s=importlib.util.spec_from_file_location('real_product_gate',os.environ['WAZUH_REAL_HELPER'])
 w=importlib.util.module_from_spec(s);s.loader.exec_module(w)
 class NoNative:
  def run(self,*args,**kwargs):record['native_calls']+=1;raise AssertionError('native command outside guard')
  def json(self,*args,**kwargs):return self.run(*args,**kwargs)
 try:w.Central(root=Path(os.environ['WAZUH_ARGV_RECORD']).parent/'forbidden-guard-root',runner=NoNative()).execute(a.version or a.legacy,a.upgrade,a.preview,a.recover,a.owner)
 except w.Refused as error:record['guard']=str(error);status=1
 else:record['guard']='DID_NOT_REFUSE'
fd=os.open(os.environ['WAZUH_ARGV_RECORD'],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:json.dump(record,f)
print(json.dumps({'changed':False,'guard':record['guard']}));sys.exit(status)
'''


def tasks(items):
 for item in items:
  yield item
  for key in ('block','rescue','always'):yield from tasks(item.get(key,[]))


def picked(play,name):
 matches=[item for item in tasks(play.get('pre_tasks',[])+play.get('tasks',[])) if item.get('name')==name]
 assert len(matches)==1,(name,len(matches))
 return copy.deepcopy(matches[0])


class ManagerScriptArgumentTests(unittest.TestCase):
 def test_actual_script_action_preserves_modes_selection_empty_values_and_quoting(self):
  source=yaml.safe_load(MANAGER.read_text())[0]
  gate=picked(source,'Gate: common and legacy Wazuh release inputs agree')
  defaults=picked(source,'Resolve inventory-overridable defaults without shadowing group_vars/host_vars')
  reset=picked(source,"Reset this play's selected manager replacement plan")
  mark=picked(source,"Mark this run's selected Wazuh manager installation plan")
  central=picked(source,'Inspect compatibility or execute the explicitly authorized central upgrade')
  reset_reader=picked(source,"Reset this play's actual forwarding selection")
  mark_reader=picked(source,'Mark selected forwarding intent without granting container authority')
  reader_request=picked(source,'Build the secret-free selected reader request')
  original=central['ansible.builtin.script']['cmd']
  self.assertEqual(original.count('files/wazuh-transaction.py'),1)
  batches=[
   ('apply-full',(),[
    ('default',{},'', '4.14.1',False,False,False),
    ('common',{'wazuh_version':'4.14.9'},'4.14.9','4.14.9',False,False,False),
    ('legacy',{'wazuh_docker_version':'4.14.9'},'','4.14.9',False,False,False),
    ('both',{'wazuh_version':'4.14.9','wazuh_docker_version':'4.14.9'},'4.14.9','4.14.9',False,False,False),
    ('empty-common',{'wazuh_version':'','wazuh_docker_version':'4.14.9'},'','4.14.9',False,False,False),
    ('upgrade',{'wazuh_upgrade':True,'wazuh_ack_rsyslog_downtime_and_replay':True,'wazuh_version':'4.14.9'},'4.14.9','4.14.9',True,False,False),
    ('recover',{'wazuh_recover':True,'wazuh_version':'4.14.9'},'4.14.9','4.14.9',False,False,True)]),
   ('check-full',('--check',),[
    ('normal',{'wazuh_version':'4.14.9'},'4.14.9','4.14.9',False,True,False),
    ('legacy',{'wazuh_docker_version':'4.14.9'},'','4.14.9',False,True,False),
    ('upgrade',{'wazuh_upgrade':True,'wazuh_version':'4.14.9'},'4.14.9','4.14.9',True,True,False),
    ('recover-refused',{'wazuh_recover':True,'wazuh_version':'4.14.9'},'4.14.9','4.14.9',False,True,True)])]
  for row in ('C1','C2','C3','C5','C10','C11','C12'):
   for check in (False,True):
    flags=('--tags',row,*(['--check'] if check else []))
    batches.append(('tag-'+row+('-check' if check else '-apply'),flags,[
     ('common-upgrade',{'wazuh_upgrade':True,'wazuh_version':'4.14.9'},'4.14.9','4.14.9',row in ('C1','C2','C3'),check,False),
     ('legacy-upgrade',{'wazuh_upgrade':True,'wazuh_docker_version':'4.14.9'},'','4.14.9',row in ('C1','C2','C3'),check,False)]))
  with tempfile.TemporaryDirectory(prefix='wazuh-manager-real-script-') as temporary:
   root=Path(temporary);receiver=root/'receiver.py';receiver.write_text(RECEIVER);receiver.chmod(0o700)
   unexpected=root/'unexpected-shell-effect';quoted="literal ' spaces; $(touch "+str(unexpected)+")"
   batches.append(('quoting',(),[('literal',{'wazuh_version':quoted,'wazuh_docker_version':quoted,'wazuh_writer_owner':quoted},quoted,quoted,False,False,False)]))
   invocations=0;cases_run=0
   for batch,flags,cases in batches:
    plays=[];expected=[];hosts={}
    for case,variables,common,legacy,upgrade,preview,recover in cases:
     stem=batch+'-'+case;args_path=root/(stem+'-argv.json');result_path=root/(stem+'-result.json')
     hosts[stem]={'ansible_connection':'local'}
     command=copy.deepcopy(central)
     command['ansible.builtin.script']['cmd']=original.replace('files/wazuh-transaction.py',shlex.quote(str(receiver)),1)
     command['environment']={'WAZUH_ARGV_RECORD':str(args_path),'WAZUH_REAL_HELPER':str(REPO/'playbooks/apply/files/wazuh-transaction.py')}
     # Keep the actual task and result behavior. Rescue only collects expected
     # fail-closed check+recover without aborting the harmless matrix batch.
     wrapper={'block':[command],'rescue':[{'ansible.builtin.set_fact':{'script_case_rescued':True},'tags':['always']}],'tags':['always']}
     tools={'pilot-wazuh-delivery':'a'*64,'pilot-siem-relp-check':'c'*64}
     values={'wazuh_writer_owner':OWNER,'docker_pre':{'rc':0},'siem_forwarding_enabled':False,
             'siem_forward_host':'','siem_forward_transport':'tcp','siem_forward_port':'514',
             'siem_relp_port':20514,'wazuh_reader_tools':tools,'wazuh_reader_checker_hash':'b'*64,**variables}
     record={'ansible.builtin.copy':{'content':"{{ {'rc': wazuh_central_transaction.rc, 'rescued': script_case_rescued} | to_json }}",'dest':str(result_path),'mode':'0600'},'check_mode':False,'tags':['always']}
     plays.append({'name':stem,'hosts':stem,'connection':'local','gather_facts':False,'vars':values,
                   'tasks':[gate,defaults,reset,mark,reset_reader,mark_reader,reader_request,{'ansible.builtin.set_fact':{'script_case_rescued':False},'tags':['always']},wrapper,record]})
     argv=['central','--version',common,'--legacy',legacy,'--owner',values['wazuh_writer_owner']]
     selected=not flags or '--tags' not in flags or flags[flags.index('--tags')+1] in ('C10','C11')
     wanted={'selected':selected,'enabled':False,'host':'','transport':'tcp','port':'514','peer':'',
             'tls':{'ca.pem':__import__('hashlib').sha256(b'').hexdigest(),
                    'cert.pem':__import__('hashlib').sha256(b'').hexdigest(),
                    'key.pem':__import__('hashlib').sha256(b'').hexdigest()},'tools':tools}
     argv+=['--reader-desired-json',json.dumps(wanted),'--reader-checker-sha256','b'*64]
     if variables.get('wazuh_ack_rsyslog_downtime_and_replay'):argv+=['--ack-rsyslog-downtime-and-replay']
     if upgrade:argv+=['--upgrade']
     if preview:argv+=['--preview']
     if recover:argv+=['--recover']
     expected.append((stem,args_path,result_path,argv,preview and recover))
    playbook=root/(batch+'.yml');playbook.write_text(yaml.safe_dump(plays,sort_keys=False))
    inventory=root/(batch+'-inventory.yml');inventory.write_text(yaml.safe_dump({'all':{'hosts':hosts}}))
    env=dict(os.environ,ANSIBLE_CONFIG=str(REPO/'ansible.cfg'),ANSIBLE_LOCAL_TEMP=str(root/'controller-tmp'),
             ANSIBLE_REMOTE_TEMP=str(root/'remote-tmp'),ANSIBLE_NOCOLOR='1',PYTHONDONTWRITEBYTECODE='1')
    run=subprocess.run(['ansible-playbook','-i',str(inventory),str(playbook),*flags],cwd=REPO,env=env,capture_output=True,text=True,timeout=120)
    invocations+=1
    self.assertEqual(run.returncode,0,(batch,run.stdout,run.stderr))
    for stem,args_path,result_path,argv,refused in expected:
     with self.subTest(case=stem):
      self.assertTrue(args_path.exists(),(stem,'receiver not executed',run.stdout,run.stderr))
      actual=json.loads(args_path.read_text());result=json.loads(result_path.read_text())
      self.assertEqual(actual['argv'],argv,(stem,'REAL_SCRIPT_ARGV_LOST_OR_SPLIT',result))
      self.assertEqual(result,{'rc':1 if refused else 0,'rescued':refused},(stem,'REAL_SCRIPT_SHELL_RC',actual))
      self.assertEqual(actual['native_calls'],0)
      if refused:self.assertEqual(actual['guard'],'check mode cannot execute central recovery')
      else:self.assertIsNone(actual['guard'])
      cases_run+=1
    self.assertFalse(unexpected.exists(),'quoted argument executed as a shell command')
   self.assertEqual(invocations,17);self.assertEqual(cases_run,40)
   print('REAL_SCRIPT_MATRIX invocations='+str(invocations)+' cases='+str(cases_run))


 def test_check_recovery_is_refused_by_original_gate_before_script(self):
  source=yaml.safe_load(MANAGER.read_text())[0]
  gate=picked(source,'Gate: interrupted writer resume requires its exact owner and stopped-operation confirmation')
  central=picked(source,'Inspect compatibility or execute the explicitly authorized central upgrade')
  with tempfile.TemporaryDirectory(prefix='wazuh-recovery-check-gate-') as temporary:
   root=Path(temporary);receiver=root/'receiver.py';receiver.write_text(RECEIVER)
   marker=root/'must-not-exist.json'
   central['ansible.builtin.script']['cmd']=central['ansible.builtin.script']['cmd'].replace('files/wazuh-transaction.py',shlex.quote(str(receiver)),1)
   central['environment']={'WAZUH_ARGV_RECORD':str(marker)}
   play=[{'hosts':'localhost','connection':'local','gather_facts':False,
          'vars':{'wazuh_recover':True,'wazuh_writer_resume_owner':OWNER,'wazuh_confirm_previous_operation_stopped':True},
          'tasks':[gate,central]}]
   path=root/'gate.yml';path.write_text(yaml.safe_dump(play,sort_keys=False))
   run=subprocess.run(['ansible-playbook','-i','localhost,',str(path),'--check'],cwd=REPO,capture_output=True,text=True,
                      env=dict(os.environ,ANSIBLE_CONFIG=str(REPO/'ansible.cfg'),ANSIBLE_LOCAL_TEMP=str(root/'tmp'),ANSIBLE_REMOTE_TEMP=str(root/'remote-tmp'),ANSIBLE_CACHE_PLUGIN='memory'),timeout=120)
   self.assertEqual(run.returncode,2,(run.stdout,run.stderr))
   self.assertIn('recovery never takes over another operation',run.stdout)
   self.assertFalse(marker.exists(),'unsupported recovery check reached the script')

 def test_sibling_script_transports_keep_quoted_values_and_mode_flags(self):
  manager=yaml.safe_load(MANAGER.read_text())[0]
  agent=yaml.safe_load((REPO/'playbooks/apply/wazuh-fim-apply.yml').read_text())[0]
  claim='Claim the host-wide Wazuh writer before any shared coordinator copy or mutation'
  quoted="agent ' ; $(false)"
  cases=[]
  for component,play in [('central',manager),('agent',agent)]:
   for resume in (False,True):
    values={'wazuh_writer_owner':OWNER,'wazuh_confirm_previous_operation_stopped':resume,
            'wazuh_writer_resume_owner':OWNER if resume else ''}
    expected=['writer-resume' if resume else 'writer-claim','--component',component,'--owner',OWNER,'--mode','apply']
    if resume:expected+=['--confirm-previous-stopped']
    cases.append((component+str(resume),picked(play,claim),values,expected))
  for family in ('Debian','RedHat'):
   for upgrade in (False,True):
    values={'ansible_os_family':family,'wazuh_observed_manager_version':'4.14.9','wazuh_version':'4.14.1',
            'wazuh_writer_owner':OWNER,'wazuh_upgrade':upgrade}
    expected=['agent-check','--family',family,'--manager','4.14.9','--version','4.14.1','--owner',OWNER]
    if upgrade:expected+=['--upgrade']
    cases.append((family+str(upgrade),picked(agent,'Check installed and requested agent compatibility against the observed manager'),values,expected))
  runtime=json.dumps({'id':'001','name':quoted,'version':'4.14.9'})
  cases.append(('verify',picked(agent,'Step 11d: Manager must observe the exact active agent identity and version before commit'),
                {'wazuh_agent_final_runtime':{'stdout':runtime}},['verify-agent','--agent-id','001','--agent-name',quoted,'--version','4.14.9']))
  with tempfile.TemporaryDirectory(prefix='wazuh-sibling-script-') as temporary:
   root=Path(temporary);receiver=root/'receiver.py';receiver.write_text(RECEIVER);plays=[];expected=[];hosts={}
   for name,task,values,argv in cases:
    host='sibling-'+name;hosts[host]={'ansible_connection':'local'};record=root/(name+'.json')
    # This checks sibling transport only; selection/delegation remains covered
    # by the existing real task graph. Preserve exact script cmd/executable.
    script=copy.deepcopy(task['ansible.builtin.script'])
    original=script['cmd'];token=shlex.split(original)[0]
    script['cmd']=original.replace(token,shlex.quote(str(receiver)),1)
    plays.append({'hosts':host,'connection':'local','gather_facts':False,'vars':values,
                  'tasks':[{'ansible.builtin.script':script,'environment':{'WAZUH_ARGV_RECORD':str(record)},
                            'check_mode':False,'no_log':True}]})
    expected.append((record,argv))
   path=root/'siblings.yml';path.write_text(yaml.safe_dump(plays,sort_keys=False))
   inventory=root/'inventory.yml';inventory.write_text(yaml.safe_dump({'all':{'hosts':hosts}}))
   run=subprocess.run(['ansible-playbook','-i',str(inventory),str(path)],cwd=REPO,capture_output=True,text=True,
                      env=dict(os.environ,ANSIBLE_CONFIG=str(REPO/'ansible.cfg'),ANSIBLE_LOCAL_TEMP=str(root/'tmp'),ANSIBLE_REMOTE_TEMP=str(root/'remote-tmp'),ANSIBLE_CACHE_PLUGIN='memory'),timeout=120)
   self.assertEqual(run.returncode,0,(run.stdout,run.stderr))
   for record,argv in expected:self.assertEqual(json.loads(record.read_text())['argv'],argv)
   print('REAL_SIBLING_SCRIPT_MATRIX cases='+str(len(cases)))


 def test_reader_code_hashes_follow_the_actual_imported_apply_context(self):
  import hashlib,shutil
  source=yaml.safe_load(MANAGER.read_text())[0]
  binder=picked(source,'Bind desired forwarding and tracked proof code to this version inspection')
  with tempfile.TemporaryDirectory(prefix='wazuh-reader-import-') as temporary:
   root=Path(temporary);apply=root/'playbooks/apply';fixtures=root/'playbooks/test/fixtures';files=root/'playbooks/files'
   for path in (apply,fixtures,files):path.mkdir(parents=True)
   expected={}
   for name in ('pilot-wazuh-heartbeat','pilot-wazuh-delivery','pilot-siem-relp-check'):
    payload=(REPO/'playbooks/files'/name).read_bytes();(files/name).write_bytes(payload)
    expected[name]=hashlib.sha256(payload).hexdigest()
   assertion={'ansible.builtin.assert':{'that':[
    'wazuh_reader_checker_hash == '+repr(expected['pilot-wazuh-heartbeat']),
    'wazuh_reader_tools["pilot-wazuh-delivery"] == '+repr(expected['pilot-wazuh-delivery']),
    'wazuh_reader_tools["pilot-siem-relp-check"] == '+repr(expected['pilot-siem-relp-check'])]}}
   child=apply/'safe-apply.yml';child.write_text(yaml.safe_dump([{'hosts':'localhost','connection':'local',
        'gather_facts':False,'tasks':[binder,assertion]}],sort_keys=False))
   wrapper=fixtures/'wrapper.yml';wrapper.write_text(yaml.safe_dump([{'ansible.builtin.import_playbook':'../../apply/safe-apply.yml'}]))
   env=dict(os.environ,ANSIBLE_CONFIG=str(REPO/'ansible.cfg'),ANSIBLE_LOCAL_TEMP=str(root/'local'),
            ANSIBLE_REMOTE_TEMP=str(root/'remote'),ANSIBLE_CACHE_PLUGIN='memory')
   run=subprocess.run(['ansible-playbook','-i','localhost,',str(wrapper)],cwd=REPO,env=env,
                      capture_output=True,text=True,timeout=90)
   self.assertEqual(run.returncode,0,(run.stdout,run.stderr))



if __name__=='__main__':unittest.main(verbosity=2)
