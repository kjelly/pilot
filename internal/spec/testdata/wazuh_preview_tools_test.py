"""RV19: actual module/filesystem controls with explicit native account/path leaves.

No VM, Docker, service, package or installed-system path is mutated. Root UID/GID
and host mount facts are declared models; bytes/inodes/modes, modules, public
coordinator CLI/locks and staged child executions are real private operations.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
import yaml
import wazuh_transaction_test as existing
from wazuh_manager_script_args_test import picked
w=existing.w
REPO=existing.REPO
OWNER='a'*32;OP='b'*32
NAMES=('pilot-wazuh-delivery','pilot-wazuh-heartbeat','pilot-siem-relp-check')


@contextlib.contextmanager
def native_metadata(overrides=None):
    """Native root account leaf ONLY; preserve real shape/identity/time fields."""
    overrides=overrides or {};stat=Path.stat;lstat=Path.lstat;fstat=os.fstat;osstat=os.stat
    def value(info,path):
        fields={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
        fields.update(st_uid=0,st_gid=0)
        # The actual service /run ancestry is root/nonwritable; controller
        # cache parents are a declared native anchor metadata substitute.
        if Path(path) in (Path(tempfile.gettempdir()),*Path(tempfile.gettempdir()).parents):fields['st_mode'] &= ~0o022
        fields.update(overrides.get(str(path),{}))
        return types.SimpleNamespace(**fields)
    def native_stat(path,*args,**kwargs):
        actual=path
        if kwargs.get('dir_fd') is not None:actual=Path(os.readlink('/proc/self/fd/'+str(kwargs['dir_fd'])))/path
        return value(osstat(path,*args,**kwargs),actual)
    with mock.patch.object(os,'stat',native_stat),mock.patch.object(Path,'stat',lambda p,*a,**kw:value(stat(p,*a,**kw),p)),\
         mock.patch.object(Path,'lstat',lambda p,*a,**kw:value(lstat(p,*a,**kw),p)),\
         mock.patch.object(os,'fstat',lambda fd:value(fstat(fd),os.readlink('/proc/self/fd/'+str(fd)))),\
         mock.patch.object(os,'geteuid',return_value=0):
        yield


def setup(root, marker=True, scripts=None):
    run=root/'run';run.mkdir(mode=0o755)
    ledger=root/'ledger';ledger.mkdir(mode=0o700)
    writer=ledger/'writer-active.json'
    if marker:writer.write_text(json.dumps({'owner':OWNER,'component':'central','mode':'apply'}));writer.chmod(0o600)
    scope=run/('pilot-wazuh-preview-'+OWNER+'-'+OP+'-unique');scope.mkdir(mode=0o700)
    for name in NAMES:
        data=(scripts or {}).get(name,(REPO/'playbooks/files'/name).read_bytes())
        (scope/name).write_bytes(data);(scope/name).chmod(0o700)
    proc=root/'proc';(proc/'self').mkdir(parents=True)
    info=scope.stat();(proc/'self/mountinfo').write_text(f'1 0 {os.major(info.st_dev)}:{os.minor(info.st_dev)} / / rw - ext4 modeled rw\n')
    descriptor={'schema':1,'kind':'WAZUH_PREVIEW_TOOLS','owner':OWNER,'operation':OP,'path':str(scope),
        'identity':[info.st_dev,info.st_ino,0,0,0o700],
        'tools':{name:hashlib.sha256((scope/name).read_bytes()).hexdigest() for name in NAMES}}
    env=runpy.run_path(str(REPO/'playbooks/files/pilot-wazuh-delivery'));cls=env['PreviewTools']
    cls.RUN=run;cls.WRITER=writer;cls.PROC=proc
    return cls,descriptor,scope,ledger,proc


@contextlib.contextmanager
def product_paths(product, run, ledger, proc, installed=None):
    original_path=product.Path;original_writer=product.HostWriter;builtin_exec=exec
    def path(value,*args):
        text=str(value)
        if text=='/run':return run
        if installed is not None and (text=='/usr/local/libexec' or text.startswith('/usr/local/libexec/')):
            return installed/Path(text).relative_to('/usr/local/libexec')
        return original_path(value,*args)
    def execute(code,namespace):
        builtin_exec(code,namespace)
        namespace['PreviewTools'].RUN=run;namespace['PreviewTools'].WRITER=ledger/'writer-active.json';namespace['PreviewTools'].PROC=proc
    with mock.patch.object(product,'Path',path),mock.patch.object(product,'ROOT',ledger),\
         mock.patch.object(product,'HostWriter',lambda root=ledger:original_writer(root)),\
         mock.patch.object(product,'exec',execute,create=True):yield


class PreviewCapabilityTests(unittest.TestCase):
    def test_fixed_full_members_and_partial_cleanup_are_real(self):
        for missing in (None,'pilot-wazuh-heartbeat','pilot-wazuh-delivery'):
            with self.subTest(missing=missing),tempfile.TemporaryDirectory() as temporary:
                cls,value,scope,ledger,proc=setup(Path(temporary))
                if missing:(scope/missing).unlink()
                with native_metadata():
                    if missing:
                        instance=object.__new__(cls);instance.value=value;instance.owner=OWNER;instance.operation=OP
                        with self.assertRaisesRegex(ValueError,'member set'):cls(value,OWNER,OP)
                    else:instance=cls(value,OWNER,OP)
                    self.assertTrue(instance.remove()['removed'])
                self.assertFalse(scope.exists());self.assertTrue((ledger/'writer-active.json').exists())

    def test_hash_members_alias_ancestry_context_and_mount_controls(self):
        failures=('hash','missing','extra','symlink','hardlink','mode','writable-parent','foreign-owner',
                  'wrong-owner','wrong-operation','outside','spelling','scope-replacement','mount','readonly')
        for failure in failures:
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);cls,value,scope,ledger,proc=setup(root);overrides={}
                file=scope/'pilot-wazuh-heartbeat'
                if failure=='hash':file.write_bytes(b'wrong bytes')
                elif failure=='missing':file.unlink()
                elif failure=='extra':(scope/'unexpected').write_text('do not delete')
                elif failure=='symlink':file.unlink();file.symlink_to(root/'outside')
                elif failure=='hardlink':os.link(file,root/'outside')
                elif failure=='mode':file.chmod(0o755)
                elif failure=='writable-parent':scope.parent.chmod(0o777)
                elif failure=='foreign-owner':overrides[str(file)]={'st_uid':123}
                elif failure=='wrong-owner':value['owner']='c'*32
                elif failure=='wrong-operation':value['operation']='c'*32
                elif failure=='outside':value['path']=str(root)
                elif failure=='spelling':value['path']=str(scope.parent)+'//'+scope.name
                elif failure=='scope-replacement':scope.rename(scope.with_name(scope.name+'-old'));scope.mkdir(mode=0o700)
                elif failure=='readonly':
                    text=(proc/'self/mountinfo').read_text();(proc/'self/mountinfo').write_text(text.replace('/ / rw -','/ / ro -'))
                elif failure=='mount':
                    with (proc/'self/mountinfo').open('a') as stream:
                        stream.write(f'2 1 0:999 / {scope} rw - tmpfs synthetic rw\n')
                with native_metadata(overrides),self.assertRaises((ValueError,OSError)):cls(value,OWNER,OP)
                self.assertTrue(scope.exists() or scope.is_symlink())

    def test_wrong_retained_fingerprint_never_executes_or_rewrites_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);cls,value,scope,ledger,proc=setup(root)
            central=w.Central(root=ledger);receipt=w.ReplayReceipt(central)
            retained={'schema':1,'kind':'LOCAL_REPLAY_ACK','tools':dict(value['tools']),
                'checker_sha256':value['tools']['pilot-wazuh-heartbeat']}
            retained['tools'].pop('pilot-wazuh-heartbeat')
            w.atomic_json(receipt.path,retained);before=receipt.path.read_bytes()
            with native_metadata():
                assets=cls(value,OWNER,OP)
                preview=w.ReplayReceipt(central,assets)
                # Stop at custody to discriminate exact required provenance;
                # all real receipt reads/lock/required-hash checks precede it.
                with mock.patch.object(preview,'custody',side_effect=RuntimeError('compatible provenance reached custody')):
                    retained['profile_sha256']='same';w.atomic_json(receipt.path,retained)
                    with mock.patch.object(w,'digest',return_value='same'):
                        with self.assertRaisesRegex(RuntimeError,'reached custody'):preview.operation(OWNER,OP,'admit',ack=True,preview=True)
                    retained['checker_sha256']='0'*64;w.atomic_json(receipt.path,retained);before=receipt.path.read_bytes()
                    with self.assertRaisesRegex(w.Refused,'retained provenance'):preview.operation(OWNER,OP,'admit',ack=True,preview=True)
            self.assertEqual(receipt.path.read_bytes(),before)

    def test_bootstrap_uses_pinned_delivery_before_loading_any_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);cls,value,scope,ledger,proc=setup(root)
            checker=value['tools']['pilot-wazuh-heartbeat'];tools={k:v for k,v in value['tools'].items() if k!='pilot-wazuh-heartbeat'}
            with native_metadata(),product_paths(w,scope.parent,ledger,proc):
                result=w.preview_tools(value,OWNER,OP,checker,tools)
                self.assertEqual(result.tool('pilot-wazuh-heartbeat',checker),scope/'pilot-wazuh-heartbeat')
                (scope/'pilot-wazuh-delivery').write_text('raise AssertionError("UNTRUSTED_CODE_EXECUTED")')
                with self.assertRaisesRegex(w.Refused,'trusted desired source'):w.preview_tools(value,OWNER,OP,checker,tools)

    def test_reader_observation_and_local_cli_use_same_explicit_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);cls,value,scope,ledger,proc=setup(root)
            class Native:
                def json(self,argv,**kwargs):
                    self.observed=argv;return {'typed_native_observation':True}
                def run(self,argv,**kwargs):self.local=argv;self.timeout=kwargs['timeout']
            native=Native();central=w.Central(root=ledger,runner=native)
            tools={name:checksum for name,checksum in value['tools'].items() if name!='pilot-wazuh-heartbeat'}
            with native_metadata():
                assets=cls(value,OWNER,OP)
                reader=w.Reader(central,value['tools']['pilot-wazuh-heartbeat'],{'tools':tools},preview=assets)
                self.assertTrue(reader.observe()['typed_native_observation']);reader.verify_tools();reader.local('preview C11')
                self.assertEqual(native.observed,[scope/'pilot-wazuh-heartbeat','inspect-reader'])
                self.assertEqual(native.local[:3],[str(scope/'pilot-wazuh-delivery'),'local','--preview-tools-json'])
                self.assertEqual(json.loads(native.local[3]),value);self.assertEqual(native.timeout,50)
                for action in ('expose','verify','complete','failed'):
                    with self.assertRaisesRegex(w.Refused,'preview admission only'):
                        w.ReplayReceipt(central,assets).operation(OWNER,OP,action,preview=True)

    def test_enabled_disabled_never_admission_observe_desired_bundle_without_installed_fallback(self):
        from wazuh_reader_test import ReaderInspectionTests
        for mode in ('never','disabled','enabled'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);baseline=root/'baseline';baseline.mkdir(mode=0o755);stage=root/'stage';stage.mkdir(mode=0o755)
                case=ReaderInspectionTests();self.addCleanup(case.doCleanups)
                reader,state,*_=case.fixture(baseline,mode!='never',mode=='enabled')
                cls,value,scope,ledger,proc=setup(stage)
                original_json=reader.r.json;original_run=reader.r.run;calls=[]
                def native_json(argv,**kwargs):
                    if Path(argv[0])==scope/'pilot-wazuh-heartbeat':
                        calls.append('desired-inspector');return original_json([reader.CHECKER,*argv[1:]],**kwargs)
                    return original_json(argv,**kwargs)
                def native_run(argv,**kwargs):
                    if Path(argv[0])==scope/'pilot-wazuh-delivery':
                        self.assertEqual(argv[1:3],['local','--preview-tools-json']);calls.append('desired-C11')
                        return subprocess.CompletedProcess(argv,0,'declared native local C11 leaf','')
                    return original_run(argv,**kwargs)
                with native_metadata(),mock.patch.object(w.pwd,'getpwnam',return_value=types.SimpleNamespace(pw_uid=0)),mock.patch.object(w.grp,'getgrnam',return_value=types.SimpleNamespace(gr_gid=0)):
                    reader.preview_tools=cls(value,OWNER,OP)
                    reader.request={'tools':{name:checksum for name,checksum in value['tools'].items() if name!='pilot-wazuh-heartbeat'}}
                    reader.checker_hash=value['tools']['pilot-wazuh-heartbeat']
                    reader.verify_tools=types.MethodType(w.Reader.verify_tools,reader)
                    with mock.patch.object(reader.r,'json',side_effect=native_json),mock.patch.object(reader.r,'run',side_effect=native_run):
                        result=reader.admit(state,preview=True)
                    self.assertEqual(result['mode'],mode);self.assertIn('desired-inspector',calls)
                    self.assertEqual('desired-C11' in calls,mode=='enabled')
                    self.assertNotIn('preview_tools',result,'capability must not become durable authority')
                case.doCleanups()

    def test_cleanup_refuses_foreign_replacement_open_child_and_unknown_bytes(self):
        for failure in ('replacement','child','extra','changed'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);cls,value,scope,ledger,proc=setup(root)
                with native_metadata():instance=cls(value,OWNER,OP)
                if failure=='replacement':scope.rename(scope.with_name(scope.name+'-old'));scope.mkdir(mode=0o700)
                elif failure=='child':
                    child=proc/'123';child.mkdir();(child/'cmdline').write_bytes(str(scope/'pilot-wazuh-heartbeat').encode()+b'\0')
                elif failure=='extra':(scope/'unknown').write_text('retain')
                else:(scope/'pilot-wazuh-heartbeat').write_text('changed')
                with native_metadata(),self.assertRaises((ValueError,OSError)):instance.remove()
                self.assertTrue(scope.exists());self.assertTrue((ledger/'writer-active.json').exists())

    def test_public_cli_rejects_context_on_every_nonpreview_effect_family(self):
        actions=('central','reader-enable-expose','reader-enable-verify','reader-enable-complete','reader-enable-failed',
                 'central-verify','agent-check','agent-install','agent-recovery','writer-release')
        for action in actions:
            with self.subTest(action=action),mock.patch.object(sys,'argv',['coordinator',action,'--preview-tools-json','{}']),\
                 mock.patch.object(os,'geteuid',return_value=0),contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(w.main(),1)
                self.assertIn('forbidden for this operation',output.getvalue())

    def test_unknown_failed_or_foreign_foreground_result_retains_scope(self):
        for failure in ('unknown','failed','foreign-op','foreign-source',None):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                cls,value,scope,ledger,proc=setup(Path(temporary));env=cls.__init__.__globals__
                response={'preview_children_settled':True,'preview_owner':OWNER,'preview_operation':OP,'preview_source_sha256':'f'*64}
                if failure=='failed':response['preview_children_settled']=False
                elif failure=='foreign-op':response['preview_operation']='c'*32
                elif failure=='foreign-source':response['preview_source_sha256']='c'*64
                outcomes={'coordinator_sha256':'f'*64,'calls':[{'dispatched':True,'response':'not JSON' if failure=='unknown' else json.dumps(response)},{'dispatched':False,'response':''}]}
                with native_metadata(),mock.patch.object(sys,'argv',['delivery','preview-cleanup',json.dumps(value),json.dumps(outcomes)]),contextlib.redirect_stdout(io.StringIO()):
                    if failure:
                        with self.assertRaisesRegex(ValueError,'foreground'):env['main']()
                    else:env['main']()
                self.assertEqual(scope.exists(),failure is not None)
                self.assertTrue((ledger/'writer-active.json').exists())

    def test_failed_observer_or_local_child_latches_unsettled_without_mutating_capability(self):
        for operation in ('observe','local'):
            with self.subTest(operation=operation),tempfile.TemporaryDirectory() as temporary:
                cls,value,scope,ledger,proc=setup(Path(temporary));before=copy.deepcopy(value)
                class Native:
                    def run(self,*args,**kwargs):raise w.Refused('modeled child failure or timeout')
                    json=run
                with native_metadata():
                    assets=cls(value,OWNER,OP);central=w.Central(root=ledger,runner=Native())
                    reader=w.Reader(central,value['tools']['pilot-wazuh-heartbeat'],{'tools':{k:v for k,v in value['tools'].items() if k!='pilot-wazuh-heartbeat'}},preview=assets)
                    with self.assertRaisesRegex(w.Refused,'modeled child'):
                        reader.observe() if operation=='observe' else reader.local('preview')
                    self.assertFalse(assets.settled);self.assertEqual(value,before)

    def test_delivery_context_is_rejected_before_every_nonlocal_mode_effect(self):
        loaded=runpy.run_path(str(REPO/'playbooks/files/pilot-wazuh-delivery'));env=loaded['main'].__globals__
        with tempfile.TemporaryDirectory() as temporary:
            marker=Path(temporary)/'must-not-exist';env['CHALLENGE']=marker
            for mode in ('challenge','inject','delivery','unknown'):
                with self.subTest(mode=mode),mock.patch.object(sys,'argv',['delivery',mode,'--preview-tools-json','{}']):
                    with self.assertRaisesRegex(ValueError,'local-only'):env['main']()
                    self.assertFalse(marker.exists())

    def test_nested_local_children_execute_exact_staged_siblings(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);events=root/'children'
            def script(name):return ('#!/usr/bin/python3\nfrom pathlib import Path\nwith Path('+repr(str(events))+').open("a") as f:f.write('+repr(name+'\n')+')\n').encode()
            cls,value,scope,ledger,proc=setup(root,scripts={name:script(name) for name in NAMES if name!='pilot-wazuh-delivery'})
            loaded=runpy.run_path(str(scope/'pilot-wazuh-delivery'));env=loaded['check_local'].__globals__;actual_cls=env['PreviewTools']
            actual_cls.RUN=scope.parent;actual_cls.WRITER=ledger/'writer-active.json';actual_cls.PROC=proc
            profile=root/'profile';profile.write_text(json.dumps({'enabled':True,'source':str(root/'logs'),'transport':'tcp','heartbeat_interval':0}))
            conf=root/'conf';conf.write_text('canonical input validated separately')
            maps=root/'maps';maps.write_text('imfile.so');source=root/'logs/alerts/alerts.json';source.parent.mkdir(parents=True);source.write_text('real source')
            env['PROFILE']=profile;env['check_input']=lambda *args:None
            original=Path;native=[]
            def paths(value,*args):return {'/etc/rsyslog.d/31-pilot-wazuh.conf':conf,'/proc/123/maps':maps}.get(str(original(value,*args)),original(value,*args))
            def run(*argv,**kwargs):
                native.append(argv)
                if str(argv[0]).startswith(str(scope)):
                    return subprocess.run(argv,check=True,capture_output=True,timeout=20).stdout
                if argv[0] in ('/usr/local/libexec/pilot-siem-relp-check','/usr/local/libexec/pilot-wazuh-heartbeat'):
                    raise AssertionError('STALE_INSTALLED_CHILD_EXECUTED')
                if argv[:3]==('systemctl','show','-p'):return b'123'
                if argv[0]=='date':return b'9999999999'
                if argv[:2]==('docker','inspect'):return json.dumps([{'Mounts':[{'Source':str(root/'logs'),'Destination':'/var/ossec/logs'}]}]).encode()
                return b'no legacy UDP block'
            with native_metadata(),mock.patch.object(env['pathlib'],'Path',paths):
                # Patch only native tool/result leaves. Child script selection
                # and actual subprocess execution remain production code.
                env['run']=run;assets=actual_cls(value,OWNER,OP);env['check_local'](assets)
            self.assertEqual(events.read_text().splitlines(),['pilot-siem-relp-check','pilot-wazuh-heartbeat'])
            self.assertTrue(all(str(argv[0]).startswith(str(scope)) for argv in native if 'pilot-' in str(argv[0])))


WORKER = r"""import json,sys,runpy,contextlib
from pathlib import Path
sys.path.insert(0,SETTINGS['testdata'])
import wazuh_preview_tools_test as fixture
w=fixture.w
args=sys.argv[1:]
if '--preview-tools-json' in args:
 index=args.index('--preview-tools-json')+1;value=json.loads(args[index]);value['identity'][2:4]=[0,0];args[index]=json.dumps(value)
with fixture.native_metadata(),fixture.product_paths(w,Path(SETTINGS['run']),Path(SETTINGS['ledger']),Path(SETTINGS['proc']),Path(SETTINGS['installed'])):
 central=w.Central(root=Path(SETTINGS['ledger']))
 central.discover=lambda:{'version':'4.14.9','directory':SETTINGS['project']}
 central.check_agents=lambda _:{}
 if SETTINGS.get('observer_failure') and args[0]=='central':
  def observe_failure(*argv,**kwargs):
   assets=argv[-1]
   reader=w.Reader(central,assets.value['tools']['pilot-wazuh-heartbeat'],preview=assets)
   class Native:
    def json(self,*args,**kwargs):raise w.Refused('MODELED_OBSERVER_FAILURE_UNSETTLED')
   reader.r=Native()
   return reader.observe()
  central.execute=observe_failure
 with fixture.mock.patch.object(w,'Central',lambda:central),fixture.mock.patch.object(sys,'argv',['desired-coordinator',*args]):
  with Path(SETTINGS['events']).open('a') as out:out.write(args[0]+'\n')
  result=w.main()
sys.exit(result)
"""
CLEANUP = r"""import json,sys,runpy
from pathlib import Path
sys.path.insert(0,SETTINGS['testdata'])
import wazuh_preview_tools_test as fixture
loaded=runpy.run_path(SETTINGS['delivery']);env=loaded['main'].__globals__;cls=env['PreviewTools']
cls.RUN=Path(SETTINGS['run']);cls.WRITER=Path(SETTINGS['ledger'])/'writer-active.json';cls.PROC=Path(SETTINGS['proc'])
value=json.loads(sys.argv[2]);value['identity'][2:4]=[0,0]
with fixture.native_metadata(),fixture.mock.patch.object(sys,'argv',[SETTINGS['delivery'],'preview-cleanup',json.dumps(value),*sys.argv[3:]]):env['main']()
"""


class PreviewModuleTests(unittest.TestCase):
    def run_case(self,root,check=True,tag='all',fresh=False,failure=None):
        run=root/'run';run.mkdir(mode=0o755);ledger=root/'ledger';ledger.mkdir(mode=0o700)
        proc=root/'proc';(proc/'self').mkdir(parents=True)
        info=root.stat();(proc/'self/mountinfo').write_text(f'1 0 {os.major(info.st_dev)}:{os.minor(info.st_dev)} / / rw - ext4 model rw\n')
        installed=root/'libexec';sbin=root/'sbin';sbin.mkdir()
        old=subprocess.check_output(['git','show','f37f37d8dd2813597352f0e574e4d2ab97c4ef7f:playbooks/apply/files/wazuh-transaction.py'],cwd=REPO)
        (sbin/'coordinator').write_bytes(old);(sbin/'coordinator').chmod(0o700)
        if not fresh:
            installed.mkdir(mode=0o755)
            for name in NAMES:
                data=subprocess.check_output(['git','show','f37f37d8dd2813597352f0e574e4d2ab97c4ef7f:playbooks/files/'+name],cwd=REPO)
                (installed/name).write_bytes(data);(installed/name).chmod(0o755)
        def snapshot():
            return {str(path.relative_to(root)):{'sha':hashlib.sha256(path.read_bytes()).hexdigest(),'inode':path.stat().st_ino,
                'uid':path.stat().st_uid,'gid':path.stat().st_gid,'mode':path.stat().st_mode} for path in [sbin/'coordinator',*(installed.iterdir() if installed.exists() else [])]}
        before=snapshot()
        if failure=='foreign-writer':
            (ledger/'writer-active.json').write_text(json.dumps({'owner':'c'*32,'component':'central','mode':'apply'}));(ledger/'writer-active.json').chmod(0o600)
        settings={'testdata':str(Path(__file__).parent),'run':str(run),'ledger':str(ledger),
            'proc':str(proc),'installed':str(installed),'project':str(root/'project'),'events':str(root/'events'),
            'delivery':str(REPO/'playbooks/files/pilot-wazuh-delivery'),'observer_failure':failure=='observer'}
        worker=root/'worker.py';worker.write_text('SETTINGS='+repr(settings)+'\n'+WORKER)
        cleanup=root/'cleanup.py';cleanup.write_text('SETTINGS='+repr(settings)+'\n'+CLEANUP)
        source=yaml.safe_load((REPO/'playbooks/apply/wazuh-manager-apply.yml').read_text())[0]
        names=['Install the root-owned Wazuh transaction coordinator',
            'Validate exact control-code destinations before any reader helper copy',
            'Prepare the root-controlled reader proof helper directory',
            'Install tracked reader inspection/proof code before version admission',
            'Bind desired forwarding and tracked proof code to this version inspection',
            'Allocate an exclusive transient desired-tool preview scope',
            "Pin this invocation's transient directory before any staged copy",
            'Bind preview scope identity and exact desired member fingerprints',
            'Stage the exact desired preview tools without deploying installed assets',
            "Reset this play's actual forwarding selection",'Mark selected forwarding intent without granting container authority',
            'Build the secret-free selected reader request',
            'Record whether this invocation dispatches a readonly central preview',
            'Inspect compatibility or execute the explicitly authorized central upgrade',
            'Record selected readonly replay preview dispatch before execution',
            'Preview selected ordinary enable with the desired coordinator and tool closure']
        selected=[picked(source,name) for name in names]
        next(task for task in selected if task['name'].startswith('Preview selected ordinary'))['register']='wazuh_reader_preview_admit'
        for task in selected:
            if 'ansible.builtin.script' in task:
                task['ansible.builtin.script']['cmd']=task['ansible.builtin.script']['cmd'].replace('files/wazuh-transaction.py',shlex.quote(str(worker)),1)
            if task['name']=='Install the root-owned Wazuh transaction coordinator':
                task['ansible.builtin.copy']['src']=str(REPO/'playbooks/apply/files/wazuh-transaction.py');task['ansible.builtin.copy']['dest']=str(sbin/'coordinator')
            if task['name']=='Prepare the root-controlled reader proof helper directory':task['ansible.builtin.file']['path']=str(installed)
            if task['name']=='Install tracked reader inspection/proof code before version admission':task['ansible.builtin.copy']['dest']=str(installed/'{{ item }}')
            if 'ansible.builtin.copy' in task:
                for key in ('owner','group'):task['ansible.builtin.copy'][key]=str(os.getuid() if key=='owner' else os.getgid())
                if '{{ item }}' in str(task['ansible.builtin.copy'].get('src')):task['ansible.builtin.copy']['src']=str(REPO/'playbooks/files'/'{{ item }}')
            if 'ansible.builtin.file' in task:
                task['ansible.builtin.file'].update(owner=str(os.getuid()),group=str(os.getgid()))
            if 'ansible.builtin.tempfile' in task:task['ansible.builtin.tempfile']['path']=str(run)
        # Controller lookup strings in the real hash-binding task resolve from
        # this private wrapper; replace ONLY their source-root prefix.
        binding=next(t for t in selected if t['name'].startswith('Bind desired forwarding'))
        binding['ansible.builtin.set_fact']={
            'wazuh_reader_tools':{name:hashlib.sha256((REPO/'playbooks/files'/name).read_bytes()).hexdigest() for name in ('pilot-wazuh-delivery','pilot-siem-relp-check')},
            'wazuh_reader_checker_hash':hashlib.sha256((REPO/'playbooks/files/pilot-wazuh-heartbeat').read_bytes()).hexdigest(),
            'wazuh_preview_coordinator_hash':hashlib.sha256((REPO/'playbooks/apply/files/wazuh-transaction.py').read_bytes()).hexdigest()}
        if failure=='copy':
            stage=next(t for t in selected if t['name'].startswith('Stage the exact'))
            stage['ansible.builtin.copy']['src']="{{ "+repr(str(root/'MISSING-heartbeat'))+" if item == 'pilot-wazuh-heartbeat' else "+repr(str(REPO/'playbooks/files'))+" ~ '/' ~ item }}"
        if failure=='checker':
            central_task=next(t for t in selected if t['name'].startswith('Inspect compatibility'))
            central_task['ansible.builtin.script']['cmd']=central_task['ansible.builtin.script']['cmd'].replace('--reader-checker-sha256 {{ wazuh_reader_checker_hash | quote }}','--reader-checker-sha256 '+'0'*64)
        claim={'ansible.builtin.script':{'cmd':str(worker)+' writer-claim --owner '+OWNER+' --component central','executable':'python3'},'check_mode':False,'changed_when':False,'tags':['always']}
        clean=picked(source,"Remove only this invocation's validated transient preview tools")
        clean['ansible.builtin.script']['cmd']=clean['ansible.builtin.script']['cmd'].replace('../files/pilot-wazuh-delivery',shlex.quote(str(cleanup)),1)
        release=picked(source,'Release only this exact writer after all mutators and recovery tasks have ended')
        release['ansible.builtin.script']['cmd']=release['ansible.builtin.script']['cmd'].replace('files/wazuh-transaction.py',shlex.quote(str(worker)),1)
        values={'wazuh_writer_owner':OWNER,'wazuh_writer_claimed':True,'wazuh_reader_operation':{'stdout':OP},
            'wazuh_preview_assets':{},'wazuh_preview_directory':{},'wazuh_preview_cleanup':{},'wazuh_preview_failed':False,
            'wazuh_preview_central_dispatched':False,'wazuh_preview_admit_dispatched':False,'wazuh_reader_preview_admit':{},
            'wazuh_docker_version':'4.14.9','docker_pre':{'rc':0},'pilot_wazuh_manager_preview_fresh':False,
            'siem_forwarding_enabled':True,'siem_forward_transport':'tcp','siem_forward_port':'514','siem_relp_port':20514,
            'siem_forward_host':'receiver.example','wazuh_receiver_bound_address':'192.0.2.15','wazuh_upgrade':False,
            'pilot_wazuh_manager_install_planned':True}
        if failure in ('replacement','original-and-replacement'):
            program="from pathlib import Path; import sys; p=Path(sys.argv[1]); p.rename(p.with_name(p.name+'-original')); p.mkdir(mode=0o700); (p/'FOREIGN').write_text('retain foreign replacement')"
            selected.append({'ansible.builtin.command':{'argv':['python3','-c',program,'{{ wazuh_preview_assets.path }}']},'check_mode':False,'tags':['always']})
            if failure=='original-and-replacement':selected.append({'ansible.builtin.fail':{'msg':'ORIGINAL_PREVIEW_SENTINEL'},'tags':['always']})
        final=picked(source,'Report unsettled transient scope without masking an earlier operation failure')
        probe=root/'desired-api.json'
        record={'ansible.builtin.copy':{'dest':str(probe),'mode':'0600','content':"{{ {'desired_api': (wazuh_reader_preview_admit.rc | default(0)) == 0, 'stale_api': 'unrecognized arguments' in (wazuh_reader_preview_admit.stderr | default(''))} | to_json }}"},'check_mode':False,'no_log':True,'tags':['always']}
        play=[{'hosts':'localhost','connection':'local','gather_facts':False,'vars':values,
            'tasks':[claim,{'block':selected,'rescue':[picked(source,"Retain the original Wazuh failure while settling transient preview ownership"),picked(source,"Surface the original Wazuh failure after its recorded task diagnostics")],'always':[record,clean,release,final]}]}]
        path=root/'play.yml';path.write_text(yaml.safe_dump(play,sort_keys=False))
        result=subprocess.run(['ansible-playbook','-i','localhost,',str(path),*(['--check'] if check else []),*(['--tags',tag] if tag!='all' else [])],
            cwd=REPO,capture_output=True,text=True,timeout=90,env=dict(os.environ,ANSIBLE_CONFIG=str(REPO/'ansible.cfg'),
                ANSIBLE_LOCAL_TEMP=str(root/'local'),ANSIBLE_REMOTE_TMP=str(root/'remote'),ANSIBLE_REMOTE_TEMP=str(root/'remote'),PYTHONDONTWRITEBYTECODE='1'))
        if probe.exists():self.assertFalse(json.loads(probe.read_text())['stale_api'],'DESIRED_PREVIEW_ADMIT_STALE_API')
        self.assertEqual(result.returncode,2 if failure else 0,(result.stdout,result.stderr))
        if check:self.assertEqual(before,snapshot(),'CHECK_MODE_DEPLOYED_ASSET_MUTATION')
        else:
            for name in NAMES:self.assertEqual((installed/name).read_bytes(),(REPO/'playbooks/files'/name).read_bytes())
        self.assertEqual(installed.exists(),not fresh or not check)
        if failure=='observer':
            self.assertEqual(len(list(run.iterdir())),1)
            self.assertEqual(json.loads((ledger/'writer-active.json').read_text())['owner'],OWNER)
            response=json.loads(next(root.glob('desired-api.json')).read_text()) if (root/'desired-api.json').exists() else {}
        elif failure in ('replacement','original-and-replacement'):
            scopes=list(run.iterdir());self.assertEqual(len(scopes),2)
            self.assertEqual(next(run.glob('*/FOREIGN')).read_text(),'retain foreign replacement')
            self.assertEqual(json.loads((ledger/'writer-active.json').read_text())['owner'],OWNER)
            if failure=='original-and-replacement':self.assertIn('ORIGINAL_PREVIEW_SENTINEL',result.stdout)
        else:
            self.assertFalse(list(run.iterdir()),'preview assets not cleaned before writer release')
            self.assertEqual((ledger/'writer-active.json').exists(),failure=='foreign-writer')
        events=(root/'events').read_text().splitlines()
        if check and not failure:
            self.assertIn('central',events)
            self.assertEqual('reader-enable-admit' in events,tag in ('all','C10','C11'))
        return result

    def test_actual_copy_temp_and_file_modules_preserve_warm_and_pristine_check(self):
        for tag,fresh in [('all',False),('C1',False),('C10',False),('C11',False),('C12',False),('all',True)]:
            with self.subTest(tag=tag,fresh=fresh),tempfile.TemporaryDirectory() as temporary:
                self.run_case(Path(temporary),tag=tag,fresh=fresh)

    def test_partial_stage_failure_cleans_owned_empty_scope_and_settles_writer(self):
        with tempfile.TemporaryDirectory() as temporary:self.run_case(Path(temporary),failure='copy')

    def test_readonly_checker_failure_cleans_scope_but_preserves_canonical_assets(self):
        with tempfile.TemporaryDirectory() as temporary:self.run_case(Path(temporary),failure='checker')

    def test_foreign_writer_refuses_before_real_copy_or_temp_creation(self):
        with tempfile.TemporaryDirectory() as temporary:self.run_case(Path(temporary),failure='foreign-writer')

    def test_foreign_replacement_retains_scope_owner_and_original_error(self):
        for failure in ('replacement','original-and-replacement'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:self.run_case(Path(temporary),failure=failure)

    def test_failed_dispatched_observer_retains_real_scope_and_writer(self):
        with tempfile.TemporaryDirectory() as temporary:self.run_case(Path(temporary),failure='observer')

    def test_normal_apply_deploys_exact_desired_helpers_after_real_writer_claim(self):
        with tempfile.TemporaryDirectory() as temporary:self.run_case(Path(temporary),check=False,fresh=True)


if __name__=='__main__':unittest.main(verbosity=2)
