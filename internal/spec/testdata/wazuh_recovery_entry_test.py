"""Whole production recovery callers with real journals/archives/files.

Only Docker/Compose/indexer and rsyslog account/software observations are native
models. No rollback, source, boundary, artifact, namespace or outcome guard is
replaced. This does not certify a VM, image payload, systemd or delivery.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import yaml
import wazuh_transaction_test as existing
w=existing.w


class Interrupted(BaseException):
    pass


def fixture(root, failure='partial', mode='disabled', retained=True):
    library=w
    managed=root/'managed';project=managed/'wazuh-docker-4.14.1/single-node'
    project.mkdir(parents=True)
    docker=root/'docker';volume=docker/'volumes/single-node_logs/_data';volume.mkdir(parents=True)
    document=volume/'document.json';document.write_text(json.dumps({'baseline':'old'}))
    (volume/'alerts/2026/Nov').mkdir(parents=True)
    (volume/'alerts/alerts.json').write_text('old alert\n')
    os.link(volume/'alerts/alerts.json',volume/'alerts/2026/Nov/dated.json')
    compose=project/'docker-compose.yml'
    def graph(release):
        return {'services':{service:{'image':'wazuh/'+service.replace('.','-')+':'+release}
                            for service in library.SERVICES}}
    compose.write_text(yaml.safe_dump(graph('4.14.1'),sort_keys=False))
    profile=root/'profile.json'
    if mode!='never':
        profile.write_text(json.dumps({'enabled':mode=='enabled','transport':'tcp','source':str(volume)}))
    spool=root/'spool'
    if retained and mode!='never':
        spool.mkdir(mode=0o700);(spool/'state').mkdir(mode=0o700)
        (spool/'state'/'native-offset').write_text('old offset')
        (spool/'wazuh_alerts.00000001').write_text('CURRENT retained queue')
    proc=root/'empty-proc';proc.mkdir()

    class Native:
        def __init__(self):
            self.release='4.14.1';self.present=set(library.SERVICES)
            self.running=set(library.SERVICES);self.failure=failure
            self.events=[];self.canary=None;self.foreign_volume=False
            self.foreign_consumer=False;self.cached_old=True;self.boundary_fail=False
            self.unit_calls=[];self.unit_process={'pid':1073741824,'start':'123','boot':'modeled-boot',
                'exe':'/usr/sbin/rsyslogd','argv':['/usr/sbin/rsyslogd','-n','-iNONE'],
                'executable_sha256':'a'*64,'uid':[102]*4,'gid':[104]*4,'mac':'rsyslogd(enforce)'}
            self.service={'ActiveState':'active','MainPID':'1073741824','InvocationID':'invocation-123',
                'ControlGroup':'/fixture','Result':'success','ExecMainCode':'0','ExecMainStatus':'0',
                'ExecMainStartTimestampMonotonic':'123','ExecMainExitTimestampMonotonic':'0',
                'ControlPID':'0','Job':''}
            self.socket={'ActiveState':'active','Job':'','Result':'success'}
            self.kernel=root/'unit-unix';self.kernel.write_text('Num RefCount Protocol Flags Type St Inode Path\n')

        def phase(self):
            item=central.active()
            return item['phase'] if item else 'idle'
        def event(self,kind,name):
            self.events.append((kind,name,self.phase()))
        def image(self,service,release):
            digit=str(library.SERVICES.index(service)+(1 if release=='4.14.1' else 4))
            identity='sha256:'+digit*64
            return {'Id':identity,'Size':1024,'RepoDigests':['wazuh/'+service.replace('.','-')+'@'+identity]}
        def config_hash(self,service,release):
            return hashlib.sha256(json.dumps(graph(release)['services'][service],sort_keys=True).encode()).hexdigest()
        def container(self,service):
            return {'Id':'container-'+service,'Image':self.image(service,self.release)['Id'],
                'State':{'Running':service in self.running},
                'Config':{'Image':'wazuh/'+service.replace('.','-')+':'+self.release,'Labels':{
                    'com.docker.compose.project':'single-node','com.docker.compose.service':service,
                    'com.docker.compose.project.working_dir':str(project),
                    'com.docker.compose.project.config_files':str(compose),
                    'com.docker.compose.config-hash':self.config_hash(service,self.release)}},
                'Mounts':[{'Type':'volume','Name':'single-node_logs','Source':str(volume),
                           'Destination':'/var/ossec/logs' if service=='wazuh.manager' else '/data'}]}
        def run(self,argv,**kwargs):
            argv=[str(value) for value in argv]
            if argv[:3]==['runuser','-u','syslog']:
                if Path(argv[-1])!=volume/'alerts/alerts.json' or not os.access(argv[-1],os.R_OK):
                    raise library.Refused('modeled native syslog source access failed')
                return subprocess.CompletedProcess(argv,0,'','')
            if argv[:2]==['/usr/local/libexec/pilot-wazuh-delivery','local']:
                if self.running!=set(library.SERVICES) or self.service['ActiveState']!='active':
                    raise library.Refused('modeled native local C11 unavailable')
                return subprocess.CompletedProcess(argv,0,'native local C11 leaf','')
            if argv[0]!='docker':
                if argv[0] not in ('du','tar'):
                    raise AssertionError('undeclared controller native command '+repr(argv))
                return library.Runner().run(argv,**kwargs)
            text=''
            if argv[1]=='info':text=str(docker)
            elif argv[1]=='ps':
                selected=set(self.present)
                if 'label=com.docker.compose.service=wazuh.manager' in argv:selected &= {'wazuh.manager'}
                text='\n'.join('container-'+service for service in sorted(selected))
                if self.foreign_consumer and any(value.startswith('volume=') for value in argv):
                    text+='\nforeign-container'
            elif argv[1:3]==['image','save']:
                destination=Path(argv[argv.index('--output')+1])
                with tarfile.open(destination,'x') as output:
                    payload=b'explicit synthetic native image archive'
                    member=tarfile.TarInfo('modeled-image');member.size=len(payload)
                    output.addfile(member,io.BytesIO(payload))
            elif argv[1:3]==['image','load']:
                self.event('effect','image-load');self.cached_old=True
            elif argv[1:3]==['image','tag']:
                if not self.cached_old:raise AssertionError('old image required before retained image load')
            elif argv[1]=='pull':pass
            elif argv[1]=='compose':
                if 'config' in argv:
                    value=yaml.safe_load(kwargs['input'])
                    service=argv[-1]
                    text=service+' '+hashlib.sha256(json.dumps(value['services'][service],sort_keys=True).encode()).hexdigest()
                elif 'stop' in argv:
                    self.event('effect','compose-stop');self.running.clear()
                elif 'up' in argv:
                    release=yaml.safe_load(compose.read_text())['services']['wazuh.manager']['image'].rsplit(':',1)[1]
                    self.event('effect','compose-up-'+release)
                    if release=='4.14.9' and self.failure:
                        self.present.clear();self.running.clear();self.release=release
                        document.write_text(json.dumps({'baseline':'target-only'}))
                        if self.failure=='interrupt':raise Interrupted('controller lost after partial replacement')
                        raise library.Refused('native Compose removed manager before target creation failed')
                    self.release=release;self.present=set(library.SERVICES);self.running=set(library.SERVICES)
            elif argv[1]=='stop':
                self.event('effect','stop');self.running.clear()
            elif argv[1]=='rm':
                self.event('effect','remove');self.present.clear()
            elif argv[1]=='exec':
                if argv[-1]=='info':text='WAZUH_VERSION="v'+self.release+'"\n'
                elif argv[-1]=='status':
                    text='\n'.join('wazuh-'+name+' is running...' for name in
                        ('modulesd','logcollector','remoted','analysisd','execd','db','authd','apid'))
                    text+='\nwazuh-clusterd not running...\n'
                    return subprocess.CompletedProcess(argv,1,text,'')
                elif argv[-1]=='-l':text='   ID: 001, Name: retained-agent, IP: any, Active\n'
                elif '-i' in argv and 'agent_control' in argv[-3]:
                    text='Agent ID: 001\nClient version: Wazuh v4.14.9\n'
                elif '-i' in argv and kwargs.get('input'):
                    if self.running!=set(library.SERVICES):raise AssertionError('canary before restored availability')
                    self.canary={'full_log':kwargs['input'],'rule':{'id':'5760'},'agent':{'id':'000'}}
                    self.event('native-proof','canary')
                else:raise AssertionError('undeclared Docker command '+repr(argv))
            else:raise AssertionError('undeclared Docker command '+repr(argv))
            return subprocess.CompletedProcess(argv,0,text,'')
        def json(self,argv,**kwargs):
            argv=[str(value) for value in argv]
            if argv[1:3]==['compose','--project-name']:
                return yaml.safe_load(kwargs['input'])
            if argv[1]=='inspect':
                requested=argv[2:]
                return [self.container(service) for service in library.SERVICES if service in self.present
                    and ('container-'+service in requested or 'single-node-'+service+'-1' in requested)]
            if argv[1:3]==['image','inspect']:
                value=argv[-1]
                for release in ('4.14.1','4.14.9'):
                    for service in library.SERVICES:
                        info=self.image(service,release)
                        if value in (info['Id'],'wazuh/'+service.replace('.','-')+':'+release):
                            if release=='4.14.1' and not self.cached_old:raise AssertionError('uncached old image queried before load')
                            return [info]
                raise AssertionError(value)
            if argv[1:3]==['volume','inspect']:
                return [{'Driver':'foreign' if self.foreign_volume else 'local','Options':None,
                    'Labels':{'com.docker.compose.project':'single-node'},'Mountpoint':str(volume)}]
            if 'curl' in argv:
                url=argv[-1]
                if '_cluster' in url:return {'status':'green'}
                if 'size=1&sort=' in url:
                    return {'hits':{'hits':[{'_index':'alerts','_id':'old','_source':json.loads(document.read_text())}]}}
                if '/_doc/' in url:return {'_source':json.loads(document.read_text())}
                return {'hits':{'hits':[{'_index':'alerts','_id':'canary','_source':self.canary}]}}
            if argv[-1] in ('/usr/share/wazuh-dashboard/plugins/wazuh/package.json','/usr/share/wazuh-indexer/VERSION.json'):
                return {'version':self.release}
            raise AssertionError('undeclared native JSON '+repr(argv))


    def unit_model(native):
        """Actual StopProof with explicit native properties/private namespaces."""
        class Systemd:
            def run(self,argv,**kwargs):
                assert argv==['systemctl','stop','--no-block','syslog.socket','rsyslog.service']
                native.unit_calls.append(('systemctl-stop',True))
                native.service.update(ActiveState='inactive',MainPID='0',ExecMainCode='1',
                    ExecMainStatus='0',ExecMainExitTimestampMonotonic=str(int(native.unit_process['start'])+1))
                native.socket['ActiveState']='inactive'
                return subprocess.CompletedProcess(argv,0,'','')
        units=library.ReaderUnits(Systemd())
        units.show=lambda name:native.service if name==units.SERVICE else native.socket
        units.process=lambda pid:dict(native.unit_process)
        units.boundary=lambda proof:None  # immutable native policy/software leaf
        def proof():
            return {'process':dict(native.unit_process),'invocation':native.service['InvocationID'],
                'start_monotonic':native.service['ExecMainStartTimestampMonotonic'],
                'cgroup':'/fixture','units':{'native-policy':'unchanged'},'fragments':{}}
        units.admit=proof
        actual_stop=units.stop
        def stop(value,requested=False):
            native.unit_calls.append(('stop-proof',requested))
            original=library.Path
            def paths(value):
                if str(value)=='/proc/net/unix':return native.kernel
                if str(value)=='/proc':return proc
                if str(value)=='/sys/fs/cgroup':return root/'empty-cgroup'
                return original(value)
            with mock.patch.object(library,'Path',paths):
                result=actual_stop(value,requested=requested)
            if central.interrupt=='after-stop':
                central.interrupt=None;raise Interrupted('after exact stop before durable stopped phase')
            return result
        units.stop=stop
        def start(value):
            native.unit_process['pid']+=1
            stamp=str(int(native.unit_process['start'])+2);native.unit_process['start']=stamp
            native.service.update(ActiveState='active',MainPID=str(native.unit_process['pid']),
                InvocationID='invocation-'+stamp,ExecMainStartTimestampMonotonic=stamp,
                ExecMainExitTimestampMonotonic='0',ExecMainCode='0',ExecMainStatus='0',Job='')
            native.socket.update(ActiveState='active',Job='')
            return dict(native.unit_process)
        units.start=start  # declared qualified native start observation leaf
        return units

    class Central(library.Central):
        def __init__(self):
            super().__init__(root=root/'private',managed_root=managed,runner=Native())
            self.interrupt=None;self.stopping_count=0
        def make_reader(self,checker_hash='',request=None,ack=False):
            reader=library.Reader(self,checker_hash,request,ack)
            reader.PROFILE=profile;reader.SPOOL=spool;reader.CONFIG=root/'absent-owned-config';reader.PROC=proc
            def observe(loaded=True):
                self.r.event('observe','reader-'+('loaded' if loaded else 'cold'))
                if self.r.boundary_fail:raise library.Refused('native reader observation unavailable')
                value={'schema':2,'mode_candidate':mode,'files':{},'profile':None,'pid':0,
                       'resources':[],'authorization':'UNVALIDATED_OBSERVATIONS'}
                if mode!='never':
                    value.update(files={str(profile):library.digest(profile)},profile=json.loads(profile.read_text()),
                                 profile_sha256=library.digest(profile))
                if mode=='enabled':value['pid']=int(self.r.service['MainPID'])
                return value
            reader.observe=observe
            # Declared native software/account facts, not custody authority.
            reader.qualify=lambda baseline:{'engine':'explicit native software identity leaf'}
            if mode=='enabled':
                reader.units=unit_model(self.r)
                reader.verify_tools=lambda:None  # native installed-tool identity leaf
                def fds(pid,source,drained=False):
                    info=(Path(source)/'alerts/alerts.json').stat()
                    return [{'device':info.st_dev,'inode':info.st_ino,'size':info.st_size,'position':info.st_size}]
                reader.fds=fds

            return reader
        def write(self,item,phase):
            if phase=='stopping':self.stopping_count+=1
            if self.interrupt=='before-intent' and phase=='recovering':
                self.interrupt=None;raise Interrupted('before recovery intent')
            super().write(item,phase)
            self.r.events.append(('write',phase,phase))
            if 'reader' in item:self.r.events.append(('reader-state',item['reader']['phase'],phase))
            if self.interrupt in ('exposure','stop-intent') and item.get('reader',{}).get('phase')==(
                    'exposure-intent' if self.interrupt=='exposure' else 'reader-stop-intent'):
                self.interrupt=None;raise Interrupted('after durable reader effect intent')

            if self.interrupt=='after-intent' and phase=='recovering':
                self.interrupt=None;raise Interrupted('after recovery intent')
            if self.interrupt=='stopping' and phase=='stopping' and self.stopping_count==2:
                self.interrupt=None;raise Interrupted('incomplete archives before switch')
            if self.interrupt=='committed' and phase=='committed':
                self.interrupt=None;raise Interrupted('after durable finalization')
        def restore(self,*args,**kwargs):
            self.r.event('effect','restore')
            return super().restore(*args,**kwargs)
    central=Central()
    return central,document,compose,spool


class RecoveryEntryTests(unittest.TestCase):
    OWNER='1'*32
    def create(self,root,failure='partial',mode='disabled',retained=True):
        user=type('NativeUser',(),{'pw_uid':os.geteuid()})()
        group=type('NativeGroup',(),{'gr_gid':os.getegid()})()
        self.enterContext(mock.patch.object(w.pwd,'getpwnam',return_value=user))
        self.enterContext(mock.patch.object(w.grp,'getgrnam',return_value=group))
        central,document,compose,spool=fixture(root,failure,mode,retained)
        # Production has one installed constant path; this private filesystem
        # seam covers receipts instantiated independently during finalization.
        self.enterContext(mock.patch.object(w.Reader,'SPOOL',spool))
        self.enterContext(mock.patch.object(w.Reader,'PROFILE',root/'profile.json'))
        w.HostWriter(central.root).claim(self.OWNER,'central')
        return central,document,compose,spool
    def prepare(self,root,mode='disabled',retained=True):
        central,document,compose,spool=self.create(root,'interrupt',mode,retained)
        with self.assertRaises(Interrupted):
            central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
        self.assertEqual(central.active()['phase'],'switching')
        self.assertFalse(central.r.present)
        return central,document,compose,spool
    def assert_restored(self,central,document,compose,spool):
        self.assertIsNone(central.active())
        self.assertEqual(json.loads(document.read_text()),{'baseline':'old'})
        self.assertIn(':4.14.1',compose.read_text());self.assertNotIn(':4.14.9',compose.read_text())
        self.assertEqual(central.discover()['version'],'4.14.1')
        manifest=json.loads(next(central.root.glob('central-*/manifest.json')).read_text())
        self.assertEqual(manifest['outcome']['outcome'],'restored_preexisting_incompatible_baseline')
        self.assertFalse(manifest['outcome']['overall_success']);self.assertFalse(manifest['outcome']['c12_pass'])
        if spool.exists():
            self.assertEqual((spool/'wazuh_alerts.00000001').read_text(),'CURRENT retained queue')
        self.assertEqual((central.root/'reader-replay-pending.json').exists(),
                         manifest['reader']['mode']=='disabled' and spool.exists())
        effects=[entry for entry in central.r.events if entry[0]=='effect']
        self.assertTrue(all(entry[2]=='recovering' for entry in effects if entry[1] in ('image-load','restore')))
        w.HostWriter(central.root).release(self.OWNER)

    def test_automatic_execute_partial_compose_failure_restores_old_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,document,compose,spool=self.create(Path(temporary))
            with self.assertRaisesRegex(w.Refused,'previous images, data and availability recovered'):
                central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
            self.assert_restored(central,document,compose,spool)

    def test_all_cold_phases_modes_partial_subset_uncached_images_and_absent_root(self):
        for phase in ('backed-up','switching','validating','recovering'):
            for mode in ('apply','recover'):
                with self.subTest(phase=phase,mode=mode),tempfile.TemporaryDirectory() as temporary:
                    central,document,compose,spool=self.prepare(Path(temporary))
                    item=central.active();central.write(item,phase)
                    central.r.present={'wazuh.indexer','wazuh.dashboard'}
                    central.r.running=set(central.r.present);central.r.cached_old=False
                    if phase=='recovering':
                        import shutil
                        shutil.rmtree(document.parent)
                    start=len(central.r.events)
                    if mode=='recover':
                        w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
                        result=central.execute('4.14.9',recover=True,owner=self.OWNER)
                        self.assertTrue(result['recovered']);self.assertFalse(result['c12_pass'])
                    else:
                        with central.lock(owner=self.OWNER):central.rollback(central.active())
                    trace=central.r.events[start:]
                    intent=next(i for i,event in enumerate(trace) if event[:2]==('write','recovering'))
                    observe=next(i for i,event in enumerate(trace) if event[0]=='observe')
                    self.assertLess(intent,observe)
                    self.assert_restored(central,document,compose,spool)


    def test_never_and_disabled_without_spool_whole_callers_do_not_invent_data(self):
        for mode in ('never','disabled'):
            for explicit in (False,True):
                with self.subTest(mode=mode,explicit=explicit),tempfile.TemporaryDirectory() as temporary:
                    if explicit:
                        central,document,compose,spool=self.prepare(Path(temporary),mode,False)
                        w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
                        central.execute('4.14.9',recover=True,owner=self.OWNER)
                    else:
                        central,document,compose,spool=self.create(Path(temporary),'partial',mode,False)
                        with self.assertRaisesRegex(w.Refused,'previous images, data and availability recovered'):
                            central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
                    manifest=json.loads(next(central.root.glob('central-*/manifest.json')).read_text())
                    self.assertEqual(manifest['reader']['checkpoints'],[])
                    self.assertIsNone(manifest['reader']['generation'])
                    self.assertFalse(spool.exists())
                    self.assert_restored(central,document,compose,spool)
        with tempfile.TemporaryDirectory() as temporary:
            central,_,_,spool=self.prepare(Path(temporary),'never',False)
            spool.mkdir();foreign=spool/'foreign';foreign.write_text('do not adopt')
            start=len(central.r.events)
            with self.assertRaisesRegex(w.Refused,'never configured'):
                with central.lock(owner=self.OWNER):central.rollback(central.active())
            self.assertEqual(central.active()['phase'],'recovering')
            self.assertFalse(any(event[0]=='effect' for event in central.r.events[start:]))
            self.assertEqual(foreign.read_text(),'do not adopt')

    def test_enabled_prestart_exposure_requires_exact_original_stop_proof(self):
        for fault in (None,'new-invocation','bad-exit','job','socket'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                central,document,compose,spool=self.create(Path(temporary),None,'enabled')
                central.interrupt='exposure'
                with self.assertRaises(Interrupted):
                    central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
                item=central.active()
                self.assertEqual(item['phase'],'switching')
                self.assertEqual(item['reader']['phase'],'exposure-intent')
                self.assertEqual(central.r.service['ActiveState'],'inactive')
                central.r.present.clear();central.r.running.clear()
                if fault=='new-invocation':
                    central.r.service.update(InvocationID='foreign',ExecMainStartTimestampMonotonic='999',
                                             ExecMainExitTimestampMonotonic='1000')
                elif fault=='bad-exit':central.r.service.update(ExecMainCode='2',ExecMainStatus='9')
                elif fault=='job':central.r.socket['Job']='42'
                elif fault=='socket':
                    central.r.kernel.write_text('Num RefCount Protocol Flags Type St Inode Path\n1: 1 0 00000000 0002 01 209 /run/systemd/journal/syslog\n')
                start=len(central.r.events);cycle=item['reader']['cycle']
                w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
                if fault:
                    with self.assertRaises(w.Refused):central.execute('4.14.9',recover=True,owner=self.OWNER)
                    current=central.active()
                    self.assertEqual(current['phase'],'recovering')
                    self.assertEqual(current['reader']['phase'],'exposure-intent')
                    self.assertEqual(current['reader']['cycle'],cycle)
                    self.assertFalse(any(event[:2]==('effect','restore') for event in central.r.events[start:]))
                    self.assertEqual(central.r.unit_calls[-1],('stop-proof',True))
                else:
                    central.execute('4.14.9',recover=True,owner=self.OWNER)
                    self.assertIn(('stop-proof',True),central.r.unit_calls)
                    self.assert_restored(central,document,compose,spool)

    def test_recorded_stop_intent_reconciles_active_inactive_and_rejects_unknown(self):
        for state in ('active','inactive','unknown'):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as temporary:
                central,_,_,_=self.create(Path(temporary),None,'enabled')
                central.interrupt='after-stop' if state=='inactive' else 'stop-intent'
                with self.assertRaises(Interrupted):
                    central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
                item=central.active()
                self.assertEqual(item['phase'],'stopping')
                self.assertEqual(item['reader']['phase'],'reader-stop-intent')
                if state=='unknown':central.r.unit_process['start']='foreign'
                start=len(central.r.events);requests=len(central.r.unit_calls)
                with central.lock(owner=self.OWNER):
                    if state=='unknown':
                        with self.assertRaisesRegex(w.Refused,'invocation changed'):
                            central.reader.pause(item)
                    else:central.reader.pause(item)
                trace=central.r.events[start:]
                self.assertNotIn(('reader-state','drained','stopping'),trace,'recorded stop intent must not rewind')
                if state=='unknown':
                    self.assertEqual(central.active()['reader']['phase'],'reader-stop-intent')
                    self.assertEqual(len(central.r.unit_calls),requests)
                else:
                    self.assertEqual(central.active()['reader']['phase'],'queue-sealed')
                    self.assertIn(('stop-proof',True),central.r.unit_calls[requests:])


    def test_narrow_reentry_does_not_authorize_other_modes_or_forged_substate(self):
        import copy
        for mode in ('disabled','enabled','never'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                central,_,_,_=self.prepare(Path(temporary),mode,mode!='never')
                central.interrupt='after-intent'
                with self.assertRaises(Interrupted):
                    with central.lock(owner=self.OWNER):central.rollback(central.active())
                item=central.active()
                self.assertEqual(item['phase'],'recovering')
                if mode!='disabled':
                    with self.assertRaisesRegex(w.Refused,'phase cannot grant'):
                        central.reader.write(item,'queue-sealed')
                # Forged in-memory mode/substate is a negative control only;
                # its genuine durable journal must never authorize that edge.
                forged=copy.deepcopy(item)
                forged['reader'].update(mode='enabled',phase='exposure-intent')
                with self.assertRaisesRegex(w.Refused,'matching durable recovery context'):
                    central.reader.write(forged,'reader-stopped')
                self.assertEqual(central.active()['reader']['phase'],'producers-start-intent')

    def test_bad_later_archive_image_owner_writer_backup_and_volume_never_grant(self):
        for fault in ('late-archive','image','owner','writer-owner','component','mode','backup','volume','consumer','memory-phase','missing-journal'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                central,document,compose,spool=self.prepare(Path(temporary));item=central.active()
                if fault=='late-archive':Path(item['archives'][-1]['archive']).write_bytes(b'corrupt')
                elif fault=='image':Path(item['image_archive']['path']).write_bytes(b'corrupt')
                elif fault=='owner':item['owner']='2'*32
                elif fault=='writer-owner':w.atomic_json(w.HostWriter(central.root).path,{'owner':'2'*32,'component':'central','mode':'apply'})
                elif fault=='component':w.atomic_json(w.HostWriter(central.root).path,{'owner':self.OWNER,'component':'agent','mode':'apply'})
                elif fault=='mode':w.atomic_json(w.HostWriter(central.root).path,{'owner':self.OWNER,'component':'central','mode':'canary'})
                elif fault=='backup':item['backup']=str(central.root/'foreign')
                elif fault=='volume':central.r.foreign_volume=True
                elif fault=='consumer':central.r.foreign_consumer=True
                elif fault=='missing-journal':w.durable_unlink(central.path)
                else:
                    durable=central.active();central.write(durable,'stopping');item['phase']='switching'
                start=len(central.r.events);prior=central.active()['phase'] if central.active() else None
                with self.assertRaises(w.Refused):central.rollback(item)
                self.assertEqual(central.active()['phase'] if central.active() else None,prior)
                self.assertFalse(any(event[0] in ('effect','write') for event in central.r.events[start:]))
                self.assertEqual(json.loads(document.read_text()),{'baseline':'target-only'})

    def test_interruption_and_boundary_failure_retry_revalidates_durable_intent(self):
        for fault in ('before-intent','after-intent','boundary'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                central,document,compose,spool=self.prepare(Path(temporary))
                central.interrupt=fault if fault!='boundary' else None
                central.r.boundary_fail=fault=='boundary'
                with self.assertRaises(w.Refused if fault=='boundary' else Interrupted):
                    with central.lock(owner=self.OWNER):central.rollback(central.active())
                self.assertEqual(central.active()['phase'],'switching' if fault=='before-intent' else 'recovering')
                self.assertFalse(any(event[1]=='image-load' for event in central.r.events))
                central.r.boundary_fail=False
                w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
                central.execute('4.14.9',recover=True,owner=self.OWNER)
                self.assert_restored(central,document,compose,spool)

    def test_direct_earlier_source_and_restart_only_and_finalized_never_gain_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,_,_,_=self.prepare(Path(temporary))
            for phase in ('reserved','stopping','backed-up','switching','validating'):
                item=central.active();central.write(item,phase)
                with self.assertRaisesRegex(w.Refused,'owner or phase'):central.reader.source(item)
        for missing in (False,True):
            with self.subTest(restart_missing=missing),tempfile.TemporaryDirectory() as temporary:
                central,document,compose,spool=self.create(Path(temporary),None);central.interrupt='stopping'
                with self.assertRaises(Interrupted):
                    central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
                self.assertEqual(central.active()['phase'],'stopping')
                self.assertNotIn('archives',central.active())
                if missing:central.r.present.clear();central.r.running.clear()
                start=len(central.r.events)
                w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
                if missing:
                    with self.assertRaises(w.Refused):central.execute('4.14.9',recover=True,owner=self.OWNER)
                    self.assertEqual(central.active()['phase'],'stopping')
                else:
                    central.execute('4.14.9',recover=True,owner=self.OWNER)
                    self.assertIsNone(central.active())
                self.assertFalse(any(event[1] in ('image-load','restore') or event[:2]==('write','recovering')
                                     for event in central.r.events[start:]))
        with tempfile.TemporaryDirectory() as temporary:
            central,_,_,_=self.create(Path(temporary),None);central.interrupt='committed'
            with self.assertRaises(Interrupted):
                central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
            self.assertEqual(central.active()['phase'],'committed')
            central.r.present.clear();central.r.running.clear();start=len(central.r.events)
            w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
            with self.assertRaises(w.Refused):central.execute('4.14.9',recover=True,owner=self.OWNER)
            self.assertEqual(central.active()['phase'],'committed')
            self.assertFalse(any(event[0] in ('effect','write') for event in central.r.events[start:]))


if __name__=='__main__':unittest.main()
