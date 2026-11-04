"""Reader custody controls: real files/tar/renames, declared native unit substitutes.

These do not certify systemd, native queue-save, Wazuh rotation or delivery.
The paired isolated native engine experiment and full candidate target evidence
are independently required.
"""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import wazuh_transaction_test as existing

w = existing.w


class Journal(w.Central):
    def __init__(self, root):
        super().__init__(root=root)
        self.events = []
    def write(self, item, phase):
        self.events.append((phase, (item.get('reader') or {}).get('phase')))
        super().write(item, phase)


class ReaderFilesystemTests(unittest.TestCase):
    def fixture(self, root):
        backup = root / 'private'
        central = Journal(backup)
        w.private_dir(backup)
        spool = root / 'spool'; spool.mkdir(mode=0o700)
        state = spool / 'state'; state.mkdir(mode=0o700)
        (state / 'imfile-state:123456').write_text('old cursor offset')
        queue = spool / 'wazuh_alerts.00000001'
        queue.write_bytes(b'OLD1\nTARGET2_AFTER_BACKUP\n')
        profile = root / 'profile.json'
        profile.write_text(json.dumps({'enabled':False,'source':str(root/'old-source'),'transport':'tcp'}))
        self.enterContext(mock.patch.object(w.Reader,'SPOOL',spool))
        self.enterContext(mock.patch.object(w.Reader,'PROFILE',profile))
        reader = w.Reader(central)
        reader.source_users=lambda *args,**kwargs:None  # native proc leaf, separately modeled below
        data = w.ReaderData(spool)
        try:
            baseline={'schema':1,'mode':'disabled','profile_sha256':w.digest(profile),'files':{},'profile':{'enabled':False},'pid':0}
            state_data={'schema':1,'mode':'disabled','phase':'producers-stopped','cycle':0,
                        'generation':None,'checkpoints':[],'checker_sha256':'','request':{},
                        'baseline':baseline,'source':str(root/'old-source'),'spool_identity':data.stamp,
                        'cursor_present':True,'cursor_identity':data.identity(state.stat()),
                        'queue_present':True,'ack':True}
        finally:
            data.close()
        item = central.begin('1'*32, {'reader':state_data})
        return central,reader,item,spool,queue,profile

    def test_current_queue_survives_real_old_source_restore_and_cursor_reset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); central,reader,item,spool,queue,_=self.fixture(root)
            source=root/'old-source';source.mkdir();(source/'alerts').write_bytes(b'OLD1\n')
            old=root/'old.tar'
            checksum=central.archive(source,old)
            reader.pause(item)
            checkpoint=copy.deepcopy(item['reader']['checkpoints'][-1])
            (source/'alerts').write_bytes(b'OLD1\nTARGET2_AFTER_BACKUP\n')
            central.restore(source,old,checksum)
            self.assertEqual((source/'alerts').read_bytes(),b'OLD1\n')
            item['reader']['data_epoch']='2'*32
            reader.retire_cursor(item)
            self.assertEqual(queue.read_bytes(),b'OLD1\nTARGET2_AFTER_BACKUP\n')
            self.assertEqual(list((spool/'state').iterdir()),[])
            self.assertEqual((spool/item['reader']['generation']['retired']/'imfile-state:123456').read_text(),'old cursor offset')
            reader.unchanged_queue(item)
            self.assertEqual(checkpoint['queue'],item['reader']['checkpoints'][-1]['queue'])
            self.assertEqual(checkpoint['kind'],'CURRENT_EVIDENCE_ONLY')
            self.assertIn(b'TARGET2_AFTER_BACKUP',(Path(checkpoint['evidence'])/queue.name).read_bytes())
            # A stale initial checkpoint cannot substitute for CURRENT.
            queue.write_bytes(b'OLD1\n')
            with self.assertRaisesRegex(w.Refused,'CURRENT reader queue changed'):
                reader.unchanged_queue(item)

    def test_cursor_rename_interruptions_reconcile_without_replaying_queue(self):
        for ordinal in (1,2):
            with self.subTest(rename=ordinal),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);central,reader,item,spool,queue,_=self.fixture(root)
                reader.pause(item);item['reader']['data_epoch']='2'*32
                original=w.os.rename;calls=[]
                def interrupted(*args,**kwargs):
                    result=original(*args,**kwargs);calls.append(args)
                    if len(calls)==ordinal:raise RuntimeError('controller interruption after actual rename')
                    return result
                with mock.patch.object(w.os,'rename',interrupted):
                    with self.assertRaises(RuntimeError):
                        reader.retire_cursor(item)
                durable=central.active()
                reader.retire_cursor(durable)
                generation=durable['reader']['generation']
                self.assertEqual(reader.use(durable)['phase'],'cursor-published')
                self.assertEqual(list((spool/'state').iterdir()),[])
                self.assertEqual(queue.read_bytes(),b'OLD1\nTARGET2_AFTER_BACKUP\n')
                self.assertEqual((spool/generation['retired']/'imfile-state:123456').read_text(),'old cursor offset')
                generation['exposed']=True
                (spool/'state'/'native-new-offset').write_text('new live cursor')
                reader.retire_cursor(durable)
                self.assertEqual((spool/'state'/'native-new-offset').read_text(),'new live cursor')

    def test_foreign_prepared_cursor_and_tampered_archive_never_gain_rename_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);central,reader,item,spool,_,_=self.fixture(root)
            reader.pause(item);item['reader']['data_epoch']='2'*32
            real=w.os.mkdir
            def stop_after_prepare(name,*args,**kwargs):
                result=real(name,*args,**kwargs)
                if str(name).startswith('.state-prepared-'):raise RuntimeError('interrupted before prepared identity')
                return result
            with mock.patch.object(w.os,'mkdir',stop_after_prepare):
                with self.assertRaises(RuntimeError):reader.retire_cursor(item)
            generation=item['reader']['generation']
            (spool/generation['prepared']/'FOREIGN').write_text('do not adopt')
            with self.assertRaisesRegex(w.Refused,'unknown prepared cursor'):
                reader.retire_cursor(item)
            self.assertTrue((spool/'state'/'imfile-state:123456').exists())
            self.assertTrue((spool/generation['prepared']/'FOREIGN').exists())
            (spool/generation['prepared']/'FOREIGN').unlink()
            Path(generation['archive']['path']).write_bytes(b'tampered')
            with self.assertRaisesRegex(w.Refused,'cursor archive changed'):
                reader.retire_cursor(item)
            self.assertTrue((spool/'state'/'imfile-state:123456').exists())

    def test_scope_hardlinks_symlinks_mount_and_namespace_swap_are_discriminating(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);_,reader,item,spool,queue,_=self.fixture(root)
            outside=root/'foreign';os.link(queue,outside)
            data=w.ReaderData(spool)
            try:
                with self.assertRaisesRegex(w.Refused,'alias'):data.queue()
                outside.unlink();queue.unlink();queue.symlink_to(outside)
                with self.assertRaises(OSError):data.queue()
                queue.unlink();queue.write_text('safe')
                renamed=root/'renamed';spool.rename(renamed);spool.mkdir()
                with self.assertRaisesRegex(w.Refused,'namespace changed'):data.namespace()
            finally:data.close()

    def test_disabled_receipt_precedes_finalize_and_new_local_ack_does_not_claim_remote_delivery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);central,reader,item,spool,queue,profile=self.fixture(root)
            reader.pause(item);item['reader']['data_epoch']='2'*32;reader.retire_cursor(item)
            reader.final(item)
            receipt=w.ReplayReceipt(central)
            self.assertEqual(receipt.inspect()['status'],'pending')
            self.assertIsNotNone(central.active(),'receipt is durable before active journal removal')
            central.finish(item,'recovered')
            owner='3'*32;operation='4'*32
            w.HostWriter(central.root).claim(owner,'central')
            with self.assertRaisesRegex(w.Refused,'new explicit acknowledgement'):
                receipt.operation(owner,operation,'admit')
            self.assertTrue(receipt.operation(owner,operation,'admit',ack=True)['pending'])
            receipt.operation(owner,operation,'expose')
            receipt.operation(owner,operation,'failed')
            self.assertTrue(receipt.inspect()['attempt']['exposed'])
            self.assertTrue(receipt.inspect()['attempt']['failed'])
            with self.assertRaisesRegex(w.Refused,'owner mismatch'):
                receipt.operation(owner,'5'*32,'complete')
            with self.assertRaisesRegex(w.Refused,'fresh acknowledged invocation'):
                receipt.operation(owner,operation,'complete')
            operation='6'*32
            # Native inspector/tool identity is a declared leaf substitute;
            # actual queue/generation/receipt/locks remain real throughout retry.
            self.enterContext(mock.patch.object(w.Reader,'inspect',lambda _: {
                'mode':'disabled','profile':{'source':str(root/'old-source')}}))
            self.enterContext(mock.patch.object(w.Reader,'verify_tools',lambda _:None))
            receipt.operation(owner,operation,'admit',ack=True)
            receipt.operation(owner,operation,'expose')
            # Native availability is an explicit leaf substitute; all receipt
            # ownership/custody/durability/queue operations above remain real.
            central.r=existing.Commands();receipt.r=central.r
            def run(argv,**kwargs):
                self.assertEqual(argv,['/usr/local/libexec/pilot-wazuh-delivery','local'])
                return subprocess.CompletedProcess(argv,0,'local proof','')
            with mock.patch.object(w.Reader,'verify_tools',lambda _:None),mock.patch.object(central.r,'run',run):
                receipt.operation(owner,operation,'verify')
                result=receipt.operation(owner,operation,'complete')
            self.assertFalse(result['remote_delivery_certified'])
            self.assertIsNone(receipt.inspect())
            history=central.root/('reader-replay-ack-'+operation+'.json')
            self.assertEqual(json.loads(history.read_text())['status'],'locally_acknowledged')
            self.assertEqual(queue.read_bytes(),b'OLD1\nTARGET2_AFTER_BACKUP\n')
            w.HostWriter(central.root).release(owner)

    def test_receipt_preview_and_pure_failure_have_no_other_generation_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);central,reader,item,_,_,_=self.fixture(root)
            reader.pause(item);item['reader']['data_epoch']='2'*32;reader.retire_cursor(item);reader.final(item)
            central.finish(item,'recovered');owner='3'*32;w.HostWriter(central.root).claim(owner,'central')
            receipt=w.ReplayReceipt(central);before=receipt.path.read_bytes()
            receipt.operation(owner,'4'*32,'admit',ack=True,preview=True)
            self.assertEqual(before,receipt.path.read_bytes())
            with self.assertRaisesRegex(w.Refused,'owner mismatch'):
                receipt.operation(owner,'4'*32,'failed')
            self.assertEqual(before,receipt.path.read_bytes())

    def test_pending_cold_custody_rejects_mutation_at_admit_expose_and_final_publish(self):
        changes = ('truncate', 'remove', 'rename', 'replace', 'symlink', 'hardlink')
        for stage in ('publish', 'admit', 'expose'):
            for change in changes:
                with self.subTest(stage=stage, change=change), tempfile.TemporaryDirectory() as temporary:
                    root=Path(temporary);central,reader,item,spool,queue,_=self.fixture(root)
                    reader.pause(item);item['reader']['data_epoch']='2'*32;reader.retire_cursor(item)
                    receipt=w.ReplayReceipt(central)
                    if stage != 'publish':
                        reader.final(item);central.finish(item,'recovered')
                        w.HostWriter(central.root).claim('3'*32,'central')
                        if stage == 'expose':
                            receipt.operation('3'*32,'4'*32,'admit',ack=True)
                    before=receipt.path.read_bytes() if receipt.path.exists() else None
                    if change=='truncate':queue.write_bytes(b'')
                    elif change=='remove':queue.unlink()
                    elif change=='rename':queue.rename(spool/'unrelated')
                    elif change=='replace':
                        payload=queue.read_bytes();queue.unlink();queue.write_bytes(payload)
                    elif change=='symlink':
                        queue.rename(root/'outside');queue.symlink_to(root/'outside')
                    else:os.link(queue,root/'outside')
                    with self.assertRaises((w.Refused,OSError)):
                        if stage=='publish':reader.final(item)
                        else:receipt.operation('3'*32,'4'*32,stage,ack=True)
                    self.assertEqual(receipt.path.read_bytes() if receipt.path.exists() else None,before)
                    self.assertEqual(list(central.root.glob('reader-replay-ack-*')),[])

    def test_cold_empty_and_absent_queue_and_live_consumed_retry_keep_generation(self):
        for mode in ('unchanged','empty','absent'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);central,reader,item,spool,queue,_=self.fixture(root)
                if mode=='empty':queue.write_bytes(b'')
                if mode=='absent':queue.unlink()
                reader.pause(item);item['reader']['data_epoch']='2'*32;reader.retire_cursor(item);reader.final(item)
                central.finish(item,'recovered');receipt=w.ReplayReceipt(central)
                owner='3'*32;operation='4'*32
                w.HostWriter(central.root).claim(owner,'central')
                receipt.operation(owner,operation,'admit',ack=True)
                receipt.operation(owner,operation,'expose');receipt.operation(owner,operation,'failed')
                generation=receipt.inspect()['generation']
                # Actual native consumption and new writes are allowed only
                # after durable exposure, under the same generation/provenance.
                if queue.exists():queue.unlink()
                (spool/'wazuh_alerts.00000002').write_bytes(b'new native queue')
                (spool/'state'/'imfile-state:456').write_text('new offset')
                w.HostWriter(central.root).release(owner);owner='5'*32
                w.HostWriter(central.root).claim(owner,'central')
                with mock.patch.object(w.Reader,'inspect',lambda _: {
                        'mode':'disabled','profile':{'source':str(root/'old-source')}}), \
                     mock.patch.object(w.Reader,'verify_tools',lambda _:None):
                    receipt.operation(owner,'6'*32,'admit',ack=True)
                    current=receipt.inspect()
                    self.assertTrue(current['ever_exposed'])
                    self.assertEqual(current['generation'],generation)
                    self.assertTrue(current['attempts'][0]['failed'])
                    receipt.operation(owner,'6'*32,'expose')
                    # Native C11 is a leaf substitute, not a queue validator.
                    with mock.patch.object(receipt.r,'run',return_value=subprocess.CompletedProcess([],0,'','')):
                        receipt.operation(owner,'6'*32,'verify')
                    receipt.operation(owner,'6'*32,'complete')
                history=json.loads((central.root/('reader-replay-ack-'+'6'*32+'.json')).read_text())
                self.assertTrue(history['ever_exposed'])
                self.assertEqual(history['generation'],generation)
                self.assertTrue((spool/'state'/'imfile-state:456').exists())

    def test_invalid_phase_never_grants_cursor_effect_and_all_phases_have_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);_,reader,item,spool,_,_=self.fixture(root)
            with self.assertRaisesRegex(w.Refused,'phase cannot grant'):
                reader.write(item,'cursor-publish-intent')
            self.assertTrue((spool/'state'/'imfile-state:123456').exists())
        self.assertEqual(set(w.READER_TRANSITIONS),w.READER_PHASES)
        self.assertTrue(all(set(next_phases)<=w.READER_PHASES for next_phases in w.READER_TRANSITIONS.values()))


class RepairOutcomeTests(unittest.TestCase):
    def test_original_skew_is_restored_honestly_without_permanent_owner_or_agent_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            central=existing.FakeCentral(Path(temporary),fail=True)
            central.command.agent_release='4.14.9'
            with self.assertRaisesRegex(w.Refused,'previous images, data and availability recovered'):
                central.execute('4.14.9',upgrade=True)
            self.assertIsNone(central.active())
            self.assertIsNone(w.HostWriter(central.root).inspect()['writer'])
            manifest=json.loads(next(central.root.glob('central-*/manifest.json')).read_text())
            self.assertEqual(manifest['outcome']['outcome'],'restored_preexisting_incompatible_baseline')
            self.assertFalse(manifest['outcome']['overall_success'])
            self.assertFalse(manifest['outcome']['c12_pass'])
            self.assertTrue(manifest['outcome']['restored_native_available'])
            self.assertEqual(central.command.agent_release,'4.14.9')
            self.assertIn('4.14.1',central.compose.read_text())

    def test_target_bound_unknown_and_newer_registry_still_refuse_before_stop(self):
        for release in ('4.14.10','unknown'):
            with self.subTest(release=release),tempfile.TemporaryDirectory() as temporary:
                central=existing.FakeCentral(Path(temporary));central.command.agent_release=release
                with self.assertRaises(w.Refused):central.execute('4.14.9',upgrade=True)
                self.assertFalse(any(args[0]=='stop' for _,args in central.calls))
                self.assertIsNone(central.active())




class SelectedReceiptGraphTests(unittest.TestCase):
    fixture = ReaderFilesystemTests.fixture
    # Reuse only fixture construction, not inherited test execution.
    def test_selected_ordinary_chokepoints_stop_before_config_or_activation(self):
        import shlex
        import yaml
        from wazuh_manager_script_args_test import picked
        source=yaml.safe_load((existing.REPO/'playbooks/apply/wazuh-manager-apply.yml').read_text())[0]
        forward=yaml.safe_load((existing.REPO/'playbooks/apply/tasks/wazuh-alert-forward.yml').read_text())
        expose=next(task for task in forward if task['name']=='Wazuh: durably record potential replay cursor exposure before activation')
        with tempfile.TemporaryDirectory(prefix='wazuh-receipt-graph-') as temporary:
            workspace=Path(temporary);plays=[];expectations=[]
            for tag,change in (('C10','before'),('C11','before'),('C12','before'),
                               ('C10','between'),('C11','between'),('C10','none')):
                root=workspace/(tag+change);root.mkdir()
                central,reader,item,spool,queue,profile=self.fixture(root)
                reader.pause(item);item['reader']['data_epoch']='2'*32
                reader.retire_cursor(item);reader.final(item);central.finish(item,'recovered')
                owner='3'*32;operation='4'*32;w.HostWriter(central.root).claim(owner,'central')
                receipt=w.ReplayReceipt(central);before=receipt.path.read_bytes()
                if change=='before':queue.unlink()
                events=root/'calls'
                worker=root/'worker.py'
                worker.write_text(
                    'import importlib.util,json,sys\nfrom pathlib import Path\n'
                    's=importlib.util.spec_from_file_location("product",'+repr(str(existing.REPO/'playbooks/apply/files/wazuh-transaction.py'))+')\n'
                    'w=importlib.util.module_from_spec(s);s.loader.exec_module(w)\n'
                    'w.Reader.SPOOL=Path('+repr(str(spool))+');w.Reader.PROFILE=Path('+repr(str(profile))+')\n'
                    'c=w.Central(root=Path('+repr(str(central.root))+'))\n'
                    'with open('+repr(str(events))+',"a") as f:f.write(sys.argv[1]+"\\n")\n'
                    'try:\n'
                    ' result=w.ReplayReceipt(c).operation('+repr(owner)+','+repr(operation)+',sys.argv[1].removeprefix("reader-enable-"),ack=True)\n'
                    ' print(json.dumps(result))\n'
                    'except w.Refused:\n print("typed custody refusal");sys.exit(2)\n')
                admit=picked(source,'Admit selected ordinary enable against any pending local replay receipt')
                expression=admit['ansible.builtin.command']['argv']
                admit['ansible.builtin.command']['argv']=expression.replace(
                    "'/usr/local/sbin/pilot-wazuh-transaction'", "'python3', "+repr(str(worker)))
                exposure=copy.deepcopy(expose)
                exposure['ansible.builtin.command']['argv']=['python3',str(worker)]+exposure['ansible.builtin.command']['argv'][1:]
                tasks=[picked(source,"Reset this play's actual forwarding selection"),
                       picked(source,'Mark selected forwarding intent without granting container authority'),admit]
                config_marker=root/'selected-config-mutation'
                tasks.append({'ansible.builtin.copy':{'dest':str(config_marker),'content':'selected','mode':'0600'},'tags':['C10','C11']})
                if change=='between':
                    tasks.append({'ansible.builtin.file':{'path':str(queue),'state':'absent'},'tags':['C10','C11']})
                exposure_file=root/'exposure.yml'
                exposure_file.write_text(yaml.safe_dump([exposure],sort_keys=False))
                include=picked(source,'Step 9c: Configure isolated host imfile forwarding')
                include['ansible.builtin.include_tasks']['file']=str(exposure_file)
                tasks.append(include)
                marker=root/'configuration-or-activation'
                tasks.append({'ansible.builtin.copy':{'dest':str(marker),'content':'selected','mode':'0600'},'tags':['C10','C11']})
                # Execute each actual selection separately, preserving no_log.
                play=workspace/(tag+change+'.yml')
                play.write_text(yaml.safe_dump([{'hosts':'localhost','connection':'local','gather_facts':False,
                    'vars':{'siem_forwarding_enabled':True,'pilot_wazuh_manager_preview_fresh':False,
                            'wazuh_writer_owner':owner,'wazuh_reader_operation':{'stdout':operation},
                            'wazuh_reader_enable_admitted':True,'wazuh_ack_rsyslog_downtime_and_replay':True},
                    'tasks':tasks}],sort_keys=False))
                run=subprocess.run(['ansible-playbook','-i','localhost,',str(play),'--tags',tag],
                    cwd=existing.REPO,capture_output=True,text=True,timeout=90,
                    env=dict(os.environ,ANSIBLE_CONFIG=str(existing.REPO/'ansible.cfg'),
                        ANSIBLE_CACHE_PLUGIN='memory',ANSIBLE_LOCAL_TEMP=str(root/'local'),
                        ANSIBLE_REMOTE_TEMP=str(root/'remote')))
                self.assertEqual(run.returncode,0 if change=='none' or tag=='C12' else 2,(tag,change,run.stdout,run.stderr))
                self.assertEqual(marker.exists(),change=='none')
                self.assertEqual(config_marker.exists(),change!='before')
                if change=='before':
                    self.assertEqual(receipt.path.read_bytes(),before)
                    self.assertEqual(events.exists(),tag!='C12')
                if change=='between':
                    self.assertFalse(receipt.inspect()['ever_exposed'])
                    self.assertEqual(events.read_text().splitlines(),['reader-enable-admit','reader-enable-expose'])
                self.assertEqual(list(central.root.glob('reader-replay-ack-*')),[])


class SelectedReceiverIdentityTests(unittest.TestCase):
    def test_numeric_pin_matches_bound_transport_not_raw_host_and_changes_refuse(self):
        for pin,desired,success in (
            ('192.0.2.15','192.0.2.15',True),
            ('2001:0db8:0:0:0:0:0:15','2001:db8::15',True),
            ('192.0.2.16','192.0.2.15',False),
            ('not-an-address','192.0.2.15',False),
            ('192.0.2.15 siem-log-server\n192.0.2.15','192.0.2.15',False),
        ):
            with self.subTest(pin=pin),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);central=Journal(root/'private')
                source=root/'source';source.mkdir()
                reader=w.Reader(central,request={'selected':True,'enabled':True,
                    'host':'receiver.example.test','address':desired,'port':514,'transport':'tcp'},ack=True)
                reader.SPOOL=root/'absent-spool'
                reader.inspect=lambda:{'mode':'enabled','pid':42,'files':{},'profile_sha256':'nativehash',
                    'profile':{'enabled':True,'source':str(source),'transport':'tcp'},'action':{'port':'514'}}
                reader.source=lambda _:str(source)
                reader.source_users=lambda *args,**kwargs:None
                reader.qualify=lambda _: {'engine':'native-leaf'}
                reader.verify_tools=lambda:None
                reader.units.admit=lambda: {'native':'unit-leaf'}
                original=Path.read_text
                def text(path,*args,**kwargs):
                    if str(path)=='/etc/hosts':return pin+' siem-log-server\n'
                    return original(path,*args,**kwargs)
                with mock.patch.object(Path,'read_text',text),mock.patch.object(reader.r,'run',
                        return_value=subprocess.CompletedProcess([],0,'native C11','')):
                    if success:self.assertEqual(reader.admit({'paths':[]})['mode'],'enabled')
                    else:
                        with self.assertRaisesRegex(w.Refused,'receiver address'):
                            reader.admit({'paths':[]})


class ReaderUnitOutcomeTests(unittest.TestCase):
    def model(self, root, outcome='graceful'):
        kernel=root/'unix';kernel.write_text('Num RefCount Protocol Flags Type St Inode Path\n')
        proc=root/'absent-process';cgroup=root/'absent-cgroup'
        properties={'LoadState':'loaded','ActiveState':'active','SubState':'running',
                    'MainPID':'1073741824','InvocationID':'native-invocation','ControlGroup':'/fixture',
                    'Result':'success','ExecMainCode':'0','ExecMainStatus':'0',
                    'ExecMainStartTimestampMonotonic':'123','ExecMainExitTimestampMonotonic':'0',
                    'ControlPID':'0','Job':''}
        service=properties.copy();socket=properties.copy()
        process={'pid':1073741824,'start':'123','boot':'boot','native_identity':'same'}
        proof={'process':process,'invocation':'native-invocation','start_monotonic':'123','cgroup':'/fixture'}
        class Native:
            calls=[]
            def run(self,argv,**kwargs):
                self.calls.append(argv)
                service.update(ActiveState='inactive',MainPID='0',ExecMainCode='1',ExecMainStatus='0',
                               ExecMainExitTimestampMonotonic='124')
                socket['ActiveState']='inactive'
                if outcome=='forced':service.update(ExecMainCode='2',ExecMainStatus='9')
                if outcome=='failed-result':service['Result']='timeout'
                if outcome=='job':socket['Job']='42'
                if outcome=='foreign-invocation':service['InvocationID']='foreign'
                if outcome=='start-drift':service['ExecMainStartTimestampMonotonic']='100'
                if outcome=='held-datagram':
                    kernel.write_text('Num RefCount Protocol Flags Type St Inode Path\n1: 1 0 00000000 0002 01 209 /run/systemd/journal/syslog\n')
                return subprocess.CompletedProcess(argv,0,'','')
        native=Native();native.calls=[]
        units=w.ReaderUnits(native)
        units.show=lambda unit:service if unit==units.SERVICE else socket
        units.process=lambda pid:process
        units.boundary=lambda _:None  # immutable policy is a separate admission control
        original_path=w.Path
        def paths(value):
            if str(value)=='/proc/net/unix':return kernel
            if str(value)=='/proc':return root/'empty-proc'
            if str(value)=='/sys/fs/cgroup':return root/'empty-cgroup'
            return original_path(value)
        return units,proof,native,paths

    def test_stop_rc_zero_does_not_replace_graceful_invocation_jobs_and_dgram_fd_proof(self):
        for outcome in ('graceful','forced','failed-result','job','foreign-invocation','start-drift','held-datagram'):
            with self.subTest(outcome=outcome),tempfile.TemporaryDirectory() as temporary:
                units,proof,native,paths=self.model(Path(temporary),outcome)
                with mock.patch.object(w,'Path',paths):
                    if outcome=='graceful':
                        self.assertTrue(units.stop(proof)['graceful'])
                    else:
                        with self.assertRaises(w.Refused):units.stop(proof)
                self.assertEqual(native.calls,[['systemctl','stop','--no-block','syslog.socket','rsyslog.service']])

    def test_same_owned_stop_intent_reconciles_before_or_after_request_without_unknown_signals(self):
        with tempfile.TemporaryDirectory() as temporary:
            units,proof,native,paths=self.model(Path(temporary))
            with mock.patch.object(w,'Path',paths):
                self.assertTrue(units.stop(proof,requested=True)['graceful'])
                count=len(native.calls)
                self.assertTrue(units.stop(proof,requested=True)['graceful'])
                self.assertEqual(len(native.calls),count,'already stopped invocation must not request blind stop')
            self.assertFalse(any('kill' in item for argv in native.calls for item in argv))


class EnabledReaderIntegrationTests(unittest.TestCase):
    def test_real_central_transaction_preserves_target_period_current_queue_and_retires_cursor(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            class Units:
                def __init__(self,central):
                    self.central=central;self.active=True;self.pid=100;self.events=[]
                def process(self,pid):return {'pid':self.pid,'executed':'declared-native-leaf'}
                def show(self,unit):
                    return {'ActiveState':'active' if self.active else 'inactive','MainPID':str(self.pid) if self.active else '0','Job':''}
                def admit(self):
                    if not self.active:raise w.Refused('native substitute inactive')
                    return {'process':self.process(self.pid),'units':{'fixed':'policy'},'fragments':{'fixed':'hash'}}
                def boundary(self,proof):pass
                def stop(self,proof,requested=False):
                    if self.central.producing:raise AssertionError('reader stopped before producers')
                    self.active=False;self.events.append('stop');return {'graceful':True}
                def start(self,proof):
                    if self.central.producing:raise AssertionError('producers started before reader')
                    self.active=True;self.pid+=1;self.events.append('start');return self.process(self.pid)
            class Native(existing.Commands):
                def run(self,argv,**kwargs):
                    if str(argv[0]) in ('/usr/local/libexec/pilot-wazuh-delivery','runuser'):
                        return subprocess.CompletedProcess(argv,0,'declared local native leaf','')
                    return super().run(argv,**kwargs)
            class ActualReader(w.Reader):
                def source_users(self,*args,**kwargs):pass
                def inspect(self):
                    return {'schema':1,'mode':'enabled','profile':{'enabled':True,'source':str(self.t.volume),'transport':'tcp'},
                            'profile_sha256':w.digest(self.PROFILE),'pid':self.units.pid if self.units.active else 0,
                            'action':{'port':'514','queue.type':'LinkedList'},
                            'files':{str(self.t.forward):w.digest(self.t.forward)}}
                def source(self,state):return str(self.t.volume)
                def qualify(self,baseline):return {'engine':'explicit-native-leaf'}
                def verify_tools(self):pass
                def fds(self,pid,source,drained=False):
                    info=(Path(source)/'alerts/alerts.json').stat()
                    return [{'device':info.st_dev,'inode':info.st_ino,'size':info.st_size,'position':info.st_size}]
            class Central(existing.FakeCentral):
                def __init__(self,workspace):
                    self.producing=True
                    super().__init__(workspace,fail=True)
                    self.command=Native();self.command.agent_release='4.14.9';self.r=self.command
                    self.spool=workspace/'spool';self.spool.mkdir(mode=0o700)
                    (self.spool/'state').mkdir(mode=0o700)
                    (self.spool/'state'/'native-offset').write_text('old cursor')
                    (self.spool/'wazuh_alerts.00000001').write_bytes(b'OLD1\n')
                    self.profile=workspace/'profile.json';self.profile.write_text('{"enabled":true}')
                    self.forward=workspace/'forward.conf';self.forward.write_text('native known profile fixture')
                    (self.volume/'alerts').mkdir()
                    (self.volume/'alerts/alerts.json').write_bytes(b'OLD1\n')
                    self.native_units=Units(self)
                def make_reader(self,checker_hash='',request=None,ack=False):
                    if not hasattr(self,'native_units'):return w.Reader(self)
                    reader=ActualReader(self,checker_hash,request,ack)
                    reader.SPOOL=self.spool;reader.PROFILE=self.profile;reader.units=self.native_units
                    return reader
                def compose_run(self,item,*args,**kwargs):
                    super().compose_run(item,*args,**kwargs)
                    if args[0]=='stop':self.producing=False
                    if args[0]=='up':
                        if not self.native_units.active:raise AssertionError('producer-before-reader')
                        self.producing=True
                        if item['phase']=='switching':
                            (self.volume/'alerts/alerts.json').write_bytes(b'OLD1\nTARGET2_AFTER_BACKUP\n')
                            with (self.spool/'wazuh_alerts.00000001').open('ab') as queue:queue.write(b'TARGET2_AFTER_BACKUP\n')
                def quiesce_for_restore(self,item,remove=True):
                    self.producing=False
                    super().quiesce_for_restore(item,remove)
            central=Central(root);owner='1'*32;w.HostWriter(central.root).claim(owner,'central')
            user=type('NativeUser',(),{'pw_uid':os.geteuid()})()
            group=type('NativeGroup',(),{'gr_gid':os.getegid()})()
            with mock.patch.object(w.pwd,'getpwnam',return_value=user),mock.patch.object(w.grp,'getgrnam',return_value=group):
                with self.assertRaisesRegex(w.Refused,'previous images, data and availability recovered'):
                    w.Central.execute(central,'4.14.9',upgrade=True,owner=owner,reader_ack=True)
            self.assertEqual(central.native_units.events,['stop','start','stop','start'])
            self.assertEqual((central.volume/'alerts/alerts.json').read_bytes(),b'OLD1\n')
            self.assertEqual((central.spool/'wazuh_alerts.00000001').read_bytes(),b'OLD1\nTARGET2_AFTER_BACKUP\n')
            self.assertEqual(list((central.spool/'state').iterdir()),[])
            manifest=json.loads(next(central.root.glob('central-*/manifest.json')).read_text())
            checkpoints=manifest['reader']['checkpoints']
            self.assertEqual(len(checkpoints),2)
            self.assertNotEqual(checkpoints[0]['queue'],checkpoints[1]['queue'])
            self.assertTrue(manifest['reader']['generation']['exposed'])
            self.assertEqual(manifest['outcome']['outcome'],'restored_preexisting_incompatible_baseline')
            self.assertIsNone(central.active())
            w.HostWriter(central.root).release(owner)



class ReaderPhysicalNamespaceTests(unittest.TestCase):
    def test_real_physical_aliases_absent_descendants_and_mountinfo_are_not_disjoint(self):
        import runpy
        helper=runpy.run_path(str(existing.REPO/'playbooks/files/pilot-wazuh-heartbeat'))
        classify=helper['reader_namespace']
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);managed=root/'managed';managed.mkdir()
            state=managed/'state';state.mkdir()
            other=root/'other';other.mkdir()
            self.assertTrue(classify(str(state),[managed]))
            self.assertTrue(classify(str(managed/'absent'/'state'),[managed]))
            self.assertFalse(classify(str(other),[managed]))
            self.assertFalse(classify(str(root),[managed]),'common parent alone grants no child access')
            for alias in (str(state)+'/.',str(managed)+'//state'):
                with self.assertRaisesRegex(ValueError,'noncanonical'):
                    classify(alias,[managed])
            link=root/'linked';link.symlink_to(managed,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'alias'):
                classify(str(link/'state'),[managed])
            source=managed/'source';source.write_text('owned')
            os.link(source,other/'foreign-name')
            with self.assertRaisesRegex(ValueError,'alias'):
                classify(str(other/'foreign-name'),[managed],pattern=True)
            with self.assertRaisesRegex(ValueError,'alias'):
                classify(str(other/'*'),[managed],pattern=True)
            original=Path.read_text
            def mountinfo(path,*args,**kwargs):
                if str(path)=='/proc/self/mountinfo':
                    return '1 0 8:1 /managed '+str(other)+' rw - ext4 /dev/test rw\n'
                return original(path,*args,**kwargs)
            with mock.patch.object(Path,'read_text',mountinfo):
                with self.assertRaisesRegex(ValueError,'subtree mount'):
                    classify(str(other/'missing-state'),[managed])


class ReaderInspectionTests(unittest.TestCase):
    def test_actual_include_graph_exclusivity_default_argv_and_readonly_mode(self):
        import runpy
        import types
        import hashlib
        helper=runpy.run_path(str(existing.REPO/'playbooks/files/pilot-wazuh-heartbeat'))
        inspect=helper['inspect_reader'];env=inspect.__globals__
        real_path=Path
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);parts=root/'rsyslog.d';parts.mkdir()
            global_config=root/'rsyslog.conf'
            owner=parts/'31-pilot-wazuh.conf'
            extra=parts/'90-operator.conf'
            profile_dir=parts/'pilot-wazuh';profile_dir.mkdir()
            profile=profile_dir/'profile.json'
            profile.write_text(json.dumps({'enabled':True,'transport':'tcp','source':'/native-source','heartbeat_interval':0}))
            global_config.write_text('$IncludeConfig '+str(parts/'*.conf')+'\n')
            owner.write_text(helper['HEADER']+'\n'
                'module(load="imfile" statefile.directory="/var/spool/rsyslog/pilot-wazuh/state")\n'
                'ruleset(name="pilotWazuhForward") {\n'
                'action(name="wazuh_alerts" type="omfwd" target="siem-log-server" port="514" '
                'queue.filename="wazuh_alerts" queue.spoolDirectory="/var/spool/rsyslog/pilot-wazuh" '
                'queue.type="LinkedList" queue.saveOnShutdown="on" queue.discardSeverity="8" '
                'queue.maxDiskSpace="256m" queue.size="10000")\n}\n'
                'input(type="imfile" File="/native-source/alerts/alerts.json" ruleset="pilotWazuhForward" '
                'PersistStateInterval="1" freshStartTail="off" reopenOnTruncate="on")\n')
            maps=root/'maps';maps.write_text('')
            argv=root/'cmdline';argv.write_bytes(b'/usr/sbin/rsyslogd\0-n\0-iNONE\0')
            def path(value,*parts):
                name=str(real_path(value,*parts))
                return {'/etc/rsyslog.conf':global_config,'/proc/42/maps':maps,
                        '/proc/42/cmdline':argv}.get(name,real_path(value,*parts))
            calls=[]
            def native(command,**kwargs):
                calls.append(command)
                if command[:2]==['systemctl','show']:
                    text='2030-01-01 00:00:00 UTC' if 'ActiveEnterTimestamp' in command else '42\n'
                elif command[0]=='date':text='1893456000.0\n'
                elif command[:2]==['rsyslogd','-N1']:text=''
                else:raise AssertionError('undeclared native call '+repr(command))
                return subprocess.CompletedProcess(command,0,text,'')
            original_stat=Path.stat
            def trusted_metadata(filename,*args,**kwargs):
                info=original_stat(filename,*args,**kwargs)
                # Explicit synthetic root-owned config fixture. Preserve real
                # inode/link/type/bytes; no chmod/chown on controller ancestors.
                attributes={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
                attributes['st_uid']=0;attributes['st_mode']=info.st_mode & ~0o022
                return types.SimpleNamespace(**attributes)
            env['OWNER']=owner
            env['pathlib']=types.SimpleNamespace(Path=path,PurePath=__import__('pathlib').PurePath)
            old_stat=Path.stat
            with mock.patch.object(Path,'stat',trusted_metadata),mock.patch.object(env['subprocess'],'run',native):
                before={str(filename):hashlib.sha256(filename.read_bytes()).hexdigest()
                        for filename in (global_config,owner,profile,argv,maps)}
                value=inspect()
                self.assertEqual(value['mode'],'enabled')
                self.assertIn(str(global_config),value['files'])
                self.assertIn(str(owner),value['files'])
                after={filename:hashlib.sha256(real_path(filename).read_bytes()).hexdigest() for filename in before}
                self.assertEqual(before,after,'inspect-reader wrote a configuration or state file')
                extra.write_text('input(type="imfile" File="/other-input" ruleset="foreign")\n')
                with self.assertRaisesRegex(ValueError,'exclusive owned imfile'):
                    inspect()
                extra.unlink()
                argv.write_bytes(b'/usr/sbin/rsyslogd\0-n\0-f\0/foreign.conf\0')
                with self.assertRaisesRegex(ValueError,'default-config selection'):
                    inspect()

                # Unknown legacy imfile declarations must never become an
                # apparently absent reader just because its FD is closed.
                argv.write_bytes(b'/usr/sbin/rsyslogd\0-n\0-iNONE\0')
                owner.unlink();profile.unlink()
                legacy_cases=[
                    '$ModLoad imfile\n$InputFileName /native-source/alerts/alerts.json\n$InputRunFileMonitor\n',
                    'module(load="imfile")\n$InputFileName /native-source/alerts/alerts.json\n$InputRunFileMonitor\n',
                    '$ModLoad /usr/lib/rsyslog/imfile.so\n',
                    '$InputFileBindRuleset other\n$InputFileStateFile old-cursor\n']
                for text in legacy_cases:
                    extra.write_text(text)
                    with self.assertRaisesRegex(ValueError,'legacy imfile'):
                        inspect()
                extra.write_text('$ModLoad imuxsock\n# $InputFileName /native-source/alerts/alerts.json\n'
                                 'set $.example = "$InputRunFileMonitor";\n')
                self.assertEqual(inspect()['mode'],'never','unrelated legacy module/comments/strings remain available')
                for declaration in (
                    'module(load="imfile" statefile.directory="/var/spool/rsyslog/pilot-wazuh/state/.")',
                    'module(load="imfile" statefile.directory="/var/spool//rsyslog/pilot-wazuh/state")',
                    'action(type="omfwd" queue.spoolDirectory="/var/spool/rsyslog/pilot-wazuh/.")',
                    'module(load="imfile" statefile.directory="relative/state")',
                    'input(type="imfile" File="$dynamic")',
                    'action(type="omfwd" queue.filename="../pilot-wazuh/wazuh_alerts")',
                    'action(type="omfwd" queue.filename="$dynamic")',

                ):
                    extra.write_text(declaration+'\n')
                    with self.assertRaisesRegex(ValueError,'namespace'):
                        inspect()
                extra.write_text('module(load="imfile" statefile.directory="/unrelated-state")\n'
                                 'input(type="imfile" File="/unrelated-source/*.json")\n')
                self.assertEqual(inspect()['mode'],'never')
                extra.write_text('module(load="imfile" statefile.directory="/unrelated-state")\n'
                                 'input(type="imfile" File="/unrelated-source/*.json")\n'
                                 'action(type="omfwd" queue.filename="foreign" queue.spoolDirectory="/var/spool/rsyslog")\n')
                self.assertEqual(inspect()['mode'],'never','shared parent plus disjoint native queue basename is not ownership')
                profile.write_text(json.dumps({'enabled':False,'transport':'tcp','source':'/native-source'}))
                self.assertEqual(inspect()['mode'],'disabled')

            self.assertTrue(all(command[0] in ('systemctl','date','rsyslogd') for command in calls))
            self.assertFalse(any(item in ('start','stop','restart','reload') for command in calls for item in command))


class SourceProcessClosureTests(unittest.TestCase):
    def test_unknown_source_fds_and_other_readers_refuse_without_stopping_unrelated_daemon(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source=root/'source';source.mkdir();data=source/'alerts.json';data.write_text('old data')
            proc=root/'proc';proc.mkdir()
            def process(pid,exe,cgroup='',opened=False):
                folder=proc/str(pid);(folder/'fd').mkdir(parents=True)
                (folder/'exe').symlink_to(exe);(folder/'cgroup').write_text(cgroup)
                if opened:(folder/'fd/5').symlink_to(data)
                return folder
            canonical=process(101,'/usr/sbin/rsyslogd',opened=True)
            central=Journal(root/'private');reader=w.Reader(central);reader.PROC=proc
            state={'images':{'wazuh.manager':{'container':'a'*64}}}
            reader.source_users(state,source,101)
            with self.assertRaisesRegex(w.Refused,'unowned process'):
                reader.source_users(state,source,101,reader_fds=False)
            (canonical/'fd/5').unlink()
            # Never/disabled does not stop or reject unrelated canonical
            # syslog merely because it owns the shared activation socket.
            reader.source_users(state,source,101,reader_fds=False)
            other=process(102,'/usr/bin/tail',opened=True)
            with self.assertRaisesRegex(w.Refused,'unowned process'):
                reader.source_users(state,source,101)
            (other/'fd/5').unlink();(other/'exe').unlink();(other/'exe').symlink_to('/usr/sbin/rsyslogd')
            with self.assertRaisesRegex(w.Refused,'additional native reader'):
                reader.source_users(state,source,101)
            (other/'exe').unlink();(other/'exe').symlink_to('/usr/bin/tail')
            owned=process(103,'/var/ossec/bin/wazuh-analysisd',
                          '0::/system.slice/docker-'+'a'*64+'.scope\n',opened=True)
            reader.source_users(state,source,101,producers=True)
            (owned/'cgroup').write_text('0::/system.slice/docker-'+'a'*64+'.scope-foreign\n')
            with self.assertRaisesRegex(w.Refused,'unowned process'):
                reader.source_users(state,source,101,producers=True)
            (owned/'cgroup').write_text('0::/system.slice/docker-'+'a'*64+'.scope\n')
            with self.assertRaisesRegex(w.Refused,'unowned process'):
                reader.source_users(state,source,101,producers=False)
            self.assertEqual(data.read_text(),'old data')

if __name__=='__main__':unittest.main(verbosity=2)
