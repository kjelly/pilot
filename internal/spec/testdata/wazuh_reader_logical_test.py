"""RV18 logical handoff controls, independent of kernel read-ahead offsets.

Real filesystem/proc FDs, native-shaped state and actual private journals/callers
are used. Docker and systemd leaves in recovery.fixture are explicit models;
these tests do not certify native queue save, service/MAC or delivery.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import wazuh_transaction_test as existing
import wazuh_reader_model as model
import wazuh_recovery_entry_test as recovery
w=existing.w


class CursorTests(unittest.TestCase):
    def fixture(self, root, content=b'x'*700+b'\n'):
        source=root/'source';(source/'alerts/2026/Nov').mkdir(parents=True)
        current=source/'alerts/alerts.json';current.write_bytes(content)
        os.link(current,source/'alerts/2026/Nov/current.json')
        spool=root/'spool';spool.mkdir(mode=0o700);(spool/'state').mkdir(mode=0o700)
        state=model.cursor(spool,source)
        return source,spool,state
    def read(self,root,source,spool,eof=True,frozen=None):
        capability=w.ReaderSource(source,root/'private')
        data=w.ReaderData(spool)
        try:return w.NativeCursor.read(data,capability,{capability.current},eof=eof,frozen=frozen)
        finally:data.close()

    def test_siphash_matches_authenticated_independent_reference_c(self):
        # Original CC0 rsyslog8.2312 member, unchanged bytes; no Python mirror.
        reference=Path(__file__).with_name('rsyslog_imfile_siphash_reference.c')
        self.assertEqual(hashlib.sha256(reference.read_bytes()).hexdigest(),
            '5a26dbc04d736e70692e369bbe1ff1a4bb4e6a1b36a8ba6af87291a1c42c71c3')
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);driver=root/'driver.c';binary=root/'reference'
            driver.write_text('#include <stdint.h>\n#include <stdio.h>\n#include <stddef.h>\n'
                'extern int rs_siphash(const uint8_t*,size_t,const uint8_t*,uint8_t*,size_t);\n'
                'int main(void){uint8_t b[512],k[16],o[8];for(int i=0;i<16;i++)k[i]=i;'
                'if(fread(b,1,512,stdin)!=512)return 2;rs_siphash(b,512,k,o,8);'
                'for(int i=0;i<8;i++)printf("%02x",o[i]);return 0;}')
            subprocess.run(['cc','-std=c99','-O0',str(reference),str(driver),'-o',str(binary)],check=True,capture_output=True)
            for content in (bytes(512),bytes(range(256))*2,b'x'*512,bytes((i*79)%256 for i in range(512))):
                result=subprocess.run([str(binary)],input=content,capture_output=True,check=True).stdout.decode()
                self.assertEqual(w.imfile_id(content),result)
                self.assertEqual(w.imfile_id(content+b'not part of the prefix'),result)
            self.assertEqual(w.imfile_id(b'x'*511),'')

    def test_native_current_date_pair_small_no_suffix_and_rotated_informational_label(self):
        for content in (b'small\n',b'x'*700+b'\n'):
            with self.subTest(size=len(content)),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source,spool,state=self.fixture(root,content)
                proof=self.read(root,source,spool)
                self.assertEqual(len(proof['groups']),1)
                self.assertEqual(len(next(iter(proof['groups'].values()))['aliases']),2)
                self.assertEqual(':' in state.name[len('imfile-state:')+len(str((source/'alerts/alerts.json').stat().st_ino)):],len(content)>=512)
                # Native retained cursor.filename still says alerts.json while
                # the watched name now denotes another group. Bind by inode.
                (source/'alerts/alerts.json').unlink();(source/'alerts/alerts.json').write_bytes(b'NEW\n')
                model.cursor(spool,source)
                proof=self.read(root,source,spool)
                self.assertEqual(len(proof['groups']),2)

    def test_kernel_eof_never_substitutes_for_logical_or_pending_segments(self):
        for change in ({'curr_offs':512,'strt_offs':512}, {'strt_offs':0},
                       {'prev_was_nl':1},{'prev_line_segment':'pending'}, {'prev_msg_segment':'pending'}):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source,spool,state=self.fixture(root)
                value=json.loads(state.read_text());value.update(change);state.write_text(json.dumps(value))
                with self.assertRaisesRegex(w.Refused,'complete EOF'):self.read(root,source,spool)
                self.read(root,source,spool,eof=False)  # structural resume-only, not handoff

    def test_strict_schema_hash_namespace_and_foreign_cursor_controls(self):
        for failure in ('bool','negative','overflow','range','unknown','duplicate','stale-hash',
                        'foreign-label','stale-inode','competing','hardlink','symlink','mode','missing','empty'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source,spool,state=self.fixture(root)
                value=json.loads(state.read_text())
                if failure=='bool':value['curr_offs']=True
                elif failure=='negative':value['strt_offs']=-1
                elif failure=='overflow':value['curr_offs']=1<<64
                elif failure=='range':value['strt_offs']=value['curr_offs']+1
                elif failure=='unknown':value['readmode']=0
                elif failure=='foreign-label':value['filename']=str(root/'foreign')
                if failure=='duplicate':state.write_text(state.read_text()[:-1]+',"curr_offs":701}')
                elif failure=='stale-hash':state.rename(state.with_name(state.name[:-16]+'0'*16))
                elif failure=='stale-inode':state.rename(state.with_name('imfile-state:999999999:0000000000000000'))
                elif failure=='competing':(state.parent/state.name.split(':',2)[0:1][0]).write_text('foreign')
                elif failure=='hardlink':os.link(state,root/'outside')
                elif failure=='symlink':state.unlink();state.symlink_to(root/'outside')
                elif failure=='mode':state.chmod(0o644)
                elif failure=='missing':state.unlink()
                elif failure=='empty':state.write_bytes(b'')
                else:state.write_text(json.dumps(value))
                with self.assertRaises((w.Refused,OSError)):self.read(root,source,spool)

    def test_source_frozen_endpoint_and_empty_incomplete_baselines_fail_closed(self):
        for content in (b'',b'unterminated'):
            with self.subTest(content=content),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source,spool,state=self.fixture(root,content)
                with self.assertRaises(w.Refused):self.read(root,source,spool)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source,spool,state=self.fixture(root)
            proof=self.read(root,source,spool)
            with (source/'alerts/alerts.json').open('ab') as stream:stream.write(b'late\n')
            model.cursor(spool,source)
            with self.assertRaisesRegex(w.Refused,'frozen source'):self.read(root,source,spool,frozen=proof['groups'])

    def test_live_o_trunc_empty_partial_and_changed_reads_retry_before_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source,spool,state=self.fixture(root)
            central=w.Central(root=root/'private');reader=w.Reader(central)
            reader.SPOOL=spool;reader.source=lambda _:str(source)
            data=w.ReaderData(spool)
            try:value={'spool_identity':data.stamp,'cursor_identity':data.identity((spool/'state').stat()),
                'generation':None,'schema':1,'phase':'admitted','request':{},'checker_sha256':'','source':str(source)}
            finally:data.close()
            payload=state.read_bytes();actual=w.NativeCursor.read;attempts=[]
            def transient(*args,**kwargs):
                attempts.append(True)
                if len(attempts)==1:state.write_bytes(b'')
                elif len(attempts)==2:state.write_bytes(payload[:20])
                else:state.write_bytes(payload)
                return actual(*args,**kwargs)
            with mock.patch.object(w.NativeCursor,'read',side_effect=transient):
                result=reader.cursor({'reader':value},eof=True,retry=True)
            self.assertEqual(len(attempts),3);self.assertEqual(len(result['records']),1)
            self.assertIsNone(central.active(),'coherent read cannot create stop/journal authority')

    def test_input_module_full_parameter_names_are_not_subset_qualification(self):
        import runpy
        helper=runpy.run_path(str(existing.REPO/'playbooks/files/pilot-wazuh-heartbeat'))
        source='/selected/logs';spool='/selected/spool';owner='/owned.conf'
        canonical=model.resources(source,spool,owner)
        observed={'resources':canonical}
        w.ReaderInputProfile.qualify(observed,source,spool,owner)
        for key in ('readmode','startmsg.regex','endmsg.regex','trimlineoverbytes','ratelimit.interval',
                    'delay','readtimeout','maxsubmitatonce','statefile'):
            changed=copy.deepcopy(canonical);changed[1]['attrs'][key]='secret-sentinel'
            with self.subTest(key=key),self.assertRaises(w.Refused):
                w.ReaderInputProfile.qualify({'resources':changed},source,spool,owner)
        # Actual tokenizer preserves unknown semantic NAME without secret value.
        raw={'/root.conf':'module(load="imfile" statefile.directory="/selected/spool/state")\n'
             'input(type="imfile" File="/selected/logs/alerts/alerts.json" password="secret-sentinel")'}
        result=helper['reader_resources'](raw,root='/root.conf')
        self.assertIn('password',result[1]['attrs']);self.assertNotIn('secret-sentinel',json.dumps(result))
        # Unrelated disjoint inputs do not alter the protected canonical input.
        observed['resources']=canonical+[{'kind':'input','attrs':{'type':'imfile','file':'/unrelated'},'file':'/other.conf'}]
        w.ReaderInputProfile.qualify(observed,source,spool,owner)


class PhysicalDescriptorTests(unittest.TestCase):
    def child(self,path):
        program=('import os,sys\nf=os.open(sys.argv[1],os.O_RDONLY)\nprint(f,flush=True)\n'
            'for line in sys.stdin:\n'
            ' if line.strip()=="quit":break\n'
            ' if line.startswith("reuse "):os.close(f);f=os.open(line.strip()[6:],os.O_RDONLY);print(f,flush=True)\n')
        child=subprocess.Popen([sys.executable,'-u','-c',program,str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        number=child.stdout.readline().strip()
        self.addCleanup(self.reap,child)
        return child,number
    @staticmethod
    def reap(child):
        if child.poll() is None:child.stdin.write('quit\n');child.stdin.flush()
        child.wait(timeout=10);child.stdin.close();child.stdout.close()
    def fixture(self,root):
        source=root/'source';(source/'alerts/dated').mkdir(parents=True)
        original=source/'alerts/original';original.write_bytes(b'real data\n')
        child,number=self.child(original)
        dated=source/'alerts/dated/retained';os.link(original,dated);original.unlink()
        current=source/'alerts/alerts.json';os.link(dated,current)
        return source,current,dated,child,number
    def test_real_deleted_dentry_with_two_closed_aliases_and_append_is_valid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);source,current,dated,child,number=self.fixture(root)
            self.assertTrue(os.readlink(Path('/proc')/str(child.pid)/'fd'/number).endswith(' (deleted)'))
            cap=w.ReaderSource(source,root/'private');records=cap.fds(child.pid)
            self.assertEqual(len(records),1);self.assertEqual(records[0]['links'],2)
            with current.open('ab') as output:output.write(b'append\n')
            self.assertEqual(len(cap.fds(child.pid)),1,'live append must not freeze data metadata')
            with self.assertRaisesRegex(w.Refused,'kernel FD positions'):
                w.Reader(w.Central(root=root/'private')).fds(child.pid,source,drained=True)
    def test_descriptor_mount_inode_flags_and_closed_namespace_cannot_be_forged(self):
        for failure in ('mount','inode','writable','opaque'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source,current,dated,child,number=self.fixture(root)
                path=Path('/proc')/str(child.pid)/'fdinfo'/number;actual=Path.read_text
                def changed(filename,*args,**kwargs):
                    value=actual(filename,*args,**kwargs)
                    if filename==path:
                        key,replacement={'mount':('mnt_id','999999999'), 'inode':('ino','1'),
                            'writable':('flags','0100002'),'opaque':('flags','010000000')}[failure]
                        value='\n'.join(key+':\t'+replacement if line.startswith(key+':') else line for line in value.splitlines())+'\n'
                    return value
                with mock.patch.object(Path,'read_text',changed),self.assertRaises(w.Refused):
                    w.ReaderSource(source,root/'private').fds(child.pid)

    def test_real_orphan_outside_alias_and_fd_reuse_refuse(self):
        for failure in ('orphan','outside','reuse','process-reuse'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);source,current,dated,child,number=self.fixture(root)
                if failure=='outside':
                    os.link(current,root/'foreign')
                    with self.assertRaisesRegex(w.Refused,'alias'):w.ReaderSource(source,root/'private')
                    continue
                if failure=='orphan':
                    current.unlink();dated.unlink()
                    with self.assertRaisesRegex(w.Refused,'orphan'):w.ReaderSource(source,root/'private').fds(child.pid)
                    continue
                cap=w.ReaderSource(source,root/'private')
                if failure=='reuse':
                    foreign=root/'foreign';foreign.write_bytes(b'outside')
                    original=cap.descriptor
                    def changed(pid,fd,reader,producer=False):
                        original_stat=w.os.readlink;seen=[]
                        def link(path,*args,**kwargs):
                            result=original_stat(path,*args,**kwargs)
                            if str(path).endswith('/fd/'+number) and not seen:
                                seen.append(True);child.stdin.write('reuse '+str(foreign)+'\n');child.stdin.flush()
                                self.assertEqual(child.stdout.readline().strip(),number)
                            return result
                        with mock.patch.object(w.os,'readlink',side_effect=link):return original(pid,fd,reader,producer)
                    with mock.patch.object(cap,'descriptor',side_effect=changed),self.assertRaises(w.Refused):cap.fds(child.pid)
                else:
                    actual=cap.process;calls=[]
                    def identity(pid):
                        value=actual(pid);calls.append(1)
                        if len(calls)>1:value[1]='different-start'
                        return value
                    with mock.patch.object(cap,'process',side_effect=identity),self.assertRaisesRegex(w.Refused,'process changed'):cap.fds(child.pid)


class ProducerOrphanTests(unittest.TestCase):
    """Wazuh's daily rotation leaves api.log.<date> (deleted), nlink 0, held by the
    selected stack's API container in the logs volume (D1 of PR #258).

    Real unlinked inodes and real /proc FD/fdinfo/mountinfo of a live child are
    used; only the process identity (cgroup, exe name) is modeled with a private
    proc directory whose entries link to the real child. These controls do not
    certify Docker, cgroup layout or native Wazuh behavior.
    """
    CONTAINER = 'a' * 64
    DOCKER = '0::/system.slice/docker-' + CONTAINER + '.scope\n'
    HOST = '0::/system.slice/cron.service\n'

    def hold(self, path):
        program = ('import os,sys\nf=os.open(sys.argv[1],os.O_RDONLY)\nprint(f,flush=True)\n'
                   'sys.stdin.readline()\n')
        child = subprocess.Popen([sys.executable, '-u', '-c', program, str(path)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        number = child.stdout.readline().strip()
        self.addCleanup(PhysicalDescriptorTests.reap, child)
        return child, number

    def source(self, root):
        source = root / 'source'
        (source / 'alerts/2026/Nov').mkdir(parents=True)
        (source / 'alerts/alerts.json').write_bytes(b'live\n')
        return source

    def orphan(self, root, relative, link=None):
        """A real nlink==0 inode (labelled '<relative> (deleted)') held by a live child."""
        source = root / 'source'
        victim = source / relative
        victim.parent.mkdir(parents=True, exist_ok=True)
        victim.write_bytes(b'rotated\n')
        if link: os.link(victim, link)
        child, number = self.hold(victim)
        victim.unlink()
        if link: Path(link).unlink()
        real = Path('/proc') / str(child.pid) / 'fd' / number
        self.assertTrue(os.readlink(real).endswith(' (deleted)'))
        self.assertEqual(real.stat().st_nlink, 0)
        return child

    def view(self, root, child, pid, cgroup, exe):
        proc = root / 'proc'
        proc.mkdir(exist_ok=True)
        for name, target in (('self', '/proc/self'), ('sys', '/proc/sys')):
            if not os.path.lexists(proc / name): (proc / name).symlink_to(target)
        folder = proc / str(pid)
        folder.mkdir()
        for name in ('stat', 'fd', 'fdinfo', 'mountinfo', 'ns', 'root'):
            (folder / name).symlink_to(Path('/proc') / str(child.pid) / name)
        (folder / 'cgroup').write_text(cgroup)
        (folder / 'exe').symlink_to(exe)
        return proc

    def reader(self, root, proc):
        reader = w.Reader(w.Central(root=root / 'private'))
        reader.PROC = proc
        return reader, {'images': {'wazuh.manager': {'container': self.CONTAINER}}}

    API = '/var/ossec/framework/python/bin/python3'

    def test_producer_container_unlinked_non_alert_log_does_not_refuse_admission(self):
        for relative in ('api.log.2026-11-04', 'ossec/ossec-04.log'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = self.source(root)
                child = self.orphan(root, relative)
                proc = self.view(root, child, 4242, self.DOCKER, self.API)
                reader, state = self.reader(root, proc)
                reader.source_users(state, source)
                # The alerts reader is held to its own closed-group rules in the same pass.
                live, number = self.hold(source / 'alerts/alerts.json')
                self.view(root, live, 4243, self.HOST, '/usr/sbin/rsyslogd')
                reader.source_users(state, source, 4243)
                reader.source_users(state, source, 4243, reader_fds=True)

    def test_same_orphan_is_refused_for_every_non_producer(self):
        for who, cgroup, exe, arguments in (
                ('host process', self.HOST, '/usr/bin/tail', {}),
                ('foreign container', '0::/system.slice/docker-' + 'b' * 64 + '.scope\n', self.API, {}),
                ('lookalike scope', '0::/system.slice/docker-' + self.CONTAINER + '.scope-foreign\n', self.API, {}),
                ('producers excluded (cold/reader-owned call)', self.DOCKER, self.API, {'producers': False}),
                ('the reader itself (host)', self.HOST, '/usr/sbin/rsyslogd', {'reader_pid': 4242}),
                ('the reader pid even inside a container cgroup', self.DOCKER, '/usr/sbin/rsyslogd',
                 {'reader_pid': 4242})):
            with self.subTest(who=who), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = self.source(root)
                child = self.orphan(root, 'api.log.2026-11-04')
                proc = self.view(root, child, 4242, cgroup, exe)
                reader, state = self.reader(root, proc)
                with self.assertRaisesRegex(w.Refused, 'orphan or unknown protected source FD'):
                    reader.source_users(state, source, **arguments)

    def test_producer_orphan_inside_the_alerts_custody_tree_still_refuses(self):
        for relative in ('alerts/2026/Nov/ossec-alerts-04.json', 'alerts/alerts.json.gone'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = self.source(root)
                child = self.orphan(root, relative)
                proc = self.view(root, child, 4242, self.DOCKER, self.API)
                reader, state = self.reader(root, proc)
                with self.assertRaisesRegex(w.Refused, 'orphan or unknown protected source FD'):
                    reader.source_users(state, source)

    def test_group_and_unknown_inode_classification_for_a_producer_descriptor(self):
        # Direct capability controls: the layout is closed BEFORE the namespace changes.
        for label, kind, expect in (
                ('closed non-alert group unlinked after inspection', 'group-gone', 'ignored'),
                ('closed group with an alerts alias unlinked, label outside alerts', 'alias-gone', 'refused'),
                ('new non-alert file after inspection (nlink>0)', 'new-outside', 'ignored'),
                ('new file under alerts after inspection (nlink>0)', 'new-alerts', 'refused')):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); source = self.source(root)
                if kind == 'group-gone': (source / 'ossec.log').write_bytes(b'x\n')
                if kind == 'alias-gone':
                    (source / 'other.log').write_bytes(b'x\n')
                    os.link(source / 'other.log', source / 'alerts/x.json')
                proc = root / 'proc'; proc.mkdir()
                (proc / 'self').symlink_to('/proc/self'); (proc / 'sys').symlink_to('/proc/sys')
                # The inspection is captured with a placeholder holder so the layout
                # closure exists first; then the child opens/unlinks to model rotation.
                cap = w.ReaderSource(source, root / 'private', proc)
                if kind == 'group-gone': target, drop = source / 'ossec.log', [source / 'ossec.log']
                elif kind == 'alias-gone': target, drop = source / 'other.log', [source / 'other.log', source / 'alerts/x.json']
                elif kind == 'new-outside': target, drop = source / 'api.log', []
                else: target, drop = source / 'alerts/new.json', []
                if not target.exists(): target.write_bytes(b'x\n')
                child, number = self.hold(target)
                for path in drop: path.unlink()
                folder = proc / '4242'; folder.mkdir()
                for name in ('stat', 'fd', 'fdinfo', 'mountinfo', 'ns', 'root'):
                    (folder / name).symlink_to(Path('/proc') / str(child.pid) / name)
                (folder / 'cgroup').write_text(self.DOCKER); (folder / 'exe').symlink_to(self.API)
                if expect == 'ignored':
                    self.assertEqual(cap.fds(4242, reader=False, producer=True), [])
                else:
                    with self.assertRaisesRegex(w.Refused, 'orphan or unknown protected source FD'):
                        cap.fds(4242, reader=False, producer=True)
                with self.assertRaisesRegex(w.Refused, 'orphan or unknown protected source FD'):
                    cap.fds(4242, reader=False, producer=False)
                with self.assertRaisesRegex(w.Refused, 'never classified as a producer'):
                    cap.fds(4242, reader=True, producer=True)


class HandoffCallerTests(recovery.RecoveryEntryTests):
    # Only new tests: explicitly remove inherited methods below. Reuse fixture
    # admission/real archives and whole production recovery entry as a fixture.
    def stopped_intent(self,root):
        central,document,compose,spool=self.create(root,None,'enabled')
        central.interrupt='stop-intent'
        with self.assertRaises(recovery.Interrupted):central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
        return central,central.active(),spool
    def test_full_handoff_after_real_stop_proof_is_required_before_cold_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,item,spool=self.stopped_intent(Path(temporary));reader=central.reader
            reader.pause(item)
            value=item['reader'];self.assertEqual(value['phase'],'queue-sealed')
            self.assertEqual(value['handoff']['kind'],'NATIVE_INPUT_HANDOFF')
            self.assertTrue(value['handoff']['stop']['graceful'])
            reader.cold_ready(item)
            self.assertEqual(central.active()['reader']['handoff'],value['handoff'])
            value.pop('handoff');central.write(item,item['phase'])
            for effect in (reader.cold_ready,reader.retire_cursor,reader.restore_intent):
                with self.subTest(effect=effect.__name__),self.assertRaisesRegex(w.Refused,'handoff certificate'):effect(item)
    def test_final_cold_lower_missing_malformed_segment_source_change_never_grants_handoff(self):
        for failure in ('lower','missing','malformed','segment','source'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                central,item,spool=self.stopped_intent(Path(temporary));reader=central.reader;actual=reader.units.stop
                def stop(*args,**kwargs):
                    result=actual(*args,**kwargs);state=next((spool/'state').iterdir())
                    if failure=='missing':state.unlink()
                    elif failure=='malformed':state.write_text('{')
                    elif failure=='source':
                        with (Path(item['reader']['source'])/'alerts/alerts.json').open('a') as out:out.write('late\n')
                    else:
                        value=json.loads(state.read_text())
                        if failure=='lower':value.update(curr_offs=0,strt_offs=0)
                        else:value['prev_msg_segment']='pending'
                        state.write_text(json.dumps(value))
                    return result
                with mock.patch.object(reader.units,'stop',side_effect=stop),self.assertRaises(w.Refused):reader.pause(item)
                self.assertEqual(central.active()['reader']['phase'],'reader-stopped')
                self.assertNotIn('handoff',central.active()['reader'])
                self.assertEqual(item['reader']['checkpoints'],[], 'no CURRENT seal before final native witness')
                self.assertEqual(central.active()['reader']['checkpoints'],[],
                    'final logical witness must precede even the cold CURRENT checkpoint')
                self.assertNotIn('capture',central.active())
                self.assertFalse(any(event[:2]==('effect','restore') for event in central.r.events))
    def test_safe_same_epoch_resume_only_cancels_cold_lower_witness_without_recursion(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,item,spool=self.stopped_intent(Path(temporary));reader=central.reader
            actual=reader.units.stop
            def stop(*args,**kwargs):
                result=actual(*args,**kwargs);model.cursor(spool,item['reader']['source'],curr_offs=0,strt_offs=0);return result
            with mock.patch.object(reader.units,'stop',side_effect=stop),self.assertRaises(w.Refused):reader.pause(item)
            with mock.patch.object(reader,'pause',side_effect=AssertionError('cancellation must not recurse pause')):
                reader.resume_unmodified(item)
            value=central.active()['reader'];self.assertEqual(value['resume_custody']['kind'],'SAME_EPOCH_RESUME_ONLY')
            self.assertNotIn('handoff',value);self.assertIsNone(value['generation'])
            self.assertEqual(central.r.service['ActiveState'],'active')
            with self.assertRaises(w.Refused):reader.restore_intent(item)
    def test_resume_only_never_crosses_durable_restore_intent_or_old_protocol(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,item,spool=self.stopped_intent(Path(temporary));reader=central.reader
            reader.pause(item);reader.restore_plan(item);reader.restore_intent(item)
            before=central.r.service.copy()
            with self.assertRaisesRegex(w.Refused,'cannot cross'):reader.resume_same_epoch(item)
            self.assertEqual(before,central.r.service)
            item['reader']['protocol']=1;central.write(item,item['phase'])
            with self.assertRaisesRegex(w.Refused,'old reader journal'):reader.cold_ready(item)

    def test_interrupted_cold_checkpoint_or_certificate_publication_reseals_without_invented_handoff(self):
        for where in ('checkpoint','certificate'):
            with self.subTest(where=where),tempfile.TemporaryDirectory() as temporary:
                central,item,spool=self.stopped_intent(Path(temporary));actual=central.write;once=[]
                def interrupted(value,phase):
                    result=actual(value,phase)
                    reader=value.get('reader',{})
                    hit=(where=='checkpoint' and reader.get('checkpoint_intents') and not reader.get('handoff')
                         or where=='certificate' and reader.get('handoff') and reader['phase']=='reader-stopped')
                    if hit and not once:
                        once.append(1);raise recovery.Interrupted('after durable '+where)
                    return result
                with mock.patch.object(central,'write',side_effect=interrupted),self.assertRaises(recovery.Interrupted):central.reader.pause(item)
                durable=central.active();self.assertEqual(durable['reader']['phase'],'reader-stopped')
                central.reader.pause(durable)
                central.reader.cold_ready(durable)
                self.assertEqual(durable['reader']['handoff']['cycle'],durable['reader']['cycle'])

    def test_malformed_stopped_cursor_retains_owner_and_no_restart_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,item,spool=self.stopped_intent(Path(temporary));reader=central.reader
            central.interrupt='after-stop'
            with self.assertRaises(recovery.Interrupted):reader.pause(item)
            next((spool/'state').iterdir()).write_text('{')
            starts=central.r.service['ExecMainStartTimestampMonotonic']
            with self.assertRaises(w.Refused):reader.resume_unmodified(item)
            self.assertEqual(central.r.service['ExecMainStartTimestampMonotonic'],starts)
            self.assertEqual(w.HostWriter(central.root).active()['owner'],self.OWNER)
            self.assertIsNotNone(central.active())
    def test_preswitch_explicit_cancellation_reconciles_still_active_same_stop_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,item,spool=self.stopped_intent(Path(temporary))
            self.assertEqual(central.r.service['ActiveState'],'active')
            w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
            central.execute('4.14.9',recover=True,owner=self.OWNER)
            self.assertIsNone(central.active())
            self.assertEqual(central.r.service['ActiveState'],'active')
            self.assertEqual(central.discover()['version'],'4.14.1')
            manifest=json.loads(next(central.root.glob('central-*/manifest.json')).read_text())
            self.assertEqual(manifest['reader']['handoff']['kind'],'NATIVE_INPUT_HANDOFF')
            self.assertIn(('stop-proof',True),central.r.unit_calls)

    def test_post_stop_crash_retries_cold_certificate_without_live_pid_fds(self):
        with tempfile.TemporaryDirectory() as temporary:
            central,item,spool=self.stopped_intent(Path(temporary));central.interrupt='after-stop'
            with self.assertRaises(recovery.Interrupted):central.reader.pause(item)
            durable=central.active();self.assertEqual(durable['reader']['phase'],'reader-stop-intent')
            central.reader.pause(durable)
            self.assertEqual(central.active()['reader']['phase'],'queue-sealed')
    def test_cursor_creation_and_both_rename_interruptions_replay_only_recorded_arrangements(self):
        for failure in ('mkdir',1,2):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);central,document,compose,spool=self.create(root,'interrupt','enabled')
                with self.assertRaises(recovery.Interrupted):central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
                real_mkdir=w.os.mkdir;real_rename=w.os.rename;count=[]
                def mkdir(name,*args,**kwargs):
                    result=real_mkdir(name,*args,**kwargs)
                    if failure=='mkdir' and str(name).startswith('.state-prepared-'):
                        raise recovery.Interrupted('after actual prepared directory creation')
                    return result
                def rename(*args,**kwargs):
                    result=real_rename(*args,**kwargs);count.append(1)
                    if failure==len(count):raise recovery.Interrupted('after actual owned cursor rename')
                    return result
                with mock.patch.object(w.os,'mkdir',side_effect=mkdir),mock.patch.object(w.os,'rename',side_effect=rename):
                    with self.assertRaises(recovery.Interrupted):central.rollback(central.active())
                before=central.active();self.assertIn('restore_intent',before['reader'])
                self.assertEqual(before['reader']['restore_intent']['state'],'restored')
                central.rollback(before)
                self.assert_restored(central,document,compose,spool)

    def test_explicit_one_redrain_after_failed_cold_witness_has_no_unbounded_loop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);central,_,_,spool=self.create(root,'interrupt','enabled')
            with self.assertRaises(recovery.Interrupted):central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
            actual=central.reader.units.stop;once=[]
            def cold_lower(*args,**kwargs):
                result=actual(*args,**kwargs)
                if not once:
                    once.append(1);model.cursor(spool,central.active()['reader']['source'],curr_offs=0,strt_offs=0)
                return result
            # A genuine explicit same-owner retry uses one same-epoch restart
            # then a new logical drain/cold certificate. No cursor is reset.
            w.HostWriter(central.root).resume(self.OWNER,'central','recover',confirmed=True)
            with mock.patch.object(central.reader.units,'stop',side_effect=cold_lower):
                central.rollback(central.active(),retry_reader=True)
            manifest=json.loads(next(central.root.glob('central-*/manifest.json')).read_text())
            self.assertEqual(len(manifest['reader']['redrain_attempts']),1)
            self.assertEqual(manifest['reader']['resume_custody']['kind'],'SAME_EPOCH_RESUME_ONLY')
            self.assertEqual(manifest['reader']['handoff']['kind'],'NATIVE_INPUT_HANDOFF')
            self.assertIsNone(central.active())

    def test_epoch_restore_intent_survives_partial_replay_without_old_cursor_rebinding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);central,document,compose,spool=self.create(root,'interrupt','enabled')
            with self.assertRaises(recovery.Interrupted):central.execute('4.14.9',upgrade=True,owner=self.OWNER,reader_ack=True)
            # Produce a native state for target-era input via explicit model.
            actual=central.restore;calls=[]
            def interrupted(*args,**kwargs):
                result=actual(*args,**kwargs);calls.append(1)
                if len(calls)==2:raise recovery.Interrupted('after physical old source restoration')
                return result
            with mock.patch.object(central,'restore',side_effect=interrupted),self.assertRaises(recovery.Interrupted):central.rollback(central.active())
            item=central.active();intent=item['reader']['restore_intent'];proof=item['reader']['handoff']
            self.assertEqual(intent['certificate'],central.reader.proof_hash(proof))
            self.assertNotEqual(intent['restore_epoch'],proof['source_epoch'])
            # Restoration changed inodes: retry uses validated intent/custody,
            # not a fresh match between target-era cursor and old restored data.
            central.rollback(item)
            self.assert_restored(central,document,compose,spool)

# Inherit fixture helpers only, not the nine previously counted tests.
for _name in list(recovery.RecoveryEntryTests.__dict__):
    if _name.startswith('test_'):setattr(HandoffCallerTests,_name,None)

if __name__=='__main__':unittest.main(verbosity=2)
