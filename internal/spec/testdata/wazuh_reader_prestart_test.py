"""RV17 controls: native serialization + real static files, explicit native leaves.

No service, parser load, cache write, package or policy action is executed.
The filesystem controls substitute only root UID for private user-owned files.
Native stock systemd execution and enforcement remain target requirements.
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
FIXTURE = json.loads(Path(__file__).with_name('wazuh_reader_units_ubuntu24.json').read_text())['units']


def record(path, args=None):
    return ('{ path=' + path + ' ; argv[]=' + ' '.join(args or [path])
            + ' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }')


class ExecTests(unittest.TestCase):
    def test_member_pins_match_independently_authenticated_archive_lineage(self):
        receipt=json.loads(Path(__file__).with_name('wazuh_reader_units_ubuntu24.json').read_text())['vendor_provenance']
        members={}
        for package in receipt['packages'].values():
            self.assertRegex(package['deb_sha256'],r'^[a-f0-9]{64}$')
            for member in package['members']:
                name=member['name'].removeprefix('.')
                if name=='/sbin/apparmor_parser':name='/usr/sbin/apparmor_parser'
                members[name]=member['sha256']
        self.assertEqual(w.ReaderPrestart.PINS,members)

    def test_actual_stock_declarations_and_runtime_only_changes(self):
        for unit in FIXTURE.values():
            for field in ('ExecStart', 'ExecStartPre'):
                raw = unit.get(field, '')
                changed = raw.replace('[n/a]', '[Thu 2026-11-05 12:00:00 UTC]').replace('pid=0', 'pid=123').replace('code=(null)', 'code=exited').replace('status=0/0', 'status=0')
                self.assertEqual(w.ReaderUnits.commands(raw), w.ReaderUnits.commands(changed))
        self.assertEqual(w.ReaderUnits.commands(''), [])

    def test_every_command_and_every_declared_field_is_consumed(self):
        one = record('/usr/sbin/rsyslogd', ['/usr/sbin/rsyslogd', '-n', '-iNONE'])
        two = record('/usr/bin/false')
        for field in ('ExecStart', 'ExecStartPre', 'ExecStartPost', 'ExecStop', 'ExecStopPost', 'ExecCondition', 'ExecReload'):
            with self.subTest(field=field):
                value = w.ReaderUnits.control({field: one + ' ' + two})[field]
                self.assertEqual(len(value), 2)
                self.assertEqual(value[1]['path'], '/usr/bin/false')
                self.assertEqual(value,w.ReaderUnits.control({field:one+' ; '+two})[field])
                for suffix in (' garbage', ' ; /bin/evil', ' { invalid }'):
                    with self.assertRaisesRegex(w.Refused, 'serialization'):
                        w.ReaderUnits.control({field: one + suffix})
        for bad in (one.replace('ignore_errors=no','ignore_errors=unknown'), one.replace(' -n ', ' \"-n\" '), one.replace('path=/usr/sbin', 'path=-/usr/sbin')):
            with self.assertRaises(w.Refused):
                w.ReaderUnits.commands(bad)

    def admit(self, temporary, mutate=None):
        values = copy.deepcopy(FIXTURE)
        values['rsyslog.service'].update(MainPID='1', ControlGroup='/system.slice/rsyslog.service', InvocationID='native-invocation', ExecMainStartTimestampMonotonic='100', Job='')
        values['syslog.socket']['Job']=''
        for value in values.values():
            fragment=Path(temporary)/value['Id'];fragment.write_text('unit native leaf');fragment.chmod(0o644)
            value['FragmentPath']=str(fragment)
        if mutate:mutate(values)
        native=w.ReaderUnits(None);native.show=lambda name:values[name]
        native.process=lambda pid:{'argv':['/usr/sbin/rsyslogd','-n','-iNONE'],'exe':'/usr/sbin/rsyslogd','mac':'rsyslogd (enforce)'}
        original=Path.read_text
        def read(path,*args,**kwargs):
            if str(path)=='/etc/os-release':return 'ID=ubuntu\nVERSION_ID="24.04"\n'
            return original(path,*args,**kwargs)
        with mock.patch.object(Path,'read_text',read), mock.patch.object(w.ReaderPrestart,'inspect',return_value={'qualified-native-leaf':True}) as hook, mock.patch.object(w.os,'stat',wraps=os.stat):
            # Root ownership of unit fragment is a native leaf here; real
            # immutable content/path admission is exercised below separately.
            original_stat=Path.stat
            class Owned:
                def __init__(self,info):self.info=info
                def __getattr__(self,name):return 0 if name=='st_uid' else getattr(self.info,name)
            with mock.patch.object(Path,'stat',lambda path,*a,**kw:Owned(original_stat(path,*a,**kw))):
                proof=native.admit(protected=['/actual-source'])
            return proof,hook.call_count

    def test_real_admission_caller_accepts_stock_and_nohook_only(self):
        with tempfile.TemporaryDirectory() as root:
            proof,calls=self.admit(root)
            self.assertEqual(calls,1);self.assertEqual(proof['schema'],2)
            proof,calls=self.admit(root,lambda values:values['rsyslog.service'].update(ExecStartPre=''))
            self.assertEqual(calls,0);self.assertIsNone(proof['prestart'])

    def test_real_admission_refuses_hidden_commands_before_native_effects(self):
        changes=[('ExecStartPre',FIXTURE['rsyslog.service']['ExecStartPre']+' '+record('/usr/bin/false')),
                 ('ExecStart',FIXTURE['rsyslog.service']['ExecStart']+' '+record('/usr/bin/false')),
                 ('ExecStartPre',FIXTURE['rsyslog.service']['ExecStartPre'].replace('ignore_errors=no','ignore_errors=yes')),
                 ('ExecStartPre',record(w.ReaderPrestart.HOOK,[w.ReaderPrestart.HOOK,'extra'])),
                 ('ExecStop',record('/usr/bin/false')),('ExecReload',record('/usr/bin/false'))]
        for field,value in changes:
            with self.subTest(field=field),tempfile.TemporaryDirectory() as root:
                with self.assertRaises(w.Refused):
                    self.admit(root,lambda values:values['rsyslog.service'].update({field:value}))


class StaticFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary=self.enterContext(tempfile.TemporaryDirectory());self.root=Path(self.temporary)
        original=Path.lstat
        ancestors=set(self.root.parents)
        class Owned:
            def __init__(self,value,ancestor):self.value=value;self.ancestor=ancestor
            def __getattr__(self,name):
                if name in ('st_uid','st_gid'):return 0
                if name=='st_mode' and self.ancestor:return self.value.st_mode & ~0o022
                return getattr(self.value,name)
        # Controller cache ancestors differ from guest /etc,/usr,/var. Only
        # those ancestor ownership/modes are native leaves; selected nodes and
        # every descendant/link/content/mount projection remain real.
        self.enterContext(mock.patch.object(Path,'lstat',lambda path,*args,**kwargs:Owned(original(path,*args,**kwargs),path in ancestors)))
        self.policy=self.root/'policy';self.policy.mkdir();(self.policy/'rsyslog.d').mkdir()
        (self.policy/'nested').mkdir();(self.policy/'nested/base').write_text('read policy\n')
        (self.policy/'usr.sbin.rsyslogd').write_text('include <nested/base>\ninclude if exists <rsyslog.d>\n')
        for entry in [self.policy,*self.policy.rglob('*')]:entry.chmod(0o755 if entry.is_dir() else 0o644)
        self.enterContext(mock.patch.object(w.ReaderPrestart,'POLICY',self.policy))

    def test_transitive_contents_and_optional_membership_are_static(self):
        before=w.ReaderPrestart.tree(self.policy);w.ReaderPrestart.includes()
        self.assertEqual(before,w.ReaderPrestart.tree(self.policy))
        (self.policy/'nested/base').write_text('different policy\n')
        self.assertNotEqual(before,w.ReaderPrestart.tree(self.policy))
        before=w.ReaderPrestart.tree(self.policy)
        (self.policy/'rsyslog.d/new-snippet').write_text('new policy\n');(self.policy/'rsyslog.d/new-snippet').chmod(0o644)
        self.assertNotEqual(before,w.ReaderPrestart.tree(self.policy));w.ReaderPrestart.includes()

    def test_includes_reject_escape_unknown_or_missing_required(self):
        for text in ('include "/outside/policy"', 'include <../outside>', 'include <missing>', 'include <@{dynamic}>', 'profile extra { include "/outside/policy" }', '# include <unknown>'):
            (self.policy/'nested/base').write_text(text+'\n')
            with self.subTest(text=text),self.assertRaises(w.Refused):w.ReaderPrestart.includes()

    def test_policy_aliases_hardlinks_and_unsafe_writes_refuse(self):
        target=self.policy/'nested/base'
        for kind in ('symlink','hardlink','writable'):
            with self.subTest(kind=kind):
                extra=self.policy/'foreign'
                if kind=='symlink':extra.symlink_to(target)
                elif kind=='hardlink':os.link(target,extra)
                else:target.chmod(0o666)
                with self.assertRaises(w.Refused):w.ReaderPrestart.tree(self.policy)
                if extra.exists() or extra.is_symlink():extra.unlink()
                target.chmod(0o644)

    def test_cache_outputs_change_without_becoming_immutable_inputs(self):
        cache=self.root/'cache';cache.mkdir(mode=0o700);entry=cache/'usr.sbin.rsyslogd';entry.write_bytes(b'old compiled cache');entry.chmod(0o600)
        root=w.ReaderPrestart.node(cache,False)
        w.ReaderPrestart.tree(cache,False)
        entry.write_bytes(b'new compiled bytes');(cache/'.features').write_bytes(b'feature output');(cache/'.features').chmod(0o600)
        w.ReaderPrestart.tree(cache,False)
        self.assertEqual(root,w.ReaderPrestart.node(cache,False))
        (cache/'alias').symlink_to(entry)
        with self.assertRaises(w.Refused):w.ReaderPrestart.tree(cache,False)

    def test_earlier_path_shadow_and_new_candidate_cannot_be_adopted(self):
        early=self.root/'early';selected=self.root/'selected'
        for path in (early,selected):path.mkdir(mode=0o755)
        tool=selected/'aa-status';tool.write_text('authenticated native tool leaf');tool.chmod(0o755)
        hook=w.ReaderPrestart(None)
        first=hook.resolve_tool('aa-status',str(tool),[str(early),str(selected)])
        self.assertIsNone(first[str(early/'aa-status')])
        shadow=early/'aa-status';shadow.write_text('foreign executable');shadow.chmod(0o755)
        with self.assertRaisesRegex(w.Refused,'PATH shadowed'):
            hook.resolve_tool('aa-status',str(tool),[str(early),str(selected)])
        shadow.unlink();tool.unlink()
        with self.assertRaisesRegex(w.Refused,'absent from service PATH'):
            hook.resolve_tool('aa-status',str(tool),[str(early),str(selected)])

    def inspection(self):
        config=self.root/'config';config.mkdir(mode=0o755);(config/'parser.conf').write_text('# stock configuration\n');(config/'parser.conf').chmod(0o644)
        features=self.root/'features';features.mkdir(mode=0o755);(features/'enabled').write_text('yes');(features/'enabled').chmod(0o444)
        cache=self.root/'cache';cache.mkdir(mode=0o755);output=cache/'feature-id';output.mkdir(mode=0o700)
        payload=output/'usr.sbin.rsyslogd';payload.write_bytes(b'cache');payload.chmod(0o600)
        protected=self.root/'producer';protected.mkdir(mode=0o755)
        # Only authenticated native member/alias/environment facts are replaced;
        # the production inspector walks, hashes, projects and compares real files.
        for attr,value in (('CONFIG',config),('FEATURES',features),('CACHE',cache)):
            self.enterContext(mock.patch.object(w.ReaderPrestart,attr,value))
        self.enterContext(mock.patch.object(w.ReaderPrestart,'PINS',{str(config/'parser.conf'):w.digest(config/'parser.conf')}))
        self.enterContext(mock.patch.object(w.ReaderPrestart,'aliases',return_value={'native-alias-leaf':'fixed'}))
        self.enterContext(mock.patch.object(w.ReaderPrestart,'environment',return_value={'LANG':'C','PATH':'native-path-leaf'}))
        self.enterContext(mock.patch.object(w.ReaderPrestart,'tools',return_value={'native-tools-leaf':'fixed'}))
        class Native:
            def run(_,argv,**kwargs):
                assert argv==['/usr/sbin/apparmor_parser','--print-cache-dir']
                return subprocess.CompletedProcess(argv,0,str(output)+'\n','')
        service={name:'' for name in w.ReaderPrestart.CONTEXT}
        service.update(DynamicUser='no',ProtectSystem='no',FragmentPath='/usr/lib/systemd/system/rsyslog.service',MainPID='0')
        return w.ReaderPrestart(Native()),service,[str(protected)],payload

    def test_actual_inspector_and_boundary_preserve_outputs_but_reject_new_inputs(self):
        hook,service,protected,payload=self.inspection()
        before=hook.inspect(service,protected)
        payload.write_bytes(b'new cache compiled by stock hook')
        self.assertEqual(before,hook.inspect(service,protected))
        units=w.ReaderUnits(hook.r);units.show=lambda _:service
        proof={'schema':2,'boot':w.AuditRuntime.boot(),'units':{units.SERVICE:units.control(service)},'fragments':{},'prestart':before}
        units.boundary(proof)
        (self.policy/'nested/base').write_text('changed included input')
        with self.assertRaisesRegex(w.Refused,'input authority changed'):units.boundary(proof)

    def test_cache_redirect_into_protected_data_and_output_alias_refuse(self):
        hook,service,protected,payload=self.inspection()
        with self.assertRaisesRegex(w.Refused,'overlap protected'):
            hook.inspect(service,[str(payload.parent)])
        bind='2 1 8:1 /other-cache '+str(payload.parent.parent)+' rw - ext4 /dev/synthetic rw\n'
        with mock.patch.dict(existing.MOUNT_NAMESPACE,{'text':existing.MOUNT_NAMESPACE['text']+bind}):
            with self.assertRaisesRegex(w.Refused,'foreign bind/subtree'):
                hook.inspect(service,protected)
        with mock.patch.dict(existing.MOUNT_NAMESPACE,{'text':'1 0 8:1 / / ro - ext4 /dev/synthetic ro\n'}):
            with self.assertRaisesRegex(w.Refused,'cache output filesystem is read-only'):
                hook.inspect(service,protected)
        config=next(iter(hook.PINS));Path(config).chmod(0o600)
        with self.assertRaisesRegex(w.Refused,'authenticated Ubuntu member'):hook.inspect(service,protected)
        Path(config).chmod(0o644)
        payload.unlink();payload.symlink_to(self.policy/'nested/base')
        with self.assertRaises(w.Refused):hook.inspect(service,protected)

    def test_entire_static_projection_is_required_during_readmission(self):
        proof={'schema':2,'units':{},'fragments':{},'boot':'same','prestart':{'policy':w.ReaderPrestart.tree(self.policy)}}
        changed=copy.deepcopy(proof);(self.policy/'nested/base').write_text('changed')
        changed['prestart']['policy']=w.ReaderPrestart.tree(self.policy)
        self.assertNotEqual(w.ReaderUnits.static(proof),w.ReaderUnits.static(changed))
        for old in ({},dict(proof,schema=1)):
            with self.assertRaisesRegex(w.Refused,'static authority'):w.ReaderUnits.static(old)

    def test_actual_pause_cannot_adopt_changed_static_closure(self):
        source=self.root/'source';(source/'alerts').mkdir(parents=True)
        (source/'alerts/alerts.json').write_bytes(b'complete record\n')
        before={'schema':2,'units':{},'fragments':{},'boot':'same','process':{'pid':1},'prestart':{'policy':'old'}}
        changed=copy.deepcopy(before);changed['prestart']['policy']='new'
        class NativeUnits:
            def show(self,name):return {'ActiveState':'active','MainPID':'1','Job':''}
            def process(self,pid):return {'pid':1}
            def admit(self,**kwargs):return changed
        reader=object.__new__(w.Reader);reader.units=NativeUnits()
        reader.use=lambda item:item['reader'];reader.boundary=lambda item:None
        reader.source_users=lambda *args,**kwargs:None  # native FD leaf
        info=(source/'alerts/alerts.json').stat()
        reader.fds=lambda *args,**kwargs:[{'device':info.st_dev,'inode':info.st_ino}]
        def forbidden(*args):raise AssertionError('WITHDRAWAL: changed static authority reached durable drain')
        reader.write=forbidden
        item={'paths':[str(source)],'reader':{'mode':'enabled','baseline':{'pid':1},
            'units':before,'source':str(source),'phase':'exposure-intent'}}
        with self.assertRaisesRegex(w.Refused,'differs from the admitted native policy'):
            reader.pause(item)



class EnvironmentTests(unittest.TestCase):
    def test_manager_environment_qualifies_effective_path_not_compiled_default(self):
        class Native:
            def run(self,argv,**kwargs):return subprocess.CompletedProcess(argv,0,self.text,'')
        native=Native();prestart=w.ReaderPrestart(native)
        for suffix in ('',':/snap/bin'):
            native.text='LANG=C.UTF-8\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin'+suffix+'\n'
            self.assertTrue(prestart.environment(0)['PATH'].endswith('/usr/bin'+suffix))
        for text in ('PATH=/tmp/bin:/usr/sbin\nLANG=C\n','PATH=/usr/sbin\nLANG=C\nLD_PRELOAD=secret\n'):
            native.text=text
            with self.assertRaises(w.Refused):prestart.environment(0)

    def test_stock_interpreter_alias_is_finite_and_live_service_environment_must_match(self):
        class Link:
            st_mode=0o120777;st_uid=0;st_dev=8;st_ino=123
        aliases={'/bin':'usr/bin','/sbin':'usr/sbin','/usr/bin/sh':'dash'}
        with mock.patch.object(Path,'lstat',return_value=Link()),mock.patch.object(w.os,'readlink',side_effect=lambda name:aliases[name]):
            self.assertEqual(len(w.ReaderPrestart.aliases()),3)
            aliases['/usr/bin/sh']='/unknown/interpreter'
            with self.assertRaisesRegex(w.Refused,'interpreter alias'):w.ReaderPrestart.aliases()
        class Native:
            def run(self,argv,**kwargs):return subprocess.CompletedProcess(argv,0,'LANG=C\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin\n','')
        hook=w.ReaderPrestart(Native())
        with mock.patch.object(Path,'read_bytes',return_value=b'LANG=C\0PATH=/different/path\0'):
            with self.assertRaisesRegex(w.Refused,'live execution environment'):hook.environment(123)

    def test_authenticated_member_gate_runs_before_policy_or_cache_queries(self):
        native=mock.Mock();service={name:'' for name in w.ReaderPrestart.CONTEXT}
        service.update(DynamicUser='no',ProtectSystem='no',FragmentPath='/usr/lib/systemd/system/rsyslog.service')
        with mock.patch.object(w.ReaderPrestart,'node',return_value=['safe native node']),mock.patch.object(w,'digest',return_value='changed-member'):
            with self.assertRaisesRegex(w.Refused,'authenticated Ubuntu member'):
                w.ReaderPrestart(native).inspect(service,['/actual-volume'])
        native.run.assert_not_called()
        for field in ('Environment','ExecSearchPath','RootDirectory','WorkingDirectory'):
            with self.subTest(field=field),self.assertRaisesRegex(w.Refused,'execution context'):
                w.ReaderPrestart(native).inspect(dict(service,**{field:'foreign'}),['/actual-volume'])


if __name__=='__main__':unittest.main()
