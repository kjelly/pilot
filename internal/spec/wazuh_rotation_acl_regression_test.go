package spec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// Exercise real POSIX ACL inheritance and hardlinks, including an actual file
// open under another UID. This local filesystem harness does not claim native
// Wazuh/AppArmor evidence; that is supplied by the immutable VM rotation arm.
func TestRegression_WazuhDailyHardlinkACLTransaction(t *testing.T) {
	for _, name := range []string{"python3", "getfacl", "setfacl", "sudo"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(err)
		}
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("native reader-identity test requires passwordless sudo")
	}
	const code = `import json,os,pathlib,runpy,shutil,subprocess,tempfile
p=runpy.run_path('../../playbooks/files/pilot-wazuh-acl');Transaction=p['Transaction']; env=Transaction.begin.__globals__
reader='nobody';uid=__import__('pwd').getpwnam(reader).pw_uid
def acl(path):return subprocess.check_output(['getfacl','-cpn','--',str(path)],text=True)
def readable(path):return subprocess.run(['sudo','-n','-u',reader,'/bin/cat',str(path)],capture_output=True).returncode==0
def fixture():
 root=pathlib.Path(tempfile.mkdtemp(prefix='i211-acl-native-',dir='/tmp'))
 source=root/'logs';month=source/'alerts/2026/Nov';month.mkdir(parents=True)
 for path in [source,source/'alerts',source/'alerts/2026',month]:path.chmod(0o750)
 file=month/'ossec-alerts-03.json';file.write_text('original');file.chmod(0o640)
 top=source/'alerts/alerts.json';os.link(file,top)
 return root,source,month,file,top
def grant(root,source,cls=Transaction):
 tx=cls(root/'journal.json');tx.begin(str(source),reader);return tx
def rotate(file,top,value):
 old=file.stat().st_ino;top.unlink();file.rename(file.with_suffix('.saved'))
 file.write_text(value);file.chmod(0o640);os.link(file,top)
 assert file.stat().st_ino!=old and file.stat().st_nlink==2 and top.stat().st_ino==file.stat().st_ino
 return readable(top)
for broken in [False,True]:
 root,source,month,file,top=fixture()
 try:
  class TopOnly(Transaction):
   def grant(self,path,required,default=False):
    if default and pathlib.Path(path)!=source/'alerts':return
    return super().grant(path,required,default)
  tx=grant(root,source,TopOnly if broken else Transaction)
  assert readable(top),'old explicit current-file ACL did not work'
  assert rotate(file,top,'new daily inode') is (not broken),'existing-month new inode did not discriminate date defaults'
  future=source/'alerts/2030/Dec';future.mkdir(parents=True,mode=0o750)
  nextfile=future/'ossec-alerts-01.json';nextfile.write_text('future');nextfile.chmod(0o640)
  top.unlink();os.link(nextfile,top)
  assert readable(top),'new nested year/month did not inherit read access'
  assert ('default:user:'+str(uid)+':r-x') in acl(future)
  assert ('user:'+str(uid)+':r-x') in acl(nextfile) and 'mask::r--' in acl(nextfile)
  if not broken:
   repeat=Transaction(root/'repeat.json');repeat.begin(str(source),reader)
   assert repeat.state['changed'] is False,'stable reapply changed ACLs'
  print('top-only counterexample rejects new daily inode' if broken else 'existing month + future nested dirs + noop apply PASS')
 finally:shutil.rmtree(root)
# New months appearing between the root grant and year grant must be discovered
# after the year is protected; an initial recursive list would miss this one.
root,source,month,file,top=fixture()
try:
 class Interleaved(Transaction):
  def grant(self,path,required,default=False):
   result=super().grant(path,required,default)
   if default and pathlib.Path(path)==source/'alerts':
    (source/'alerts/2026/Dec').mkdir(mode=0o750)
   return result
 grant(root,source,Interleaved)
 created=source/'alerts/2026/Dec/ossec-alerts-04.json';created.write_text('interleaved');created.chmod(0o640)
 top.unlink();os.link(created,top);assert readable(top),'parent-first discovery missed concurrent new month'
 print('parent-first concurrent new month PASS')
finally:shutil.rmtree(root)
# Prior reader rights must not be shadowed by an x-only/r-only named entry.
root,source,month,file,top=fixture()
try:
 root.chmod(0o755)
 root_before=acl(root)
 subprocess.run(['setfacl','-m','u:'+reader+':rw',str(file)],check=True)
 file_before=acl(file)
 grant(root,source)
 assert acl(root)==root_before,'already sufficient other::r-x was narrowed'
 assert acl(file)==file_before,'existing reader write access was narrowed'
 print('existing reader effective rights preserved PASS')
finally:shutil.rmtree(root)
# A new named default entry must retain fallback other/group policy rights.
for fallback in ['other','group']:
 root,source,month,file,top=fixture()
 try:
  spec='d:u::rwx,d:g::---,d:o::rwx' if fallback=='other' else 'd:u::rwx,d:g::---,d:g:65534:rwx,d:o::---,d:m::rwx'
  subprocess.run(['setfacl','-n','-m',spec,str(month)],check=True)
  grant(root,source)
  assert ('default:user:'+str(uid)+':rwx') in acl(month),'default fallback rights were narrowed'
  print('default '+fallback+' fallback reader rights preserved PASS')
 finally:shutil.rmtree(root)
# Restrictive shared masks must fail closed, never unmask another principal.
for kind in ['default','access']:
 root,source,month,file,top=fixture()
 try:
  path=month if kind=='default' else source
  spec='d:u:daemon:rwx,d:m::r' if kind=='default' else 'u:daemon:rwx,m::r'
  subprocess.run(['setfacl','-n','-m',spec,str(path)],check=True)
  paths=[root,source,source/'alerts',source/'alerts/2026',month,top]
  before={str(x):acl(x) for x in paths}
  tx=Transaction(root/'journal.json')
  try:tx.begin(str(source),reader)
  except ValueError as error:assert 'unmask another principal' in str(error),str(error)
  else:raise AssertionError('restrictive '+kind+' mask was silently expanded')
  tx.restore()
  assert before=={str(x):acl(x) for x in paths},'failed grant rollback did not restore exact ACLs'
  print('restrictive '+kind+' mask + exact rollback PASS')
 finally:shutil.rmtree(root)
# Recovery removes inherited grants from new date directories/files without
# deleting data, then exactly restores all pre-existing ACLs.
root,source,month,file,top=fixture()
try:
 paths=[root,source,source/'alerts',source/'alerts/2026',month,top]
 before={str(x):acl(x) for x in paths};tx=grant(root,source)
 future=source/'alerts/2031/Jan';future.mkdir(parents=True,mode=0o750)
 data=future/'ossec-alerts-01.json';data.write_text('retain this data');data.chmod(0o640)
 siblings=[month/'ossec-alerts-04.log',month/'ossec-alerts-04.json.sum',month/'ossec-alerts-04.json.gz']
 for sibling in siblings:sibling.write_text('retain sibling');sibling.chmod(0o640)
 assert readable(data),'new fixture did not inherit the temporary reader grant'
 assert all(('user:'+str(uid)+':') in acl(sibling) for sibling in siblings),'new sibling did not inherit grant'
 tx.restore()
 assert data.read_text()=='retain this data' and not readable(data),'new data/grant recovery incorrect'
 assert all(sibling.read_text()=='retain sibling' and ('user:'+str(uid)+':') not in acl(sibling) for sibling in siblings),'text/checksum/archive sibling grant cleanup incorrect'
 assert before=={str(x):acl(x) for x in paths},'pre-existing ACLs were not exactly restored'
 assert 'default:user:'+str(uid)+':' not in acl(future),'new directory retained temporary default grant'
 print('new inherited directory/file cleanup + exact prior ACL restore PASS')
finally:shutil.rmtree(root)
# Reject physical-path replacement and symlinks without touching their targets.
root,source,month,file,top=fixture()
try:
 outside=root/'outside';outside.mkdir();before=acl(outside)
 (source/'alerts/2027').symlink_to(outside,target_is_directory=True)
 tx=Transaction(root/'journal.json')
 try:tx.begin(str(source),reader)
 except ValueError as error:assert 'physical directory' in str(error)
 else:raise AssertionError('symlinked date directory accepted')
 assert acl(outside)==before,'symlink target mutated'
 print('symlink target rejected unchanged PASS')
finally:shutil.rmtree(root)
root,source,month,file,top=fixture()
try:
 tx=grant(root,source)
 year=source/'alerts/2026';year.rename(root/'displaced-year');year.mkdir(mode=0o750);before=acl(year)
 try:tx.restore()
 except ValueError as error:assert 'identity changed' in str(error),str(error)
 else:raise AssertionError('replacement identity was treated as original')
 assert acl(year)==before,'old ACL was applied to replacement object'
 print('replacement identity refused without clobbering PASS')
finally:shutil.rmtree(root)
# Unknown leaf types must reject without waiting for a FIFO writer.
root,source,month,file,top=fixture()
try:
 top.unlink();os.mkfifo(top)
 result=subprocess.run(['python3','../../playbooks/files/pilot-wazuh-acl','grant',str(root/'fifo.json'),str(source),reader],capture_output=True,text=True,timeout=5)
 assert result.returncode!=0 and 'physical directory/regular file' in result.stderr,'FIFO current path accepted or failed before its type gate'
 print('FIFO current path rejected without blocking PASS')
finally:shutil.rmtree(root)
# Replace the current path between the native ACL read and write. Descriptor
# binding must update only the captured inode and refuse the replacement path.
root,source,month,file,top=fixture()
try:
 outside=root/'outside.conf';outside.write_text('unrelated');outside.chmod(0o600);before=acl(outside)
 tx=Transaction(root/'journal.json');original_command=env['command'];swapped=[False]
 def interpose(*args,**kwargs):
  if args[0]=='setfacl' and not swapped[0] and tx.state['entries'].get(str(top),{}).get('touched'):
   swapped[0]=True;top.unlink();top.symlink_to(outside)
  return original_command(*args,**kwargs)
 env['command']=interpose
 try:
  try:tx.begin(str(source),reader)
  except (OSError,ValueError):assert swapped[0],'failed before the intended replacement'
  else:raise AssertionError('replacement during ACL mutation was not detected')
 finally:env['command']=original_command
 assert acl(outside)==before and outside.read_text()=='unrelated','replacement target was modified'
 try:tx.restore()
 except ValueError as error:assert 'rollback incomplete' in str(error),str(error)
 else:raise AssertionError('replacement rollback falsely reported exact success')
 assert acl(outside)==before,'rollback followed a replacement symlink'
 print('descriptor-bound mutation refuses replacement target PASS')
finally:shutil.rmtree(root)
`
	if out, err := exec.Command("python3", "-c", code).CombinedOutput(); err != nil {
		t.Fatalf("native ACL/hardlink transaction: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

func TestRegression_WazuhACLJournalLifecycleThroughAnsible(t *testing.T) {
	for _, tool := range []string{"ansible-playbook", "python3", "getfacl", "setfacl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(err)
		}
	}
	root, err := os.MkdirTemp("/tmp", "i211-acl-ansible-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	source := filepath.Join(root, "logs")
	setup := `import os,pathlib,sys
p=pathlib.Path(sys.argv[1]);m=p/'alerts/2026/Nov';m.mkdir(parents=True)
for x in [p,p/'alerts',p/'alerts/2026',m]:x.chmod(0o750)
f=m/'ossec-alerts-03.json';f.write_text('journal lifecycle');f.chmod(0o640);os.link(f,p/'alerts/alerts.json')
`
	if out, err := exec.Command("python3", "-c", setup, source).CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	before, err := exec.Command("getfacl", "-cpn", filepath.Join(source, "alerts/2026/Nov")).Output()
	if err != nil {
		t.Fatal(err)
	}
	for index, fail := range []bool{true, false, false} {
		tasks := loadYAML(t, "../../playbooks/apply/tasks/wazuh-alert-forward.yml")
		main := loadFirstPlay(t, "wazuh-manager-apply.yml")
		helper := filepath.Join(root, "bin", "pilot-wazuh-acl")
		dir := findNamedTask(t, tasks, "Wazuh: ensure the ACL helper directory exists")
		dir["ansible.builtin.file"].(map[string]any)["path"] = filepath.Dir(helper)
		install := findNamedTask(t, tasks, "Wazuh: install the bounded ACL transaction helper")
		copyArgs := install["ansible.builtin.copy"].(map[string]any)
		copyArgs["src"], _ = filepath.Abs("../../playbooks/files/pilot-wazuh-acl")
		copyArgs["dest"] = helper
		delete(copyArgs, "owner")
		delete(copyArgs, "group")
		allocate := findNamedTask(t, tasks, "Wazuh: allocate a private transient ACL rollback journal")
		allocate["ansible.builtin.tempfile"].(map[string]any)["path"] = root
		grant := findNamedTask(t, tasks, "Wazuh: grant identity-aware reader ACLs including existing date directories")
		argv := grant["ansible.builtin.command"].(map[string]any)["argv"].([]any)
		argv[0], argv[4] = helper, "nobody"
		restore := findNamedTask(t, main, "ROLLBACK — restore original ACLs only on the captured objects")
		restore["ansible.builtin.command"].(map[string]any)["argv"].([]any)[0] = helper
		commit := findNamedTask(t, main, "Record that the ACL transaction completed successfully")
		cleanup := findNamedTask(t, main, "Retire the transient ACL journal only after commit or successful recovery")
		block := []any{dir, install, allocate, grant}
		if fail {
			block = append(block, map[string]any{"ansible.builtin.fail": map[string]any{"msg": "controlled ACL recovery"}})
		}
		block = append(block, commit)
		body, err := yaml.Marshal([]any{map[string]any{"hosts": "all", "gather_facts": false,
			"vars":  map[string]any{"siem_forwarding_enabled": true, "wazuh_logs_source": source, "wazuh_acl_journal_committed": false},
			"tasks": []any{map[string]any{"block": block, "rescue": []any{restore}, "always": []any{cleanup}}}}})
		if err != nil {
			t.Fatal(err)
		}
		playbook := filepath.Join(root, "play.yml")
		if err := os.WriteFile(playbook, body, 0600); err != nil {
			t.Fatal(err)
		}
		config := filepath.Join(root, "ansible.cfg")
		if err := os.WriteFile(config, []byte("[defaults]\n"), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("ansible-playbook", "-i", "localhost,", "-c", "local", playbook)
		cmd.Env = append(os.Environ(), "ANSIBLE_CONFIG="+config, "ANSIBLE_LOCAL_TEMP="+root)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("journal transaction: %v\n%s", err, out)
		}
		if fail {
			after, err := exec.Command("getfacl", "-cpn", filepath.Join(source, "alerts/2026/Nov")).Output()
			if err != nil || string(after) != string(before) {
				t.Fatal("native Ansible rescue did not restore the exact directory ACL")
			}
		} else if index == 2 && !strings.Contains(string(out), "changed=0") {
			t.Fatalf("stable native Ansible reapply must report changed=0: %s", out)
		} else if index == 2 {
			t.Log("native Ansible stable reapply changed=0")
		}
		journals, err := filepath.Glob(filepath.Join(root, "pilot-wazuh-acl-*.json"))
		if err != nil || len(journals) != 0 {
			t.Fatal("successful commit/recovery left a transient ACL journal")
		}
	}
}
