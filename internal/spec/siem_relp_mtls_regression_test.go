package spec

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A trusted TLS socket is insufficient: the probe must wait for a positive
// RELP reply, tolerate a fragmented reply, and fail on a wrong server name.
func TestRegression_SIEMRelpProbeRequiresMTLSAndACK(t *testing.T) {
	for _, name := range []string{"python3", "openssl"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(err)
		}
	}
	const code = `import pathlib,runpy,socket,ssl,subprocess,sys,threading
root=pathlib.Path(sys.argv[1])/'pki'
subprocess.run(['python3','../../scripts/siem-relp-test-pki.py','--output',str(root)],check=True,stdout=subprocess.DEVNULL)
p=runpy.run_path('../../playbooks/files/pilot-siem-relp-check')
directory=root/'sender'; directory.mkdir()
for target,source in [('ca.pem','ca.pem'),('cert.pem','aq-ubuntu.pem'),('key.pem','aq-ubuntu.key')]:
 (directory/target).write_bytes((root/source).read_bytes())
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(root/'aq-log.pem'),str(root/'aq-log.key'))
context.load_verify_locations(str(root/'ca.pem'));context.verify_mode=ssl.CERT_REQUIRED
real_connect=socket.create_connection
for mode,peer in [('ack','aq-log.test'),('no-ack','aq-log.test'),('wrong-name','wrong-server.test')]:
 listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();listener.settimeout(5)
 port=listener.getsockname()[1]; errors=[]; received=[]
 def server():
  try:
   raw,_=listener.accept()
   with raw:
    with context.wrap_socket(raw,server_side=True) as conn:
     assert conn.getpeercert(), 'no client identity'
     for transaction in [1,2]:
      header=b''
      while header.count(b' ')<3:
       char=conn.recv(1)
       if not char:return
       header+=char
      fields=header.strip().split();size=int(fields[2]);data=b''
      while len(data)<size:data+=conn.recv(size-len(data))
      assert conn.recv(1)==b'\n'
      received.append(fields[1])
      if mode=='no-ack':return
      for byte in ('%d rsp 7 200 OK\n\n'%transaction).encode():conn.sendall(bytes([byte]))
  except (ssl.SSLError,ConnectionError):pass
  except BaseException as exc:errors.append(exc)
 thread=threading.Thread(target=server,daemon=True);thread.start()
 socket.create_connection=lambda address,timeout:real_connect(('127.0.0.1',port),timeout=timeout)
 profile={'directory':directory,'port':port,'peers':[peer]}
 try:
  p['relp_probe'](profile)
  assert mode=='ack', 'accepted '+mode
 except (ssl.SSLError,ValueError,OSError):
  assert mode!='ack', 'valid mTLS RELP failed'
 finally:
  socket.create_connection=real_connect;thread.join(6);listener.close()
 assert not thread.is_alive() and not errors,(mode,errors)
 if mode=='ack':assert received==[b'open',b'syslog'],received
print('mTLS ACK, fragmented response, missing ACK and wrong peer name checked')
`
	if out, err := exec.Command("python3", "-c", code, t.TempDir()).CombinedOutput(); err != nil {
		t.Fatalf("RELP protocol probe: %v\n%s", err, out)
	}
}

func TestRegression_SIEMRelpUsesDedicatedRulesetAndVaultInputs(t *testing.T) {
	for _, file := range []string{"log-server", "audit-log-forwarding"} {
		data, err := os.ReadFile("../../playbooks/apply/" + file + "-apply.yml")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"rsyslog-relp-inputs.yml", "rsyslog-relp-tls.yml", "rsyslog-relp-restore.yml", `tls="on" tls.authMode="name"`, `tls.priorityString="NORMAL:-VERS-TLS1.0:-VERS-TLS1.1"`} {
			if !strings.Contains(string(data), want) {
				t.Errorf("%s missing %s", file, want)
			}
		}
	}
	data, err := os.ReadFile("../../playbooks/apply/log-server-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `input(type="imrelp" port="{{ siem_relp_port }}" ruleset="siemReceiver"`) {
		t.Fatal("RELP input must not re-enter the default forwarding ruleset")
	}
	if !strings.Contains(string(data), `{% if siem_receiver_relp_enabled | bool %} address="127.0.0.1"{% endif %}`) {
		t.Fatal("RELP mode must prevent remote clients bypassing mTLS through legacy TCP")
	}
	data, err = os.ReadFile("../../playbooks/apply/audit-log-forwarding-apply.yml")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), `tls.permanentFailureDisablesAction="off"`) != 2 {
		t.Fatal("both actions must retain queued messages across TLS authentication errors")
	}
	capability := strings.Index(string(data), "file: tasks/rsyslog-relp-capability.yml")
	material := strings.Index(string(data), "file: tasks/rsyslog-relp-tls.yml")
	if capability < 0 || material < capability {
		t.Fatal("reject incompatible modules before replacing live TLS material")
	}
}
