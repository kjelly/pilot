"""Synthetic typed OCI proof for gate mechanics; never claims native execution."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PROFILE = "images/evidence-controller/"
NAMES = {"Dockerfile":"recipe_sha256", "profile.lock.json":"lock_sha256", "ansible.cfg":"config_sha256", "launch.py":"launch_sha256", "probe.py":"probe_sha256"}
STAGES = ("L1 syntax check", "L3 check-mode dry-run", "L4 apply", "L5 verify", "L6 idempotency")
PLUGINS = ("action_plugins", "become_plugins", "cache_plugins", "callback_plugins", "cliconf_plugins", "connection_plugins", "doc_fragments", "filter_plugins", "httpapi_plugins", "inventory_plugins", "library", "lookup_plugins", "module_utils", "netconf_plugins", "shell_plugins", "strategy_plugins", "terminal_plugins", "test_plugins", "vars_plugins")

def fixture_files():
    return {**{PROFILE+name:(ROOT/PROFILE/name).read_bytes() for name in NAMES}, "go.mod":b"module github.com/kjelly/pilot\n", "go.sum":b"", "cmd/pilot/main.go":b"package main\nfunc main() {}\n"}

def descriptor(path, raw):
    oid=hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    return {"path":path,"mode":"100644","blob":oid,"sha256":hashlib.sha256(raw).hexdigest()}

def add_controller(record):
    files=fixture_files()
    profile={key:hashlib.sha256(files[PROFILE+name]).hexdigest() for name,key in NAMES.items()}
    native={"uid":1000,"gid":1000,"user":"pilot-controller","group":"pilot-controller","ssh_identity":"ssh-config/v1","schema":"pilot-controller-probe/v3", "go":"go version go1.26.8 linux/amd64", "ansible":"2.21.5", "python":"3.14.8", "ansible_origin":"/usr/local/lib/python3.14/site-packages/ansible/__init__.py", "python_executable":"/usr/bin/python3.14", "config_file":"/opt/pilot-controller/ansible.cfg", "config_sha256":profile["config_sha256"], "collections":["/opt/pilot-controller/collections"], "collections_scan_sys_path":False, "roles":["/opt/pilot-controller/empty"], "sys_path":["/usr/local/lib64/python3.14/site-packages", "/usr/local/lib/python3.14/site-packages", "/usr/lib64/python314.zip", "/usr/lib64/python3.14", "/usr/lib64/python3.14/lib-dynload", "/usr/lib64/python3.14/site-packages", "/usr/lib/python3.14/site-packages"], "loaders":{}}
    for name in PLUGINS:
        paths=["/opt/pilot-controller/empty"]
        if name=="shell_plugins": paths=["shell_plugins"]
        if name=="doc_fragments": paths=["/tmp/controller/home/.ansible/plugins/doc_fragments","/usr/share/ansible/plugins/doc_fragments"]
        native["loaders"][name]={"config":paths,"paths":["$CANDIDATE/shell_plugins"] if name=="shell_plugins" else paths}
    native["callback"]={"version":"2.1.0","origin":"/opt/pilot-controller/collections/ansible_collections/ansible/posix/plugins/callback/json.py","sha256":"cc2f6a845b1b7d8d87e16b7fed79b860e10ea9e9b372dd0bdcbd850b9654a032","manifest_sha256":"3899df5b1b390f51a7fc95ad8997c7e7030daf4f5265898f96977ef9ed8d4df5","execution":"json-command/v1"}
    digest=hashlib.sha256(json.dumps(native,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    proof={"schema":"pilot-controller/v3", "image_id":"sha256:"+"a"*64, "profile":profile, "native_probe":native, "inventory_kind":"pilot-rendered-ssh/v1", "steps":dict.fromkeys(STAGES,1), "build":{"go_version":"go1.26.8", "path":"github.com/kjelly/pilot/cmd/pilot", "module":"github.com/kjelly/pilot", "goos":"linux", "goarch":"amd64", "goamd64":"v1", "cgo":"0", "settings_sha256":"b"*64, "modules_sha256":"c"*64,"sources_sha256":"e"*64,"rebuilt_binary_sha256":"d"*64}}
    for key in ("inventory_sha256","rendered_inventory_sha256","binary_sha256"): proof[key]="d"*64
    proof.update(config_sha256=profile["config_sha256"],pre_probe_sha256=digest,post_probe_sha256=digest)
    record.update(controller=proof,pilot_binary={"sha256":"d"*64},steps=[{"name":name,"status":"pass"} for name in STAGES],verify=[{"verdict":"PASS","pass":1,"fail":0}])
    record["inventory"]={"hosts":["synthetic-host"],"groups":{"all":["synthetic-host"]}}
    record["verify"][0].update(diagnostics_schema="pilot-verify-diagnostics/v1",diagnostics_complete=True,rows=[{"id":"C1","host":"synthetic-host","status":"pass","exit_code":0,"probe_status":"ok"}])
    record["closure"]["resolution_version"]=10
    record["closure"]["files"].extend(descriptor(path,raw) for path,raw in files.items())
    return record
