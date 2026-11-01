"""Native effective configuration/origins; consumed before and after execution."""
import hashlib
import json
import os
import platform
import pwd
import grp
import sys
import subprocess
import ansible
from ansible import constants as C
from ansible.plugins.loader import get_all_plugin_loaders, callback_loader, init_plugin_loader

# OpenSSH itself resolves the current uid before parsing this non-connecting
# request. Constructor syntax checks alone cannot prove real SSH usability.
ssh = subprocess.run(["ssh", "-G", "-F", "/dev/null", "-o", "BatchMode=yes", "-l", "ubuntu", "192.0.2.1"], capture_output=True, text=True, check=False)
if ssh.returncode or "user ubuntu\n" not in ssh.stdout:
    raise SystemExit("native SSH identity resolution failed: " + ssh.stderr.strip())
identity = pwd.getpwuid(os.getuid())
group = grp.getgrgid(os.getgid())
config = "/opt/pilot-controller/ansible.cfg"
with open(config, "rb") as stream:
    config_sha = hashlib.sha256(stream.read()).hexdigest()
def origin(path):
    if path == os.path.join(os.getcwd(), "shell_plugins"):
        return "$CANDIDATE/shell_plugins"
    return path

loaders = {}
for _, loader in get_all_plugin_loaders():
    loaders[loader.subdir] = {
        "config": loader.config,
        "paths": [origin(p.path) for p in loader._get_paths_with_context()],
    }
# Resolve and execute the callback actually selected by the per-host verifier.
# Merely finding its documentation does not prove runtime compatibility.
init_plugin_loader()
resolved = callback_loader.find_plugin_with_context("ansible.posix.json")
if not resolved.resolved:
    raise SystemExit("required native verifier callback could not be resolved")
callback_path = os.path.realpath(resolved.plugin_resolved_path)
collection_root = "/opt/pilot-controller/collections/ansible_collections/ansible/posix"
with open(collection_root + "/MANIFEST.json", "rb") as stream:
    manifest_raw = stream.read()
manifest = json.loads(manifest_raw)
with open(callback_path, "rb") as stream:
    callback_sha = hashlib.sha256(stream.read()).hexdigest()
probe_inventory = "/tmp/controller/callback-inventory.yml"
with open(probe_inventory, "w") as stream:
    stream.write("all:\n  hosts:\n    callback-probe:\n      ansible_connection: local\n      ansible_python_interpreter: /usr/bin/python3.14\n")
callback_env = dict(os.environ, ANSIBLE_LOAD_CALLBACK_PLUGINS="1", ANSIBLE_STDOUT_CALLBACK="ansible.posix.json")
command = subprocess.run(["ansible", "callback-probe", "-i", probe_inventory, "-m", "ansible.builtin.command", "-a", "printf pilot-controller-callback"], env=callback_env, capture_output=True, text=True)
if command.returncode:
    raise SystemExit("native verifier callback execution failed: " + command.stderr.strip())
result = json.loads(command.stdout)
hosts = [host for play in result["plays"] for task in play["tasks"] for name, host in task["hosts"].items() if name == "callback-probe"]
if len(hosts) != 1 or hosts[0].get("stdout") != "pilot-controller-callback" or hosts[0].get("rc") != 0 or result["stats"]["callback-probe"].get("failures") != 0:
    raise SystemExit("native verifier callback semantic probe failed")
callback = {"version": manifest["collection_info"]["version"], "origin": callback_path, "sha256": callback_sha, "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(), "execution": "json-command/v1"}
print(json.dumps({
    "schema": "pilot-controller-probe/v3",
    "callback": callback,
    "uid": os.getuid(), "gid": os.getgid(), "user": identity.pw_name, "group": group.gr_name,
    "ssh_identity": "ssh-config/v1",
    "go": subprocess.check_output(["/opt/go/bin/go", "version"], text=True).strip(),
    "ansible": ansible.__version__,
    "python": platform.python_version(),
    "ansible_origin": os.path.realpath(ansible.__file__),
    "python_executable": os.path.realpath(sys.executable),
    "sys_path": sys.path,
    "config_file": C.CONFIG_FILE,
    "config_sha256": config_sha,
    "collections": list(C.COLLECTIONS_PATHS),
    "collections_scan_sys_path": C.COLLECTIONS_SCAN_SYS_PATH,
    "roles": list(C.DEFAULT_ROLES_PATH),
    "loaders": loaders,
}, sort_keys=True))
