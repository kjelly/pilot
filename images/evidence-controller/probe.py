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
from ansible.plugins.loader import get_all_plugin_loaders

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
print(json.dumps({
    "schema": "pilot-controller-probe/v2",
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
