"""Fixed process boundary; no host environment or writable source inheritance."""
import os
import sys

base = "/tmp/controller"
for name in ("home", "tmp", "data", "reports", "local"):
    os.makedirs(base + "/" + name, mode=0o700, exist_ok=True)
env = {
    "PATH": "/opt/go/bin:/usr/local/bin:/usr/bin:/bin",
    "CGO_ENABLED": "0",
    "GOOS": "linux",
    "GOARCH": "amd64",
    "GOAMD64": "v1",
    "GOENV": "off",
    "GOWORK": "off",
    "GOFLAGS": "",
    "GOTOOLCHAIN": "local",
    "GOPROXY": "off",
    "GOSUMDB": "off",
    "GOMODCACHE": "/opt/pilot-modcache",
    "GOPATH": base + "/go",
    "GOCACHE": base + "/go-cache",
    "HOME": base + "/home",
    "TMPDIR": base + "/tmp",
    "LANG": "C.UTF-8",
    "USER": "root",
    "PYTHONNOUSERSITE": "1",
    "PYTHONSAFEPATH": "1",
    "PYTHONPATH": "/usr/local/lib64/python3.14/site-packages:/usr/local/lib/python3.14/site-packages",
    "PYTHONDONTWRITEBYTECODE": "1",
    "ANSIBLE_CONFIG": "/opt/pilot-controller/ansible.cfg",
    "ANSIBLE_LOCAL_TEMP": base + "/local",
    "ANSIBLE_NOCOLOR": "1",
    "PILOT_DATA_DIR": base + "/data",
}
args = sys.argv[1:]
if not args:
    raise SystemExit("controller command required")
if args[0] == "probe":
    args = ["/usr/bin/python3", "-P", "/opt/pilot-controller/probe.py"]
elif args[0] == "pilot":
    args = ["/opt/pilot-bin/pilot", "--data-dir", base + "/data"] + args[1:] + ["--report-dir", base + "/reports"]
elif args[0] == "go-list":
    args = ["/opt/go/bin/go", "list", "-mod=readonly", "-deps", "-json", "./cmd/pilot"]
elif args[0] == "go-verify":
    args = ["/opt/go/bin/go", "mod", "verify"]
elif args[0] == "inventory":
    args = ["ansible-inventory"] + args[1:]
elif args[0] != "ansible-playbook":
    raise SystemExit("unsupported controller entry point")
os.execvpe(args[0], args, env)
