"""Fixed process boundary; no host environment or writable source inheritance."""
import os
import hashlib
import subprocess
import json
import pathlib
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
    "USER": "pilot-controller",
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
    result = subprocess.run(args, env=env)
    complete = False
    rows = []
    try:
        files = sorted(pathlib.Path(base + "/reports").glob("*.ndjson"))
        if len(files) != 1 or files[0].is_symlink() or not files[0].is_file():
            raise ValueError("one regular verifier report required")
        raw = files[0].read_bytes()
        if len(raw) > 16*1024*1024:
            raise ValueError("verifier report exceeds bounded export")
        for line in raw.splitlines():
            row = json.loads(line)
            if not isinstance(row, dict) or len(rows) >= 10000:
                raise ValueError("verifier row export invalid")
            # Native VerifyRow omits its zero int field. The export makes that
            # known successful-probe zero explicit without changing the report.
            if row.get("probe_status") == "ok":
                row.setdefault("exit_code", 0)
            rows.append(row)
        complete = bool(rows)
    except (OSError, ValueError):
        complete = False
    framed = ["PILOT_CONTROLLER_VERIFY_ROW " + json.dumps(row, separators=(",", ":")) for row in rows]
    if sum(len(line.encode()) + 1 for line in framed) > 16*1024*1024:
        rows, framed, complete = [], [], False
    for line in framed:
        print(line, file=sys.stderr, flush=True)
    print("PILOT_CONTROLLER_VERIFY_REPORT " + json.dumps({"schema":"pilot-verify-diagnostics/v1", "rows":len(rows), "complete":complete}, separators=(",", ":")), file=sys.stderr, flush=True)
    raise SystemExit(result.returncode if result.returncode else (0 if complete else 74))
elif args[0] == "go-rebuild":
    output = base + "/pilot-rebuilt"
    result = subprocess.run(["/opt/go/bin/go", "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-o", output, "./cmd/pilot"], env=env)
    if result.returncode:
        raise SystemExit(result.returncode)
    digest = hashlib.sha256()
    with open(output, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""):
            digest.update(chunk)
    print(digest.hexdigest())
    raise SystemExit(0)
elif args[0] == "go-list":
    args = ["/opt/go/bin/go", "list", "-mod=readonly", "-deps", "-json", "./cmd/pilot"]
elif args[0] == "go-verify":
    args = ["/opt/go/bin/go", "mod", "verify"]
elif args[0] == "inventory":
    args = ["ansible-inventory"] + args[1:]
elif args[0] != "ansible-playbook":
    raise SystemExit("unsupported controller entry point")
os.execvpe(args[0], args, env)
