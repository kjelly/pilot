"""Fixed process boundary; no host environment or writable source inheritance."""
import os
import hashlib
import subprocess
import json
import pathlib
import sys
import re
import stat

def regular_canonical(path, root):
    # No lexical symlink or path outside the verified immutable boundary.
    path, root = pathlib.Path(path), pathlib.Path(root)
    if not path.is_absolute() or not root.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("noncanonical assembly input")
    path.relative_to(root.resolve(strict=True))
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("nonregular assembly input")
    return path.read_bytes()


def audit_sdk_headers(include):
    # The pinned SDK supplies the final include search root. Prove its whole
    # flat header tree is closed, including macro continuations, not two names.
    headers = list(pathlib.Path(include).iterdir())
    if not headers:
        raise ValueError("missing pinned assembly header boundary")
    for path in headers:
        if path.suffix != ".h":
            raise ValueError("unsupported pinned assembly header context")
        raw = regular_canonical(path, include)
        continuation = False
        for line in raw.split(b"\n"):
            stripped = line.strip(b" ")
            if b"#" in line:
                # A full-line comment cannot synthesize a directive. Inside a
                # macro continuation even that spelling is conservatively refused.
                if not continuation and stripped.startswith(b"//"):
                    continue
                if continuation or not re.fullmatch(rb" *#(?:define|ifdef|ifndef|if|else|elif|endif|undef)(?: +[^#\r\n]*)? *", line):
                    raise ValueError("unclosed pinned assembly header context")
            continuation = line.rstrip(b" ").endswith(b"\\")
        if continuation:
            raise ValueError("unfinished pinned assembly macro")


def audit_module_assembly(packages, modcache="/opt/pilot-modcache", include="/opt/go/pkg/include"):
    audit_sdk_headers(include)
    for package in packages:
        if package.get("Standard") or not (package.get("SFiles") or package.get("SysoFiles")):
            continue
        directory = pathlib.Path(package["Dir"])
        # Candidate assembly is refused atomically by the Go listing consumer.
        if not directory.is_relative_to(modcache):
            continue
        module = package.get("Module") or {}
        module_dir = pathlib.Path(module.get("Dir", ""))
        if (not module_dir.is_absolute() or not module_dir.is_relative_to(modcache)
                or module_dir.resolve(strict=True) != module_dir
                or not directory.is_relative_to(module_dir) or directory.resolve(strict=True) != directory
                or module.get("Replace") or not module.get("Sum")
                or package.get("HFiles") or package.get("SysoFiles")):
            raise ValueError("unproved verified-module assembly context")
        for name in package.get("SFiles", []):
            if not re.fullmatch(r"[A-Za-z0-9_.-]+\.[sS]", name):
                raise ValueError("unsupported assembly source identity")
            raw = regular_canonical(directory / name, module_dir)
            for line in raw.split(b"\n"):
                if b"#" not in line:
                    continue
                match = re.fullmatch(rb' *#include "([A-Za-z0-9_.-]+\.h)" *', line)
                if not match:
                    raise ValueError("unsupported module assembly preprocessor syntax")
                basename = match[1].decode("ascii")
                # CWD and original .s directory coincide in the Go builder.
                # HFiles would introduce renamed object-directory shadows; the
                # generated object header is never admitted by this subset.
                if basename == "go_asm.h" or os.path.lexists(directory / basename):
                    raise ValueError("module assembly include shadow")
                regular_canonical(pathlib.Path(include) / basename, include)
        package["ControllerAssembly"] = "verified-module-literal-includes/v1"


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
    result = subprocess.run(["/opt/go/bin/go", "list", "-mod=readonly", "-deps", "-json", "./cmd/pilot"], env=env, stdout=subprocess.PIPE)
    if result.returncode:
        raise SystemExit(result.returncode)
    try:
        decoder, packages, offset = json.JSONDecoder(), [], 0
        text = result.stdout.decode("utf-8")
        while offset < len(text):
            while offset < len(text) and text[offset].isspace():
                offset += 1
            if offset == len(text):
                break
            package, offset = decoder.raw_decode(text, offset)
            if not isinstance(package, dict):
                raise ValueError("invalid Go package")
            packages.append(package)
        audit_module_assembly(packages)
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit("unproved native module assembly/header context")
    for package in packages:
        print(json.dumps(package, separators=(",", ":")))
    raise SystemExit(0)
elif args[0] == "go-verify":
    args = ["/opt/go/bin/go", "mod", "verify"]
elif args[0] == "inventory":
    args = ["ansible-inventory"] + args[1:]
elif args[0] != "ansible-playbook":
    raise SystemExit("unsupported controller entry point")
os.execvpe(args[0], args, env)
