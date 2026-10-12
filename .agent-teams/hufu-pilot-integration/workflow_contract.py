"""Team-owned, fixed Minimal PoC contract; no natural-language interpretation."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess

TEAM = Path(__file__).resolve().parent
PROJECT = TEAM.parent.parent
HOSTS = ("freeipa-server", "nexus", "client-vm")
LOGIN_GROUP = "team-sysops"
SUDO_GROUP = "role-service-admin"
SUDO_COMMAND = "/usr/bin/systemctl status ssh"
DRIFT_COMMAND = "/usr/bin/id"
COMPONENTS = {
    "freeipa-server": "freeipa-server", "docker": "docker",
    "freeipa-nfs-server": "freeipa-nfs-server", "freeipa-nfs-client": "freeipa-nfs-client",
    "seaweedfs-s3": "seaweedfs-s3", "prometheus": "prometheus",
    "thanos-query": "thanos-query", "alertmanager": "alertmanager", "dashboard": "dashboard",
    "log-server": "log-server", "log-shipping": "log-server", "wazuh-manager": "wazuh-manager",
    "wazuh-fim": "wazuh-fim", "audit-log-forwarding": "audit-log-forwarding",
    "restic-backup": "restic-backup", "freeipa-dns-client": "freeipa-dns-client",
    "freeipa-ca-trust": "all", "reverse-proxy": "reverse-proxy",
    "internal-endpoint": "freeipa-server", "host-monitoring": "host-monitoring",
}
# The runbook §1 explicitly excludes fixture-bound client/identity/DNS specs;
# this campaign proves its own alice/bob and DNS state in the §4 checks instead.
SECTIONS = ("4.1", "4.2", "4.3", "4.4", "4.5")
SCENARIOS = ("edit.json", "roster.json", "cycle/disable-allow-all.json", "deploy.json", "components/freeipa-dns-client.json",
             "components/freeipa-ca-trust.json", "components/reverse-proxy.json",
             "reconcile/freeipa-identity.json", "reconcile/freeipa-dns.json",
             "reconcile/internal-endpoint.json", "cycle/revoke.json", "cycle/restore.json")


def checkpoint():
    return Path(os.environ["HUFU_CHECKPOINT_WORKSPACE"])


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def bundle_hash(root):
    digest = hashlib.sha256()
    for name in SCENARIOS:
        path = root / "actions" / name
        digest.update(name.encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def run(name, argv, *, input_text=None, timeout=7200):
    """Store complete diagnostics; secrets supplied on stdin never enter argv/logs."""
    logs = checkpoint() / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    path = logs / (name + ".log")
    with path.open("a+", encoding="utf-8") as stream:
        start = stream.tell()
        try:
            result = subprocess.run(argv, input=input_text, text=True, stdout=stream,
                                    stderr=subprocess.STDOUT, cwd=PROJECT,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            stream.write(f"\n[local timeout={timeout}]\n")
            raise
        stream.flush()
        stream.seek(start)
        output = stream.read()
        stream.seek(0, os.SEEK_END)
        stream.write(f"\n[local exit={result.returncode}]\n")
    if result.returncode:
        raise RuntimeError(f"{name} failed ({result.returncode}); see {path}")
    return output


def remote(name, host, command, *, input_text=None, timeout=180):
    # Pilot vm-target exec intentionally returns 0 for a remote nonzero exit.
    # A final sentinel preserves the actual remote status independently of it.
    wrapper = ("bash -c " + shlex.quote(command) +
               '; rc=$?; printf "\\n__HUFU_REMOTE_RC=%s\\n" "$rc"')
    output = run(name, [str(PROJECT / "pilot"), "vm-target", "exec", "--name", host,
                       "--", "bash", "-c", wrapper], input_text=input_text, timeout=timeout)
    matches = re.findall(r"^__HUFU_REMOTE_RC=(\d+)\s*$", output, re.MULTILINE)
    if len(matches) != 1 or matches[0] != "0" or not output.rstrip().endswith("__HUFU_REMOTE_RC=0"):
        raise RuntimeError(f"{name}: target command failed or missing exit evidence")
    return output[:output.rfind("__HUFU_REMOTE_RC=")].strip()


def recap(path, *, idempotent=False):
    # Restrict assertions to recap lines after PLAY RECAP, not arbitrary task text.
    content = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", path.read_text())
    blocks = content.split("PLAY RECAP")[1:]
    if not blocks:
        raise RuntimeError(f"{path.name}: missing PLAY RECAP")
    seen = set()
    for block in blocks:
        rows = re.findall(r"(?m)^\s*([\w.-]+)\s*:\s*ok=(\d+)\s+changed=(\d+)\s+unreachable=(\d+)\s+failed=(\d+)", block)
        if not rows:
            raise RuntimeError(f"{path.name}: empty PLAY RECAP")
        for host, ok, changed, unreachable, failed in rows:
            # Controller preflight plays also emit recaps. Validate their
            # status, but do not count localhost as a rebuilt target VM.
            if host not in ("localhost", "127.0.0.1"):
                seen.add(host)
            if int(ok) == 0 or int(unreachable) or int(failed) or (idempotent and int(changed)):
                raise RuntimeError(f"{path.name}: failed, empty or non-idempotent recap for {host}")
    return seen


def scenario(name, kind, label=None):
    root = checkpoint()
    log_name = label or name.replace("/", "-").removesuffix(".json")
    run(log_name, ["bash", str(TEAM / "run-in-pty.sh"), str(PROJECT / "pilot"), kind,
                   "--timeout", "2h", "--actions", str(root / "actions" / name),
                   "--trace-out", str(root / "logs" / (log_name + ".jsonl"))])
    return root / "logs" / (log_name + ".log")
