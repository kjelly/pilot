#!/usr/bin/env python3
"""Pre-mutation source snapshots and observational stage/failure evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import stat
import subprocess
import sys
import time
import uuid

TEAM = Path(__file__).resolve().parent
PROJECT = TEAM.parent.parent
SOURCE_ROOTS = ("cmd", "internal", "playbooks", "templates", "scripts",
                "contracts", "group_vars", "ansible_callback", "monitoring",
                "docs/verification", "docs/topologies", ".agent-teams/hufu-pilot-integration")
SOURCE_FILES = ("pilot", "go.mod", "go.sum", "run.sh", "docs/runbooks/minimal-poc-architecture.md",
                "docs/topologies/minimal-poc-topology.yaml", "ansible.cfg")
PIPELINE_STAGES = ("prepare-topology", "capture-topology-inventory-facts", "author-structured-actions",
                   "validate-structured-actions", "run-structured-actions")
EXCLUDED = {"__pycache__", ".git", ".vault", "tmp", "node_modules"}


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    if not stat.S_ISREG(path.stat().st_mode):
        raise RuntimeError("evidence source is not a regular file")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            result.update(data)
    return result.hexdigest()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x") as stream:
        temporary.chmod(0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def sources(project):
    paths = []
    for relative in SOURCE_FILES:
        path = project / relative
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(project.resolve()):
            raise RuntimeError("required source missing or symlink: " + relative)
        paths.append(path)
    for relative in SOURCE_ROOTS:
        base = project / relative
        if not base.exists():
            continue
        if base.is_symlink() or not base.is_dir() or not base.resolve().is_relative_to(project.resolve()):
            raise RuntimeError("source root is a symlink: " + relative)
        for directory, children, files in os.walk(base, followlinks=False):
            children[:] = sorted(name for name in children if name not in EXCLUDED)
            for name in children + files:
                path = Path(directory) / name
                if path.is_symlink():
                    raise RuntimeError("source symlink is not permitted")
            for name in sorted(files):
                if name.endswith((".pyc", ".pyo", ".swp")) or name.startswith(".env"):
                    continue
                paths.append(Path(directory) / name)
    return {str(path.relative_to(project)): digest(path) for path in sorted(set(paths))}


def pin_sources(root, project=PROJECT):
    path = root / "facts/source-snapshot.json"
    current = sources(project)
    modes = {name: (project / name).stat().st_mode & 0o777 for name in current}
    if path.exists():
        pinned = json.loads(path.read_text())
        if pinned.get("version") != 1 or pinned.get("sources") != current or pinned.get("modes") != modes:
            raise RuntimeError("campaign source inventory changed")
        return pinned
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=project,
                              capture_output=True, text=True, check=False)
    value = {"version": 1, "captured_at": now(), "revision": revision.stdout.strip() if revision.returncode == 0 else None,
             "sources": current, "modes": modes}
    write_json(path, value)
    return value


def verify_sources(root, project=PROJECT):
    pinned = json.loads((root / "facts/source-snapshot.json").read_text())
    current = sources(project)
    modes = {name: (project / name).stat().st_mode & 0o777 for name in current}
    if pinned.get("version") != 1 or pinned.get("sources") != current or pinned.get("modes") != modes:
        raise RuntimeError("campaign source inventory changed")
    return pinned["sources"]


def progress(stage, status):
    print("HUFU_ACTION_PROGRESS " + json.dumps({"version": 1, "kind": "stage", "stage": stage,
          "status": status, "message": "campaign stage " + status}), file=sys.stderr, flush=True)


def record_stage(root, stage, status, log=None, exit_code=None):
    if not stage or len(stage) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for c in stage):
        raise ValueError("invalid stage identity")
    path = root / "logs/stages.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {"version": 1, "stage": stage, "status": status, "observed_at": now(), "exit_code": exit_code}
    if log is not None and log.exists():
        if log.is_symlink() or not log.resolve().is_relative_to(root.resolve()):
            raise RuntimeError("stage log escapes checkpoint")
        value.update(log=str(log.relative_to(root)), log_sha256=digest(log), log_bytes=log.stat().st_size)
    with path.open("a") as stream:
        path.chmod(0o600)
        stream.write(json.dumps(value) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    progress(stage, "completed" if status == "completed" else "started" if status == "started" else "failed")


def proof_hashes(root):
    paths = []
    for name in ("logs", "reports", "facts"):
        base = root / name
        if base.exists():
            if base.is_symlink() or not base.resolve().is_relative_to(root.resolve()):
                raise RuntimeError("proof directory escapes checkpoint")
            for path in base.rglob("*"):
                if path.is_symlink():
                    raise RuntimeError("proof symlink is not permitted")
                if path.is_file() and not path.name.endswith(".tmp"):
                    paths.append(path)
    return {str(path.relative_to(root)): digest(path) for path in sorted(paths)}


def seal_failure(root, status, exit_code, reason):
    # Metadata never includes argv, stdin, exception messages or credentials.
    # Every seal has a fresh immutable path, so resume preserves prior failures.
    captured = proof_hashes(root)
    stop = root / "receipts/resource-stop.json"
    if stop.exists():
        captured["receipts/resource-stop.json"] = digest(stop)
    directory = "receipts/failures/" + uuid.uuid4().hex
    proofs, originals = {}, {}
    for original, expected in captured.items():
        relative = directory + "/proofs/" + original
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / original, target)
        target.chmod(0o600)
        if digest(target) != expected:
            raise RuntimeError("proof changed while failure was being sealed")
        proofs[relative], originals[relative] = expected, original
    value = {"version": 1, "status": status, "exit_code": exit_code, "reason": reason,
             "sealed_at": now(), "proofs": proofs, "original_paths": originals}
    stages = root / "logs/stages.jsonl"
    rows = [json.loads(line) for line in stages.read_text().splitlines()] if stages.exists() else []
    value["last_stage"] = next((row for row in reversed(rows) if row["stage"] != "campaign"), None)
    value["last_failed_command"] = next((row for row in reversed(rows)
        if row["stage"] not in (*PIPELINE_STAGES, "campaign") and row["status"] in ("failed", "timeout", "cancelled")), None)
    name = directory + "/manifest.json"
    write_json(root / name, value)
    write_json(root / "receipts/failed-evidence.json", {"version": 1, "manifest": name, "sha256": digest(root / name)})
    return value


def verify_pipeline(root, require_completed=True):
    stages = [json.loads(line) for line in (root / "logs/stages.jsonl").read_text().splitlines()]
    latest, positions, campaign = {}, {}, None
    for index, value in enumerate(stages):
        if value["stage"] == "campaign" and value["status"] == "started":
            latest.clear()
            positions.clear()
            campaign = "started"
        elif value["stage"] == "campaign":
            campaign = value["status"]
        else:
            latest[value["stage"]] = value["status"]
            positions[value["stage"]] = index
    if any(latest.get(name) != "completed" for name in PIPELINE_STAGES):
        raise RuntimeError("campaign pipeline has unfinished stages")
    order = [positions[name] for name in PIPELINE_STAGES]
    if order != sorted(order) or campaign != ("completed" if require_completed else "started"):
        raise RuntimeError("campaign pipeline ordering or terminal state is invalid")


def seal_success(root, project=PROJECT):
    source_hashes = verify_sources(root, project)
    execution = json.loads((root / "receipts/execution.json").read_text())
    manifest_path = root / "receipts/evidence-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if execution.get("status") != "passed" or manifest.get("sources") != source_hashes:
        raise RuntimeError("successful campaign lacks bound execution evidence")
    verify_pipeline(root, require_completed=False)
    record_stage(root, "campaign", "completed", exit_code=0)
    manifest["proofs"].update(proof_hashes(root))
    manifest["proofs"]["receipts/execution.json"] = digest(root / "receipts/execution.json")
    manifest["pipeline_complete"] = True
    write_json(manifest_path, manifest)


class CampaignCancelled(Exception):
    def __init__(self, number):
        self.number = number


def install_signal_handlers():
    def handler(number, _frame):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        raise CampaignCancelled(number)
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, handler)


def kill_group(process):
    if process is not None:
        # script(1) owns a separate PTY session. Give it TERM so it can forward
        # termination before killing ordinary descendants in our group.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=0.03)
        except subprocess.TimeoutExpired:
            pass
        time.sleep(0.03)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    root = Path(os.environ["HUFU_CHECKPOINT_WORKSPACE"])
    install_signal_handlers()
    process = None
    log = root / "logs" / (args.stage + ".log")
    try:
        verify_sources(root)
        record_stage(root, args.stage, "started")
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a") as stream:
            log.chmod(0o600)
            start = stream.tell()
            # Stay in the supervisor's group; stage wrappers must not escape it.
            process = subprocess.Popen(command, cwd=PROJECT, stdout=stream, stderr=subprocess.STDOUT)
            # Tail the regular log file to relay only bounded progress frames.
            # This avoids an inherited pipe keeping the supervisor alive.
            with log.open() as reader:
                reader.seek(start)
                pending = ""
                while True:
                    data = reader.read(4096)
                    if data:
                        pending += data
                        while "\n" in pending:
                            line, pending = pending.split("\n", 1)
                            if line.startswith("HUFU_ACTION_PROGRESS ") and len(line) <= 4096:
                                print(line, file=sys.stderr, flush=True)
                        if len(pending) > 4096:
                            pending = ""
                    elif process.poll() is not None:
                        break
                    else:
                        time.sleep(0.05)
            code = process.wait()
        record_stage(root, args.stage, "completed" if code == 0 else "failed", log, code)
        return code if code >= 0 else 128 - code
    except CampaignCancelled as error:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=0.03)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        record_stage(root, args.stage, "cancelled", log, 128 + error.number)
        return 128 + error.number
    except Exception:
        record_stage(root, args.stage, "failed", log)
        return 1


if __name__ == "__main__":
    sys.exit(main())
