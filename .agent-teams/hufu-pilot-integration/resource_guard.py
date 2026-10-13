#!/usr/bin/env python3
"""Team-owned resource policy and supervision of the fixed EXECUTE workflow."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from campaign_evidence import pin_sources, seal_failure, seal_success, record_stage

TEAM = Path(__file__).resolve().parent
PROJECT = TEAM.parent.parent
HOSTS = ("nexus", "client-vm", "freeipa-server")
PROGRESS_PREFIX = "HUFU_ACTION_PROGRESS "


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate resource policy field")
        result[key] = value
    return result


def load_policy():
    policy = json.loads((TEAM / "resource-policy.json").read_text(), object_pairs_hook=strict_pairs)
    if not isinstance(policy, dict):
        raise ValueError("resource policy must be an object")
    override = json.loads(os.environ.get("HUFU_RESOURCE_POLICY", "{}"), object_pairs_hook=strict_pairs)
    if not isinstance(override, dict) or set(override) - set(policy):
        raise ValueError("resource policy contains unknown fields")
    policy.update(override)
    if type(policy.get("version")) is not int or policy["version"] != 1:
        raise ValueError("unsupported resource policy version")
    limits = {
        "sample_interval_seconds": (5, 60), "probe_timeout_seconds": (1, 10),
        "stale_after_seconds": (10, 300), "consecutive_samples": (2, 10),
        "max_unknown_guest_samples": (3, 20), "host_min_available_mib": (128, 8192),
        "guest_min_available_mib": (32, 2048), "pressure_full_avg60_percent": (5, 90),
    }
    if not isinstance(policy, dict) or set(policy) != set(limits) | {"version", "stop_vms_on_resource_failure"}:
        raise ValueError("resource policy schema fields do not match")
    for name, (minimum, maximum) in limits.items():
        value = policy[name]
        if type(value) not in (int, float) or not math.isfinite(value) or not minimum <= value <= maximum:
            raise ValueError("invalid resource policy field: " + name)
    for name in ("consecutive_samples", "max_unknown_guest_samples"):
        if type(policy[name]) is not int:
            raise ValueError("resource policy sample counts must be integers")
    if type(policy["stop_vms_on_resource_failure"]) is not bool:
        raise ValueError("stop_vms_on_resource_failure must be boolean")
    return policy


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def terminate(process):
    # The child owns a separate group; stop all ordinary descendants, then
    # bound reaping even if one of them is holding an inherited output pipe.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=0.03)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        return False
    return True


def probe(argv, timeout):
    process = subprocess.Popen(argv, cwd=PROJECT, start_new_session=True,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        if process.returncode or len(output) > 32768:
            raise ValueError("resource probe failed")
        return output
    finally:
        terminate(process)


def parse_memory(meminfo, pressure, vmstat, boot_id):
    for line in meminfo.splitlines():
        if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:")) and line.split()[-1] != "kB":
            raise ValueError("memory sample unit is not KiB")
    memory = {line.split(":", 1)[0]: int(line.split()[1])
              for line in meminfo.splitlines() if line.startswith(("MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"))}
    if not 0 <= memory["MemAvailable"] <= memory["MemTotal"] or memory["MemTotal"] <= 0:
        raise ValueError("invalid memory sample")
    full = next(line for line in pressure.splitlines() if line.startswith("full "))
    psi = float(dict(field.split("=", 1) for field in full.split()[1:])["avg60"])
    if not math.isfinite(psi) or not 0 <= psi <= 100:
        raise ValueError("invalid memory pressure sample")
    oom = next(int(line.split()[1]) for line in vmstat.splitlines() if line.startswith("oom_kill "))
    if oom < 0 or not boot_id.strip():
        raise ValueError("invalid OOM counter or boot identity")
    return {"valid": True, "sampled_at": time.time(), "mem_total_kib": memory["MemTotal"],
            "mem_available_kib": memory["MemAvailable"], "swap_used_kib": memory.get("SwapTotal", 0) - memory.get("SwapFree", 0),
            "pressure_full_avg60_percent": psi, "oom_kill": oom, "boot_id": boot_id.strip()}


def sample_host():
    proc = Path("/proc")
    return parse_memory((proc / "meminfo").read_text(), (proc / "pressure/memory").read_text(),
                        (proc / "vmstat").read_text(), (proc / "sys/kernel/random/boot_id").read_text())


def sample_guest(name, policy):
    timeout = policy["probe_timeout_seconds"]
    balloon = {}
    try:
        text = probe(["virsh", "-c", "qemu:///system", "dommemstat", name], timeout)
        balloon = {line.split()[0]: int(line.split()[1]) for line in text.splitlines() if len(line.split()) == 2}
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    fresh = 0 <= time.time() - balloon.get("last_update", 0) <= policy["stale_after_seconds"]
    # QEMU RSS is host process RSS, not guest memory availability. Even fresh
    # balloon statistics do not provide an OOM counter; always read the guest.
    command = ("set -eu; cat /proc/meminfo; cat /proc/pressure/memory; "
               "cat /proc/vmstat; printf '\\n__HUFU_BOOT_ID='; "
               "cat /proc/sys/kernel/random/boot_id; printf '__HUFU_RESOURCE_RC=0\\n'")
    try:
        output = probe([str(PROJECT / "pilot"), "vm-target", "exec", "--name", name,
                        "--", "bash", "-c", command], timeout)
        if not output.rstrip().endswith("__HUFU_RESOURCE_RC=0") or output.count("__HUFU_RESOURCE_RC=") != 1:
            raise ValueError("missing guest exit evidence")
        boot = next(line.split("=", 1)[1] for line in output.splitlines() if line.startswith("__HUFU_BOOT_ID="))
        result = parse_memory(output, output, output, boot)
        result["source"] = "guest_proc"
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError):
        result = {"valid": False, "reason": "guest_resource_probe_unavailable"}
    result["balloon"] = {"fresh": fresh, "last_update": balloon.get("last_update"), "qemu_rss_kib": balloon.get("rss")}
    return result


def sample(policy, checkpoint):
    guests = {}
    if (checkpoint / "facts/topology-inventory.json").is_file():
        guests = {name: sample_guest(name, policy) for name in HOSTS}
    try:
        host = sample_host()
    except (OSError, ValueError, KeyError, StopIteration):
        host = {"valid": False, "reason": "host_resource_probe_unavailable"}
    return {"version": 1, "observed_at": datetime.now(timezone.utc).isoformat(), "host": host, "guests": guests}


class ResourceDecision:
    def __init__(self, policy):
        self.policy, self.counts, self.baselines = policy, {}, {}

    def observe(self, snapshot):
        subjects = {"host": snapshot["host"], **snapshot["guests"]}
        reasons = []
        for name, value in subjects.items():
            fresh = 0 <= time.time() - value.get("sampled_at", 0) <= self.policy["stale_after_seconds"]
            if not value["valid"] or not fresh:
                self.counts[name] = 0
                unknown = name + ":unknown"
                self.counts[unknown] = self.counts.get(unknown, 0) + 1
                limit = 1 if name == "host" else self.policy["max_unknown_guest_samples"]
                if self.counts[unknown] >= limit:
                    reasons.append(name + ":resource_observation_unavailable")
                continue
            self.counts[name + ":unknown"] = 0
            key = (name, value["boot_id"])
            previous = self.baselines.get(key, value["oom_kill"])
            self.baselines[key] = value["oom_kill"]
            if value["oom_kill"] > previous:
                reasons.append(name + ":oom_kill")
            minimum = self.policy["host_min_available_mib" if name == "host" else "guest_min_available_mib"]
            low = value["mem_available_kib"] < minimum * 1024
            pressure = value["pressure_full_avg60_percent"] >= self.policy["pressure_full_avg60_percent"]
            self.counts[name] = self.counts.get(name, 0) + 1 if low or pressure else 0
            if self.counts[name] >= self.policy["consecutive_samples"]:
                reasons.append(name + (":memory_available_below_policy" if low else ":sustained_memory_pressure"))
        return reasons


def stop_vms(policy):
    results = {}
    for name in HOSTS:
        try:
            state = probe(["virsh", "-c", "qemu:///system", "domstate", name], 5).strip()
            if state != "shut off":
                probe(["virsh", "-c", "qemu:///system", "shutdown", name], 5)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    time.sleep(5)
    for name in HOSTS:
        try:
            state = probe(["virsh", "-c", "qemu:///system", "domstate", name], 5).strip()
            if state != "shut off":
                probe(["virsh", "-c", "qemu:///system", "destroy", name], 5)
            results[name] = {"state": probe(["virsh", "-c", "qemu:///system", "domstate", name], 5).strip()}
        except (OSError, ValueError, subprocess.SubprocessError):
            results[name] = {"state": "unknown", "reason": "stop_not_confirmed"}
    return results


def supervise(argv, policy, checkpoint, sampler=sample, stopper=stop_vms):
    checkpoint.mkdir(parents=True, exist_ok=True)
    policy_path = checkpoint / "facts/resource-policy.json"
    if policy_path.exists() and json.loads(policy_path.read_text()) != policy:
        raise ValueError("resource policy changed since campaign startup")
    write_json(policy_path, policy)
    decision = ResourceDecision(policy)
    process = None
    try:
        while True:
            if process is not None and process.poll() is not None:
                return process.returncode, None
            snapshot = sampler(policy, checkpoint)
            trace = checkpoint / "logs/resource-samples.jsonl"
            trace.parent.mkdir(parents=True, exist_ok=True)
            with trace.open("a") as stream:
                trace.chmod(0o600)
                stream.write(json.dumps(snapshot) + "\n")
            reasons = decision.observe(snapshot)
            if process is None and snapshot["host"]["valid"]:
                if snapshot["host"]["mem_available_kib"] < policy["host_min_available_mib"] * 1024:
                    reasons.append("host:preflight_available_below_policy")
                if snapshot["host"]["pressure_full_avg60_percent"] >= policy["pressure_full_avg60_percent"]:
                    reasons.append("host:preflight_memory_pressure")
            print(PROGRESS_PREFIX + json.dumps({"version": 1, "kind": "heartbeat", "stage": "resource_monitor", "message": "resource sample captured"}), file=sys.stderr, flush=True)
            if reasons:
                confirmed = process is None or terminate(process)
                stop_required = policy["stop_vms_on_resource_failure"] and process is not None
                result = {"version": 1, "status": "stopped" if confirmed else "blocked", "stop_reason": "resource_policy",
                          "reasons": reasons, "last_sample": snapshot, "vm_stop_results": {},
                          "workflow_stop_confirmed": confirmed, "vm_shutdown_state": "pending" if stop_required else "skipped",
                          "policy_sha256": hashlib.sha256(json.dumps(policy, sort_keys=True).encode()).hexdigest()}
                record = checkpoint / "receipts/resource-stop.json"
                write_json(record, result)
                if stop_required:
                    result["vm_stop_results"] = stopper(policy)
                    result["vm_shutdown_state"] = ("completed" if all(result["vm_stop_results"].get(name, {}).get("state") == "shut off" for name in HOSTS) else "unconfirmed")
                    write_json(record, result)
                return 75, result
            if process is None:
                process = subprocess.Popen(argv, cwd=PROJECT, start_new_session=True, stdout=sys.stderr, stderr=sys.stderr)
            deadline = time.monotonic() + policy["sample_interval_seconds"]
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    return process.returncode, None
                time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    finally:
        if process is not None:
            terminate(process)


class StopSignal(Exception):
    def __init__(self, number):
        self.number = number


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    checkpoint = None
    try:
        policy = load_policy()
        if args.check:
            return 0
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        if not command:
            raise ValueError("resource guard requires an explicit command")
        checkpoint = Path(os.environ["HUFU_CHECKPOINT_WORKSPACE"])
        def on_signal(number, _frame):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            raise StopSignal(number)
        for number in (signal.SIGINT, signal.SIGTERM):
            signal.signal(number, on_signal)
        pin_sources(checkpoint, PROJECT)
        old_manifest = checkpoint / "receipts/evidence-manifest.json"
        if old_manifest.exists():
            previous = json.loads(old_manifest.read_text())
            previous["pipeline_complete"] = False
            write_json(old_manifest, previous)
        record_stage(checkpoint, "campaign", "started")
        code, stopped = supervise(command, policy, checkpoint)
        code = code if code >= 0 else 128 - code
        if stopped is not None:
            record_stage(checkpoint, "campaign", "resource_stop", exit_code=code)
            seal_failure(checkpoint, "stopped", code, "resource_policy")
            print(json.dumps({"error": {"failure_class": "environment", "message": "resource policy stopped workflow; see " + str(checkpoint / "receipts/resource-stop.json")}}))
        elif code:
            record_stage(checkpoint, "campaign", "cancelled" if code in (130, 143) else "failed", exit_code=code)
            seal_failure(checkpoint, "cancelled" if code in (130, 143) else "failed", code, "workflow_exit")
            print(json.dumps({"error": {"failure_class": "execution", "message": "workflow failed; see " + str(checkpoint / "receipts/failed-evidence.json")}}))
        else:
            seal_success(checkpoint, PROJECT)
        return code
    except StopSignal as stopped:
        if checkpoint is not None:
            record_stage(checkpoint, "campaign", "cancelled", exit_code=128 + stopped.number)
            seal_failure(checkpoint, "cancelled", 128 + stopped.number, "operator_signal")
        return 128 + stopped.number
    except (ValueError, KeyError, OSError, RuntimeError) as error:
        if checkpoint is not None:
            record_stage(checkpoint, "campaign", "failed", exit_code=75)
            seal_failure(checkpoint, "failed", 75, "supervisor_contract")
        print(json.dumps({"error": {"failure_class": "environment", "message": "resource guard could not establish its contract: " + type(error).__name__}}))
        return 75


if __name__ == "__main__":
    sys.exit(main())
