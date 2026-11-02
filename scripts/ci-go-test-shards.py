#!/usr/bin/env python3
"""Record and audit Go CI executions; raw streams stay in CI artifacts."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import statistics
import subprocess
import sys
import time


SCHEMA = 1
GROUPS = ("spec", "cmd", "rest")
ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "scripts/ci-go-test-shards.json"
WEIGHTS = ROOT / "scripts/ci-go-test-weights.json"
PACKAGES = {"spec": "github.com/kjelly/pilot/internal/spec", "cmd": "github.com/kjelly/pilot/cmd/pilot/cmd", "rest": None}


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_config(path=CONFIG):
    value = read_json(path)
    if not isinstance(value, dict) or set(value) != {"schema_version", "groups"} or type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA:
        raise ValueError("invalid shard configuration schema")
    groups = value["groups"]
    if not isinstance(groups, dict) or set(groups) != set(GROUPS):
        raise ValueError("configuration requires exactly spec, cmd and rest")
    for group, package in PACKAGES.items():
        row = groups[group]
        if not isinstance(row, dict) or set(row) != {"package", "shards"} or row["package"] != package:
            raise ValueError(f"invalid package for {group}")
        count = row["shards"]
        if type(count) is not int or not 1 <= count <= (1 if group == "rest" else 3):
            raise ValueError(f"invalid shard count for {group}")
    return value


def matrix(configuration):
    return {"include": [
        {"shard": group if count == 1 else f"{group}-{index + 1}-of-{count}",
         "group": group, "index": index, "total": count}
        for group in GROUPS
        for count in [configuration["groups"][group]["shards"]]
        for index in range(count)]}


def package_inventory():
    groups = {}
    for group in GROUPS:
        output = subprocess.check_output(["bash", str(ROOT / "scripts/ci-go-test-packages.sh"), group], text=True)
        groups[group] = output.split()
        if not groups[group] or len(set(groups[group])) != len(groups[group]):
            raise ValueError(f"empty or duplicate package list for {group}")
        if group != "rest" and groups[group] != [PACKAGES[group]]:
            raise ValueError(f"unexpected {group} package set")
    all_packages = subprocess.check_output(["go", "list", "-race", "./..."], text=True).split()
    combined = sum(groups.values(), [])
    if len(set(combined)) != len(combined) or sorted(combined) != sorted(all_packages):
        raise ValueError("package groups do not cover the module exactly once")
    return groups


def discover(command, package, target):
    """Use the same race build/flags and TestMain as execution, capturing Go's list output."""
    path = Path(target) / "discovery.jsonl"
    with path.open("wb") as stdout, (Path(target) / "discovery.stderr.log").open("wb") as stderr:
        completed = subprocess.run([*command, "-list=^(Test|Example|Fuzz)"], stdout=stdout, stderr=stderr, check=False)
    if completed.returncode != 0:
        raise ValueError(f"Go discovery failed: exit {completed.returncode}")
    return discovered_names(path, package)


def discovered_names(path, package):
    # Also validate the package-level stream and its terminal success.
    parsed = events_report(path)
    if set(parsed["packages"]) != {package} or parsed["tests"]:
        raise ValueError("discovery returned unexpected packages or executed tests")
    names = []
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            event = strict_json(line)
            if event["Action"] != "output":
                continue
            output = event.get("Output", "")
            for name in output.splitlines():
                if re.fullmatch(r"(?:Test|Example|Fuzz)\w*", name):
                    if name == "TestMain":
                        raise ValueError("TestMain is not a runnable test")
                    names.append(name)
                elif not (name == "PASS" or name.startswith(("ok\t", "ok  ", "?\t", "?   "))):
                    raise ValueError(f"unrecognized discovery output: {name[:200]}")
    if not names or len(set(names)) != len(names):
        raise ValueError("empty or duplicate test discovery")
    return sorted(names)


def partition(names, total, measured):
    if type(total) is not int or total < 1 or len(names) < total or len(set(names)) != len(names):
        raise ValueError("invalid or empty partition")
    if any(not isinstance(n, str) or not re.fullmatch(r"(?:Test|Example|Fuzz)\w*", n) or n == "TestMain" for n in names):
        raise ValueError("invalid top-level test name")
    if not isinstance(measured, dict) or any(type(v) is not int or v <= 0 for v in measured.values()):
        raise ValueError("weights must be positive integer milliseconds")
    unknown = sorted(set(names) - measured.keys())
    obsolete = sorted(measured.keys() - set(names))
    costs = {name: measured.get(name, 1000) for name in sorted(names)}
    bins = [[] for _ in range(total)]
    totals = [0] * total
    for name in sorted(names, key=lambda n: (-costs[n], n)):
        index = min(range(total), key=lambda i: (totals[i], i))
        bins[index].append(name)
        totals[index] += costs[name]
    bins = [sorted(bucket) for bucket in bins]
    flat = sum(bins, [])
    if any(not bucket for bucket in bins) or sorted(flat) != sorted(names) or len(set(flat)) != len(flat):
        raise ValueError("partition does not cover every test exactly once")
    return {"discovered": sorted(names), "shards": bins, "weights_ms": costs,
            "totals_ms": totals, "unknown": unknown, "obsolete_weights": obsolete}


def load_weights(path):
    value = read_json(path)
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value.get("schema_version") != SCHEMA or value.get("unit") != "milliseconds" or not value.get("sources"):
        raise ValueError("invalid measured weights metadata")
    if not isinstance(value["sources"], list):
        raise ValueError("weights sources must be a list")
    for source in value["sources"]:
        if (not isinstance(source, dict) or source.get("dirty") is not False
                or any(not isinstance(source.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", source[key]) for key in ("revision", "tree"))
                or any(not isinstance(source.get(key), str) or not source[key] for key in ("run_id", "run_attempt", "go_version", "platform"))):
            raise ValueError("weights must identify their clean measured candidate and toolchain")
    measured = value.get("weights")
    if not isinstance(measured, dict) or not measured:
        raise ValueError("missing measured weights")
    for package, rows in measured.items():
        if not isinstance(package, str) or not isinstance(rows, dict) or any(type(v) is not int or v <= 0 for v in rows.values()):
            raise ValueError("invalid measured weights")
    return measured


def selector(names):
    if not names:
        raise ValueError("empty selector")
    return "^(" + "|".join(re.escape(name) for name in names) + ")$"


def verify_selection(parsed, manifest, index):
    if set(parsed["packages"]) != set(manifest["packages"]):
        raise ValueError("actual packages do not match the manifest")
    if manifest["group"] != "rest":
        actual = sorted(row["name"] for row in parsed["tests"] if "/" not in row["name"])
        if actual != manifest["shards"][index]:
            raise ValueError("actual top-level tests do not match the selected shard")


def prepare(command, target, group, index, config_path=CONFIG, weight_path=WEIGHTS):
    configuration = load_config(config_path)
    entries = matrix(configuration)["include"]
    entry = next((e for e in entries if e["group"] == group and e["index"] == index), None)
    if type(index) is not int or entry is None:
        raise ValueError("invalid shard index")
    packages = package_inventory()[group]
    manifest = {"schema_version": SCHEMA, "group": group, "packages": packages,
                "config_hash": file_hash(config_path), "weights_hash": None}
    if group != "rest":
        names = discover(command, packages[0], target)
        measured = {}
        if entry["total"] > 1:
            measured = load_weights(weight_path).get(packages[0], {})
            if not measured:
                raise ValueError(f"no measured weights for {packages[0]}")
            manifest["weights_hash"] = file_hash(weight_path)
        manifest.update(partition(names, entry["total"], measured))
        if entry["total"] > 1:
            command = [*command, "-run=" + selector(manifest["shards"][index])]
    else:
        manifest["shards"] = [None]
    write_json(Path(target) / "manifest.json", manifest)
    return command, manifest, entry


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_json(path, value):
    Path(path).write_text(canonical(value) + "\n", encoding="utf-8")


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(text, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid number: {value}")))


def read_json(path):
    return strict_json(Path(path).read_text(encoding="utf-8"))


def events_report(path):
    """Validate package/test lifecycles, including legitimate skips and no-test packages."""
    with Path(path).open(encoding="utf-8") as stream:
        return _events_report(stream)


def _events_report(stream):
    packages = {}
    tests = {}
    for number, line in enumerate(stream, 1):
        if not line.endswith("\n"):
            raise ValueError(f"truncated JSON at line {number}")
        event = strict_json(line)
        if not isinstance(event, dict):
            raise ValueError(f"invalid event at line {number}")
        action, package, test = (event.get(k) for k in ("Action", "Package", "Test"))
        if action in {"build-output", "build-fail"}:
            if not isinstance(event.get("ImportPath"), str) or not event["ImportPath"]:
                raise ValueError("build event without ImportPath")
            if action == "build-fail":
                raise ValueError(f"build failure: {event['ImportPath']}")
            continue
        if not isinstance(package, str) or not package or not isinstance(action, str):
            raise ValueError(f"event without package/action at line {number}")
        if action not in {"start", "run", "pause", "cont", "pass", "skip", "fail", "output", "build-output", "build-fail"}:
            raise ValueError(f"unknown event action: {action}")
        if test is not None:
            if not isinstance(test, str) or not test:
                raise ValueError("invalid test name")
            key = (package, test)
            if key not in tests:
                if action != "run":
                    raise ValueError(f"test event before run: {key}")
                tests[key] = {"runs": 0, "verdict": None, "elapsed_seconds": None, "skip_reason": ""}
            row = tests[key]
            if row["verdict"] is not None:
                raise ValueError(f"test event after terminal: {key}")
            if action == "run":
                row["runs"] += 1
                if row["runs"] != 1:
                    raise ValueError(f"duplicate test run: {key}")
            elif action == "output":
                output = event.get("Output", "")
                if not isinstance(output, str):
                    raise ValueError("invalid test output")
                # Keep the last diagnostic, not Go's final '--- SKIP' marker.
                if output.strip() and not output.lstrip().startswith(("===", "---")):
                    row["skip_reason"] = output.strip()[:1000]
            elif action in {"pass", "skip", "fail"}:
                elapsed = event.get("Elapsed", 0)
                if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError("invalid test elapsed time")
                row.update(verdict=action, elapsed_seconds=elapsed)
                if action != "skip":
                    row["skip_reason"] = ""
            elif action not in {"pause", "cont"}:
                raise ValueError(f"invalid test lifecycle action: {action}")
        else:
            row = packages.setdefault(package, {"started": False, "verdict": None, "elapsed_seconds": None})
            if row["verdict"] is not None:
                raise ValueError(f"package event after terminal: {package}")
            if action == "start":
                if row["started"]:
                    raise ValueError(f"duplicate package start: {package}")
                row["started"] = True
            elif action in {"pass", "skip", "fail"}:
                if not row["started"]:
                    raise ValueError(f"package terminal without start: {package}")
                elapsed = event.get("Elapsed", 0)
                if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0:
                    raise ValueError("invalid package elapsed time")
                row.update(verdict=action, elapsed_seconds=elapsed)
            elif action != "output":
                raise ValueError(f"invalid package lifecycle action: {action}")
    if not packages:
        raise ValueError("empty Go event stream")
    for package, row in packages.items():
        if row["verdict"] not in {"pass", "skip"}:
            raise ValueError(f"package did not succeed: {package}")
    for (package, test), row in tests.items():
        if package not in packages or row["verdict"] not in {"pass", "skip"}:
            raise ValueError(f"test did not complete successfully: {package}/{test}")
    return {"packages": packages,
            "tests": [{"package": p, "name": n, **row} for (p, n), row in sorted(tests.items())]}


def identity():
    def output(*args):
        return subprocess.check_output(args, text=True, stderr=subprocess.PIPE).strip()
    return {"revision": output("git", "rev-parse", "HEAD"),
            "tree": output("git", "rev-parse", "HEAD^{tree}"),
            "dirty": bool(output("git", "status", "--porcelain", "--untracked-files=no")),
            "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
            "go_version": output("go", "version"),
            "go_environment": strict_json(output("go", "env", "-json", "GOOS", "GOARCH", "CGO_ENABLED", "GOEXPERIMENT")),
            "goflags_hash": hashlib.sha256(os.environ.get("GOFLAGS", "").encode()).hexdigest(),
            "platform": platform.system() + "/" + platform.machine()}


def record(command, directory, group, index=None, config_path=CONFIG, weight_path=WEIGHTS):
    """Run the unchanged suite with JSON enabled; never hide the child's exit status."""
    if not command or command[0:2] != ["go", "test"] or "-json" not in command:
        raise ValueError("record requires go test with -json")
    if "-race" not in command or "-count=1" not in command:
        raise ValueError("baseline requires -race -count=1")
    forbidden = ("-run", "-skip", "-short", "-bench", "-fuzz", "-list", "-args")
    if any(arg.split("=", 1)[0] in forbidden for arg in command[2:] + shlex.split(os.environ.get("GOFLAGS", ""))):
        raise ValueError("baseline must not filter the full suite")
    if group not in GROUPS:
        raise ValueError("unknown baseline group")
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=False)
    report = {"schema_version": SCHEMA, "mode": "baseline" if index is None else "shard", "group": group,
              "identity": identity(), "command": command,
              "started_at": datetime.now(timezone.utc).isoformat(), "success": False}
    started = time.monotonic()
    code = 2
    try:
        manifest = None
        if index is not None:
            command, manifest, entry = prepare(command, target, group, index, config_path, weight_path)
            report.update(command=command, shard=entry, manifest_digest=digest(manifest))
        with (target / "events.jsonl").open("wb") as stdout, (target / "stderr.log").open("wb") as stderr:
            code = subprocess.run(command, stdout=stdout, stderr=stderr, check=False).returncode
        report["exit_code"] = code
        parsed = events_report(target / "events.jsonl")
        if manifest is not None:
            verify_selection(parsed, manifest, index)
        report.update(parsed)
        report["success"] = code == 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        report["error"] = str(error)
    finally:
        report["wall_seconds"] = time.monotonic() - started
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_json(target / "report.json", report)
    passed = sum(t["verdict"] == "pass" for t in report.get("tests", []))
    skipped = sum(t["verdict"] == "skip" for t in report.get("tests", []))
    print(f"Go {group}: exit={code}, verified={report['success']}, pass={passed}, skip={skipped}, seconds={report['wall_seconds']:.3f}", flush=True)
    if not report["success"]:
        # Keep failure diagnosis visible without flooding successful CI logs.
        for name in ("stderr.log", "events.jsonl"):
            path = target / name
            if path.exists():
                for line in path.read_text(errors="replace").splitlines()[-30:]:
                    print(line, file=sys.stderr)
        if "error" in report:
            print(report["error"], file=sys.stderr)
    return code if code > 0 else (128 - code if code < 0 else (0 if report["success"] else 2))


def verified_reports(paths):
    reports = []
    for path in paths:
        path = Path(path)
        report = read_json(path)
        if not isinstance(report, dict) or type(report.get("schema_version")) is not int or report.get("schema_version") != SCHEMA or report.get("success") is not True or report.get("exit_code") != 0:
            raise ValueError(f"unsuccessful report: {path}")
        parsed = events_report(path.parent / "events.jsonl")
        if parsed["packages"] != report.get("packages") or parsed["tests"] != report.get("tests"):
            raise ValueError(f"report does not match actual events: {path}")
        if report.get("mode") == "shard":
            manifest = read_json(path.parent / "manifest.json")
            if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest.get("schema_version") != SCHEMA:
                raise ValueError("invalid manifest schema")
            if report.get("manifest_digest") != digest(manifest):
                raise ValueError("manifest digest mismatch")
            verify_selection(parsed, manifest, report["shard"]["index"])
            if manifest["group"] != "rest" and discovered_names(path.parent / "discovery.jsonl", manifest["packages"][0]) != manifest["discovered"]:
                raise ValueError("manifest does not match actual discovery")
        reports.append(report)
    if not reports:
        raise ValueError("no reports supplied")
    return reports


def verify_run(directory, config_path=CONFIG, weight_path=WEIGHTS, expected_identity=None, prefix=""):
    """Gate image on the exact matrix artifacts, independently rechecking all event streams."""
    configuration = load_config(config_path)
    entries = matrix(configuration)["include"]
    root = Path(directory)
    if not re.fullmatch(r"[\w-]*", prefix):
        raise ValueError("invalid artifact prefix")
    wanted = {prefix + entry["shard"] for entry in entries}
    if not root.is_dir() or {p.name for p in root.iterdir()} != wanted or any(not p.is_dir() for p in root.iterdir()):
        raise ValueError("artifact directory set does not match the expected matrix")
    reports = verified_reports([root / (prefix + e["shard"]) / "report.json" for e in entries])
    identities = [r["identity"] for r in reports]
    expected_identity = expected_identity or identities[0]
    common = ("revision", "tree", "dirty", "run_id", "run_attempt", "go_version", "platform", "go_environment", "goflags_hash")
    for ident in identities:
        if ident.get("dirty") is not False or any(ident.get(k) != expected_identity.get(k) for k in common):
            raise ValueError("mixed or dirty candidate/run/toolchain identity")
    per_group = {}
    for entry, report in zip(entries, reports):
        if report.get("mode") != "shard" or report.get("group") != entry["group"] or report.get("shard") != entry:
            raise ValueError("artifact shard identity does not match the matrix")
        manifest = read_json(root / (prefix + entry["shard"]) / "manifest.json")
        if manifest["group"] != entry["group"] or manifest["config_hash"] != file_hash(config_path):
            raise ValueError("artifact uses the wrong configuration")
        expected_hash = file_hash(weight_path) if entry["total"] > 1 else None
        if manifest["weights_hash"] != expected_hash:
            raise ValueError("artifact uses the wrong weights")
        if entry["group"] in per_group and manifest != per_group[entry["group"]]:
            raise ValueError("shards disagree about the full partition")
        per_group[entry["group"]] = manifest
    package_sets = []
    actual_inventory = package_inventory()
    for group, manifest in per_group.items():
        package_sets.extend(manifest["packages"])
        if manifest["packages"] != actual_inventory[group]:
            raise ValueError("manifest packages differ from the current module inventory")
        if group == "rest":
            if manifest["shards"] != [None] or not manifest["packages"]:
                raise ValueError("invalid rest manifest")
        else:
            if manifest["packages"] != [PACKAGES[group]]:
                raise ValueError("manifest changed a fixed package")
            measured = load_weights(weight_path).get(PACKAGES[group], {}) if configuration["groups"][group]["shards"] > 1 else {}
            rebuilt = partition(manifest["discovered"], configuration["groups"][group]["shards"], measured)
            for key in rebuilt:
                if rebuilt[key] != manifest[key]:
                    raise ValueError("invalid full partition")
    if len(package_sets) != len(set(package_sets)):
        raise ValueError("overlapping packages in artifacts")
    return summarize(reports)


def compare(directory, control_paths, config_path=CONFIG, weight_path=WEIGHTS, expected_identity=None, prefix=""):
    """Compare full and partitioned observations from the same immutable candidate."""
    summary = verify_run(directory, config_path, weight_path, expected_identity, prefix)
    entries = matrix(load_config(config_path))["include"]
    reports = verified_reports([Path(directory) / (prefix + e["shard"]) / "report.json" for e in entries])
    controls = verified_reports(control_paths)
    expected_identity = expected_identity or reports[0]["identity"]
    if sorted(r.get("group") for r in controls) != ["cmd", "spec"]:
        raise ValueError("comparison requires exactly one complete cmd and spec control")
    comparisons = []
    for control in controls:
        group = control["group"]
        if control.get("mode") != "baseline" or control["identity"] != expected_identity:
            raise ValueError("comparison control uses another candidate, run or environment")
        if set(control["packages"]) != {PACKAGES[group]}:
            raise ValueError("comparison control is not the complete target package")
        selected = [r for r in reports if r["group"] == group]
        def observations(rows):
            out = {}
            for row in rows:
                key = (row["package"], row["name"])
                if key in out:
                    raise ValueError(f"duplicate observation in comparison: {key}")
                out[key] = (row["verdict"], row["skip_reason"] if row["verdict"] == "skip" else "")
            return out
        full = observations(control["tests"])
        split = observations([t for r in selected for t in r["tests"]])
        if full != split:
            differences = sorted(key for key in set(full) | set(split) if full.get(key) != split.get(key))
            raise ValueError(f"full/shard verdict or skip mismatch: {differences[:10]}")
        longest = max(r["wall_seconds"] for r in selected)
        comparisons.append({"group": group, "observations": len(full), "full_seconds": control["wall_seconds"],
                            "max_shard_seconds": longest, "speedup": control["wall_seconds"] / longest if longest else None})
    return {"schema_version": SCHEMA, "identity": expected_identity, "comparisons": comparisons, "shards": summary}


def weights(reports):
    samples = {}
    sources = []
    for report in reports:
        full = report.get("mode") == "baseline" or (report.get("mode") == "shard" and report.get("shard", {}).get("total") == 1)
        if not full or report["identity"].get("dirty") is not False:
            raise ValueError("weights require a clean, full baseline")
        sources.append(report["identity"])
        for row in report["tests"]:
            if "/" not in row["name"]:
                samples.setdefault((row["package"], row["name"]), []).append(row["elapsed_seconds"])
    if not samples:
        raise ValueError("baseline has no top-level tests")
    values = {}
    for (package, test), elapsed in sorted(samples.items()):
        values.setdefault(package, {})[test] = max(1, math.ceil(statistics.median(elapsed) * 1000))
    return {"schema_version": SCHEMA, "unit": "milliseconds", "sources": sources, "weights": values}


def summarize(reports):
    return {"schema_version": SCHEMA, "samples": [
        {"group": r["group"], "identity": r["identity"], "wall_seconds": r["wall_seconds"],
         "package_count": len(r["packages"]),
         "top_level_count": sum("/" not in t["name"] for t in r["tests"]),
         "skips": [{"package": t["package"], "name": t["name"], "reason": t["skip_reason"]}
                   for t in r["tests"] if t["verdict"] == "skip"]} for r in reports]}


def job_timings(jobs, run):
    """Use authoritative Actions timestamps, keeping unavailable durations explicit."""
    def elapsed(start, end):
        if start is None or end is None:
            return None
        first = datetime.fromisoformat(start.replace("Z", "+00:00"))
        last = datetime.fromisoformat(end.replace("Z", "+00:00"))
        if first.tzinfo is None or last.tzinfo is None or last < first:
            raise ValueError("invalid Actions timestamp interval")
        return (last - first).total_seconds()
    if not isinstance(jobs.get("jobs"), list) or not jobs["jobs"]:
        raise ValueError("missing Actions jobs")
    if "total_count" in jobs and jobs["total_count"] != len(jobs["jobs"]):
        raise ValueError("incomplete Actions jobs pagination")
    seen = set()
    rows = []
    for job in jobs["jobs"]:
        if job.get("run_id") != run.get("id") or job.get("id") in seen:
            raise ValueError("mixed run or duplicate Actions job")
        seen.add(job["id"])
        # Skipped jobs allocate no runner; GitHub can even return reversed timestamps.
        skipped = job.get("conclusion") == "skipped"
        complete = job.get("status") == "completed" and not skipped
        execution = elapsed(job.get("started_at"), job.get("completed_at")) if complete else None
        test = next((s for s in job.get("steps", []) if s.get("name") == "go test"), {})
        build = next((s for s in job.get("steps", []) if s.get("name") == "go build"), {})
        rows.append({"id": job["id"], "name": job["name"], "status": job["status"], "conclusion": job.get("conclusion"),
                     "queue_seconds": elapsed(job.get("created_at"), job.get("started_at")) if not skipped else None,
                     "execution_seconds": execution,
                     "before_test_seconds": elapsed(job.get("started_at"), test.get("started_at")),
                     "build_step_seconds": elapsed(build.get("started_at"), build.get("completed_at")),
                     "test_step_seconds": elapsed(test.get("started_at"), test.get("completed_at")),
                     "after_test_seconds": elapsed(test.get("completed_at"), job.get("completed_at")) if complete else None})
    missing = [r["id"] for r in rows if r["execution_seconds"] is None and r["conclusion"] != "skipped"]
    workflow = elapsed(run.get("created_at"), run.get("updated_at")) if run.get("status") == "completed" else None
    return {"run_id": run["id"], "run_attempt": run["run_attempt"], "event": run["event"],
            "status": run["status"], "conclusion": run.get("conclusion"), "workflow_wall_seconds": workflow,
            "known_runner_minutes": sum(r["execution_seconds"] for r in rows if r["execution_seconds"] is not None) / 60,
            "runner_cost_complete": run.get("status") == "completed" and not missing, "missing_execution_durations": missing, "jobs": rows}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="operation", required=True)
    run = subs.add_parser("record")
    run.add_argument("command", nargs=argparse.REMAINDER)
    for operation in ("weights", "summarize"):
        sub = subs.add_parser(operation)
        sub.add_argument("--output", required=True)
        sub.add_argument("reports", nargs="+")
        if operation == "summarize":
            sub.add_argument("--jobs")
            sub.add_argument("--run-metadata")
    config = subs.add_parser("matrix")
    config.add_argument("--config", default=str(CONFIG))
    config.add_argument("--github-output", action="store_true")
    verify = subs.add_parser("verify-run")
    verify.add_argument("directory")
    verify.add_argument("--config", default=str(CONFIG))
    verify.add_argument("--weights", default=str(WEIGHTS))
    verify.add_argument("--output", required=True)
    verify.add_argument("--artifact-prefix", default="")
    comparison = subs.add_parser("compare")
    comparison.add_argument("--shards", required=True)
    comparison.add_argument("--controls", nargs="+", required=True)
    comparison.add_argument("--config", default=str(CONFIG))
    comparison.add_argument("--weights", default=str(WEIGHTS))
    comparison.add_argument("--artifact-prefix", default="")
    comparison.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "record":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if "GO_TEST_RUN_REGEX" in os.environ:
                regex = os.environ["GO_TEST_RUN_REGEX"]
                if not regex or "CI_SHARD_INDEX" in os.environ or os.environ.get("GO_TEST_REPORT_DIR"):
                    raise ValueError("empty or conflicting GO_TEST_RUN_REGEX")
                return subprocess.run([*command, "-run=" + regex], check=False).returncode
            index = int(os.environ["CI_SHARD_INDEX"]) if "CI_SHARD_INDEX" in os.environ else None
            return record(command, os.environ["GO_TEST_REPORT_DIR"], os.environ["PILOT_TEST_SHARD"], index)
        if args.operation == "matrix":
            value = matrix(load_config(args.config))
            if args.github_output:
                print("matrix=" + canonical(value))
                print("max_parallel=" + str(len(value["include"])))
            else:
                print(canonical(value))
            return 0
        if args.operation == "verify-run":
            result = verify_run(args.directory, args.config, args.weights, identity(), args.artifact_prefix)
            write_json(args.output, result)
            print(f"Verified {len(result['samples'])} Go shard artifacts")
            return 0
        if args.operation == "compare":
            result = compare(args.shards, args.controls, args.config, args.weights, identity(), args.artifact_prefix)
            write_json(args.output, result)
            print("Full/shard observations match for cmd and spec")
            return 0
        reports = verified_reports(args.reports)
        result = weights(reports) if args.operation == "weights" else summarize(reports)
        if args.operation == "summarize" and (args.jobs or args.run_metadata):
            if not args.jobs or not args.run_metadata:
                raise ValueError("both jobs and run metadata are required")
            run = read_json(args.run_metadata)
            if any(r["identity"]["run_id"] != str(run["id"]) or r["identity"]["run_attempt"] != str(run["run_attempt"]) for r in reports):
                raise ValueError("Actions metadata belongs to a different report run/attempt")
            result["timing"] = job_timings(read_json(args.jobs), run)
        write_json(args.output, result)
        print(f"{args.operation}: {len(reports)} verified reports -> {args.output}")
        return 0
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Go CI evidence rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
