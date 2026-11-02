#!/usr/bin/env python3
"""Record and audit Go CI executions; raw streams stay in CI artifacts."""
import argparse
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import sys
import time


SCHEMA = 1
GROUPS = ("spec", "cmd", "rest")


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
            "platform": platform.system() + "/" + platform.machine()}


def record(command, directory, group):
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
    report = {"schema_version": SCHEMA, "mode": "baseline", "group": group,
              "identity": identity(), "command": command,
              "started_at": datetime.now(timezone.utc).isoformat(), "success": False}
    started = time.monotonic()
    code = 2
    try:
        with (target / "events.jsonl").open("wb") as stdout, (target / "stderr.log").open("wb") as stderr:
            code = subprocess.run(command, stdout=stdout, stderr=stderr, check=False).returncode
        report["exit_code"] = code
        parsed = events_report(target / "events.jsonl")
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
        if report.get("schema_version") != SCHEMA or report.get("success") is not True or report.get("exit_code") != 0:
            raise ValueError(f"unsuccessful report: {path}")
        parsed = events_report(path.parent / "events.jsonl")
        if parsed["packages"] != report.get("packages") or parsed["tests"] != report.get("tests"):
            raise ValueError(f"report does not match actual events: {path}")
        reports.append(report)
    if not reports:
        raise ValueError("no reports supplied")
    return reports


def weights(reports):
    samples = {}
    sources = []
    for report in reports:
        if report.get("mode") != "baseline" or report["identity"].get("dirty"):
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="operation", required=True)
    run = subs.add_parser("record")
    run.add_argument("command", nargs=argparse.REMAINDER)
    for operation in ("weights", "summarize"):
        sub = subs.add_parser(operation)
        sub.add_argument("--output", required=True)
        sub.add_argument("reports", nargs="+")
    args = parser.parse_args(argv)
    try:
        if args.operation == "record":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            return record(command, os.environ["GO_TEST_REPORT_DIR"], os.environ["PILOT_TEST_SHARD"])
        reports = verified_reports(args.reports)
        result = weights(reports) if args.operation == "weights" else summarize(reports)
        write_json(args.output, result)
        print(f"{args.operation}: {len(reports)} verified reports -> {args.output}")
        return 0
    except (KeyError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Go CI evidence rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
