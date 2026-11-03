#!/usr/bin/env python3
"""Check the generated session-store endpoint without trusting an HTTP status alone.

Linux only. The config reader accepts the scalar ingest fields emitted by the
apply playbook; it deliberately fails on other YAML syntax instead of guessing.
It is not a general YAML parser or a replacement for the service's KnownFields
parser. No keys, tokens or recording data are read.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


UNIT = "pilot-session-store.service"


def service_state():
    result = subprocess.run(
        ["systemctl", "show", UNIT, "--property=LoadState", "--property=ActiveState", "--property=MainPID"],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if result.returncode:
        raise RuntimeError("systemctl discovery failed: " + result.stderr.strip())
    state = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if not {"LoadState", "ActiveState", "MainPID"} <= state.keys() or not state["MainPID"].isdigit():
        raise RuntimeError("systemctl discovery returned incomplete/invalid state: " + result.stdout.strip())
    return state


def listener_inodes(port):
    inodes = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in Path(table).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port:
                inodes.add(fields[9])
    return inodes


def check_owner(port, require_listener):
    state = service_state()
    listeners = listener_inodes(port)
    if not listeners and not require_listener:
        return
    if state["LoadState"] != "loaded" or state["ActiveState"] != "active" or int(state["MainPID"]) <= 0:
        raise RuntimeError("session-store is not active: " + json.dumps(state))
    if not listeners:
        raise RuntimeError("session-store has no listener on port " + str(port))
    owned = set()
    for fd in Path("/proc/" + state["MainPID"] + "/fd").iterdir():
        try:
            target = os.readlink(fd)
        except FileNotFoundError:
            continue  # descriptor closed while enumerating
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            owned.add(match.group(1))
    if not listeners <= owned:
        raise RuntimeError("session-store MainPID=" + state["MainPID"] + " does not own every listener on port " + str(port))


def scalar(value):
    if value.startswith('"'):
        return json.loads(value)
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    if not value or any(c in value for c in "#{}[]&*!|>"):
        raise ValueError("unsupported generated ingest scalar")
    return value


def endpoint(config):
    ingest = {}
    section = None
    for line in Path(config).read_text().splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        top = re.fullmatch(r"([a-z_]+):\s*", line)
        if top:
            section = top.group(1)
            continue
        if section == "ingest":
            match = re.fullmatch(r"  ([a-z_]+):\s*(.+)", line)
            if not match or match.group(1) in ingest:
                raise ValueError("unsupported/duplicate generated ingest field")
            ingest[match.group(1)] = scalar(match.group(2).strip())
    address = ingest["listen_addr"]
    if not isinstance(address, str) or not isinstance(ingest["tls_cert_file"], str):
        raise ValueError("generated ingest address/certificate path must be strings")
    port = int(address.rsplit(":", 1)[1])
    return port, ingest["tls_cert_file"]


def configured_fqdn(args):
    # Expected identity comes from operator configuration, never from the
    # certificate being tested. Reusing a stale tracked certificate must fail.
    fqdn = args.fqdn if args.fqdn is not None else Path(args.fqdn_file).read_text().removesuffix("\n")
    label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    if len(fqdn) > 253 or not re.fullmatch(label + r"(?:\." + label + r")*", fqdn):
        raise ValueError("invalid configured ingest FQDN: " + repr(fqdn))
    return fqdn


def diagnostics(port, cert_file):
    # NRestarts is historical context, never a readiness predicate.
    commands = [
        ["systemctl", "show", UNIT, "--property=LoadState", "--property=ActiveState", "--property=MainPID", "--property=Result", "--property=ExecMainStatus", "--property=NRestarts"],
        ["journalctl", "--unit=" + UNIT, "--no-pager", "-n", "50"],
    ]
    if port:
        commands.append(["ss", "-Hltnp", "sport = :" + str(port)])
    if cert_file:
        commands.append(["getcert", "list", "-f", cert_file])
    for command in commands:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
            print("diagnostic " + " ".join(command) + " rc=" + str(result.returncode), file=sys.stderr)
            print((result.stdout + result.stderr)[-65536:], file=sys.stderr)
        except (OSError, subprocess.TimeoutExpired) as exc:
            print("diagnostic unavailable: " + str(exc), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--port", type=int, help="read-only preflight before mutation")
    mode.add_argument("--config", help="deployed playbook-generated session-store.yaml")
    identity = parser.add_mutually_exclusive_group()
    identity.add_argument("--fqdn", help="configured ingest TLS hostname")
    identity.add_argument("--fqdn-file", help="root-owned configured ingest hostname sidecar")
    parser.add_argument("--ca-file", default="/etc/ipa/ca.crt")
    args = parser.parse_args()
    if args.config and args.fqdn is None and args.fqdn_file is None:
        parser.error("--config requires exactly one of --fqdn or --fqdn-file")
    if args.port is not None and (args.fqdn is not None or args.fqdn_file is not None):
        parser.error("--port preflight does not accept TLS identity arguments")
    port, cert_file = args.port, None
    try:
        if args.config:
            port, cert_file = endpoint(args.config)
            fqdn = configured_fqdn(args)
        if not 1 <= port <= 65535:
            raise ValueError("invalid ingest port: " + str(port))
        check_owner(port, require_listener=bool(args.config))
        if args.config:
            result = subprocess.run([
                "curl", "--noproxy", "*", "--silent", "--show-error", "--cacert", args.ca_file,
                "--max-time", "5", "--resolve", fqdn + ":" + str(port) + ":127.0.0.1",
                "--output", "/dev/null", "--write-out", "%{http_code}",
                "https://" + fqdn + ":" + str(port) + "/v1/sessions/start",
            ], capture_output=True, text=True, timeout=10, check=False)
            if result.returncode or not re.fullmatch(r"[45]\d\d", result.stdout):
                raise RuntimeError("ingest TLS probe failed: curl rc=" + str(result.returncode) + " HTTP=" + result.stdout + " " + result.stderr.strip())
            check_owner(port, require_listener=True)  # preflight is not a socket reservation
            print("session-store active; MainPID owns port " + str(port) + "; trusted TLS identity " + fqdn + "; HTTP=" + result.stdout)
        else:
            print("ingest port " + str(port) + " is free or owned by the active session-store MainPID")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("session-store endpoint check failed: " + str(exc), file=sys.stderr)
        diagnostics(port, cert_file)
        return 1


if __name__ == "__main__":
    sys.exit(main())
