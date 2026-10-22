#!/usr/bin/env python3
"""Durable SSH-key propagation journal and bounded SSSD key-set verification.

Run through Ansible with JSON on stdin; never handles passwords. Provider calls
are serialized by the identity operator; flock/epoch checks protect journal
updates and reject late acknowledgements. No cached keys are trusted as input
to FreeIPA mutation.
"""

import base64
import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid


def keyset(keys):
    result = set()
    for key in keys:
        parts = key.split()
        if len(parts) < 2 or not parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
            raise ValueError("invalid SSH public key")
        raw = base64.b64decode(parts[1], validate=True)
        # SSH wire format begins with the algorithm string, not a comment.
        size = int.from_bytes(raw[:4], "big")
        if len(raw) < 4 + size or raw[4:4 + size].decode("ascii") != parts[0]:
            raise ValueError("invalid SSH public key algorithm")
        result.add(parts[0] + " " + parts[1])
    return sorted(result)


def refresh(data):
    user, domain = data["user"], data["domain"]
    if not re.fullmatch(r"[a-z_][a-z0-9_.-]*", user):
        raise ValueError("invalid user")
    expected = keyset(data["keys"])
    deadline = time.monotonic() + 30

    def run(argv):
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=max(0.01, deadline - time.monotonic()))

    # An uncached user can make sss_cache return nonzero. Populate through the
    # responder and retry invalidation once, within the SAME overall budget.
    expired = run(["sss_cache", "-d", domain, "-u", user])
    if expired.returncode != 0:
        populated = run(["sss_ssh_authorizedkeys", "-d", domain, user])
        if populated.returncode != 0:
            raise RuntimeError("SSSD initial key lookup failed (rc=%d)" % populated.returncode)
        expired = run(["sss_cache", "-d", domain, "-u", user])
    if expired.returncode != 0:
        raise RuntimeError("SSSD invalidation failed (rc=%d)" % expired.returncode)
    observed = run(["sss_ssh_authorizedkeys", "-d", domain, user])
    if observed.returncode != 0:
        raise RuntimeError("SSSD key lookup failed (rc=%d, invalidate_rc=%d)" %
                           (observed.returncode, expired.returncode))
    if keyset(observed.stdout.splitlines()) != expected:
        raise RuntimeError("SSSD key set does not match desired keys")
    return {"verified": True}


def work(state):
    return [{"user": name, "host": host, "epoch": entry["epoch"],
             "keys": entry["keys"]}
            for name, entry in sorted(state["users"].items())
            for host in sorted(entry["pending"])]


def update(state, action, data):
    users = state["users"]
    if state["domain"] != data["domain"]:
        raise ValueError("journal domain mismatch")
    if action == "auth_prepare":
        previous = state.get("auth_pending", False)
        state["auth_pending"] = True
        return {"previous": previous}
    if action == "auth_settle":
        state["auth_pending"] = bool(data["previous"] or data["changed"])
        return {"dirty": state["auth_pending"]}
    if action == "auth_ack":
        state["auth_pending"] = False
        return {}
    if action == "prepare":
        hosts = sorted(set(data["hosts"]))
        if not hosts:
            raise ValueError("no enrolled inventory hosts")
        prepared = {}
        for item in data["users"]:
            name, keys = item["name"], keyset(item["ssh_keys"])
            if not re.fullmatch(r"[a-z_][a-z0-9_.-]*", name):
                raise ValueError("invalid user")
            if name in prepared:
                raise ValueError("duplicate managed user")
            previous = users.get(name)
            required = sorted(set(hosts) | set(previous["pending"] if previous else []))
            if previous and previous["keys"] == keys:
                # Pending from an interrupted prepare is intentionally retained.
                required = sorted(set(previous["pending"]) |
                                  (set(hosts) - set(previous["hosts"])))
            epoch = uuid.uuid4().hex
            users[name] = {"keys": keys, "epoch": epoch,
                           "hosts": hosts, "pending": sorted(set(hosts) |
                           set(previous["pending"] if previous else []))}
            prepared[name] = {"epoch": epoch, "required": required}
        return {"prepared": prepared}
    if action == "settle":
        changed = set(data["changed_users"])
        for name, before in data["prepared"].items():
            entry = users[name]
            if entry["epoch"] != before["epoch"]:
                raise ValueError("concurrent identity apply; retry serially")
            if name not in changed:
                entry["pending"] = before["required"]
        return {"work": work(state)}
    if action == "ack":
        for pair in data["verified"]:
            entry = users[pair["user"]]
            if entry["epoch"] != pair["epoch"]:
                raise ValueError("stale SSH cache acknowledgement; retry")
            entry["pending"] = [h for h in entry["pending"] if h != pair["host"]]
        return {"pending": [{"host": p["host"], "user": p["user"]}
                            for p in work(state)]}
    raise ValueError("unknown journal action")


def journal(path, action, data):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    with open(path + ".lock", "a", encoding="utf-8") as lock:
        os.chmod(path + ".lock", 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            with open(path, encoding="utf-8") as stream:
                state = json.load(stream)
            if state["version"] != 1 or not isinstance(state["users"], dict):
                raise ValueError("invalid SSH cache journal")
        except FileNotFoundError:
            state = {"version": 1, "domain": data["domain"], "users": {}}
        result = update(state, action, data)
        fd, temporary = tempfile.mkstemp(prefix=".ssh-cache-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return result


def main():
    data = json.load(sys.stdin)
    action = sys.argv[1]
    if action == "refresh":
        result = refresh(data)
    else:
        result = journal(sys.argv[2], action, data)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError,
            subprocess.TimeoutExpired) as error:
        # No child stdout/stderr: they can contain public identity material or
        # unrelated diagnostics. Ansible reports the failed host/user pair.
        print(json.dumps({"error": str(error)}))
        sys.exit(1)
