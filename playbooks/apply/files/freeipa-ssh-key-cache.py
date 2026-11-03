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


def retirement_plan(state, data):
    """Bind explicit roster retirement intent to exact inventory identities."""
    absent = {h["name"].lower() for h in data.get("absent", [])}
    inventory = data.get("inventory", [])
    receipts = state.get("retired", {})
    selected = {}
    for item in data.get("retirements", []):
        alias, fqdn = item["alias"], item["fqdn"].lower()
        if (fqdn not in absent or item["stage"] != data["stage"]
                or not item.get("reason", "").strip()
                or not item.get("origin", "").strip()):
            raise ValueError("retirement requires absent roster intent, authorized stage, reason and origin")
        matches = [h for h in inventory if h["alias"] == alias]
        if matches and (matches[0].get("fqdn", "").lower() != fqdn
                        or matches[0]["stage"] != data["stage"]):
            raise ValueError("retirement inventory identity/stage mismatch")
        if alias in selected and selected[alias] != dict(item, fqdn=fqdn):
            raise ValueError("ambiguous retirement alias")
        selected[alias] = dict(item, fqdn=fqdn)
    for fqdn in sorted(absent):
        matches = [h for h in inventory if h.get("fqdn", "").lower() == fqdn]
        if len(matches) > 1:
            raise ValueError("ambiguous retirement FQDN in inventory")
        for h in matches:
            if h["stage"] != data["stage"]:
                raise ValueError("retirement target outside authorized stage")
            selected.setdefault(h["alias"], dict(alias=h["alias"], fqdn=fqdn,
                stage=data["stage"], reason="canonical roster state: absent",
                origin="canonical-roster"))
        for alias, receipt in receipts.items():
            if receipt["fqdn"] == fqdn:
                if receipt["stage"] != data["stage"]:
                    raise ValueError("retirement receipt outside authorized stage")
                selected.setdefault(alias, {k: receipt[k] for k in
                    ("alias", "fqdn", "stage", "reason", "origin")})
    for alias, item in selected.items():
        if not item["fqdn"].endswith("." + state["domain"]):
            raise ValueError("retirement target outside journal domain")
        for h in inventory:
            if h["alias"] == alias and (h.get("fqdn", "").lower() != item["fqdn"]
                                       or h["stage"] != item["stage"]):
                raise ValueError("retirement inventory identity/stage mismatch")
        if alias in receipts and any(receipts[alias][k] != item[k] for k in ("fqdn", "stage")):
            raise ValueError("retirement identity conflicts with durable receipt")
    # A tombstone remains a barrier even if the roster later drops its entry.
    for h in inventory:
        if h["alias"] in receipts and h["alias"] not in selected:
            raise ValueError("retired alias reuse requires a separate authorized lifecycle")
    return [selected[a] for a in sorted(selected)]


def update(state, action, data):
    users = state["users"]
    if state["domain"] != data["domain"]:
        raise ValueError("journal domain mismatch")
    if action == "inspect":
        return {"work": work(state), "retired": state.get("retired", {})}
    if action == "retirement_status":
        matches = [r for r in state.get("retired", {}).values()
                   if r["fqdn"] == data["fqdn"].lower()
                   and (not data.get("alias") or r["alias"] == data["alias"])
                   and r["stage"] == data["stage"]]
        settled = bool(matches) and all(
            not any(p["host"] == r["alias"] for p in work(state)) for r in matches)
        return {"settled": settled, "retirements": matches, "observation": {
            "schema_version": 1, "kind": "ssh_retirement",
            "fqdn": data["fqdn"].lower(), "alias": data.get("alias", ""),
            "stage": data["stage"], "status": "settled" if settled else "pending"}}
    if action == "plan":
        retirements = retirement_plan(state, data)
        pending = {pair["host"] for pair in work(state)}
        receipts = state.get("retired", {})
        # Exclusion from future propagation needs cleanup even when there is
        # no old work. Only an exact, completed receipt permits partial runs.
        cleanup_required = [item["alias"] for item in retirements
                            if item["alias"] in pending
                            or item["alias"] not in receipts
                            or any(receipts[item["alias"]].get(k) != item[k]
                                   for k in ("alias", "fqdn", "stage"))]
        return {"work": work(state), "retirements": retirements,
                "cleanup_required": cleanup_required}
    if action == "retire":
        items = data["retirements"]
        retired = state.get("retired", {})
        # Validate the complete batch before touching any state.
        batch = {}
        for item in items:
            if (item["stage"] != data["stage"] or not item["reason"].strip()
                    or not item["origin"].strip()
                    or item["fqdn"] != item["fqdn"].lower()
                    or not item["fqdn"].endswith("." + data["domain"])
                    or not item["alias"]):
                raise ValueError("invalid authorized retirement")
            if item["alias"] in batch and batch[item["alias"]] != item:
                raise ValueError("ambiguous retirement alias")
            batch[item["alias"]] = item
            if item["alias"] in retired and any(
                    retired[item["alias"]][k] != item[k] for k in ("fqdn", "stage")):
                raise ValueError("retirement identity conflicts with durable receipt")
        changed = False
        for item in items:
            alias = item["alias"]
            if alias in retired:
                if any(alias in e["pending"] for e in users.values()):
                    raise ValueError("retired alias has unexpected pending work")
                continue
            count = 0
            for entry in users.values():
                if alias in entry["pending"]:
                    entry["pending"] = [h for h in entry["pending"] if h != alias]
                    entry["epoch"] = uuid.uuid4().hex
                    count += 1
            retired[alias] = dict(item, discharged=count, result="retired",
                                  recorded_at=int(time.time()))
            changed = True
        if changed:
            state["retired"] = retired
        return {"changed": changed, "retired": retired, "work": work(state)}
    if action == "auth_prepare":
        # A journal that never recorded authorization state cannot show that
        # earlier runs (older playbooks, whose tagged runs never refreshed)
        # reached every client, so the first run refreshes once.
        previous = state.get("auth_pending", True)
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
        if set(hosts) & set(state.get("retired", {})):
            raise ValueError("retired alias reuse requires a separate authorized lifecycle")
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


def durability_barrier(stream, directory):
    """Confirm the observed inode and its directory before reporting success."""
    os.fsync(stream.fileno())
    dirfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dirfd)
    finally:
        os.close(dirfd)


def read_state(stream):
    state = json.load(stream)
    if state["version"] != 1 or not isinstance(state["users"], dict):
        raise ValueError("invalid SSH cache journal")
    return state


def journal(path, action, data):
    directory = os.path.dirname(path)
    if action in ("inspect", "plan", "retirement_status"):
        # Atomic replacement makes an unlocked read a coherent snapshot. Do
        # not create even a sidecar lock during preview/read-only discovery.
        try:
            with open(path, encoding="utf-8") as stream:
                state = read_state(stream)
        except FileNotFoundError:
            state = {"version": 1, "domain": data["domain"], "users": {}}
        result = update(state, action, data)
        def trusts_receipt(result):
            if action == "retirement_status":
                return result["settled"]
            if action == "plan":
                return len(result["retirements"]) > len(result["cleanup_required"])
            return False

        if not trusts_receipt(result):
            return result
        # A visible receipt may come from an interrupted directory fsync.
        # Use the writer's EXISTING sidecar, re-read, and sync that same
        # opened inode under LOCK_SH. Never create/replace state on a query.
        with open(path + ".lock", "r", encoding="utf-8") as lock:
            fcntl.flock(lock, fcntl.LOCK_SH)
            with open(path, encoding="utf-8") as stream:
                result = update(read_state(stream), action, data)
                if trusts_receipt(result):
                    durability_barrier(stream, directory)
                return result
    os.makedirs(directory, mode=0o700, exist_ok=True)
    with open(path + ".lock", "a", encoding="utf-8") as lock:
        os.chmod(path + ".lock", 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        existed = True
        try:
            with open(path, encoding="utf-8") as stream:
                state = read_state(stream)
        except FileNotFoundError:
            existed = False
            state = {"version": 1, "domain": data["domain"], "users": {}}
        before = json.dumps(state, sort_keys=True)
        result = update(state, action, data)
        if existed and json.dumps(state, sort_keys=True) == before:
            with open(path, encoding="utf-8") as stream:
                durability_barrier(stream, directory)
            return result
        fd, temporary = tempfile.mkstemp(prefix=".ssh-cache-", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(state, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            with open(path, encoding="utf-8") as stream:
                durability_barrier(stream, directory)
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
