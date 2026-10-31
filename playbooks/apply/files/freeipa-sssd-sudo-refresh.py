#!/usr/bin/env python3
"""Force one SSSD sudo full refresh on this host and prove it finished.

Run through Ansible with JSON on stdin ({"domain": ..., "timeout": N}); never
handles passwords. `sss_cache -E` only expires rules the host already holds:
a rule that newly applies to a user or host reaches the cache through the
smart/full refresh ptask (15 min / 6 h) or SSSD start-up. So this expires the
cache, restarts SSSD (start-up runs a full refresh) and waits until
sudoLastFullRefreshTime in the domain cache is at or after the restart.
Time is compared on this host's clock only. Child output is never printed.
"""

import json
import re
import subprocess
import sys
import time

MARKER = re.compile(r"^sudoLastFullRefreshTime: (\d+)$", re.MULTILINE)


def run(argv, deadline):
    # A floor, so the last poll near the deadline is not starved into a bare
    # "timed out" that hides why the refresh did not complete.
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=max(2.0, deadline - time.monotonic()))
    except FileNotFoundError:
        # A client enrolled before ldb-tools joined freeipa-client-apply.yml.
        hint = ("; ldb-tools is installed by freeipa-client-apply.yml, re-run it "
                "on this client" if argv[0] == "ldbsearch" else "")
        raise RuntimeError("%s not found%s" % (argv[0], hint))


def marker(domain, deadline):
    out = run(["ldbsearch", "-H", "/var/lib/sss/db/cache_%s.ldb" % domain,
               "-b", "cn=sudorules,cn=custom,cn=%s,cn=sysdb" % domain,
               "-s", "base", "sudoLastFullRefreshTime"], deadline)
    if out.returncode != 0:
        raise RuntimeError("cannot read the SSSD sudo cache (ldbsearch rc=%d); "
                           "ldb-tools is installed by freeipa-client-apply.yml"
                           % out.returncode)
    # An empty container (no refresh has ever completed) has no attribute.
    found = MARKER.search(out.stdout)
    return int(found.group(1)) if found else None


def converge(data):
    domain = data["domain"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", domain):
        raise ValueError("invalid domain")
    timeout = int(data.get("timeout", 60))
    interval = float(data.get("interval", 1))
    start = time.monotonic()
    deadline = start + timeout

    # Fail on a missing reader before touching SSSD.
    marker(domain, deadline)
    began = int(time.time())
    for argv in (["sss_cache", "-E"], ["systemctl", "restart", "sssd"]):
        done = run(argv, deadline)
        if done.returncode != 0:
            raise RuntimeError("%s failed (rc=%d)" % (argv[0], done.returncode))
    while True:
        seen = marker(domain, deadline)
        if seen is not None and seen >= began:
            return {"converged": True, "waited": round(time.monotonic() - start, 1)}
        if time.monotonic() + interval >= deadline:
            raise RuntimeError(
                "SSSD sudo full refresh did not complete within %ds "
                "(restarted at %d, last refresh %s); is the host offline from FreeIPA?"
                % (timeout, began, seen))
        time.sleep(interval)


def main():
    try:
        print(json.dumps(converge(json.load(sys.stdin))))
    except subprocess.TimeoutExpired as exc:
        print("timed out running %s" % exc.cmd[0], file=sys.stderr)
        return 1
    except (RuntimeError, ValueError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
