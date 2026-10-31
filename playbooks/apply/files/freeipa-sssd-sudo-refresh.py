#!/usr/bin/env python3
"""Force one SSSD sudo full refresh on this host and prove it finished.

Run through Ansible with JSON on stdin ({"domain": ..., "timeout": N}); never
handles passwords. `sss_cache -E` only expires rules the host already holds:
a rule that newly applies to a user or host reaches the cache through the
smart/full refresh ptask (15 min / 6 h) or SSSD start-up. So this expires the
cache, restarts SSSD (start-up runs a full refresh) and waits until
sudoLastFullRefreshTime in the domain cache is a value that was not there
before and is later than the second the restart finished. Time is compared on
this host's clock only. Child output is never printed.

"Not older than the restart" is not enough. The old SSSD instance can record a
refresh that was already running while it stopped (in the restart's own
second), and a clock stepped back leaves an older marker newer than the
restart; neither is the start-up refresh. `systemctl restart` returns once the
old instance has stopped, so whatever it wrote is at or before the second read
after the restart returns, while the start-up refresh runs about 10 s later.
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

    # Read before touching SSSD: a missing reader fails here, and the value is
    # what a refresh that predates the restart would leave behind.
    before = marker(domain, deadline)
    for argv in (["sss_cache", "-E"], ["systemctl", "restart", "sssd"]):
        done = run(argv, deadline)
        if done.returncode != 0:
            raise RuntimeError("%s failed (rc=%d)" % (argv[0], done.returncode))
    # After both returned: the old instance has stopped, so its last write is
    # at or before this second.
    restarted = int(time.time())
    while True:
        seen = marker(domain, deadline)
        if seen is not None and seen != before and seen > restarted:
            return {"converged": True, "waited": round(time.monotonic() - start, 1)}
        if time.monotonic() + interval >= deadline:
            raise RuntimeError(
                "SSSD sudo full refresh did not complete within %ds "
                "(sudoLastFullRefreshTime before=%s, restarted at %d, now=%s); "
                "is the host offline from FreeIPA?"
                % (timeout, before, restarted, seen))
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
