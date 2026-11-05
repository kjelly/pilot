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

Failures. Only the read before the restart fails fast, before SSSD is touched.
If sss_cache or the restart fails or times out, SSSD may be stopped, so the
helper reads `systemctl is-active sssd`, starts it when it is down, and says
which in the error. A read that fails after the restart is retried until the
deadline and the last error is reported. Every failure exits 1.
"""

import json
import re
import subprocess
import sys
import time

MARKER = re.compile(r"^sudoLastFullRefreshTime: (\d+)$", re.MULTILINE)


def run(argv, deadline, floor=2.0):
    # A floor, so the last poll near the deadline is not starved into a bare
    # "timed out" that hides why the refresh did not complete.
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              timeout=max(floor, deadline - time.monotonic()))
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


# What `systemctl is-active` prints; anything else is reported as "unknown"
# (child output is never printed).
UNIT_STATES = ("active", "inactive", "failed", "activating", "deactivating", "reloading")
# Each recovery command gets at least this long even past the deadline: the
# Ansible task allows 30 s beyond it, and a start can take a few seconds.
RECOVERY_FLOOR = 10.0


def sssd_state(deadline):
    """Say what became of SSSD after sss_cache or the restart failed.

    A restart that failed or was killed by this helper's own timeout can leave
    SSSD stopped (the restart job may even go on after systemctl is killed), and
    PAM/SSH logins on this client depend on it. So the state is read after the
    failure, never assumed, and a stopped SSSD is started again.
    """
    try:
        state = run(["systemctl", "is-active", "sssd"], deadline, RECOVERY_FLOOR)
        word = state.stdout.strip()
        word = word if word in UNIT_STATES else "unknown"
        if state.returncode == 0:
            return "SSSD is active"
        started = run(["systemctl", "start", "sssd"], deadline, RECOVERY_FLOOR)
        if started.returncode == 0:
            return "SSSD was %s and was started" % word
        return ("SSSD was %s and could not be started (systemctl start rc=%d)"
                % (word, started.returncode))
    except subprocess.TimeoutExpired as exc:
        return "SSSD state is unknown (%s timed out)" % " ".join(exc.cmd)
    except RuntimeError as exc:
        return "SSSD state is unknown (%s)" % exc


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
        name = " ".join(argv)
        try:
            done = run(argv, deadline)
            failure = "%s failed (rc=%d)" % (name, done.returncode) if done.returncode != 0 else None
        except subprocess.TimeoutExpired:
            failure = "%s timed out" % name
        except RuntimeError as exc:
            # The command is missing: SSSD was not touched by it.
            failure = str(exc)
        if failure:
            raise RuntimeError("%s; %s" % (failure, sssd_state(deadline)))
    # After both returned: the old instance has stopped, so its last write is
    # at or before this second.
    restarted = int(time.time())
    seen, error = None, None
    while True:
        # Only the read before the restart fails fast. SSSD is restarting now:
        # a read can fail while it comes up, so keep polling to the deadline and
        # report the last error if the refresh never shows.
        try:
            seen = marker(domain, deadline)
        except RuntimeError as exc:
            error = str(exc)
        except subprocess.TimeoutExpired as exc:
            error = "%s timed out" % exc.cmd[0]
        else:
            if seen is not None and seen != before and seen > restarted:
                return {"converged": True, "waited": round(time.monotonic() - start, 1)}
        if time.monotonic() + interval >= deadline:
            raise RuntimeError(
                "SSSD sudo full refresh did not complete within %ds "
                "(sudoLastFullRefreshTime before=%s, restarted at %d, now=%s%s); "
                "is the host offline from FreeIPA?"
                % (timeout, before, restarted, seen,
                   "; last read error: " + error if error else ""))
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
