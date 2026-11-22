"""Run ONE command with a bound, and end the whole process group it started when the bound is reached.

This is the one way the skill scripts and `scripts/pr_loop.py` start a command and wait for it (kjelly/pilot#427, the
class follow-up of the `git_change` fix of kjelly/pilot#426); tests/test_bounded_run_lint.py keeps it so. The invariant,
observable from outside: a command started here returns control to its caller within `limit + kill_after + drain` (and
one `poll`; `drain` twice when the command's own process cannot be ended), whatever its descendants do with its pipes
or with SIGTERM, and a command that has already exited is judged by its exit code alone.

How it works. The command leads a process group and a session of its own (`start_new_session=True`), so the whole
group can be signalled and the terminal cannot be asked anything. There is ONE deadline, `limit` seconds from the start.

* The caller reads the output in steps of `poll` seconds. When a step ends and the leader has exited, what is left in the
  pipes is read for at most `drain` seconds, both pipes are closed, and the result is returned with the leader's exit
  code: what a finished command left behind (a daemon, a background job that kept its output open) is not waited for
  beyond `drain` and is NOT signalled. Python's `communicate(timeout=)` alone would call that a timeout, and
  `subprocess.run(timeout=)` ends the leader only.
* At the deadline the group gets SIGTERM (git removes its own lock files on it), and SIGKILL goes to whatever is
  still in the group `kill_after` seconds after that: also when the leader has exited by then and a member that ignores
  SIGTERM stays (the group is probed every 50 ms once the leader is reaped, because a reaped leader's zombie no longer
  keeps it "there"). A group that answered ESRCH is never signalled again: it is empty and its id may belong to another
  group by now. A group that cannot be signalled (EPERM, a member that changed user) is left alone too. The leftover
  output is then read for at most `drain` seconds and the pipes are closed, so that a process that left the group
  (`setsid`) while holding a pipe cannot hold the caller: its next write meets a closed pipe. The call raises `Timeout`.
* An interrupt (Ctrl-C reaches Python only: the command has a session of its own). `on_interrupt="end"` ends the group
  the same way and re-raises the interrupt; a second interrupt while that runs SIGKILLs the group at once, still drains,
  and is raised. `on_interrupt="finish"` is for a command that must end or fail whole (a tree update): the first
  interrupt is saved, the command is waited for until the same deadline, and the saved interrupt is raised afterwards, in
  place of the result and of `Timeout`; a second interrupt while waiting is absorbed, and one while the group is being
  ended at the deadline kills it at once.
* Any other exception while waiting ends the group and is re-raised. `OSError` from the start (no such program)
  propagates: nothing was started.

What it does not do. It is not a sandbox: a member that leaves the group by itself (`setsid`) is not signalled, only
its pipes are closed. An interrupt that arrives while the command is being STARTED (after the fork, before `run()` holds
the process handle) is raised with the command left running, as it was at every site this helper replaced; the window is
the few milliseconds of `Popen`, and hardening it is tracked in the follow-up comment of kjelly/pilot#428. A command in
its own session is not reached when the CALLER is killed by a signal to the caller's group (`timeout(1)`, an agent
tool's timeout): there is no SIGTERM handler here (kjelly/pilot#309). It reports "exit 0 and a descendant that holds the
pipes" as the command's success, where Go's `WaitDelay` reports an error (kjelly/pilot#261). A caller that must not start
descendants has to say so to its command.

`input` goes to the first read only (a retry with input would raise ValueError in `communicate`). `limit` is required, a
positive finite number: there is no default, and the lint rejects a call that does not name it.
"""
from __future__ import annotations

import contextlib
import math
import os
import signal
import subprocess
import time

# Seconds. Read when a call starts, so that a caller's own constant (or a test) can say otherwise per call.
KILL_AFTER = 30  # from SIGTERM to SIGKILL
DRAIN = 5  # reading what a finished or ended command left in its pipes, and collecting it
POLL = 1  # one wait for the command's output, after which the leader is looked at

ENDED_TERM = "SIGTERM"
ENDED_KILL = "SIGTERM, then SIGKILL"
ENDED_REFUSED = "not signalled (EPERM)"


class Timeout(subprocess.TimeoutExpired):
    """The command outlived `limit` and its process group was ended. `ended` says how: `SIGTERM` (it, and what it
    started, were gone before SIGKILL was needed), `SIGTERM, then SIGKILL`, or `not signalled (EPERM)` (the kernel
    refused to signal the group). `output` and `stderr` are what was read, decoded in text mode. `str()` is
    TimeoutExpired's: `Command '[...]' timed out after N seconds`."""

    def __init__(self, cmd, timeout, ended, output=None, stderr=None):
        super().__init__(cmd, timeout, output=output, stderr=stderr)
        self.ended = ended


def _seconds(name, value, *, zero_ok):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 \
            or (value == 0 and not zero_ok):
        raise ValueError(f"{name} must be a {'non-negative' if zero_ok else 'positive'} finite number of seconds, "
                         f"not {value!r}")
    return value


def _decoded(data, encoding):
    """Partial output as a timed-out `communicate` carries it: bytes, also in text mode on Python 3.10. `encoding` is
    `(encoding, errors)` of the pipe in text mode and None in binary mode. What was read stops wherever the command was
    when it was cut off, so it can end in the middle of a character: it is decoded with `errors="replace"` (the pipe's own
    strict error handling would raise UnicodeDecodeError here, in place of the Timeout or of the result)."""
    if encoding is None:
        return data or b""
    if isinstance(data, str):
        return data
    return (data or b"").decode(encoding[0], "replace").replace("\r\n", "\n").replace("\r", "\n")


def _drain(proc, drain, text):
    """What is left in `proc`'s pipes, `(stdout, stderr)`, read for at most `drain` seconds: then both pipes are closed,
    `proc` is collected (for `drain` seconds at most) and what was read so far is returned. What is left was cut off
    wherever the command was, so it can end in the middle of a character, and the last read decodes it: the pipes are told
    to replace what they cannot decode first (the strict default would raise UnicodeDecodeError out of the read, in place
    of the Timeout or of the result). The read that ends a command that finished is not touched: it decodes as it always did."""
    if text:
        for pipe in (proc.stdout, proc.stderr):
            with contextlib.suppress(ValueError):  # a pipe that is closed already has nothing left to decode
                pipe.reconfigure(errors="replace")
    try:
        return proc.communicate(timeout=drain)
    except subprocess.TimeoutExpired as exc:
        encodings = [(pipe.encoding, pipe.errors) if text else None for pipe in (proc.stdout, proc.stderr)]
        for pipe in (proc.stdout, proc.stderr):
            pipe.close()
        try:
            proc.wait(drain)
        except subprocess.TimeoutExpired:
            pass
        return tuple(_decoded(data, encoding) for data, encoding in zip((exc.stdout, exc.stderr), encodings))


def _stop_group(proc, kill_after, drain, text):
    """End `proc` and every process still in its group (it leads one), then collect what is left in its pipes.
    Returns `(ended, (stdout, stderr))`. SIGTERM goes first; whatever is still in the group at one fixed instant,
    `kill_after` seconds after that, gets SIGKILL. An interrupt while this runs (a second Ctrl-C) SIGKILLs the group at
    once, still drains, and is raised."""
    kill_at = time.monotonic() + kill_after
    gone = termed = killed = refused = False

    def signal_group(sig):
        nonlocal gone, refused
        if gone:
            return False
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            gone = True
            return False
        except PermissionError:
            gone = refused = True
            return False
        return True
    try:
        termed = signal_group(signal.SIGTERM)
        try:
            proc.wait(max(0.0, kill_at - time.monotonic()))
        except subprocess.TimeoutExpired:
            pass
        while proc.returncode is not None and not gone and time.monotonic() < kill_at:
            signal_group(0)  # the leader is reaped, so a group without members answers ESRCH
            if not gone:
                time.sleep(0.05)
        killed = signal_group(signal.SIGKILL)
    except KeyboardInterrupt:
        signal_group(signal.SIGKILL)
        _drain(proc, drain, text)
        raise
    ended = ENDED_KILL if killed else ENDED_REFUSED if refused and not termed else ENDED_TERM
    return ended, _drain(proc, drain, text)


def run(argv, *, limit, cwd=None, env=None, input=None, text=True, kill_after=None, drain=None, poll=None,
        on_interrupt="end"):
    """Run `argv` with its stdout and stderr captured and its stdin closed (or fed `input`), for at most `limit`
    seconds; the result is a `subprocess.CompletedProcess` whatever the command exits with (the caller judges the
    return code). `text` selects str or bytes output. `kill_after`, `drain` and `poll` default to the module constants
    (read now); `on_interrupt` is `"end"` or `"finish"`. See the module docstring. Raises `Timeout` at the deadline,
    `ValueError` for a `limit` that is not a positive finite number, `OSError` when the program cannot be started."""
    _seconds("limit", limit, zero_ok=False)
    kill_after = _seconds("kill_after", KILL_AFTER if kill_after is None else kill_after, zero_ok=True)
    drain = _seconds("drain", DRAIN if drain is None else drain, zero_ok=True)
    poll = _seconds("poll", POLL if poll is None else poll, zero_ok=False)
    if on_interrupt not in ("end", "finish"):
        raise ValueError(f"on_interrupt must be 'end' or 'finish', not {on_interrupt!r}")
    proc = subprocess.Popen(argv, cwd=cwd, env=env, text=text, start_new_session=True,
                            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    deadline, interrupted, pending, stopped = time.monotonic() + limit, None, input, False
    try:
        while True:
            left = deadline - time.monotonic()  # outside the try: the deadline is judged also after an interrupt
            if left <= 0:
                stopped = True
                ended, (out, err) = _stop_group(proc, kill_after, drain, text)
                if interrupted is not None:
                    raise interrupted
                raise Timeout(argv, limit, ended, out, err)
            try:
                out, err = proc.communicate(pending, timeout=min(left, poll))
                break
            except subprocess.TimeoutExpired:
                pending = None  # the input was handed over by the first call; a second one would raise ValueError
                if proc.poll() is not None:  # the leader is done; what it left behind holds the pipes
                    out, err = _drain(proc, drain, text)
                    break
            except KeyboardInterrupt as exc:
                pending = None
                interrupted = interrupted or exc
                if on_interrupt == "end":
                    stopped = True
                    _stop_group(proc, kill_after, drain, text)
                    raise
    except BaseException:
        if not stopped:  # an exception of any other kind must not leave a group running in a session of its own
            _stop_group(proc, kill_after, drain, text)
        raise
    if interrupted is not None:
        raise interrupted
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)
