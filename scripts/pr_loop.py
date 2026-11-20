#!/usr/bin/env python3
"""Run Pilot's Draft/Ready PR skills in order using managed tmux panes."""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from urllib.parse import urlsplit


sys.dont_write_bytecode = True
SKILLS = Path(__file__).resolve().parents[1] / ".agents/skills"
sys.path[:0] = [str(SKILLS / skill / "scripts") for skill in ("pr-review-merge", "_shared")]
from gh_runtime import GitHubError, Repo, issue_comments, pr_view, viewer_login
from list_ready import QUEUE_LABEL
from needs_person import LABEL as PERSON_LABEL, latest_marker
from pr_loop_result import OUTCOMES, SHA


class Stop(RuntimeError):
    pass


def tell(message):
    print(message, flush=True)


def command(*args, cwd=None, data=None):
    options = {"input": data} if data is not None else {"stdin": subprocess.DEVNULL}
    proc = subprocess.run(args, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=120, check=False, **options)
    if proc.returncode != 0:
        raise Stop(f"{' '.join(args[:2])} failed ({proc.returncode}): {proc.stderr.strip()[:500]}")
    return proc.stdout


def state_of(view):
    if view.get("state") == "MERGED":
        return "merged"
    if view.get("state") != "OPEN":
        raise Stop(f"PR #{view['number']} is not open or merged")
    if view.get("isDraft") is True:
        return "draft"
    if view.get("isDraft") is not False:
        raise Stop(f"PR #{view['number']} has no Draft state")
    return "queued" if has_label(view, QUEUE_LABEL) else "ready"


def has_label(view, label):
    labels = view.get("labels")
    if not isinstance(labels, list) or any(not isinstance(entry, dict) for entry in labels):
        raise Stop(f"PR #{view['number']} returned invalid labels")
    return any(entry.get("name") == label for entry in labels)


def head_of(view):
    head = view.get("headRefOid")
    if not isinstance(head, str) or not SHA.fullmatch(head):
        raise Stop(f"PR #{view['number']} has no valid HEAD SHA")
    return head.lower()


def observe(repo, number):
    view = pr_view(repo, number)
    phase = state_of(view)
    if phase == "ready" and has_label(view, PERSON_LABEL):
        head = head_of(view)
        marker = latest_marker(issue_comments(repo, number), viewer_login(repo))
        if marker and marker["head"] == head:
            fresh = pr_view(repo, number)
            if state_of(fresh) == "ready" and has_label(fresh, PERSON_LABEL) and head_of(fresh) == head:
                raise Stop(f"PR #{number} needs a person at HEAD {head[:12]}; see the PR conversation")
            return fresh
    return view


class Checkout:
    def __init__(self, view, repo):
        url = urlsplit(view.get("url", ""))
        host = repo.host or "github.com"
        path = f"/{repo.owner}/{repo.name}"
        if url.scheme != "https" or url.netloc.casefold() != host.casefold() or \
           url.path.casefold() != f"{path}/pull/{view['number']}".casefold() or url.query or url.fragment:
            raise Stop("GitHub returned an unexpected PR URL")
        root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "pilot" / "pr-loop"
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = Path(tempfile.mkdtemp(prefix="batch-", dir=root.resolve()))
        tell(f"Managed checkout: {self.path}")
        command("gh", "repo", "clone", f"https://{host}{path}", str(self.path))
        remote_ref = self.git("symbolic-ref", "refs/remotes/origin/HEAD")
        prefix = "refs/remotes/origin/"
        if not remote_ref.startswith(prefix):
            raise Stop("cannot verify the origin default branch")
        self.branch = "refs/heads/" + remote_ref[len(prefix):]
        self.head = self.git("rev-parse", "--verify", remote_ref + "^{commit}")
        self.verify()
        self.git("cat-file", "-e", "HEAD:.agents/skills/_shared/scripts/pr_loop_result.py")
        with (self.path / ".git/info/exclude").open("a", encoding="utf-8") as stream:
            stream.write("\n/.pr-ready/\n/.tmux-ai-pr/\n")

    def git(self, *args):
        return command("git", *args, cwd=self.path).strip()

    def verify(self):
        if self.git("symbolic-ref", "HEAD") != self.branch or self.git("rev-parse", "HEAD") != self.head:
            raise Stop(f"skill did not restore the checked default branch at {self.head}")
        if self.git("status", "--porcelain=v1", "--untracked-files=normal"):
            raise Stop(f"managed checkout contains uncommitted work: {self.path}")

    def task(self, repo, number, phase, head):
        nonce = uuid.uuid4().hex
        directory = self.path / ".tmux-ai-pr" / ("tmux-ai-pr-" + nonce)
        directory.mkdir(parents=True, mode=0o700)
        task = dict(version=1, repo=f"{repo.owner}/{repo.name}", pr=number, phase=phase,
                    nonce=nonce, start_head=head)
        path = directory / "task.json"
        path.write_text(json.dumps(task), encoding="utf-8")
        return path, task

    def clean_up(self):
        if (self.path / ".pr-ready").exists() or self.git("status", "--porcelain=v1") or \
           self.git("rev-list", "--max-count=1", "HEAD", "--branches", "--not", "--remotes") or \
           self.git("stash", "list"):
            tell(f"Retained checkout and evidence: {self.path}")
            return
        shutil.rmtree(self.path)


PROMPT = re.compile(r"^(?:[›❯](?:\s.*)?|>)$")
CHOICE = re.compile(r"^[›❯>]\s*\d+[.)]\s")
BUSY = re.compile(r"(?:esc|ctrl\+c) to interrupt(?:\))?$", re.IGNORECASE)
SHELLS = {"bash", "sh", "zsh", "fish", "dash", "ksh", "nu"}


class Agent:
    def __init__(self, executable, checkout, number, phase):
        path = shutil.which(executable)
        if not path:
            raise Stop(f"agent executable not found: {executable}")
        self.session = f"pilot-pr-{number}-{phase}-{uuid.uuid4().hex[:10]}"
        self.pane = command("tmux", "new-session", "-d", "-P", "-F", "#{pane_id}", "-s", self.session,
                            "-c", str(checkout.path), "--", "exec " + shlex.quote(os.path.abspath(path))).strip()
        if not re.fullmatch(r"%\d+", self.pane):
            raise Stop("tmux did not return a pane ID")
        tell(f"PR #{number} {phase} agent: {self.pane} in session {self.session}")
        command("tmux", "set-option", "-w", "-t", self.pane, "remain-on-exit", "on")

    def status(self):
        raw = command("tmux", "display-message", "-p", "-t", self.pane,
                      "#{pane_dead}|#{pane_in_mode}|#{pane_current_command}").strip()
        parts = raw.split("|")
        if len(parts) != 3 or parts[0] not in ("0", "1") or parts[1] not in ("0", "1"):
            raise Stop(f"tmux could not read pane {self.pane}")
        return parts[0] == "1", parts[1] == "1", parts[2].lstrip("-")

    def wait_for_prompt(self, timeout, *, allow_exit=False):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            dead, in_mode, process = self.status()
            if dead:
                if allow_exit:
                    return False
                raise Stop(f"agent exited during startup in {self.pane}")
            if process and process not in SHELLS and not in_mode:
                screen = command("tmux", "capture-pane", "-p", "-J", "-t", self.pane)
                recent = [line.strip() for line in screen.splitlines() if line.strip()][-16:]
                if not any(BUSY.search(line) or CHOICE.match(line) for line in recent) and \
                   any(PROMPT.fullmatch(line) for line in recent[-6:]):
                    return True
            time.sleep(0.25)
        raise Stop(f"agent did not return to its input prompt in {self.pane}; inspect session {self.session}")

    def submit(self, text):
        buffer = "pilot-pr-" + uuid.uuid4().hex
        command("tmux", "load-buffer", "-b", buffer, "-", data=text)
        try:
            command("tmux", "paste-buffer", "-p", "-d", "-b", buffer, "-t", self.pane)
        except Stop:
            try:
                command("tmux", "delete-buffer", "-b", buffer)
            except Stop:
                pass
            raise
        time.sleep(0.25)
        dead, in_mode, foreground = self.status()
        if dead or in_mode or not foreground or foreground in SHELLS:
            raise Stop(f"pane {self.pane} changed while pasting; inspect before resuming")
        command("tmux", "send-keys", "-t", self.pane, "Enter")

    def close(self):
        command("tmux", "kill-pane", "-t", self.pane)


def check_result(path, task, head):
    result = path.with_name("result.json")
    if not result.exists():
        return
    with result.open("rb") as stream:
        data = stream.read(4097)
    if len(data) > 4096:
        raise Stop("skill result exceeded the size limit")
    report = json.loads(data)
    if not isinstance(report, dict) or any(report.get(key) != value for key, value in task.items()):
        raise Stop("skill result does not belong to this dispatch")
    judged, outcome, reason = report.get("head_sha"), report.get("outcome"), report.get("reason")
    if not isinstance(judged, str) or not SHA.fullmatch(judged) or \
       not isinstance(outcome, str) or outcome not in OUTCOMES[task["phase"]] or \
       not isinstance(reason, str) or (reason and not reason.isprintable()):
        raise Stop("invalid skill result")
    if judged.lower() == head and outcome not in ("READY", "DRAFT", "ENQUEUED", "MERGED"):
        kind = report.get("wait_kind")
        detail = f" ({kind})" if kind in ("person", "transient") else ""
        raise Stop(f"PR #{task['pr']} {outcome}{detail} at {head[:12]}: {reason}")


class Batch:
    def __init__(self, repo, args):
        self.repo, self.args = repo, args
        self.checkout = None

    def run(self):
        for number in self.args.pr:
            try:
                self.run_pr(number)
            except (Stop, GitHubError, OSError, ValueError, subprocess.SubprocessError) as exc:
                raise Stop(f"PR #{number}: {exc}") from exc
        if self.checkout is not None:
            self.checkout.clean_up()

    def run_pr(self, number):
        agents = {}
        active = None
        current, task_path, task = None, None, None
        actions, exited = 0, 0
        deadline = time.monotonic() + self.args.phase_timeout
        while True:
            view = observe(self.repo, number)
            phase = state_of(view)
            if self.args.dry_run:
                tell(f"PR #{number}: {phase}")
                return
            if phase != current:
                if current == "queued" and phase == "ready":
                    raise Stop("left the merge train while still Ready; inspect the PR conversation")
                if phase != "queued" and active is not None:
                    role, agent = active
                    if not agent.wait_for_prompt(self.args.startup_timeout, allow_exit=True):
                        agent.close()
                        del agents[role]
                    active = None
                if phase == "merged":
                    for agent in agents.values():
                        agent.close()
                    tell(f"PR #{number}: merged")
                    return
                deadline = time.monotonic() + self.args.phase_timeout
                current = phase
                if phase == "queued":
                    tell(f"PR #{number}: waiting for merge train")
                else:
                    actions += 1
                    if actions > self.args.max_actions:
                        raise Stop("maximum agent dispatches reached")
                    if self.checkout is None:
                        self.checkout = Checkout(view, self.repo)
                    self.checkout.verify()
                    agent = agents.get(phase)
                    if agent is not None and agent.status()[0]:
                        agent.close()
                        agent = None
                    if agent is None:
                        agent = Agent(getattr(self.args, phase + "_agent"), self.checkout, number, phase)
                        agents[phase] = agent
                    agent.wait_for_prompt(self.args.startup_timeout)
                    # An approval prompt at startup can take long enough for GitHub to change.
                    view = observe(self.repo, number)
                    if state_of(view) != phase:
                        raise Stop("GitHub state changed before dispatch; retry against the current PR")
                    task_path, task = self.checkout.task(self.repo, number, phase, head_of(view))
                    prompt = getattr(self.args, phase + "_command").replace("{pr}", str(number))
                    agent.submit(prompt + " --pr-loop-task=" + json.dumps(str(task_path), ensure_ascii=False))
                    active, exited = (phase, agent), 0
            elif active is not None and phase != "queued":
                check_result(task_path, task, head_of(view))
                dead, _, foreground = active[1].status()
                exited = exited + 1 if dead or foreground in SHELLS else 0
                if exited >= 2:
                    raise Stop(f"{phase} agent exited before GitHub confirmed a state change")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Stop(f"timed out in {phase}")
            time.sleep(min(self.args.poll_interval, remaining))


def seconds(value):
    duration = float(value)
    if not math.isfinite(duration) or duration <= 0:
        raise argparse.ArgumentTypeError("expected positive seconds")
    return duration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pr", metavar="PR", type=int, nargs="+")
    parser.add_argument("--repo", default="kjelly/pilot", help="GitHub repository (default: kjelly/pilot)")
    parser.add_argument("--draft-agent", default="claude")
    parser.add_argument("--ready-agent", default="codex")
    parser.add_argument("--draft-command", default="/pr-ready {pr}")
    parser.add_argument("--ready-command", default="$pr-review-merge {pr}")
    parser.add_argument("--phase-timeout", type=seconds, default=7200, help="seconds waiting per phase (default: 7200)")
    parser.add_argument("--startup-timeout", type=seconds, default=60, help="seconds waiting for an agent prompt (default: 60)")
    parser.add_argument("--poll-interval", type=seconds, default=10, help="seconds between GitHub reads (default: 10)")
    parser.add_argument("--max-actions", type=int, default=20, help="maximum dispatches per PR (default: 20)")
    parser.add_argument("--dry-run", action="store_true", help="show current PR states without starting agents")
    args = parser.parse_args()
    if any(n <= 0 for n in args.pr) or len(set(args.pr)) != len(args.pr) or args.max_actions <= 0:
        parser.error("PR numbers must be positive and unique, and --max-actions must be positive")
    if any(not template.strip() or not template.isprintable() for template in (args.draft_command, args.ready_command)):
        parser.error("agent commands must be nonempty single lines")
    os.environ.setdefault("GH_PROMPT_DISABLED", "1")
    try:
        Batch(Repo.parse(args.repo), args).run()
        return 0
    except KeyboardInterrupt:
        print("Interrupted; any active panes and checkout were retained.", file=sys.stderr)
        return 130
    except (Stop, GitHubError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"pr-loop: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
