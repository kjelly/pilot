"""Scratch git repositories for the shared-contract tests (not a test module)."""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def load_module(path):
    """Import a script by path (the scripts are not a package)."""
    spec = importlib.util.spec_from_file_location(path.stem + "_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    return module


def hermetic_env(home):
    """Environment that ignores the developer's git configuration."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(HOME=str(home), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid",
               LC_ALL="C")
    return env


class Repo:
    """A throw-away repository on branch `main`, inside a private temp dir."""

    def __init__(self, case: unittest.TestCase, name="repo", clone_of=None):
        tmp = tempfile.TemporaryDirectory(prefix="single-item-test-")
        case.addCleanup(tmp.cleanup)
        self.base = Path(os.path.realpath(tmp.name))
        self.env = hermetic_env(self.base / "home")
        (self.base / "home").mkdir()
        self.path = self.base / name
        if clone_of:
            subprocess.run(["git", "clone", "-q", str(clone_of), str(self.path)], check=True,
                           capture_output=True, env=self.env)
        else:
            self.path.mkdir()
            self.git("init", "-q", "-b", "main")

    def git(self, *args, check=True):
        p = subprocess.run(["git", "-C", str(self.path), *args], capture_output=True,
                           text=True, env=self.env)
        if check and p.returncode:
            raise AssertionError(f"git {' '.join(args)}: {p.stderr}")
        return p

    def out(self, *args):
        return self.git(*args).stdout.strip()

    def write(self, rel, text="x\n"):
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def commit(self, message="c", *add):
        self.git("add", *(add or ("-A",)))
        self.git("commit", "-q", "-m", message)
        return self.out("rev-parse", "HEAD")

    def branch_from_main(self, name):
        self.git("switch", "-q", "-c", name, "main")

    def nested(self, rel, **files):
        """An independent git repository (own .git) at `rel`, with the given files committed."""
        path = self.path / rel
        path.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"], check=True,
                       capture_output=True, env=self.env)
        for name, text in files.items():
            (path / name).write_text(text)
        if files:
            subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, capture_output=True,
                           env=self.env)
            subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", "n"], check=True,
                           capture_output=True, env=self.env)
        return path

    def add_origin(self):
        """A bare `origin` with main pushed (upstream set), like a clone of the real remote."""
        bare = self.base / "origin.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True,
                       capture_output=True, env=self.env)
        self.git("remote", "add", "origin", str(bare))
        self.git("push", "-q", "-u", "origin", "main")
        return bare

    def side_commit(self, branch, rel, text):
        """Create `branch` = HEAD plus a commit that force-tracks `rel`, without touching the checkout."""
        env = dict(self.env, GIT_INDEX_FILE=str(self.base / "side-index"))
        run = lambda *a, **kw: subprocess.run(["git", "-C", str(self.path), *a], check=True, capture_output=True,
                                              text=True, env=env, **kw).stdout.strip()
        blob = run("hash-object", "-w", "--stdin", input=text)
        run("read-tree", "HEAD")
        run("update-index", "--add", "--cacheinfo", f"100644,{blob},{rel}")
        commit = run("commit-tree", run("write-tree"), "-p", "HEAD", "-m", f"track {rel}")
        run("update-ref", f"refs/heads/{branch}", commit)
        return commit
