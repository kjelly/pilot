#!/usr/bin/env python3
"""Repository-declared evidence rules shared by the quality gates.

Two things only the repository can know, read from a manifest on the **base branch**
(`.github/pr-evidence.json`, never from the PR head, so a PR cannot grant itself exemptions):

* `evidence_only_paths` — globs of files that hold evidence, not behaviour (for example
  `qa/evidence/**`). A check receipt or review taken at commit R stays valid for HEAD when
  every file that changed between R and HEAD matches these globs. Default: none (strict).
* `required_evidence` — evidence the repository demands for every change (for example a
  real-VM run), each with an `id`, a `source` and an optional `artifact_glob` where the
  committed artifact must live. Those globs are also treated as evidence-only paths.

The evidence JSON then carries `repo_required_evidence`: one entry per required id.

    {"id": "e2e-run", "status": "pass", "head_sha": "<commit that was run>",
     "artifact": "qa/evidence/x/2026-10-28.md", "summary": "..."}      # committed file
    {"id": "coverage", "status": "pass", "head_sha": "<commit>", "url": "https://ci.example/run/123",
     "summary": "..."}                                                # evidence kept elsewhere
    {"id": "e2e-run", "status": "not-applicable", "reason": "...", "reviewer_confirmed": true}

Run `python3 repo_evidence.py --worktree WT --base-ref origin/main` to print the manifest as the
gate sees it.
"""
from __future__ import annotations

import argparse
import copy
import json
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

MANIFEST_PATH = ".github/pr-evidence.json"
SHA = re.compile(r"[0-9a-f]{40}\Z")
ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
# A glob that matches every path of any one group exempts all code of a language or all build
# files, which would defeat SHA binding. Evidence globs must be narrower than that.
PROBES = (("a.go", "cmd/main.go", "internal/x/y_test.go"), ("a.py", "src/lib/z.py"),
          ("a.ts", "web/src/x.ts", "lib/x.js"), ("a.rs", "src/lib.rs"), ("A.java", "src/main/B.java"),
          ("a.sh", "scripts/x.sh"), ("a.yml", "playbooks/x.yml"), ("Makefile", "go.mod", "package.json"))


def safe_path(path: Any) -> bool:
    return (isinstance(path, str) and bool(path) and not path.startswith("/") and
            all(p not in ("", ".", "..") for p in path.split("/")) and
            not any(c in path for c in "\\\0*?[]"))


def non_runtime_path(path: Any) -> bool:
    """Eligibility only, never an automatic exemption; the reviewer audits each edit.

    CI/Makefile can affect actual runs too. Their explanation must establish that
    the changed targets/steps were outside the recorded target execution.
    Production code, playbooks, locks and inventory cannot be waived this way.
    """
    return safe_path(path) and (
        (path.startswith(("docs/", ".agents/")) and path.endswith(".md")) or
        path.endswith("_test.go") or
        (path.rsplit("/", 1)[-1].startswith("test_") and path.endswith(".py")) or
        path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")) or
        path == "Makefile")


def glob_regex(pattern: str) -> re.Pattern[str]:
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z")


def check_glob(pattern: Any, label: str) -> str | None:
    if not isinstance(pattern, str) or not pattern.strip():
        return f"{label}: glob must be a non-empty string"
    if pattern.startswith("/") or ".." in pattern.split("/"):
        return f"{label}: glob {pattern!r} must be relative and stay inside the repository"
    rx = glob_regex(pattern)
    if any(all(rx.match(p) for p in group) for group in PROBES):
        return f"{label}: glob {pattern!r} covers all code or all build files and would defeat SHA binding"
    return None


def git(worktree: Path, *args: str) -> tuple[int, str]:
    try:
        p = subprocess.run(["git", "-C", str(worktree), *args], capture_output=True, text=True, check=False)
    except OSError:
        return 127, ""
    return p.returncode, p.stdout


def validate_manifest(data: Any) -> list[str]:
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return [f"{MANIFEST_PATH}: must be an object with schema_version 1"]
    errors: list[str] = []
    only = data.get("evidence_only_paths", [])
    if not isinstance(only, list):
        errors.append("evidence_only_paths must be a list")
    else:
        errors += [e for i, p in enumerate(only) if (e := check_glob(p, f"evidence_only_paths[{i}]"))]
    required = data.get("required_evidence", [])
    if not isinstance(required, list):
        return errors + ["required_evidence must be a list"]
    seen: set[str] = set()
    for i, item in enumerate(required):
        label = f"required_evidence[{i}]"
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not ID.fullmatch(item["id"]):
            errors.append(f"{label}: needs an id like 'e2e-run'")
            continue
        if item["id"] in seen:
            errors.append(f"{label}: duplicate id {item['id']}")
        seen.add(item["id"])
        if not isinstance(item.get("source"), str) or not item["source"].strip():
            errors.append(f"{label}: source (where the repository mandates it) is required")
        if "kind" in item and item["kind"] != "target-run":
            errors.append(f"{label}.kind must be target-run when present")
        if "artifact_glob" in item and (e := check_glob(item["artifact_glob"], f"{label}.artifact_glob")):
            errors.append(e)
        # Paths whose change always needs this evidence. Unlike evidence_only_paths a broad glob only
        # makes the rule stricter, so check_glob's whole-tree probe does not apply.
        paths = item.get("required_paths", [])
        if not isinstance(paths, list) or not all(
                isinstance(p, str) and p.strip() and not p.startswith("/") and ".." not in p.split("/")
                and "\\" not in p for p in paths):
            errors.append(f"{label}.required_paths must be a list of repository-relative globs")
    return errors


CONTROLLER_PROFILE = "images/evidence-controller/"
CONTROLLER_FILES = {"Dockerfile": "recipe_sha256", "profile.lock.json": "lock_sha256", "ansible.cfg": "config_sha256", "launch.py": "launch_sha256", "probe.py": "probe_sha256"}
CONTROLLER_STAGES = ("L1 syntax check", "L3 check-mode dry-run", "L4 apply", "L5 verify", "L6 idempotency")
CONTROLLER_PLUGINS = ("action_plugins", "become_plugins", "cache_plugins", "callback_plugins", "cliconf_plugins", "connection_plugins", "doc_fragments", "filter_plugins", "httpapi_plugins", "inventory_plugins", "library", "lookup_plugins", "module_utils", "netconf_plugins", "shell_plugins", "strategy_plugins", "terminal_plugins", "test_plugins", "vars_plugins")


def validate_controller(record: dict, files: list, read_profile) -> None:
    """Typed native boundary proof; no flag or supplied execution path list can replace it."""
    def require(condition, reason):
        if not condition:
            raise ValueError("controller proof: " + reason)
    digest = re.compile(r"[0-9a-f]{64}")
    proof = record.get("controller")
    require(isinstance(proof, dict) and proof.get("schema") == "pilot-controller/v1", "missing current OCI proof")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", str(proof.get("image_id"))), "immutable image ID required")
    require(proof.get("inventory_kind") == "pilot-rendered-ssh/v1", "unsupported rendered inventory")
    for key in ("config_sha256", "inventory_sha256", "rendered_inventory_sha256", "binary_sha256", "pre_probe_sha256", "post_probe_sha256"):
        require(isinstance(proof.get(key), str) and digest.fullmatch(proof[key]), "invalid " + key)
    require(proof["binary_sha256"] == record.get("pilot_binary", {}).get("sha256"), "binary identity differs")
    require(proof["pre_probe_sha256"] == proof["post_probe_sha256"], "native pre/post context differs")
    profile = proof.get("profile", {})
    scoped = {entry.get("path"): entry for entry in files if isinstance(entry, dict)}
    for name, key in CONTROLLER_FILES.items():
        path = CONTROLLER_PROFILE + name
        raw = read_profile(path)
        require(isinstance(raw, bytes) and raw, "profile missing from tested candidate: " + path)
        value = hashlib.sha256(raw).hexdigest()
        require(profile.get(key) == value and scoped.get(path, {}).get("sha256") == value,
                "profile identity differs from closure: " + path)
    require(profile.get("config_sha256") == proof["config_sha256"], "effective config differs from profile")
    lock = json.loads(read_profile(CONTROLLER_PROFILE + "profile.lock.json"))
    require(lock.get("schema") == "pilot-controller-profile/v1" and lock.get("ansible") == "2.21.5" and lock.get("python") == "3.14.8" and lock.get("platform") == "linux/amd64", "unsupported profile lock")
    require(re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", str(lock.get("base"))), "base is not digest pinned")
    require(lock.get("go")=="go1.26.8" and re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}",str(lock.get("go_base"))), "Go toolchain lock differs")
    recipe=read_profile(CONTROLLER_PROFILE + "Dockerfile")
    require(recipe.startswith(("FROM "+lock["go_base"]+" AS go_toolchain\n").encode()) and ("\nFROM "+lock["base"]+"\n").encode() in recipe, "recipe/base lock differs")
    native = proof.get("native_probe")
    require(isinstance(native, dict) and native.get("schema") == "pilot-controller-probe/v1", "missing native origin/config probe")
    raw = json.dumps(native, sort_keys=True, separators=(",", ":")).encode()
    require(hashlib.sha256(raw).hexdigest() == proof["pre_probe_sha256"], "native probe digest differs")
    require(native.get("go")=="go version go1.26.8 linux/amd64" and native.get("ansible") == lock["ansible"] and native.get("python") == lock["python"] and
            native.get("ansible_origin") == "/usr/local/lib/python3.14/site-packages/ansible/__init__.py" and
            native.get("python_executable") == "/usr/bin/python3.14" and
            native.get("config_file") == "/opt/pilot-controller/ansible.cfg" and
            native.get("config_sha256") == proof["config_sha256"], "native effective origins/config differ")
    require(native.get("collections_scan_sys_path") is False and
            native.get("collections") == ["/opt/pilot-controller/empty"] and
            native.get("roles") == ["/opt/pilot-controller/empty"], "uncontrolled collection/role discovery")
    require(native.get("sys_path") == ["/usr/local/lib64/python3.14/site-packages", "/usr/local/lib/python3.14/site-packages", "/usr/lib64/python314.zip", "/usr/lib64/python3.14", "/usr/lib64/python3.14/lib-dynload", "/usr/lib64/python3.14/site-packages", "/usr/lib/python3.14/site-packages"], "uncontrolled Python discovery")
    loaders = native.get("loaders", {})
    require(isinstance(loaders, dict) and set(loaders) == set(CONTROLLER_PLUGINS), "native loader inventory differs")
    for name, loader in loaders.items():
        expected = ["/opt/pilot-controller/empty"]
        if name == "shell_plugins":
            expected = ["shell_plugins"]
        elif name == "doc_fragments":
            expected = ["/tmp/controller/home/.ansible/plugins/doc_fragments", "/usr/share/ansible/plugins/doc_fragments"]
        require(isinstance(loader, dict) and loader.get("config") == expected and isinstance(loader.get("paths"), list) and loader["paths"], "uncontrolled loader config: " + name)
        for path in loader["paths"]:
            require(isinstance(path, str) and (path in ("/opt/pilot-controller/empty", "$CANDIDATE/shell_plugins", "/tmp/controller/home/.ansible/plugins/doc_fragments", "/usr/share/ansible/plugins/doc_fragments") or path.startswith("/usr/local/lib/python3.14/site-packages/ansible/")), "uncontrolled loader origin: " + name)
    build=proof.get("build",{})
    require(isinstance(build,dict) and build.get("go_version")=="go1.26.8" and build.get("path")=="github.com/kjelly/pilot/cmd/pilot" and build.get("module")=="github.com/kjelly/pilot", "unproved Go binary identity")
    require(all(build.get(key)==value for key,value in {"goos":"linux","goarch":"amd64","goamd64":"v1","cgo":"0"}.items()), "unsupported Go build context")
    require(all(isinstance(build.get(key),str) and digest.fullmatch(build[key]) for key in ("settings_sha256","modules_sha256")), "missing Go build/module fingerprints")
    require(all(path in scoped for path in ("go.mod","go.sum","cmd/pilot/main.go")), "compiled Go source closure missing")
    counts = proof.get("steps", {})
    require(isinstance(counts, dict) and set(counts) == set(CONTROLLER_STAGES), "routed stage identities missing")
    for name in CONTROLLER_STAGES:
        value = counts.get(name)
        require(type(value) is int and (value >= 1 if name == "L5 verify" else value == 1), "stage was not routed through OCI: " + name)
    recorded = record.get("steps", [])
    for name in CONTROLLER_STAGES:
        matching = [step for step in recorded if isinstance(step, dict) and step.get("name") == name]
        require(len(matching) == 1 and matching[0].get("status") == "pass", "required recorded stage did not pass: " + name)
    verdicts = record.get("verify", [])
    require(len(verdicts) == counts["L5 verify"] and all(isinstance(v, dict) and v.get("verdict") == "PASS" and type(v.get("pass")) is int and v["pass"] > 0 and v.get("fail") == 0 for v in verdicts), "whole L5 verification evidence missing or failed")


class Context:
    """Evidence rules for one gate run at a fixed HEAD."""

    def __init__(self, worktree: Path, head: str, manifest: dict[str, Any] | None,
                 errors: list[str], warnings: list[str], base_ref: str | None = None):
        self.worktree, self.head, self.manifest, self.base_ref = worktree, head, manifest, base_ref
        self.errors, self.warnings = errors, warnings
        self.accepted: list[dict[str, Any]] = []
        self._cache: dict[str, list[str] | None] = {}
        self._target_errors: dict[str, str] = {}
        manifest = manifest or {}
        self.required = {r["id"]: r for r in manifest.get("required_evidence", [])}
        globs = list(manifest.get("evidence_only_paths", []))
        globs += [r["artifact_glob"] for r in self.required.values() if "artifact_glob" in r]
        self.patterns = [glob_regex(g) for g in globs]

    @classmethod
    def load(cls, worktree: Path, head: str, base_ref: str | None) -> "Context":
        errors: list[str] = []
        warnings: list[str] = []
        manifest = None
        if not base_ref:
            warnings.append("No base ref given; repository evidence rules not loaded (strict SHA binding applies)")
        else:
            rc, _ = git(worktree, "rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}")
            if rc:
                warnings.append(f"Base ref {base_ref} not found locally (run git fetch); repository evidence rules not loaded")
            else:
                rc, text = git(worktree, "show", f"{base_ref}:{MANIFEST_PATH}")
                if rc:
                    warnings.append(f"No {MANIFEST_PATH} on {base_ref}: repository-mandated evidence is NOT machine-checked. "
                                    "List what AGENTS.md/CONTRIBUTING require and get the user's confirmation.")
                else:
                    try:
                        manifest = json.loads(text)
                    except json.JSONDecodeError as exc:
                        errors.append(f"{MANIFEST_PATH} on {base_ref} is not valid JSON: {exc}")
                    else:
                        bad = validate_manifest(manifest)
                        if bad:
                            errors += [f"{MANIFEST_PATH} on {base_ref}: {e}" for e in bad]
                            manifest = None
        return cls(worktree, head, manifest, errors, warnings, base_ref)

    def delta_files(self, sha: str) -> list[str] | None:
        """Files changed from `sha` to HEAD, or None when `sha` is not an ancestor."""
        if sha in self._cache:
            return self._cache[sha]
        result = None
        if SHA.fullmatch(sha):
            rc, _ = git(self.worktree, "merge-base", "--is-ancestor", sha, self.head)
            if rc == 0:
                rc, out = git(self.worktree, "diff", "--name-only", "--no-renames", "-z", f"{sha}..{self.head}")
                if rc == 0:
                    result = [p for p in out.split("\0") if p]
        self._cache[sha] = result
        return result

    def change_files(self) -> list[str] | None:
        """Files the change touches (merge base of the base ref to HEAD, both names of a rename), or
        None when they cannot be listed."""
        if not self.base_ref:
            return None
        rc, out = git(self.worktree, "diff", "--name-only", "--no-renames", "-z", f"{self.base_ref}...{self.head}")
        return None if rc else [p for p in out.split("\0") if p]

    def accepts(self, sha: Any, label: str) -> bool:
        """True if evidence taken at `sha` still covers HEAD."""
        if sha == self.head:
            return True
        if not isinstance(sha, str) or not self.patterns:
            return False
        changed = self.delta_files(sha)
        if changed is None or any(not any(rx.match(p) for rx in self.patterns) for p in changed):
            return False
        self.accepted.append({"label": label, "from": sha, "head": self.head, "changed": changed})
        return True

    def comparison(self, base: str, head: str) -> dict[str, Any] | None:
        rc, out = git(self.worktree, "merge-base", "--all", base, head)
        ancestors = out.splitlines()
        if rc or len(ancestors) != 1:
            return None
        ancestor = ancestors[0]
        return {"merge_base": ancestor, "ancestor": ancestor == base}

    def base_revision(self) -> str | None:
        if not self.base_ref:
            return None
        rc, out = git(self.worktree, "rev-parse", "--verify", f"{self.base_ref}^{{commit}}")
        return None if rc else out.strip()

    def tree_entries(self, revision: str) -> dict[str, tuple[str, str]] | None:
        rc, out = git(self.worktree, "ls-tree", "-r", "-z", "--full-tree", revision)
        if rc:
            return None
        entries = {}
        for row in out.split("\0"):
            if row:
                metadata, path = row.split("\t", 1)
                mode, _, oid = metadata.split()
                entries[path] = (mode, oid)
        return entries

    def read_file(self, revision: str, path: str) -> bytes | None:
        if not safe_path(path):
            return None
        proc = subprocess.run(["git", "-C", str(self.worktree), "show", f"{revision}:{path}"],
                              capture_output=True, check=False)
        return None if proc.returncode else proc.stdout

    def commit_tree(self, revision: str) -> str | None:
        rc, out = git(self.worktree, "rev-parse", f"{revision}^{{tree}}")
        return None if rc else out.strip()

    def _machine_scope(self, sha: str, artifact: Any) -> tuple[dict[str, Any] | None, list[str]]:
        """Read committed bytes, never an uncommitted worktree record or a supplied path list."""
        if not safe_path(artifact):
            return None, ["machine record artifact must be a safe repository path"]
        text = self.read_file(self.head, artifact)
        if text is None:
            return None, ["machine record artifact is not committed at HEAD"]
        if b"<!-- pilot-evidence-record" not in text:
            return None, []  # legacy manual records keep the independent closure review
        match = re.search(rb"<!-- pilot-evidence-record[^>]*-->\s*```json\n(.*?)\n```", text, re.S)
        try:
            record = json.loads(match[1]) if match else None
            if not isinstance(record, dict) or record.get("schema") != "pilot-evidence-record/v1":
                raise ValueError("unsupported schema or missing machine block")
            candidate = record.get("candidate", {})
            if (candidate.get("commit") != sha or candidate.get("dirty") or
                    candidate.get("source") not in ("git", "flag") or
                    candidate.get("tree") != self.commit_tree(sha)):
                raise ValueError("candidate/tree mismatch or dirty candidate")
            if record.get("outcome") != "success":
                raise ValueError("target chain did not succeed")
            closure = record.get("closure")
            if not isinstance(closure, dict) or closure.get("unresolved") or closure.get("external"):
                raise ValueError("closure has unresolved or external inputs")
            if closure.get("resolution_version") != 7 or closure.get("frozen") is not True:
                raise ValueError("closure needs current resolution version and frozen pre-run inputs")
            files, patterns = closure.get("files"), closure.get("patterns")
            if not isinstance(files, list) or not files or not isinstance(patterns, list):
                raise ValueError("closure needs files and machine search patterns")
            tested, head = self.tree_entries(sha), self.tree_entries(self.head)
            if tested is None or head is None:
                raise ValueError("complete Git trees unavailable")
            scope = []
            for entry in files:
                if (not isinstance(entry, dict) or not safe_path(entry.get("path")) or
                        entry.get("mode") not in ("100644", "100755") or
                        not isinstance(entry.get("blob"), str) or not SHA.fullmatch(entry["blob"])):
                    raise ValueError("invalid closure file")
                path = entry["path"]
                if path in scope or tested.get(path) != (entry["mode"], entry["blob"]):
                    raise ValueError("closure blob/mode differs from candidate: " + path)
                scope.append(path)
            validate_controller(record, files, lambda path: self.read_file(sha, path))
            for pattern in patterns:
                if (not isinstance(pattern, str) or not pattern or pattern.startswith("/") or
                        ".." in pattern.split("/") or "\\" in pattern or "\0" in pattern):
                    raise ValueError("invalid closure search pattern")
                # filepath.Glob supports brackets; fail closed until the shared matcher does too.
                if "[" in pattern or "]" in pattern:
                    raise ValueError("unsupported closure search pattern")
                rx = glob_regex(pattern)
                if {p for p in tested if rx.match(p)} != {p for p in head if rx.match(p)}:
                    raise ValueError("closure search membership changed: " + pattern)
            return {"execution_paths": scope}, []
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            return None, ["machine record: " + str(exc)]

    def accepts_target(self, sha: Any, label: str, reuse: Any = None, artifact: Any = None) -> bool:
        """Target-run reuse only. Never call this for reviews or general check receipts.

        A fresh independent reviewer supplies the complete execution/dependency scope.
        Git verifies unchanged scoped blobs AND modes, and proves that every other
        change is imported unchanged from base, or an individually audited non-runtime
        file. It cannot prove the semantic completeness of the reviewer's scope.
        """
        if reuse is None:
            return self.accepts(sha, label)
        reuse = copy.deepcopy(reuse)
        if artifact is not None:
            machine, errors = self._machine_scope(sha, artifact)
            if errors:
                self._target_errors[str(sha)] = "; ".join(errors)
                return False
            if machine is not None:
                if not isinstance(reuse, dict):
                    self._target_errors[str(sha)] = "target reuse must be an object"
                    return False
                reuse.update(machine)
        errors = self._target_reuse_errors(sha, reuse)
        if errors:
            self._target_errors[str(sha)] = "; ".join(errors)
            return False
        self.accepted.append({"label": label, "from": sha, "head": self.head,
                              "method": "reviewed-base-integration", "base": reuse["base_sha"],
                              "execution_paths": reuse["execution_paths"],
                              "non_execution_changes": reuse["non_execution_changes"]})
        return True

    def _target_reuse_errors(self, sha: Any, reuse: Any) -> list[str]:
        if not isinstance(reuse, dict):
            return ["target reuse must be an object"]
        if not isinstance(sha, str) or not SHA.fullmatch(sha):
            return ["target reuse needs a full tested candidate SHA"]
        if reuse.get("head_sha") != self.head or reuse.get("reviewer_confirmed") is not True:
            return ["target reuse needs independent reviewer confirmation at current HEAD"]
        reason = reuse.get("dependency_review")
        if not isinstance(reason, str) or len(reason.strip()) < 60:
            return ["target reuse needs a dependency review (60+ characters)"]
        base = reuse.get("base_sha")
        if not isinstance(base, str) or not SHA.fullmatch(base) or not self.base_ref:
            return ["target reuse needs the current full base SHA"]
        if self.base_revision() != base:
            return ["target reuse base SHA does not match current base"]
        return self._verify_target_trees(sha, base, reuse)

    def _verify_target_trees(self, sha: str, base: str, reuse: dict[str, Any]) -> list[str]:
        old_to_head = self.comparison(sha, self.head)
        base_to_head = self.comparison(base, self.head)
        fork = self.comparison(sha, base)
        if not old_to_head or not old_to_head["ancestor"]:
            return ["tested candidate is not an ancestor of HEAD"]
        if not base_to_head or not base_to_head["ancestor"]:
            return ["current base has not been integrated into HEAD"]
        if not fork or fork["merge_base"] in (sha, base):
            return ["target reuse requires a candidate branch and an advanced base"]
        scope = reuse.get("execution_paths")
        if (not isinstance(scope, list) or not scope or
                any(not safe_path(p) for p in scope) or len(set(scope)) != len(scope)):
            return ["execution_paths must list unique exact files, including all execution dependencies"]
        audited = reuse.get("non_execution_changes")
        if not isinstance(audited, list):
            return ["non_execution_changes must be a list"]
        exemptions = {}
        for item in audited:
            if (not isinstance(item, dict) or not non_runtime_path(item.get("path")) or
                    not isinstance(item.get("reason"), str) or len(item["reason"].strip()) < 30):
                return ["each non-execution change needs an eligible exact path and a 30+ character explanation"]
            path = item["path"]
            if path in exemptions or path in scope:
                return ["duplicate or overlapping non-execution change: " + path]
            exemptions[path] = item
        trees = [self.tree_entries(r) for r in (sha, self.head, base, fork["merge_base"])]
        if any(t is None for t in trees):
            return ["complete Git trees unavailable for target reuse"]
        tested, head, upstream, ancestor = trees
        for path in scope:
            before, after = tested.get(path), head.get(path)
            if not before or before[0] not in ("100644", "100755") or before != after:
                return ["execution input changed, missing or not a regular file: " + path]
        changed = sorted(p for p in tested.keys() | head.keys() if tested.get(p) != head.get(p))
        for path in exemptions:
            if path not in changed:
                return ["non-execution audit names an unchanged path: " + path]
        for path in changed:
            if any(rx.match(path) for rx in self.patterns):
                continue
            if path in exemptions:
                # A symlink/submodule is not a documentation or test text edit.
                if any(t.get(path) and t[path][0] not in ("100644", "100755") for t in (tested, head)):
                    return ["non-execution audit cannot exempt a symlink or submodule: " + path]
                continue
            # Pure upstream import: candidate had no local edit, and HEAD kept base
            # byte for byte. This rejects unreviewed blends/conflict resolutions,
            # candidate code deletion, renames into evidence, and local runtime edits.
            if tested.get(path) != ancestor.get(path) or head.get(path) != upstream.get(path):
                return ["change is neither a pure base import nor an audited non-execution change: " + path]
        return []

    def target_stale_reason(self, sha: Any) -> str:
        if str(sha) in self._target_errors:
            return self._target_errors[str(sha)]
        return self.stale_reason(sha)

    def stale_reason(self, sha: Any) -> str:
        if not self.patterns:
            return "no evidence_only_paths declared on the base branch"
        changed = self.delta_files(sha) if isinstance(sha, str) else None
        if changed is None:
            return "SHA is not an ancestor of HEAD"
        outside = [p for p in changed if not any(rx.match(p) for rx in self.patterns)]
        return "files outside evidence_only_paths changed: " + ", ".join(outside[:5])

    def check_required(self, entries: Any) -> list[str]:
        errors = list(self.errors)
        if entries is None:
            entries = []
        if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
            return errors + ["repo_required_evidence must be a list of objects"]
        by_id: dict[str, list[dict[str, Any]]] = {}
        for e in entries:
            by_id.setdefault(str(e.get("id")), []).append(e)
        for rid in self.required:
            if rid not in by_id:
                errors.append(f"Repository-required evidence '{rid}' missing "
                              f"({self.required[rid].get('source')}); add it to repo_required_evidence")
        for rid, items in by_id.items():
            if len(items) > 1:
                errors.append(f"repo_required_evidence '{rid}' listed more than once")
            glob = self.required.get(rid, {}).get("artifact_glob")
            errors += self._check_entry(rid, items[0], glob)
        return errors

    def _check_entry(self, rid: str, entry: dict[str, Any], glob: str | None) -> list[str]:
        label = f"repo_required_evidence[{rid}]"
        status = entry.get("status")
        if status == "not-applicable":
            reason = entry.get("reason")
            if not isinstance(reason, str) or len(reason.strip()) < 30 or entry.get("reviewer_confirmed") is not True:
                return [f"{label}: not-applicable needs a specific reason (30+ chars) and reviewer_confirmed true"]
            return self._required_paths_touched(rid, label)
        if status != "pass":
            return [f"{label}: status must be 'pass' or 'not-applicable'"]
        errors: list[str] = []
        sha = entry.get("head_sha")
        reuse = entry.get("target_reuse")
        if reuse is not None and self.required.get(rid, {}).get("kind") != "target-run":
            errors.append(f"{label}: target_reuse requires kind: target-run on the base manifest")
            reuse = None
        if not self.accepts_target(sha, label, reuse, entry.get("artifact")):
            errors.append(f"{label}: run was taken at {str(sha)[:12]}, not HEAD ({self.target_stale_reason(sha)})")
        summary = entry.get("summary")
        if not isinstance(summary, str) or len(summary.strip()) < 20:
            errors.append(f"{label}: summary of what was observed is required")
        art, url = entry.get("artifact"), entry.get("url")
        if art is None and glob is None and url is not None:
            # Evidence kept outside the repository (CI run, test-management system, wiki).
            if not isinstance(url, str) or not re.fullmatch(r"https://[^\s]+", url):
                errors.append(f"{label}: url must be an https:// link")
        elif not isinstance(art, str) or not art.strip() or art.startswith("/") or ".." in art.split("/"):
            errors.append(f"{label}: artifact must be a repository-relative path"
                          + ("" if glob else " (or give an https:// url when the evidence lives outside the repository)"))
        else:
            rc, kind = git(self.worktree, "cat-file", "-t", f"{self.head}:{art}")
            if rc or kind.strip() != "blob":
                errors.append(f"{label}: artifact {art} is not committed at HEAD (commit the evidence file)")
            if glob and not glob_regex(glob).match(art):
                errors.append(f"{label}: artifact {art} is outside the required location {glob}")
        return errors

    def _required_paths_touched(self, rid: str, label: str) -> list[str]:
        """not-applicable is refused when the change touches the manifest's required_paths for this
        evidence (pr-review-merge refuses not-needed for them the same way)."""
        paths = self.required.get(rid, {}).get("required_paths") or []
        if not paths:
            return []
        changed = self.change_files()
        if changed is None:
            return [f"{label}: not-applicable cannot be checked against required_paths: "
                    f"the changed files against {self.base_ref} cannot be listed"]
        patterns = [glob_regex(p) for p in paths]
        hits = sorted({p for p in changed if any(rx.match(p) for rx in patterns)})
        if hits:
            return [f"{label}: not-applicable is refused: the change touches {', '.join(hits[:5])}, which "
                    f"required_paths on the base branch always cover; run it and record status 'pass'"]
        return []

    def report(self) -> dict[str, Any]:
        return {"manifest_loaded": self.manifest is not None,
                "required": sorted(self.required),
                "delta_accepted": self.accepted,
                "warnings": self.warnings}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--worktree", type=Path, required=True)
    ap.add_argument("--base-ref", required=True, help="e.g. origin/main")
    a = ap.parse_args()
    rc, head = git(a.worktree, "rev-parse", "HEAD")
    ctx = Context.load(a.worktree, head.strip(), a.base_ref)
    print(json.dumps({"manifest": ctx.manifest, "errors": ctx.errors, **ctx.report()}, indent=2))
    return 2 if ctx.errors else 0


if __name__ == "__main__":
    sys.exit(main())
