#!/usr/bin/env python3
"""Value-free secret scan over EVERY commit of BASE..HEAD (standard library + git only).

A later commit does not undo an earlier one: a branch that added a credential and then replaced it
with a placeholder still publishes the credential through its history. So the scan walks each commit
of the range (one streamed `git log -p`, plus each commit message) instead of the final diff, and
the three quality gates (issue-to-pr, pr-ready, pr-review-merge) refuse a branch with any finding.

What it reports: the class, the file, the line and the commit. Never the value, a hash of it or any
part of it; no exception text is ever echoed either. The rules, and what to do on a finding, are in
`.agents/skills/_shared/committed-secrets.md`.

Classes are decided by the shape of the value, never by a name that merely contains "password":
  freeipa-secret-attribute  ipanthash/userpassword/krbprincipalkey/ipatokenotpkey used as a key whose
                            value is secret-shaped (not the fixture placeholder)
  private-key               `-----BEGIN ... PRIVATE KEY-----` followed by a key body
  authorization-header      `Authorization:` with a bearer/basic/... credential
  cookie-header             `Cookie:`/`Set-Cookie:` with a credential-shaped name=value
  ipa-session               `ipa_session=` followed by a session value
  known-value               a value the operator supplied with --secret-file (never exempted)

Exit status of the CLI: 0 clean, 1 findings, 2 error (the scan could not be completed).
"""
from __future__ import annotations

import argparse
import bisect
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify` counts any
# added file and would STOP every later step.
sys.dont_write_bytecode = True

SCHEMA = "pilot-secret-scan/v1"
GUIDE = ".agents/skills/_shared/committed-secrets.md"
EXEMPTIONS_PATH = ".github/secret-scan.json"
MESSAGE_PATH = "(commit message)"

FREEIPA_ATTRIBUTE = "freeipa-secret-attribute"
PRIVATE_KEY = "private-key"
AUTHORIZATION = "authorization-header"
COOKIE = "cookie-header"
IPA_SESSION = "ipa-session"
KNOWN_VALUE = "known-value"
CLASSES = (FREEIPA_ATTRIBUTE, PRIVATE_KEY, AUTHORIZATION, COOKIE, IPA_SESSION, KNOWN_VALUE)

# Kept equal to internal/freeiparpc/fixture_secrets_test.go (secretFixtureAttributes and
# fixtureSecretPlaceholder); test_secret_scan.py parses that file and fails when they drift.
SECRET_ATTRIBUTES = ("ipanthash", "userpassword", "krbprincipalkey", "ipatokenotpkey")
PLACEHOLDER = "AAAAAAAAAAAAAAAAAAAAAA=="

MIN_KNOWN_LENGTH = 8
MAX_CONTEXT_BYTES = 16 << 20     # a file larger than this is judged on its added trigger lines only
LINE_WINDOW = 2 << 20            # a diff line longer than this is read in windows
WINDOW_OVERLAP = 4096            # bytes of the previous window that the next one starts with
MAX_KNOWN_LENGTH = 1 << 16       # a --secret-file value longer than this is refused (windows overlap by its length)
MAX_TRIGGER_BYTES = 2 * MAX_CONTEXT_BYTES  # trigger text kept per file before it is judged and dropped
MAX_LISTED = 12                  # findings spelled out in a gate message
MAX_REPORTED = 500               # findings kept in a result


# --------------------------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    commit: str
    path: str
    line: int | None
    cls: str

    def to_json(self) -> dict[str, Any]:
        return {"commit": self.commit, "path": self.path, "line": self.line, "class": self.cls}


@dataclass
class ScanResult:
    base: str
    head: str
    commits: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    exempted: list[Finding] = field(default_factory=list)
    known_values: int = 0
    exemptions_source: str = "absent"
    truncated: int = 0

    @property
    def status(self) -> str:
        if self.findings:
            return "FOUND"
        return "ERROR" if self.errors else "CLEAN"

    def to_json(self) -> dict[str, Any]:
        return {"schema": SCHEMA, "status": self.status, "base": self.base, "head": self.head,
                "commits_scanned": self.commits, "known_values": self.known_values,
                "exemptions_source": self.exemptions_source,
                "findings": [f.to_json() for f in self.findings],
                "findings_truncated": self.truncated,
                "exempted": [f.to_json() for f in self.exempted],
                "errors": list(self.errors)}

    def summary(self) -> dict[str, Any]:
        """The value-free digest a gate puts into its own JSON."""
        return {"status": self.status, "base": self.base, "head": self.head,
                "commits_scanned": self.commits, "findings": len(self.findings) + self.truncated,
                "exempted": len(self.exempted), "known_values": self.known_values,
                "exemptions_source": self.exemptions_source}


class SecretScanError(ValueError):
    """A usage or input problem; the message never contains a value."""


# --------------------------------------------------------------------------------------------
# Value shapes
# --------------------------------------------------------------------------------------------

B64_RUN = re.compile(r"[A-Za-z0-9+/]{12,}={0,2}")
SCHEME = re.compile(r"\{[A-Z0-9][A-Z0-9_-]{1,19}\}[A-Za-z0-9+/=$.]{8,}")
CREDENTIAL = re.compile(r"[A-Za-z0-9._~+/=-]+")
COOKIE_VALUE = re.compile(r"[A-Za-z0-9._~+/=%-]+")
BASE64_VALUE = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def _classes(token: str) -> int:
    return (any(c.islower() for c in token) + any(c.isupper() for c in token)
            + any(c.isdigit() for c in token))


def credential_shaped(token: str, *, charset: re.Pattern[str] = CREDENTIAL) -> bool:
    """Random-looking data, not a word: `[A-Za-z0-9._~+/=-]`, and at least two of lower, upper and
    digit, or 32+ characters. A placeholder (`<..>`, `$VAR`, `{{..}}`, `***`) has characters outside
    the charset; a name such as `krbprincipalkey` is one class and short."""
    return bool(charset.fullmatch(token)) and (_classes(token) >= 2 or len(token) >= 32)


def _placeholder_value(value: str) -> bool:
    return (value.startswith(("<", "$", "{", "[", "*", "(", "%", "`")) or "{{" in value
            or bool(re.fullmatch(r"(?i)(?:x+|\*+|\.+|redacted|placeholder|changeme)", value)))


def secret_like_string(text: str) -> bool:
    """True when `text` carries a secret-shaped token: a `{SCHEME}` prefix with data after it, or a
    run of 12+ base64/hex characters that is credential-shaped. The fixture placeholder is not one."""
    text = text.replace(PLACEHOLDER, "")
    if SCHEME.search(text):
        return True
    return any(credential_shaped(m.group(0).rstrip("=") or m.group(0)) for m in B64_RUN.finditer(text))


def _unsafe_value(obj: Any) -> bool:
    """Whether a parsed JSON value of a secret attribute carries a secret. Safe: a non-empty list of
    exactly {"__base64__": placeholder}, or anything without a secret-shaped string (the real
    attributelevelrights answer for these attributes is the string "s")."""
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) and x == {"__base64__": PLACEHOLDER} for x in obj):
            return False
        return any(_unsafe_value(x) for x in obj)
    if isinstance(obj, dict):
        if "__base64__" in obj:
            value = obj["__base64__"]
            if not isinstance(value, str) or (value != PLACEHOLDER and value != ""):
                return True
        return any(_unsafe_value(v) for v in obj.values())
    if isinstance(obj, str):
        return secret_like_string(obj)
    return False


# --------------------------------------------------------------------------------------------
# Classification of a whole text (the file as it stands after a commit, or a commit message)
# --------------------------------------------------------------------------------------------

_ATTR = "|".join(SECRET_ATTRIBUTES)
# A quote may arrive escaped once or twice when the JSON sits inside a string literal.
_KEY_QUOTED = re.compile(rf"""(?i)\\{{0,3}}["'](?P<attr>{_ATTR})\\{{0,3}}["'][ \t]*:""")
# `attr: value` (YAML, LDIF, a Go composite literal, --raw output), `attr:: base64` (LDIF) and `attr=value`.
_KEY_BARE = re.compile(rf"""(?i)(?<![A-Za-z0-9_])(?P<attr>{_ATTR})[ \t]*"""
                       rf"""(?P<sep>::(?=[ \t]|$)|:(?=[ \t]|$|["'\[{{\\])|=(?!=))""", re.MULTILINE)
_PEM_HEADER = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")
_PEM_PIECE_SPLIT = re.compile(r"\r?\n|\\r\\n|\\n|\\r")
_PEM_STRIP = " \t\"'`,+;\\)]}"
_PEM_ARMOR = re.compile(r"[A-Za-z][A-Za-z0-9-]*:\s.*")
_AUTH = re.compile(r"""(?i)(?<![A-Za-z0-9_-])(?:proxy-)?authorization\\{0,3}["']?[ \t]*:[ \t]*\\{0,3}["']?(?P<rest>[^\n]*)""")
_AUTH_SCHEME = re.compile(r"""(?i)(?:bearer|basic|negotiate|digest|token|apikey|api-key)[ \t]+(?P<cred>[^\s"'\\,;]+)""")
_AUTH_BARE = re.compile(r"""(?P<tok>[A-Za-z0-9._~+/=-]{24,})[\s"'\\,;)]*\Z""")
_COOKIE = re.compile(r"""(?i)(?<![A-Za-z0-9_-])(?:set-)?cookie\\{0,3}["']?[ \t]*:[ \t]*\\{0,3}["']?(?P<rest>[^\n]*)""")
_COOKIE_PAIR = re.compile(r"""[ \t]*[A-Za-z0-9_.-]+=(?P<value>[^\s;"',\\)]+)""")
_IPA_SESSION = re.compile(r"""(?i)ipa_session\\{0,3}["']?[ \t]*[:=][ \t]*\\{0,3}["']?(?P<value>[^\s;"',\\]{16,})""")

_JSON = json.JSONDecoder()
_RESTRICT = 1 << 16  # characters of "the rest of the line" ever examined for one key


class _Text:
    """A text decoded as latin-1 (one character per byte, so offsets stay byte offsets) with line lookup."""

    def __init__(self, data: bytes) -> None:
        self.s = data.decode("latin-1")
        self._starts: list[int] | None = None

    def line_of(self, offset: int) -> int:
        if self._starts is None:
            self._starts = [0] + [m.end() for m in re.finditer("\n", self.s)]
        return bisect.bisect_right(self._starts, max(offset, 0))

    def line_end(self, offset: int) -> int:
        end = self.s.find("\n", offset)
        return len(self.s) if end < 0 else end


def _attribute_spans(t: _Text) -> Iterator[tuple[int, int, str]]:
    s = t.s
    seen: set[int] = set()
    matches: list[tuple[int, int, str]] = []  # (key end, key start, separator)
    for m in _KEY_QUOTED.finditer(s):
        matches.append((m.end(), m.start(), ":"))
    for m in _KEY_BARE.finditer(s):
        matches.append((m.end(), m.start(), m.group("sep")))
    for end, start, sep in sorted(matches):
        if start in seen:
            continue
        seen.add(start)
        line_end = t.line_end(end)
        p = end
        while p < line_end and s[p] in " \t":
            p += 1
        unsafe, value_end = None, line_end
        if p < len(s) and s[p] in '[{"':
            try:
                obj, parsed_end = _JSON.raw_decode(s, p)
            except (ValueError, RecursionError):
                pass
            else:
                unsafe = _unsafe_value(obj)
                if unsafe or _value_ends_at(s, parsed_end, line_end):
                    value_end = parsed_end
                else:
                    # The JSON was only the start of the value (`[]` of `[]string{"..."}`): the rest of
                    # it is judged as text as well.
                    unsafe = None
        if unsafe is None:
            rest = s[p:min(line_end, p + _RESTRICT)]
            continuation = line_end
            if sep == "::":
                # LDIF wraps a long value onto lines that begin with exactly one space.
                while continuation < len(s) and s[continuation + 1:continuation + 2] == " " \
                        and s[continuation + 2:continuation + 3] not in ("", " ", "\n"):
                    nxt = t.line_end(continuation + 1)
                    rest += s[continuation + 2:nxt]
                    continuation = nxt
                value_end = continuation
            unsafe = _text_value_is_secret(rest, sep)
        if unsafe:
            yield t.line_of(start), t.line_of(max(value_end - 1, start)), FREEIPA_ATTRIBUTE


def _value_ends_at(s: str, end: int, line_end: int) -> bool:
    """Whether the value parsed up to `end` is the whole value: only whitespace, then the end of the
    line or a `,` `}` `]` that closes it, follows."""
    while end < line_end and s[end] in " \t\r":
        end += 1
    return end >= line_end or s[end] in ",}]"


def _text_value_is_secret(rest: str, sep: str) -> bool:
    value = rest.replace(PLACEHOLDER, "").strip()
    if sep == "::":
        bare = value.strip(" \t\"'")
        if BASE64_VALUE.fullmatch(bare) and len(bare) >= MIN_KNOWN_LENGTH:
            return True
    return secret_like_string(value)


def _private_key_spans(t: _Text) -> Iterator[tuple[int, int, str]]:
    s = t.s
    for m in _PEM_HEADER.finditer(s):
        stop = s.find("-----END", m.end(), m.end() + 200_000)
        segment = s[m.end():stop if stop >= 0 else min(len(s), m.end() + 200_000)]
        body, longest, consumed, pos = 0, 0, 0, 0
        pieces = list(_PEM_PIECE_SPLIT.finditer(segment))
        bounds = [(x.start(), x.end()) for x in pieces] + [(len(segment), len(segment))]
        for piece_end, next_start in bounds:
            piece = segment[pos:piece_end].strip(_PEM_STRIP)
            pos = next_start
            if piece == "":
                if body:
                    break
                continue
            if piece.startswith("-----"):
                break
            if body == 0 and _PEM_ARMOR.fullmatch(piece):
                continue  # Proc-Type / DEK-Info / armor header lines come before the body
            if BASE64_VALUE.fullmatch(piece):
                body += len(piece)
                longest = max(longest, len(piece))
                consumed = piece_end
                continue
            break
        # A PEM body line is 64 or 76 characters; a run of short words after a bare header is not a key.
        if body >= 40 and longest >= 32:
            yield t.line_of(m.start()), t.line_of(m.end() + consumed), PRIVATE_KEY


def _authorization_spans(t: _Text) -> Iterator[tuple[int, int, str]]:
    for m in _AUTH.finditer(t.s):
        rest = m.group("rest")[:_RESTRICT]
        scheme = _AUTH_SCHEME.match(rest)
        if scheme:
            cred = scheme.group("cred")
            hit = len(cred) >= 16 and credential_shaped(cred)
        else:
            bare = _AUTH_BARE.match(rest)
            hit = bool(bare) and credential_shaped(bare.group("tok"))
        if hit:
            line = t.line_of(m.start())
            yield line, line, AUTHORIZATION


def _cookie_spans(t: _Text) -> Iterator[tuple[int, int, str]]:
    for m in _COOKIE.finditer(t.s):
        for part in m.group("rest")[:_RESTRICT].split(";"):
            pair = _COOKIE_PAIR.fullmatch(part.rstrip("\"'\\,) \t"))
            if pair:
                value = pair.group("value")
                if len(value) >= 12 and credential_shaped(value, charset=COOKIE_VALUE):
                    line = t.line_of(m.start())
                    yield line, line, COOKIE
                    break


def _ipa_session_spans(t: _Text) -> Iterator[tuple[int, int, str]]:
    for m in _IPA_SESSION.finditer(t.s):
        if not _placeholder_value(m.group("value")):
            line = t.line_of(m.start())
            yield line, line, IPA_SESSION


def classify(data: bytes) -> list[tuple[int, int, str]]:
    """Every secret-shaped span of `data` as (first line, last line, class); lines are 1-based."""
    t = _Text(data)
    spans: list[tuple[int, int, str]] = []
    for detector in (_attribute_spans, _private_key_spans, _authorization_spans, _cookie_spans,
                     _ipa_session_spans):
        spans.extend(detector(t))
    return spans


def _first_added(added: Sequence[int], first: int, last: int) -> int | None:
    """The smallest number in the sorted `added` within [first, last], or None."""
    i = bisect.bisect_left(added, first)
    return added[i] if i < len(added) and added[i] <= last else None


def _as_bytes(text: bytes | str) -> bytes:
    return text if isinstance(text, bytes) else text.encode("utf-8", "surrogateescape")


def _known_regex(known: Sequence[bytes]) -> re.Pattern[bytes] | None:
    return re.compile(b"|".join(re.escape(v) for v in sorted(set(known), key=len, reverse=True))) if known else None


def scan_text(path: str, text: bytes | str, added_lines: Iterable[int] | None = None, *,
              known: Sequence[bytes] = ()) -> list[Finding]:
    """Findings in `text`. With `added_lines` (1-based), only spans that overlap one of those lines
    count: secret-shaped content that was already there is not this change's."""
    data = _as_bytes(text)
    added = None if added_lines is None else sorted(set(added_lines))
    found: dict[tuple[str, int], Finding] = {}
    for first, last, cls in classify(data):
        line = first if added is None else _first_added(added, first, last)
        if line is not None:
            found.setdefault((cls, line), Finding("", path, line, cls))
    pattern = _known_regex(known)
    if pattern is not None:
        for number, raw in enumerate(data.split(b"\n"), 1):
            if (added is None or _first_added(added, number, number) is not None) and pattern.search(raw):
                found.setdefault((KNOWN_VALUE, number), Finding("", path, number, KNOWN_VALUE))
    return sorted(found.values(), key=lambda f: (f.line or 0, f.cls))


# --------------------------------------------------------------------------------------------
# Inputs: known values and the base-branch exemptions
# --------------------------------------------------------------------------------------------

def load_secret_files(paths: Iterable[str | os.PathLike[str]], worktree: str | os.PathLike[str] | None) -> list[bytes]:
    """The values in --secret-file files (one per line; read as bytes, one trailing CR stripped,
    blank lines ignored). A file must be a regular file outside the repository, a value shorter
    than 8 bytes is refused (it would match half of the repository) and so is one longer than 64 KiB
    (a very long added line is read in windows that overlap by the longest value, so that a value
    split across two windows is still found). Errors name the file and line number, never a value."""
    root = Path(os.path.realpath(worktree)) if worktree is not None else None
    values: list[bytes] = []
    for raw in paths:
        name = str(raw)
        try:
            real = Path(os.path.realpath(raw))
            mode = os.stat(real).st_mode
        except OSError as exc:
            raise SecretScanError(f"secret file {name} cannot be read ({exc.strerror or 'error'})") from None
        if not stat.S_ISREG(mode):
            raise SecretScanError(f"secret file {name} is not a regular file")
        if root is not None and (real == root or root in real.parents):
            raise SecretScanError(f"secret file {name} is inside the repository; keep it outside "
                                  "so it can never be committed")
        try:
            content = real.read_bytes()
        except OSError as exc:
            raise SecretScanError(f"secret file {name} cannot be read ({exc.strerror or 'error'})") from None
        for number, line in enumerate(content.split(b"\n"), 1):
            if line.endswith(b"\r"):
                line = line[:-1]
            if not line:
                continue
            if len(line) < MIN_KNOWN_LENGTH:
                raise SecretScanError(f"secret file {name} line {number}: a value shorter than "
                                      f"{MIN_KNOWN_LENGTH} bytes would match ordinary text; refusing it")
            if len(line) > MAX_KNOWN_LENGTH:
                raise SecretScanError(f"secret file {name} line {number}: a value longer than "
                                      f"{MAX_KNOWN_LENGTH} bytes is not a credential this scan can window; refusing it")
            values.append(line)
    return list(dict.fromkeys(values))


@dataclass(frozen=True)
class Exemption:
    cls: str
    path_glob: str
    reason: str


def glob_regex(pattern: str) -> re.Pattern[str]:
    """The dialect of issue-to-pr's repo_evidence.glob_regex (`**/`, `**`, `*`, `?`); the test suite
    checks the two agree."""
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


_PROBES = ("a.go", "docs/x.md", "internal/x/y.json", "playbooks/x.yml", ".agents/skills/x/SKILL.md")


def parse_exemptions(raw: bytes) -> list[Exemption]:
    """Validate `.github/secret-scan.json`. Anything malformed raises SecretScanError: a scan with a
    broken exemption list is an error, never an unguarded pass."""
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SecretScanError(f"{EXEMPTIONS_PATH} is not valid UTF-8 JSON") from None
    if not isinstance(data, dict) or data.get("schema_version") != 1 or set(data) - {"schema_version", "allow"}:
        raise SecretScanError(f"{EXEMPTIONS_PATH} must be an object with schema_version 1 and an allow list")
    allow = data.get("allow", [])
    if not isinstance(allow, list):
        raise SecretScanError(f"{EXEMPTIONS_PATH}: allow must be a list")
    result: list[Exemption] = []
    for index, item in enumerate(allow):
        label = f"{EXEMPTIONS_PATH}: allow[{index}]"
        if not isinstance(item, dict) or set(item) != {"class", "path_glob", "reason"}:
            raise SecretScanError(f"{label} must have exactly class, path_glob and reason")
        cls, glob, reason = item["class"], item["path_glob"], item["reason"]
        if cls == KNOWN_VALUE:
            raise SecretScanError(f"{label}: a known value can never be exempted")
        if cls not in CLASSES:
            raise SecretScanError(f"{label}: unknown class")
        if not isinstance(glob, str) or not glob.strip() or glob.startswith("/") or ".." in glob.split("/"):
            raise SecretScanError(f"{label}: path_glob must be a relative glob inside the repository")
        rx = glob_regex(glob)
        if all(rx.match(p) for p in _PROBES):
            raise SecretScanError(f"{label}: path_glob covers every file and would switch the class off")
        if not isinstance(reason, str) or len(reason.strip()) < 10:
            raise SecretScanError(f"{label}: reason must say why the match is not a secret")
        result.append(Exemption(cls, glob, reason))
    return result


# --------------------------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------------------------

_GIT_ENV_DROP = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_NAMESPACE",
                 "GIT_REPLACE_REF_BASE", "GIT_PREFIX")


def _git_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_DROP}
    env.update(LC_ALL="C", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0",
               GIT_TERMINAL_PROMPT="0")
    return env


def _git_base(repo: str) -> list[str]:
    return ["git", "--no-replace-objects", "-C", repo, "-c", "core.quotepath=off", "-c", "log.showRoot=true"]


def _run_git(repo: str, *args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(_git_base(repo) + list(args), capture_output=True, check=False, env=_git_env())


class _CatFile:
    """One long-lived `git cat-file --batch`; objects are requested by SHA or `<sha>:<path>`."""

    def __init__(self, repo: str) -> None:
        self.proc = subprocess.Popen(_git_base(repo) + ["cat-file", "--batch"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_git_env())

    def read(self, spec: str, *, limit: int | None = None) -> tuple[str, bytes | None]:
        """(type, content); content is None when the object is missing or larger than `limit`
        (MAX_CONTEXT_BYTES unless given)."""
        assert self.proc.stdin is not None and self.proc.stdout is not None
        limit = MAX_CONTEXT_BYTES if limit is None else limit
        if "\n" in spec or "\0" in spec:
            return "missing", None
        self.proc.stdin.write(spec.encode("utf-8", "surrogateescape") + b"\n")
        self.proc.stdin.flush()
        answer = self.proc.stdout.readline().rstrip(b"\n")
        if answer.endswith(b" missing"):
            return "missing", None
        header = answer.split(b" ")
        if len(header) != 3 or not header[2].isdigit():
            raise OSError("unexpected cat-file answer")
        kind, size = header[1].decode("ascii", "replace"), int(header[2])
        if size > limit:
            remaining = size + 1
            while remaining:
                chunk = self.proc.stdout.read(min(remaining, 1 << 20))
                if not chunk:
                    raise OSError("cat-file ended early")
                remaining -= len(chunk)
            return kind, None
        content = self.proc.stdout.read(size + 1)
        if len(content) != size + 1:
            raise OSError("cat-file ended early")
        return kind, content[:-1]

    def close(self) -> None:
        for stream in (self.proc.stdin, self.proc.stdout):
            if stream:
                try:
                    stream.close()
                except OSError:
                    pass
        self.proc.kill()
        self.proc.wait()


# --------------------------------------------------------------------------------------------
# Parsing the patch stream
# --------------------------------------------------------------------------------------------

_HUNK = re.compile(rb"^(@{2,}) ((?:-\d+(?:,\d+)? )+)\+(\d+)(?:,(\d+))? \1(?: |$)")
_C_ESCAPES = {ord("a"): 7, ord("b"): 8, ord("f"): 12, ord("n"): 10, ord("r"): 13, ord("t"): 9,
              ord("v"): 11, ord("\\"): ord("\\"), ord('"'): ord('"')}
_TRIGGER = re.compile(rb"""(?i)ipanthash|userpassword|krbprincipalkey|ipatokenotpkey|private key|"""
                      rb"""authorization|cookie|ipa_session|__base64__|"""
                      rb"""^[ \t\-]*["']?[A-Za-z0-9+/]{20,}={0,2}["',]*[ \t\r]*$""")


def _unquote(raw: bytes) -> bytes:
    """Git's C-style quoting of a path (a path is quoted only when it holds `"`, a backslash or a
    control character; non-ASCII bytes are literal because core.quotepath is off)."""
    out, i = bytearray(), 0
    while i < len(raw):
        c = raw[i]
        if c != 0x5C:
            out.append(c)
            i += 1
            continue
        i += 1
        if i < len(raw) and 0x30 <= raw[i] <= 0x37:
            digits = raw[i:i + 3]
            octal = re.match(rb"[0-7]{1,3}", digits)
            assert octal is not None
            out.append(int(octal.group(0), 8) & 0xFF)
            i += len(octal.group(0))
        elif i < len(raw) and raw[i] in _C_ESCAPES:
            out.append(_C_ESCAPES[raw[i]])
            i += 1
        else:
            out.append(0x5C)
    return bytes(out)


def _header_path(rest: bytes, prefix: bytes) -> bytes | None:
    """The path of a `--- `/`+++ ` header line (None for /dev/null)."""
    rest = rest.rstrip(b"\n")
    if rest.rstrip(b"\t") == b"/dev/null":
        return None
    if rest.startswith(b'"'):
        end = 1
        while end < len(rest) and not (rest[end] == 0x22 and (len(rest[1:end]) - len(rest[1:end].rstrip(b"\\"))) % 2 == 0):
            end += 1
        name = _unquote(rest[1:end])
    else:
        name = rest.rstrip(b"\t")
    return name[len(prefix):] if name.startswith(prefix) else name


def _display(raw: bytes, known: re.Pattern[bytes] | None) -> str:
    """A path or label safe to print: control characters replaced, a known value masked."""
    if known is not None and known.search(raw):
        return "(path contains a supplied secret value)"
    text = raw.decode("utf-8", "replace")
    return "".join("?" if ord(ch) < 32 or ord(ch) == 127 else ch for ch in text)


def _read_windows(stream: Any) -> Iterator[tuple[bytes, bool]]:
    """Lines of the stream; a line longer than LINE_WINDOW arrives as consecutive windows, all but the
    first flagged as continuations."""
    continuation = False
    while True:
        chunk = stream.readline(LINE_WINDOW)
        if not chunk:
            return
        yield chunk, continuation
        continuation = not chunk.endswith(b"\n")


class _Collector:
    """Per-commit state of the patch walk: turns hunks into added lines and files into findings."""

    def __init__(self, scanner: "_Scan") -> None:
        self.scan = scanner
        self.commit = ""
        self.path: bytes | None = None
        self.old: bytes | None = None
        self.added: list[int] = []
        self.trigger_lines: list[tuple[int, bytes]] = []
        self.known_lines: list[int] = []
        self.hunk: dict[str, Any] | None = None
        self.tail = b""
        self.line_added = False   # the line being read (all of its windows) is an added line
        self.line_number = 0
        self.trigger_bytes = 0
        self.judged: dict[tuple[str, int], None] = {}

    def start_commit(self, sha: str) -> None:
        self.finish_file()
        self.commit = sha

    def start_file(self) -> None:
        self.finish_file()
        self.path = self.old = None
        self.hunk = None

    def set_path(self, new: bytes | None, old: bytes | None) -> None:
        self.path = new if new is not None else old
        self.scan.check_path(self.commit, self.path)

    def begin_hunk(self, match: re.Match[bytes]) -> None:
        parents = len(match.group(1)) - 1
        old_counts = [int(tok.split(b",")[1]) if b"," in tok else 1
                      for tok in match.group(2).split() if tok.startswith(b"-")]
        if len(old_counts) != parents:
            self.scan.error("a diff hunk header could not be understood")
            self.hunk = None
            return
        new_count = int(match.group(4)) if match.group(4) is not None else 1
        self.hunk = {"parents": parents, "old": old_counts, "new": new_count, "line": int(match.group(3))}
        if new_count == 0 and not any(old_counts):
            self.hunk = None

    def content_line(self, raw: bytes) -> None:
        """The first (or only) window of a line of the current hunk (already known to be inside one)."""
        hunk = self.hunk
        assert hunk is not None
        n = hunk["parents"]
        if raw.startswith(b"\\"):
            return  # "\ No newline at end of file"
        prefix, body = raw[:n], raw[n:].rstrip(b"\n")
        if len(prefix) < n or any(c not in b" +-" for c in prefix):
            self.scan.error("a diff line could not be understood")
            self.hunk = None
            return
        for i, c in enumerate(prefix):
            if c in b" -":
                hunk["old"][i] -= 1
        has_new = b"-" not in prefix
        added = has_new and all(c == 0x2B for c in prefix)
        number = hunk["line"]
        if has_new:
            hunk["new"] -= 1
            hunk["line"] += 1
        self.line_added = added
        self.line_number = number
        self.tail = body[-self.scan.overlap:]
        if added:
            self.added.append(number)
            self.window(body, number)
        # The hunk may end with this line, but the line may go on in more windows: continue_line() does
        # not depend on the hunk, so a secret past the first window of the last line is still read.
        if hunk["new"] <= 0 and not any(c > 0 for c in hunk["old"]):
            self.hunk = None

    def continue_line(self, raw: bytes) -> None:
        """A further window of the line being read. Only an added line's windows are examined, each
        starting with the end of the previous one so that a value split across two is still seen."""
        if not self.line_added:
            return
        data = self.tail + raw.rstrip(b"\n")
        self.tail = data[-self.scan.overlap:]
        self.window(data, self.line_number)

    def window(self, body: bytes, number: int) -> None:
        pattern = self.scan.known_pattern
        if pattern is not None and pattern.search(body):
            self.known_lines.append(number)
        if _TRIGGER.search(body):
            self.trigger_lines.append((number, body))
            self.trigger_bytes += len(body)
            if self.trigger_bytes > MAX_TRIGGER_BYTES:
                # Only a file that is too large to be read back whole gets here (the added text of one
                # that can be is far smaller): judge what is held now and let it go, so memory stays bounded.
                self.judged.update(self.judge_triggers(self.trigger_lines))
                self.trigger_lines, self.trigger_bytes = [], 0

    @staticmethod
    def judge_triggers(triggers: list[tuple[int, bytes]]) -> dict[tuple[str, int], None]:
        """Classify trigger windows on their own (one per line of the joined text)."""
        hits: dict[tuple[str, int], None] = {}
        if triggers:
            joined = b"\n".join(body for _, body in triggers)
            for first, last, cls in classify(joined):
                index = min(max(first, 1), len(triggers)) - 1
                hits[(cls, triggers[index][0])] = None
        return hits

    def finish_file(self) -> None:
        added, triggers, known_lines, judged = self.added, self.trigger_lines, self.known_lines, self.judged
        path = self.path
        self.added, self.trigger_lines, self.known_lines, self.judged = [], [], [], {}
        self.trigger_bytes = 0
        self.hunk = None
        self.line_added = False
        if path is None or not added:
            return
        hits: dict[tuple[str, int], None] = dict(judged)
        for number in known_lines:
            hits[(KNOWN_VALUE, number)] = None
        if triggers:
            blob = None
            if b"\n" not in path:
                kind, blob = self.scan.catfile.read(f"{self.commit}:{path.decode('utf-8', 'surrogateescape')}")
                if kind not in ("blob", "missing"):
                    blob = None
            if blob is not None:
                for first, last, cls in classify(blob):
                    line = _first_added(added, first, last)
                    if line is not None:
                        hits[(cls, line)] = None
            else:
                hits.update(self.judge_triggers(triggers))
        for (cls, line) in hits:
            self.scan.add(self.commit, path, line, cls)


class _Scan:
    def __init__(self, repo: str, base: str, head: str, known: Sequence[bytes],
                 exemptions: Sequence[Exemption] | None) -> None:
        self.repo, self.base, self.head = repo, base, head
        self.known = list(known)
        self.known_pattern = _known_regex(self.known)
        # A very long line is read in windows that share this many bytes: a known value is at most this
        # long plus one, so one split across two windows still lies whole inside the second.
        self.overlap = max(WINDOW_OVERLAP, max(map(len, self.known), default=0) - 1)
        self.exemption_arg = exemptions
        self.result = ScanResult(base=base, head=head, known_values=len(self.known))
        self.catfile: _CatFile
        self._seen: set[tuple[str, bytes, str]] = set()
        self._raw: list[tuple[Finding, bytes]] = []
        self.exemptions: list[Exemption] = []

    def error(self, message: str) -> None:
        if message not in self.result.errors:
            self.result.errors.append(message)

    def add(self, commit: str, path: bytes, line: int | None, cls: str) -> None:
        key = (commit, path, cls)
        if key in self._seen:
            return
        self._seen.add(key)
        self._raw.append((Finding(commit, _display(path, self.known_pattern), line, cls), path))

    def check_path(self, commit: str, path: bytes | None) -> None:
        if path is not None and self.known_pattern is not None and self.known_pattern.search(path):
            self.add(commit, path, None, KNOWN_VALUE)

    # -- driver ------------------------------------------------------------------------------

    def run(self) -> ScanResult:
        res = self.result
        if not Path(self.repo).is_dir():
            self.error(f"repository {self.repo} does not exist")
            return res
        if self.overlap >= MAX_KNOWN_LENGTH:
            self.error(f"a supplied secret value is longer than {MAX_KNOWN_LENGTH} bytes; "
                       "a scan cannot window a line around it")
            return res
        base = self._resolve(self.base, "base")
        head = self._resolve(self.head, "head")
        if base is None or head is None:
            return res
        res.base, res.head = base, head
        counted = _run_git(self.repo, "rev-list", "--count", f"{base}..{head}", "--")
        if counted.returncode or not counted.stdout.strip().isdigit():
            self.error("cannot count the commits of the range")
            return res
        expected = int(counted.stdout.strip())
        self.catfile = _CatFile(self.repo)
        try:
            self._load_exemptions(base)  # a failure is an error; findings simply stay unexempted
            self._walk(base, head, expected)
        except OSError:
            self.error("git could not be read while scanning")
        except Exception as exc:  # whatever it was, never echo it: its text could quote scanned content
            self.error(f"the scanner failed unexpectedly ({type(exc).__name__})")
        finally:
            self.catfile.close()
        self._finish()
        return res

    def _resolve(self, rev: str, label: str) -> str | None:
        if not rev or rev.startswith("-"):
            self.error(f"the {label} revision {rev!r} is not a commit")
            return None
        p = _run_git(self.repo, "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        sha = p.stdout.decode("ascii", "replace").strip()
        if p.returncode or not re.fullmatch(r"[0-9a-f]{40}", sha):
            self.error(f"the {label} revision {rev if len(rev) < 80 else rev[:80]} does not resolve to a commit in this "
                       f"clone; fetch it (git fetch origin) or name another one, and run the scan again")
            return None
        return sha

    def _load_exemptions(self, base: str) -> bool:
        res = self.result
        if self.exemption_arg is not None:
            self.exemptions = list(self.exemption_arg)
            res.exemptions_source = "argument"
            return True
        try:
            kind, raw = self.catfile.read(f"{base}:{EXEMPTIONS_PATH}")
        except OSError:
            self.error(f"cannot read {EXEMPTIONS_PATH} at the base commit")
            res.exemptions_source = "unreadable"
            return False
        if kind == "missing":
            res.exemptions_source = "absent"
            return True
        res.exemptions_source = f"{base[:12]}:{EXEMPTIONS_PATH}"
        if raw is None or kind != "blob":
            self.error(f"{EXEMPTIONS_PATH} at the base commit is not a readable file")
            return False
        try:
            self.exemptions = parse_exemptions(raw)
        except SecretScanError as exc:
            self.error(str(exc))
            return False
        return True

    def _walk(self, base: str, head: str, expected: int) -> None:
        argv = _git_base(self.repo) + [
            "log", "--reverse", "-p", "-U0", "--diff-merges=dense-combined", "--no-renames", "--text",
            "--no-ext-diff", "--no-textconv", "--no-color", "--no-relative", "--submodule=short",
            "--src-prefix=a/", "--dst-prefix=b/", "--format=%x01C %H", f"{base}..{head}", "--"]
        with tempfile.TemporaryFile() as stderr:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=stderr, env=_git_env())
            assert proc.stdout is not None
            try:
                self._consume(proc.stdout)
            finally:
                proc.stdout.close()
                code = proc.wait()
        if code:
            self.error(f"git log failed (exit {code}) while reading the commits")
        elif self.result.commits != expected:
            self.error(f"scanned {self.result.commits} commit(s) but the range has {expected}")

    def _consume(self, stream: Any) -> None:
        col = _Collector(self)
        for raw, continuation in _read_windows(stream):
            if continuation:
                # The rest of a line longer than one window. Whether the hunk is still open does not
                # matter: the last line of a hunk may be the long one, and its tail is still content.
                col.continue_line(raw)
                continue
            col.line_added = False
            if col.hunk is not None:
                col.content_line(raw)
                continue
            if raw.startswith(b"\x01C "):
                sha = raw[3:].strip().decode("ascii", "replace")
                col.start_commit(sha)
                self.result.commits += 1
                self._scan_message(sha)
            elif raw.startswith((b"diff --git ", b"diff --cc ", b"diff --combined ")):
                col.start_file()
            elif raw.startswith(b"--- "):
                col.old = _header_path(raw[4:], b"a/")
            elif raw.startswith(b"+++ "):
                col.set_path(_header_path(raw[4:], b"b/"), col.old)
            elif raw.startswith(b"@@"):
                match = _HUNK.match(raw)
                if match is None:
                    self.error("a diff hunk header could not be understood")
                elif col.path is None:
                    self.error("a diff hunk could not be attributed to a file")
                else:
                    col.begin_hunk(match)
        col.finish_file()

    def _scan_message(self, sha: str) -> None:
        kind, content = self.catfile.read(sha)
        if kind != "commit" or content is None:
            self.error("a commit object could not be read")
            return
        message = content.split(b"\n\n", 1)[1] if b"\n\n" in content else b""
        hits = scan_text(MESSAGE_PATH, message, known=self.known)
        for hit in hits:
            self.add(sha, MESSAGE_PATH.encode(), hit.line, hit.cls)

    def _finish(self) -> None:
        res = self.result
        rules = [(e, glob_regex(e.path_glob)) for e in self.exemptions]
        for finding, raw_path in self._raw:
            exempt = finding.cls != KNOWN_VALUE and raw_path != MESSAGE_PATH.encode() and any(
                e.cls == finding.cls and rx.match(raw_path.decode("utf-8", "surrogateescape"))
                for e, rx in rules)
            if exempt:
                res.exempted.append(finding)
            elif len(res.findings) < MAX_REPORTED:
                res.findings.append(finding)
            else:
                res.truncated += 1


def scan_range(repo: str | os.PathLike[str], base: str, head: str, *, known: Sequence[bytes] = (),
               exemptions: Sequence[Exemption] | None = None) -> ScanResult:
    """Scan every commit of `base..head` (and each commit message) in `repo`.

    `exemptions=None` reads `.github/secret-scan.json` from the BASE commit only (a branch cannot
    exempt itself); pass a list to supply them. Anything that stops the scan from covering the whole
    range is recorded in `errors`; the caller must treat that as a refusal, never as a pass."""
    return _Scan(str(repo), base, head, known, exemptions).run()


# --------------------------------------------------------------------------------------------
# Messages for the gates
# --------------------------------------------------------------------------------------------

STOP = ("STOP: do not push, mark Ready or merge. Report the class, file and commit to the user, who "
        "decides on revoking or rotating the credential and on the history. A commit that scrubs the "
        f"value does not clear this finding: the secret stays in the earlier commit. See {GUIDE}")


def finding_messages(result: ScanResult) -> list[str]:
    """What a gate says about findings; empty when there are none. Never a value."""
    if not result.findings:
        return []
    commits = {f.commit for f in result.findings}
    shown = [f"{f.cls} in {f.path}{'' if f.line is None else f':{f.line}'} (commit {f.commit[:12]})"
             for f in result.findings[:MAX_LISTED]]
    more = len(result.findings) + result.truncated - len(shown)
    detail = "; ".join(shown) + (f"; and {more} more" if more > 0 else "")
    return [f"Secret scan: {len(result.findings) + result.truncated} finding(s) in {len(commits)} of "
            f"{result.commits} commit(s) of {result.base[:12]}..{result.head[:12]}: {detail}", STOP]


def error_messages(result: ScanResult) -> list[str]:
    """What a gate says when the scan could not cover the whole range; empty when it could."""
    return [f"Secret scan could not be completed: {e}. A branch is only clean when every commit was "
            "scanned; nothing was skipped silently" for e in result.errors]


def refusal_messages(result: ScanResult) -> list[str]:
    """Every reason a gate must refuse on `result`: findings first, then scan errors."""
    return finding_messages(result) + error_messages(result)


# --------------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                     epilog=f"Rules and what to do on a finding: {GUIDE}")
    parser.add_argument("--repo", required=True, help="Repository (or worktree) directory")
    parser.add_argument("--base", required=True, help="Base revision; commits reachable from it are not scanned")
    parser.add_argument("--head", required=True, help="Head revision; every commit in BASE..HEAD is scanned")
    parser.add_argument("--secret-file", action="append", default=[], metavar="FILE",
                        help="File outside the repository with one secret value per line (8+ bytes each); "
                             "matched as bytes in added lines, commit messages and paths. Repeatable.")
    parser.add_argument("--compact", action="store_true", help="One-line JSON")
    args = parser.parse_args(argv)
    try:
        known = load_secret_files(args.secret_file, args.repo)
    except SecretScanError as exc:
        failed = ScanResult(base=args.base, head=args.head, errors=[str(exc)])
        print(json.dumps(failed.to_json(), ensure_ascii=False, indent=None if args.compact else 2))
        return 2
    result = scan_range(args.repo, args.base, args.head, known=known)
    print(json.dumps(result.to_json(), ensure_ascii=False, indent=None if args.compact else 2))
    return {"CLEAN": 0, "FOUND": 1}.get(result.status, 2)


if __name__ == "__main__":
    sys.exit(main())
