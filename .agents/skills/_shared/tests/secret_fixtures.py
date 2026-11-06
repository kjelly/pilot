"""Synthetic secrets for the secret-scan tests (not a test module).

Every value here is made up at run time with `secrets`/`os.urandom` inside a temporary repository and
is never written to a file of this repository: the scanner's own tests and the gates' tests must not
trip the scanner (test_secret_scan.py scans every tracked skill file). Trigger words are assembled from
pieces for the same reason.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import string
import subprocess
from pathlib import Path

# The four secret-bearing FreeIPA attributes, assembled so no literal copy sits in this file.
NT_HASH = "ipa" + "nthash"
USER_PASSWORD = "user" + "password"
KRB_KEY = "krb" + "principalkey"
OTP_KEY = "ipatoken" + "otpkey"
ATTRIBUTES = (NT_HASH, USER_PASSWORD, KRB_KEY, OTP_KEY)
PLACEHOLDER = "AAAAAAAAAAAAAAAAAAAAAA=="


def mixed(length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    """A random token with at least one lower-case letter, one upper-case letter and one digit."""
    while True:
        token = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in token) and any(c.isupper() for c in token) and any(c.isdigit() for c in token):
            return token


def random_b64(nbytes: int = 16) -> str:
    """Base64 of random bytes, as a FreeIPA binary value (credential-shaped)."""
    while True:
        value = base64.b64encode(os.urandom(nbytes)).decode()
        if any(c.islower() for c in value) and any(c.isupper() for c in value) and any(c.isdigit() for c in value):
            return value


def pem(kind: str = "", lines: int = 24) -> str:
    """A PEM block with a random body. `kind` is e.g. "RSA " or "OPENSSH "."""
    body = [mixed(64, string.ascii_letters + string.digits + "+/") for _ in range(lines)]
    begin, end = "-----BEGIN " + kind + "PRIVATE " + "KEY-----", "-----END " + kind + "PRIVATE " + "KEY-----"
    return "\n".join([begin, *body, end]) + "\n"


def attribute_document(attr: str, value: str, *, indent: int = 2) -> str:
    """A pretty-printed FreeIPA capture whose attribute holds `{"__base64__": value}` on its own line."""
    return json.dumps({"result": {"uid": ["u1"], attr: [{"__base64__": value}], "sn": ["User"]}}, indent=indent) + "\n"


def run_git(repo: Path, *args: str, env: dict[str, str]) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env)
    if p.returncode:
        raise AssertionError(f"git {' '.join(args)}: {p.stderr}")
    return p.stdout.strip()


def build_leak_branches(repo: Path, env: dict[str, str]) -> dict[str, str]:
    """In `repo` (on a branch with one base commit), create B1 and B2 with the same final tree.

    b1: commit 1 adds a real-shaped NT-hash fixture, commit 2 replaces it with the placeholder.
    b2: one commit adding only the placeholder fixture.
    Returns the SHAs and the value (so a test can prove it never reaches any output).
    """
    git = lambda *a: run_git(repo, *a, env=env)  # noqa: E731
    base = git("rev-parse", "HEAD")
    git("switch", "-q", "-c", "b1")
    value = random_b64(16)
    fixture = repo / "testdata" / "user.json"
    fixture.parent.mkdir(exist_ok=True)
    fixture.write_text(attribute_document(NT_HASH, value))
    git("add", "-A")
    git("commit", "-q", "-m", "test: add a captured user")
    leak_commit = git("rev-parse", "HEAD")
    fixture.write_text(attribute_document(NT_HASH, PLACEHOLDER))
    git("add", "-A")
    git("commit", "-q", "-m", "test: replace the value with the placeholder")
    b1 = git("rev-parse", "HEAD")
    git("switch", "-q", "-c", "b2", base)
    fixture.parent.mkdir(exist_ok=True)
    fixture.write_text(attribute_document(NT_HASH, PLACEHOLDER))
    git("add", "-A")
    git("commit", "-q", "-m", "test: add a captured user")
    b2 = git("rev-parse", "HEAD")
    assert git("rev-parse", f"{b1}^{{tree}}") == git("rev-parse", f"{b2}^{{tree}}"), "B1 and B2 must end on the same tree"
    return {"base": base, "b1": b1, "b2": b2, "leak_commit": leak_commit, "value": value}
