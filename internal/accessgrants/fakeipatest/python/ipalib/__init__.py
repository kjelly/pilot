"""Fake ipalib.api for the identity object observer tests (see ../README.txt).

PILOT_FAKE_IPA_SCENARIO names a JSON file:
  {"user_find": <user_find reply>, "preserved_find": <reply of the preserved-
   users search>, "group_find": <group_find reply>, "config_show": <reply>,
   "fail": {"where": "connect" | "user_find" | "preserved_find" | "group_find" |
                     "config_show",
            "error": "<a class in ipalib.errors>", "text": "<message>"}}
The reply objects are what ipalib returns (result, count, truncated, ...).
"""
import json
import os

from ipalib import errors


def _scenario():
    with open(os.environ["PILOT_FAKE_IPA_SCENARIO"], encoding="utf-8") as handle:
        return json.load(handle)


def _maybe_fail(where):
    fail = _scenario().get("fail") or {}
    if fail.get("where") == where:
        raise getattr(errors, fail["error"])(fail.get("text", ""))


class _RPCClient:
    def connect(self):
        log = os.environ.get("PILOT_FAKE_IPA_LOG")
        if log:
            # One line per attempt, so a test can tell how often (and on how many
            # hosts) the observer reached for FreeIPA.
            with open(log, "a", encoding="utf-8") as handle:
                handle.write("connect\n")
        _maybe_fail("connect")
        # What the real client needs and the probe's private cache provides: a
        # ticket that its own kinit wrote. The fake kinit writes the word.
        cache = os.environ.get("KRB5CCNAME", "")
        path = cache[len("FILE:"):] if cache.startswith("FILE:") else ""
        try:
            with open(path, encoding="utf-8") as handle:
                ticket = "ticket" in handle.read()
        except OSError:
            ticket = False
        if not ticket:
            raise errors.KerberosError("no Kerberos credentials available")

    def disconnect(self):
        return None


class _Backend:
    rpcclient = _RPCClient()


class _Command:
    # The only option sets the observer is allowed to send; anything else is a
    # change in what it asks FreeIPA that a test must look at.
    _FIND = {"all": True, "sizelimit": 0, "timelimit": 0}
    _PRESERVED = {"preserved": True, "pkey_only": True, "sizelimit": 0, "timelimit": 0}

    def __getitem__(self, name):
        def call(**options):
            if name == "config_show" and not options:
                _maybe_fail(name)
                return _scenario()[name]
            if name == "group_find" and options == self._FIND:
                _maybe_fail(name)
                return _scenario()[name]
            if name == "user_find" and options == self._FIND:
                _maybe_fail(name)
                return _scenario()[name]
            if name == "user_find" and options == self._PRESERVED:
                _maybe_fail("preserved_find")
                return _scenario()["preserved_find"]
            raise errors.PublicError("unexpected command or options")
        return call


class _API:
    Backend = _Backend()
    Command = _Command()

    def bootstrap(self, **kwargs):
        return None

    def finalize(self):
        return None


api = _API()
