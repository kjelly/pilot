"""Adapter regression tests using captured FreeIPA JSON-RPC responses."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parents[2] / "internal/freeiparpc/testdata"
FAKE_IPA = HERE.parents[2] / "internal/accessgrants/fakeipatest/python"
# What the REAL ipapython.ssh.SSHPublicKey(k).openssh() answered on FreeIPA 4.13.4.
SSH_NORMALIZER_CAPTURE = HERE.parents[2] / "internal/accessgrants/fakeipatest/testdata/ssh-normalizer-4.13.4.json"
# ipapython.ssh there is a MODEL of FreeIPA's SSHPublicKey (see its README.txt);
# the observer imports it exactly as it imports the real one on a FreeIPA host.
sys.path.insert(0, str(FAKE_IPA))
spec = importlib.util.spec_from_file_location("observer", HERE / "freeipa-identity-object-observer.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)


def capture(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())["result"]


def user(name, state="present", **extra):
    row = {"name": name, "state": state, "enabled": state != "absent"}
    row.update(extra)
    return row


class KeyIdentityTests(unittest.TestCase):
    """F1: key identity is what apply compares, and only for managed users."""

    @classmethod
    def setUpClass(cls):
        # A key FreeIPA 4.13.4 stored and returned (captured fixture).
        cls.key = capture("user-find-states")["result"][0]["ipasshpubkey"][0]
        cls.type_and_blob, cls.comment = cls.key.rsplit(" ", 1)
        cls.normalize = staticmethod(observer.load_key_normalizer())

    def digest(self, text):
        return observer.key_digests([text], self.normalize, "desired_key_invalid")

    def test_option_prefixed_key_is_accepted_for_a_managed_user(self):
        for options in ('from="10.0.0.0/8"', 'command="echo a, b",no-pty', 'no-pty,from="10.0.0.0/8,192.0.2.0/24"'):
            row = observer.desired([user("u", ssh_keys=[options + " " + self.key])], "user", self.normalize)[0]
            self.assertEqual(1, len(row["key_hashes"]), options)

    def test_option_prefixed_key_of_an_unmanaged_user_is_never_parsed(self):
        # The live user holds an option-prefixed key and one nothing can parse; the
        # roster does not manage that user's keys, so nothing may parse them.
        entry = copy.deepcopy(capture("user-find-states")["result"][0])
        entry["ipasshpubkey"] = ['from="10.0.0.0/8" ' + self.key, "not a key at all"]
        rows = observer.observed([entry], "user", key_users=frozenset(), normalize=None)
        self.assertNotIn("key_hashes", rows[0])
        # A managed user's option-prefixed key gets a digest, still no failure.
        entry["ipasshpubkey"] = ['from="10.0.0.0/8" ' + self.key]
        rows = observer.observed([entry], "user", key_users=frozenset({"p1-keys"}), normalize=self.normalize)
        self.assertEqual(1, len(rows[0]["key_hashes"]))

    def test_users_that_manage_no_keys_never_load_the_normalizer(self):
        # state absent and ssh_keys null do not manage keys: no normalizer is needed.
        data = {"users": [user("gone", state="absent", ssh_keys=["garbage"]), user("keep")], "groups": []}

        class FakeAPI:
            Command = {"user_find": lambda **kw: {"result": [], "count": 0, "truncated": False},
                       "group_find": lambda **kw: {"result": [], "count": 0, "truncated": False}}

        with mock.patch.object(observer, "load_key_normalizer", side_effect=AssertionError("loaded")):
            snap = observer.snapshot(data, FakeAPI())
        self.assertNotIn("key_hashes", snap["desired_users"][0])
        self.assertNotIn("key_hashes", snap["desired_users"][1])

    def test_spellings_freeipa_normalizes_away_are_not_a_difference(self):
        # FreeIPA normalizes whitespace and option-name case before it compares,
        # so apply would not rewrite these.
        spelled = '  FROM="10.0.0.0/8"   ' + self.type_and_blob + "    " + self.comment + "  "
        self.assertEqual(self.digest('from="10.0.0.0/8" ' + self.key), self.digest(spelled))

    def test_comment_only_difference_is_a_difference(self):
        # apply: `ipa user-mod --sshpubkey=...` answers "Modified user".
        self.assertNotEqual(self.digest(self.key), self.digest(self.type_and_blob + " renamed-comment"))
        self.assertNotEqual(self.digest(self.key), self.digest(self.type_and_blob))

    def test_options_only_difference_is_a_difference(self):
        self.assertNotEqual(self.digest(self.key), self.digest('from="10.0.0.0/8" ' + self.key))
        self.assertNotEqual(self.digest('from="10.0.0.0/8" ' + self.key), self.digest('from="192.0.2.0/24" ' + self.key))
        self.assertNotEqual(self.digest("no-pty " + self.key), self.digest("no-agent-forwarding " + self.key))

    def test_quoted_options_may_hold_spaces_and_commas(self):
        a = self.digest('command="echo a, b",no-pty ' + self.key)
        self.assertEqual(a, self.digest('no-pty,command="echo a, b" ' + self.key))  # FreeIPA sorts options
        self.assertNotEqual(a, self.digest('command="echo a,b",no-pty ' + self.key))

    def test_digest_never_carries_key_material(self):
        row = observer.desired([user("u", ssh_keys=['from="10.0.0.0/8" ' + self.key])], "user", self.normalize)[0]
        text = json.dumps(row)
        blob = self.type_and_blob.split(" ")[1]
        for forbidden in (blob, "ssh-ed25519", self.comment, "10.0.0.0"):
            self.assertNotIn(forbidden, text)
        self.assertTrue(row["key_hashes"][0].startswith("SHA256:"))

    def test_invalid_desired_key_is_a_fixed_class_not_a_traceback(self):
        for bad in ("not a key", "ssh-ed25519 AAAA", 'from="x ' + self.key, ""):
            with self.assertRaises(observer.ObserverError) as caught:
                observer.desired([user("u", ssh_keys=[bad])], "user", self.normalize)
            self.assertEqual("desired_key_invalid", caught.exception.error_class, bad)

    def test_missing_normalizer_is_ipalib_unavailable(self):
        with mock.patch.dict(sys.modules, {"ipapython": None, "ipapython.ssh": None}):
            with self.assertRaises(observer.ObserverError) as caught:
                observer.load_key_normalizer()
        self.assertEqual("ipalib_unavailable", caught.exception.error_class)


class ObserverTests(unittest.TestCase):
    def test_captured_user_states_and_key_redaction(self):
        normalize = observer.load_key_normalizer()
        rows = observer.observed(capture("user-find-states")["result"], "user", {"p1-keys", "p1-nokeys"}, normalize)
        keys = next(r for r in rows if r["name"] == "p1-keys")
        self.assertEqual(2, len(keys["key_hashes"]))
        self.assertTrue(all(k.startswith("SHA256:") for k in keys["key_hashes"]))
        self.assertEqual([], next(r for r in rows if r["name"] == "p1-nokeys")["key_hashes"])
        self.assertNotIn("key_hashes", next(r for r in rows if r["name"] == "p1-off"))
        self.assertFalse(next(r for r in rows if r["name"] == "p1-off")["enabled"])
        for forbidden in ("ssh-ed25519", "krblastpwdchange", "memberof_group", "password"):
            self.assertNotIn(forbidden, json.dumps(rows))

    def test_nested_members_are_direct_only(self):
        rows = observer.observed(capture("group-find-nested")["result"], "group")
        top = next(r for r in rows if r["name"] == "p1-top")
        self.assertEqual([], top["users"])
        self.assertEqual(["p1-mid"], top["groups"])

    def test_desired_projection_preserves_key_clear(self):
        normalize = observer.load_key_normalizer()
        row = observer.desired([user("u", ssh_keys=[])], "user", normalize)[0]
        self.assertEqual([], row["key_hashes"])
        self.assertNotIn("key_hashes", observer.desired([user("u")], "user")[0])

    def test_credential_fields_are_refused_not_handled(self):
        for field in observer.CREDENTIAL_KEYS:
            with self.assertRaises(observer.ObserverError) as caught:
                observer.desired([user("u", **{field: "VAULT_SENTINEL"})], "user")
            self.assertEqual("bad_input", caught.exception.error_class)

    def test_incomplete_find_is_never_empty_success(self):
        class FakeAPI:
            def __init__(self, reply):
                self.calls = []

                def call(**kwargs):
                    self.calls.append(kwargs)
                    return reply
                self.Command = {"user_find": call}
        good = capture("user-find-states")
        api = FakeAPI(good)
        self.assertTrue(observer.complete_find(api, "user_find"))
        self.assertEqual([{"all": True, "sizelimit": 0, "timelimit": 0}], api.calls)
        for key in ("result", "truncated", "count"):
            broken = copy.deepcopy(good)
            del broken[key]
            with self.assertRaises(observer.ObserverError) as caught:
                observer.complete_find(FakeAPI(broken), "user_find")
            self.assertEqual("incomplete_search", caught.exception.error_class)
        broken = copy.deepcopy(good)
        broken["truncated"] = True
        with self.assertRaises(observer.ObserverError) as caught:
            observer.complete_find(FakeAPI(broken), "user_find")
        self.assertEqual("incomplete_search", caught.exception.error_class)

    def test_missing_disabled_observation_fails_closed(self):
        row = capture("user-find-states")["result"][0]
        del row["nsaccountlock"]
        with self.assertRaises(observer.ObserverError) as caught:
            observer.observed([row], "user")
        self.assertEqual("account_state_missing", caught.exception.error_class)


class FakeAPI:
    """Serves captured replies; records every call so a test can see what was asked."""

    def __init__(self, users=None, preserved=None, groups=None, config=None):
        self.calls = []
        self.replies = {
            "user_find": users if users is not None else {"result": [], "count": 0, "truncated": False},
            "preserved": preserved if preserved is not None else {"result": [], "count": 0, "truncated": False},
            "group_find": groups if groups is not None else {"result": [], "count": 0, "truncated": False},
            # The captured config_show reply (FreeIPA 4.13.4, live vm-target 2026-10-31).
            "config_show": config if config is not None else capture("config-show"),
        }
        self.Command = self

    def __getitem__(self, name):
        def call(**options):
            self.calls.append((name, options))
            if name == "user_find" and options.get("preserved"):
                return self.replies["preserved"]
            return self.replies[name]
        return call


class DesiredNormalizationTests(unittest.TestCase):
    """F7: FreeIPA stores --email=alice as alice@<default domain>."""

    def test_default_domain_is_appended_only_to_a_value_without_an_at(self):
        rows = observer.desired([user("a", email="alice"), user("b", email="bob@example.test"), user("c", email=""),
                                 user("d")], "user", None, "ipa.pilot.internal")
        self.assertEqual(["alice@ipa.pilot.internal"], rows[0]["attributes"]["mail"])
        self.assertEqual(["bob@example.test"], rows[1]["attributes"]["mail"])
        self.assertEqual([], rows[2]["attributes"]["mail"])  # an empty value clears the attribute
        self.assertNotIn("mail", rows[3]["attributes"])

    def test_the_captured_config_show_reply_yields_the_default_domain(self):
        # The real reply: ipadefaultemaildomain is a one-element list, value and
        # summary are null, and 23 other attributes are present and ignored.
        reply = capture("config-show")
        self.assertIsNone(reply["value"])
        self.assertEqual(["ipa.pilot.internal"], reply["result"]["ipadefaultemaildomain"])
        self.assertEqual("ipa.pilot.internal", observer.default_email_domain(FakeAPI()))

    def test_without_a_default_domain_the_value_is_left_alone(self):
        row = observer.desired([user("a", email="alice")], "user", None, "")[0]
        self.assertEqual(["alice"], row["attributes"]["mail"])

    def test_config_is_read_only_when_a_desired_email_needs_it(self):
        for users, asked in (([user("a")], False), ([user("a", email="x@y.test")], False), ([user("a", state="absent", email="alice")], False),
                             ([user("a", email="alice")], True)):
            api = FakeAPI()
            snap = observer.snapshot({"users": users, "groups": []}, api)
            self.assertEqual(asked, any(name == "config_show" for name, _ in api.calls), users)
            self.assertEqual(1, snap["schema_version"])
        api = FakeAPI()
        snap = observer.snapshot({"users": [user("a", email="alice")], "groups": []}, api)
        self.assertEqual(["alice@ipa.pilot.internal"], snap["desired_users"][0]["attributes"]["mail"])

    def test_config_failures_are_fixed_classes(self):
        for config, want in (({"result": "nope"}, "invalid_response"), ({"result": {"ipadefaultemaildomain": [5]}}, "invalid_response")):
            with self.assertRaises(observer.ObserverError) as caught:
                observer.default_email_domain(FakeAPI(config=config))
            self.assertEqual(want, caught.exception.error_class)

        class Broken(FakeAPI):
            def __getitem__(self, name):
                def call(**options):
                    raise RuntimeError("secret text")
                return call
        with self.assertRaises(observer.ObserverError) as caught:
            observer.default_email_domain(Broken())
        self.assertEqual("rpc_failed", caught.exception.error_class)


class PreservedUserTests(unittest.TestCase):
    """L1: user_find hides preserved users; the observer must read them too."""

    def test_the_snapshot_lists_preserved_users_from_a_second_complete_search(self):
        # The captured replies of FreeIPA 4.13.4 (live vm-target 2026-10-31): one
        # preserved user, and none (byte-identical to user-find-no-match).
        api = FakeAPI(preserved=capture("user-find-preserved-one"))
        snap = observer.snapshot({"users": [], "groups": []}, api)
        self.assertEqual(["pv-capture"], snap["preserved_users"])
        self.assertEqual([], observer.snapshot({"users": [], "groups": []}, FakeAPI(preserved=capture("user-find-no-match")))["preserved_users"])
        searches = [options for name, options in api.calls if name == "user_find"]
        self.assertIn({"sizelimit": 0, "timelimit": 0, "preserved": True, "pkey_only": True}, searches)
        self.assertEqual(2, len(searches))

    def test_an_incomplete_preserved_search_is_never_an_empty_list(self):
        for broken in ({"result": [], "count": 0, "truncated": True}, {"result": [], "count": 3, "truncated": False}, {"count": 0, "truncated": False}):
            with self.assertRaises(observer.ObserverError) as caught:
                observer.snapshot({"users": [], "groups": []}, FakeAPI(preserved=broken))
            self.assertEqual("incomplete_search", caught.exception.error_class)

    def test_a_preserved_entry_without_exactly_one_login_is_refused(self):
        for entry in ({"dn": "x"}, {"uid": ["a", "b"]}, {"uid": "a"}):
            with self.assertRaises(observer.ObserverError) as caught:
                observer.preserved_names([entry])
            self.assertEqual("invalid_response", caught.exception.error_class)


class KeyNormalizerModelTests(unittest.TestCase):
    """The test double ipapython/ssh.py is pinned to the real FreeIPA class.

    Every key identity the observer computes goes through `SSHPublicKey(k).openssh()`
    (load_key_normalizer). In these tests that is a model (see the README beside it);
    the capture holds the real class's answer to 18 inputs on FreeIPA 4.13.4, so a
    model that drifts from the real one fails here instead of in a live run.
    """

    @classmethod
    def setUpClass(cls):
        cls.capture = json.loads(SSH_NORMALIZER_CAPTURE.read_text(encoding="utf-8"))
        cls.normalize = staticmethod(observer.load_key_normalizer())

    def test_the_observer_is_running_the_model_not_a_real_ipapython(self):
        import ipapython.ssh
        self.assertEqual(FAKE_IPA.resolve(), Path(ipapython.ssh.__file__).resolve().parents[1])

    def test_the_capture_is_what_it_claims_to_be(self):
        cases = self.capture["cases"]
        self.assertEqual(18, len(cases))
        self.assertEqual(3, sum("error" in case for case in cases))
        for case in cases:
            if "error" in case:
                self.assertEqual({"in", "error", "user_mod"}, set(case), case["in"])
                self.assertEqual(("ValueError", "ValidationError"), (case["error"], case["user_mod"]))
            else:
                # FreeIPA stored exactly what openssh() returned: the premise of key identity.
                self.assertEqual({"in", "openssh", "user_mod", "stored"}, set(case), case["in"])
                self.assertEqual(case["openssh"], case["stored"])
        # The spellings the observer's tests rely on: option order and case, whitespace, a
        # bare blob, an empty comment, a quoted option holding a space and a comma.
        accepted = [case["in"] for case in cases if "openssh" in case]
        for needle in ('no-pty,from="10.0.0.1" ', 'NO-PTY,FROM=', "   kA@test  ", 'environment="A=B c",from="10.*,!10.1.1.1"'):
            self.assertTrue(any(needle in text for text in accepted), needle)

    def test_the_model_answers_every_captured_input_as_the_real_class_did(self):
        for case in self.capture["cases"]:
            with self.subTest(case["in"][:60]):
                if "error" in case:
                    with self.assertRaises(ValueError):
                        self.normalize(case["in"])
                else:
                    self.assertEqual(case["openssh"], self.normalize(case["in"]))


class FailureVocabularyTests(unittest.TestCase):
    """F6: a failure is one fixed class on stdout; no exception text, no value."""

    SENTINEL = "Pr204LeakSentinel-do-not-print"

    def run_main(self, stdin_text, fake_ipalib):
        out = io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(stdin_text)), \
                mock.patch.object(sys, "stdout", out), \
                mock.patch.dict(sys.modules, {"ipalib": fake_ipalib}):
            rc = observer.main()
        return rc, out.getvalue()

    def fake_ipalib(self, connect=None, find=None, import_fails=False):
        if import_fails:
            return None  # a None entry in sys.modules makes `from ipalib import api` raise ImportError
        module = mock.Mock()
        module.api.Backend.rpcclient.connect.side_effect = connect

        def call(**kwargs):
            if find is not None:
                raise find
            return {"result": [], "count": 0, "truncated": False}
        module.api.Command = {"user_find": call, "group_find": call}
        return module

    def assert_class(self, want, stdin_text, fake):
        rc, out = self.run_main(stdin_text, fake)
        self.assertEqual(1, rc)
        self.assertEqual(observer.ERROR_PREFIX + want + "\n", out)

    def test_each_failure_prints_exactly_its_class(self):
        good = json.dumps({"users": [], "groups": []})
        kerberos = type("KerberosError", (type("AuthenticationError", (Exception,), {}),), {})
        self.assert_class("bad_input", "{not json", self.fake_ipalib())
        self.assert_class("bad_input", json.dumps({"users": [user("u", password=self.SENTINEL)], "groups": []}), self.fake_ipalib())
        self.assert_class("ipalib_unavailable", good, self.fake_ipalib(import_fails=True))
        self.assert_class("kerberos", good, self.fake_ipalib(connect=kerberos(self.SENTINEL)))
        self.assert_class("kerberos", good, self.fake_ipalib(find=kerberos(self.SENTINEL)))
        self.assert_class("rpc_failed", good, self.fake_ipalib(connect=OSError(self.SENTINEL)))
        self.assert_class("rpc_failed", good, self.fake_ipalib(find=RuntimeError(self.SENTINEL)))
        self.assert_class("desired_key_invalid",
                          json.dumps({"users": [user("u", ssh_keys=[self.SENTINEL])], "groups": []}), self.fake_ipalib())

    def test_the_vocabulary_is_closed(self):
        self.assertEqual(len(observer.ERROR_CLASSES), len(set(observer.ERROR_CLASSES)))
        with self.assertRaises(AssertionError):
            observer.ObserverError("made_up_class")

    def test_success_is_one_json_line_and_exit_zero(self):
        rc, out = self.run_main(json.dumps({"users": [], "groups": []}), self.fake_ipalib())
        self.assertEqual(0, rc)
        self.assertEqual(1, json.loads(out)["schema_version"])
        self.assertEqual(1, len(out.strip().splitlines()))


if __name__ == "__main__":
    unittest.main()
