"""Adapter regression tests using captured FreeIPA JSON-RPC responses."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("observer", HERE / "freeipa-identity-object-observer.py")
observer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(observer)
FIXTURES = HERE.parents[2] / "internal/freeiparpc/testdata"


def capture(name):
    return json.loads((FIXTURES / (name + ".json")).read_text())["result"]


class ObserverTests(unittest.TestCase):
    def test_captured_user_states_and_key_redaction(self):
        rows = observer.observed(capture("user-find-states")["result"], "user")
        keys = next(r for r in rows if r["name"] == "p1-keys")
        self.assertEqual(2, len(keys["key_hashes"]))
        self.assertTrue(all(k.startswith("SHA256:") for k in keys["key_hashes"]))
        self.assertFalse(next(r for r in rows if r["name"] == "p1-off")["enabled"])
        for forbidden in ("ssh-ed25519", "krblastpwdchange", "memberof_group", "password"):
            self.assertNotIn(forbidden, json.dumps(rows))

    def test_nested_members_are_direct_only(self):
        rows = observer.observed(capture("group-find-nested")["result"], "group")
        top = next(r for r in rows if r["name"] == "p1-top")
        self.assertEqual([], top["users"])
        self.assertEqual(["p1-mid"], top["groups"])

    def test_desired_projection_drops_sentinels_and_preserves_key_clear(self):
        user = {"name": "u", "state": "present", "enabled": True,
                "password": "VAULT_SENTINEL", "ssh_keys": []}
        row = observer.desired([user], "user")[0]
        self.assertEqual([], row["key_hashes"])
        self.assertNotIn("VAULT_SENTINEL", json.dumps(row))
        del user["ssh_keys"]
        self.assertNotIn("key_hashes", observer.desired([user], "user")[0])

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
            with self.assertRaises(ValueError):
                observer.complete_find(FakeAPI(broken), "user_find")
        broken = copy.deepcopy(good)
        broken["truncated"] = True
        with self.assertRaises(ValueError):
            observer.complete_find(FakeAPI(broken), "user_find")

    def test_missing_disabled_observation_fails_closed(self):
        row = capture("user-find-states")["result"][0]
        del row["nsaccountlock"]
        with self.assertRaises(ValueError):
            observer.observed([row], "user")


if __name__ == "__main__":
    unittest.main()
