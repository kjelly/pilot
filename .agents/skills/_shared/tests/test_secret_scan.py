"""secret_scan.py: every commit of BASE..HEAD, class by value shape, never the value.

Real git repositories, secrets built at run time (secret_fixtures.py), and the same kind of case on
both sides (AGENTS.md 5.12): what must be caught and what must pass. No test writes a secret into a
file of this repository; the last class scans every tracked skill file to prove that.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import secret_fixtures as fx  # noqa: E402
from gitrepo import Repo, load_module  # noqa: E402

SKILLS = Path(__file__).resolve().parents[2]
ROOT = SKILLS.parents[1]
SCRIPT = SKILLS / "_shared" / "scripts" / "secret_scan.py"
scan = load_module(SCRIPT)


def block(kind: str = "", lines: int = 24) -> str:
    return fx.pem(kind, lines)


class Classes(unittest.TestCase):
    """scan_text: what each class catches and what it leaves alone."""

    def classes(self, text, **kw):
        return sorted({h.cls for h in scan.scan_text("f", text, **kw)})

    def fires(self, text, cls, **kw):
        self.assertEqual([cls], self.classes(text, **kw), text[:80])

    def passes(self, text, **kw):
        self.assertEqual([], self.classes(text, **kw), text[:80])

    # -- freeipa-secret-attribute -------------------------------------------------------------

    def test_each_attribute_fires_in_multiline_json(self):
        for attr in fx.ATTRIBUTES:
            with self.subTest(attr=attr):
                self.fires(fx.attribute_document(attr, fx.random_b64()), scan.FREEIPA_ATTRIBUTE)

    def test_attribute_names_are_matched_case_insensitively(self):
        self.fires(fx.attribute_document("IPA" + "NTHash", fx.random_b64()), scan.FREEIPA_ATTRIBUTE)

    def test_single_line_json_and_a_second_value(self):
        a, b = fx.random_b64(), fx.random_b64(32)
        doc = '{"uid":["u"],"%s":[{"__base64__":"%s"},{"__base64__":"%s"}]}' % (fx.KRB_KEY, fx.PLACEHOLDER, b)
        self.fires(doc, scan.FREEIPA_ATTRIBUTE)
        self.passes('{"uid":["u"],"%s":[{"__base64__":"%s"}]}' % (fx.KRB_KEY, fx.PLACEHOLDER))
        self.fires('{"%s": [{"__base64__": "%s"}]}' % (fx.OTP_KEY, a), scan.FREEIPA_ATTRIBUTE)

    def test_a_non_placeholder_binary_value_fires_whatever_its_shape(self):
        # One class of characters and short: not credential-shaped, but binary data in a secret attribute.
        self.fires('{"%s": [{"__base64__": "BBBBBBBBBBBBBBBBBBBBBB=="}]}' % fx.NT_HASH, scan.FREEIPA_ATTRIBUTE)

    def test_hashed_and_plain_string_values_fire(self):
        for value in ("{SSHA512}" + fx.random_b64(48), "{PBKDF2_SHA256}" + fx.random_b64(24), fx.random_b64(24)):
            with self.subTest(value=value[:5]):
                self.fires('{"%s": ["%s"]}' % (fx.USER_PASSWORD, value), scan.FREEIPA_ATTRIBUTE)

    def test_ldif_base64_and_wrapped_values_fire(self):
        value = fx.random_b64(64)
        self.fires("dn: uid=u\n%s:: %s\n" % ("ipa" + "NTHash", value), scan.FREEIPA_ATTRIBUTE)
        wrapped = "%s:: %s\n %s\n" % ("user" + "Password", value[:40], value[40:])
        self.fires("dn: uid=u\n" + wrapped, scan.FREEIPA_ATTRIBUTE)
        self.passes("dn: uid=u\n%s:: %s\n" % ("ipa" + "NTHash", fx.PLACEHOLDER))

    def test_yaml_and_ipa_raw_forms_fire(self):
        self.fires("  %s: %s\n" % (fx.NT_HASH, fx.random_b64()), scan.FREEIPA_ATTRIBUTE)
        self.fires("  %s: %s\n" % (fx.NT_HASH, secrets.token_hex(16)), scan.FREEIPA_ATTRIBUTE)
        self.fires("- %s: {SSHA}%s\n" % (fx.USER_PASSWORD, fx.random_b64(30)), scan.FREEIPA_ATTRIBUTE)
        self.fires("ipa user-mod u --setattr %s=%s\n" % (fx.NT_HASH, fx.random_b64()), scan.FREEIPA_ATTRIBUTE)

    def test_json_escaped_inside_a_string_literal_fires(self):
        escaped = r'"{\"uid\":[\"u\"],\"%s\":[{\"__base64__\":\"%s\"}]}"' % (fx.NT_HASH, fx.random_b64())
        self.fires("const doc = " + escaped, scan.FREEIPA_ATTRIBUTE)
        self.passes(r'const doc = "{\"%s\":[{\"__base64__\":\"%s\"}]}"' % (fx.NT_HASH, fx.PLACEHOLDER))

    def test_placeholder_rights_strings_identifiers_and_prose_pass(self):
        self.passes(fx.attribute_document(fx.NT_HASH, fx.PLACEHOLDER))
        self.passes('{"%s": [{"__base64__": "%s"}, {"__base64__": "%s"}]}' % (fx.KRB_KEY, fx.PLACEHOLDER, fx.PLACEHOLDER))
        # attributelevelrights answers with permission letters ("s"), as the real host_show capture does.
        self.passes('{"%s": "s", "%s": "rsc"}' % (fx.KRB_KEY, fx.USER_PASSWORD))
        self.passes('{"%s": null, "%s": []}' % (fx.NT_HASH, fx.OTP_KEY))
        self.passes("type User struct {\n\tUserPassword string\n\tuserPasswordHash []byte\n}\n")
        self.passes("The NT hash (`%s`) and `%s` hashes are secrets.\n" % (fx.NT_HASH, fx.USER_PASSWORD))
        self.passes('fields := []string{"%s", "%s"}\n' % (fx.NT_HASH, fx.OTP_KEY))
        self.passes("%s: <redacted>\n%s: ${HASH}\n%s: {{ vault_hash }}\n" % (fx.NT_HASH, fx.USER_PASSWORD, fx.KRB_KEY))
        self.passes("- %s: the derived value, never committed\n" % fx.NT_HASH)

    def test_a_name_that_merely_contains_password_is_not_a_secret(self):
        # The class is decided by the value's shape, never by the name (kjelly/pilot#260).
        self.passes("ipa_admin_password: \"{{ ipa_admin_password }}\"\nkeycloak_db_password: !vault |\n"
                    "no_log: true\npassword_policy: strict\nuser_password_hash_field: name\n")

    def test_the_real_captured_fixtures_pass(self):
        # Real captures committed in this repository (AGENTS.md 5.6): rights strings and placeholders.
        fixtures = [ROOT / "internal/freeipaaccess/testdata/host_show_userclass_rights.json",
                    *sorted((ROOT / "internal/freeiparpc/testdata").glob("*.json"))]
        existing = [f for f in fixtures if f.is_file()]
        if not existing:
            self.skipTest("the Go fixtures are not part of this checkout")
        for path in existing:
            with self.subTest(path=path.name):
                self.assertEqual([], scan.scan_text(path.name, path.read_bytes()))

    # -- private-key --------------------------------------------------------------------------

    def test_pem_shapes_fire(self):
        cases = {"multi-line rsa": block("RSA "), "openssh": block("OPENSSH "), "pkcs8": block("", 25),
                 "encrypted": block("ENCRYPTED ", 18)}
        for name, text in cases.items():
            with self.subTest(case=name):
                self.fires(text, scan.PRIVATE_KEY)

    def test_pem_with_literal_backslash_n_escapes_fires(self):
        escaped = block("RSA ").strip().replace("\n", "\\n")
        self.fires('{"key": "%s"}\n' % escaped, scan.PRIVATE_KEY)
        self.fires('key = "%s"\n' % escaped, scan.PRIVATE_KEY)

    def test_ed25519_pkcs8_and_legacy_headers_fire(self):
        body = "MC4CAQAwBQYDK2VwBCIEI" + fx.mixed(43, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        self.fires("-----BEGIN " + "PRIVATE " + "KEY-----\n" + body + "\n-----END " + "PRIVATE " + "KEY-----\n", scan.PRIVATE_KEY)
        legacy = ("-----BEGIN " + "RSA PRIVATE " + "KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n"
                  + fx.mixed(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/") + "\n")
        self.fires(legacy, scan.PRIVATE_KEY)

    def test_pgp_private_key_block_fires(self):
        body = "\n".join(fx.mixed(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/") for _ in range(6))
        text = ("-----BEGIN PGP " + "PRIVATE " + "KEY BLOCK-----\nVersion: GnuPG v2\n\n" + body + "\n=ab12\n-----END PGP "
                + "PRIVATE " + "KEY BLOCK-----\n")
        self.fires(text, scan.PRIVATE_KEY)

    def test_a_header_without_a_body_passes(self):
        header = "-----BEGIN " + "PRIVATE " + "KEY-----"
        self.passes('if strings.Contains(s, "%s") {\n\treturn true\n}\n' % header)
        self.passes('re := regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*' + "PRIVATE " + 'KEY-----`)\n')
        self.passes("  - grep -q '%s' \"$f\"\n  failed_when: false\n" % header)
        self.passes("%s\n...\n-----END %s\n" % (header, "PRIVATE " + "KEY-----"))
        self.passes("%s\nshort\nwords\n" % header)

    def test_a_public_key_and_a_certificate_pass(self):
        public = "-----BEGIN " + "PUBLIC KEY-----\n" + fx.mixed(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/") + "\n"
        self.passes(public)
        self.passes("-----BEGIN CERTIFICATE-----\n" + fx.mixed(64, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/") + "\n")

    # -- authorization / cookie / session -------------------------------------------------------

    def test_authorization_headers_fire(self):
        token = fx.mixed(40)
        for line in (f"Authorization: Bearer {token}", f"authorization: basic {fx.random_b64(18)}",
                     f"Proxy-Authorization: Negotiate {fx.random_b64(30)}",
                     f'  -H "Authorization: Bearer {token}" \\', f'headers = {{"Authorization": "Bearer {token}"}}',
                     f'"authorization":"Token {token}"', f"Authorization: {fx.mixed(40)}"):
            with self.subTest(line=line[:30]):
                self.fires(line + "\n", scan.AUTHORIZATION)

    def test_placeholder_and_prose_authorization_lines_pass(self):
        for line in ("Authorization: Bearer <redacted>", "Authorization: Bearer $TOKEN", 'Authorization: Bearer ${TOKEN}',
                     "Authorization: Bearer {{ token }}", "Authorization: Bearer ***", "Authorization: Bearer [REDACTED]",
                     "authorization: explicit", "Authorization: Bearer abc", "Authorization: Negotiate",
                     'req.Header.Set("Authorization", "Bearer "+token)', "Authorization: Basic $(cat /run/cred)",
                     "\tAuthorization: authorization,", "\tAuthorization  string `json:\"authorization\"`",
                     "A bearer token travels in the Authorization header."):
            with self.subTest(line=line[:40]):
                self.passes(line + "\n")

    def test_cookie_headers_fire_and_dig_cookies_pass(self):
        sid = fx.mixed(40)
        self.fires(f"Cookie: sid={sid}; other=1\n", scan.COOKIE)
        # An ipa_session cookie is both a cookie header and a session value.
        self.assertEqual([scan.COOKIE, scan.IPA_SESSION], self.classes(f"Cookie: ipa_session={sid}; other=1\n"))
        self.fires(f"Set-Cookie: sid={sid}; Path=/; HttpOnly; Secure\n", scan.COOKIE)
        self.assertEqual([scan.COOKIE, scan.IPA_SESSION],
                         self.classes(f"Set-Cookie: ipa_session={sid}; Path=/; HttpOnly\n"))
        self.fires(f'"Cookie": "theme=dark; session={sid}"\n', scan.COOKIE)
        self.passes("; COOKIE: 1f0e0d0c0b0a0908 (good)\n")
        self.passes("Set-Cookie: theme=dark; Path=/; Max-Age=3600; SameSite=Lax\n")
        self.passes("Cookie: sid=<redacted>; theme=dark\n")
        self.passes("The Cookie: header carries it.\n")

    def test_ipa_session_fires_unless_it_is_a_placeholder(self):
        self.fires(f"curl -b 'ipa_session={fx.mixed(48)}' https://ipa/\n", scan.IPA_SESSION)
        self.fires(f'{{"ipa_session": "{fx.mixed(48)}"}}\n', scan.IPA_SESSION)
        for value in ("<redacted>", "${IPA_SESSION}", "$(cat /run/ipa-session-file)", "{{ session }}", "%s%s%s%s%s"):
            with self.subTest(value=value):
                self.passes(f"curl -b ipa_session={value} https://ipa/\n")

    # -- added lines ---------------------------------------------------------------------------

    def test_only_spans_that_overlap_an_added_line_count(self):
        doc = fx.attribute_document(fx.NT_HASH, fx.random_b64())
        lines = doc.splitlines()
        value_line = next(i for i, text in enumerate(lines, 1) if "__base64__" in text)
        key_line = next(i for i, text in enumerate(lines, 1) if fx.NT_HASH in text)
        self.assertEqual([key_line], [h.line for h in scan.scan_text("f", doc)])
        # The commit changed only the value line: the span still reaches it.
        self.assertEqual([value_line], [h.line for h in scan.scan_text("f", doc, added_lines=[value_line])])
        # Secret-shaped content that was already there is not this change's.
        self.assertEqual([], scan.scan_text("f", doc, added_lines=[1]))

    def test_known_values_match_as_bytes(self):
        value = fx.mixed(20).encode()
        hits = scan.scan_text("f", b"a\nb " + value + b" c\n", known=[value])
        self.assertEqual([(2, scan.KNOWN_VALUE)], [(h.line, h.cls) for h in hits])
        self.assertEqual([], scan.scan_text("f", b"a\nb\n", known=[value]))


class RangeFixture(unittest.TestCase):
    """A repository with one base commit and helpers to scan BASE..HEAD."""

    def setUp(self):
        self.r = Repo(self)
        self.r.write("README.md", "base\n")
        self.base = self.r.commit("base")
        self.r.branch_from_main("feature")

    def scan(self, head="HEAD", base=None, **kw):
        return scan.scan_range(self.r.path, base or self.base, head, **kw)

    def classes(self, result):
        return sorted((f.cls, f.path) for f in result.findings)

    def assertClean(self, result):
        self.assertEqual(([], []), (result.findings, result.errors), result.to_json())

    def dump(self, result) -> str:
        return json.dumps(result.to_json()) + "\n".join(scan.refusal_messages(result))


class History(RangeFixture):
    def test_a_value_replaced_by_the_placeholder_in_a_later_commit_is_still_found(self):
        built = fx.build_leak_branches(self.r.path, self.r.env)
        b1 = scan.scan_range(self.r.path, built["base"], built["b1"])
        self.assertEqual("FOUND", b1.status)
        self.assertEqual([(scan.FREEIPA_ATTRIBUTE, "testdata/user.json")], self.classes(b1))
        self.assertEqual(built["leak_commit"], b1.findings[0].commit)
        self.assertEqual(2, b1.commits)
        # Control: the same final tree, produced by one commit that adds only the placeholder.
        b2 = scan.scan_range(self.r.path, built["base"], built["b2"])
        self.assertClean(b2)
        self.assertEqual(1, b2.commits)
        # The value is in no output channel: result JSON, messages.
        self.assertNotIn(built["value"], self.dump(b1))
        for part in (built["value"][:8], built["value"][-8:]):
            self.assertNotIn(part, self.dump(b1))

    def test_each_commit_of_a_long_range_is_scanned(self):
        for i in range(4):
            self.r.write(f"f{i}.txt", f"{i}\n")
            self.r.commit(f"c{i}")
        token = fx.mixed(40)
        self.r.write("notes.txt", f"Authorization: Bearer {token}\n")
        leak = self.r.commit("notes")
        self.r.write("notes.txt", "Authorization: Bearer <redacted>\n")
        self.r.commit("scrub")
        result = self.scan()
        self.assertEqual(6, result.commits)
        self.assertEqual([(scan.AUTHORIZATION, "notes.txt")], self.classes(result))
        self.assertEqual(leak, result.findings[0].commit)
        self.assertNotIn(token, self.dump(result))

    def test_a_commit_that_changes_only_the_value_line_is_found(self):
        self.r.write("fx.json", fx.attribute_document(fx.KRB_KEY, fx.PLACEHOLDER))
        self.r.commit("placeholder fixture")
        base = self.r.out("rev-parse", "HEAD")
        value = fx.random_b64()
        self.r.write("fx.json", fx.attribute_document(fx.KRB_KEY, value))
        leak = self.r.commit("re-capture")
        # The attribute is already on the base; only its value line is added. The span still reaches it.
        result = self.scan(base=base)
        self.assertEqual([(scan.FREEIPA_ATTRIBUTE, "fx.json")], self.classes(result))
        self.assertEqual(leak, result.findings[0].commit)
        patch = self.r.out("show", "-U0", "--format=", "HEAD")
        self.assertNotIn(fx.KRB_KEY, patch, "premise: the diff of that commit has no attribute name")
        # Control: a commit that does not touch the value line leaves nothing to report.
        self.r.write("fx.json", fx.attribute_document(fx.KRB_KEY, value).replace("User", "Other"))
        self.r.commit("touch another line")
        self.assertClean(self.scan(base=leak))

    def test_a_changed_value_line_without_any_marker_word_is_found(self):
        # The value sits on its own line in a list: no attribute name, no __base64__ on the changed line.
        doc = '{\n  "%s": [\n    "%s"\n  ]\n}\n'
        self.r.write("list.json", doc % (fx.NT_HASH, "redacted"))
        self.r.commit("list with a harmless value")
        base = self.r.out("rev-parse", "HEAD")
        self.r.write("list.json", doc % (fx.NT_HASH, fx.random_b64()))
        self.r.commit("value changed")
        self.assertEqual([(scan.FREEIPA_ATTRIBUTE, "list.json")], self.classes(self.scan(base=base)))

    def test_a_commit_that_changes_only_a_pem_body_line_is_found(self):
        key = block("RSA ")
        self.r.write("keys/old.pem", key.replace(key.splitlines()[1], "x" * 8))
        self.r.commit("a key whose body is a stub")
        base = self.r.out("rev-parse", "HEAD")
        self.r.write("keys/old.pem", key)
        self.r.commit("replace one body line")
        self.assertEqual([(scan.PRIVATE_KEY, "keys/old.pem")], self.classes(self.scan(base=base)))

    def test_crlf_files_are_scanned_like_lf_files(self):
        key = block("OPENSSH ").replace("\n", "\r\n")
        self.r.write("crlf.pem", key)
        self.r.commit("crlf key")
        doc = fx.attribute_document(fx.OTP_KEY, fx.random_b64()).replace("\n", "\r\n")
        self.r.write("crlf.json", doc)
        self.r.commit("crlf capture")
        self.assertEqual([(scan.FREEIPA_ATTRIBUTE, "crlf.json"), (scan.PRIVATE_KEY, "crlf.pem")], self.classes(self.scan()))

    def test_an_unexpected_failure_is_an_error_that_never_quotes_what_it_was_scanning(self):
        token = fx.mixed(40)
        self.r.write("a.txt", f"Authorization: Bearer {token}\n")
        self.r.commit("a")

        def explode(data):
            raise RuntimeError(f"cannot classify {data[:60]!r}")

        with mock.patch.object(scan, "classify", explode):
            result = self.scan()
        self.assertEqual("ERROR", result.status)
        self.assertIn("RuntimeError", " ".join(result.errors))
        self.assertNotIn("Authorization", self.dump(result))
        self.assertNotIn(token, self.dump(result))
        self.assertTrue(scan.refusal_messages(result))

    def test_a_secret_added_in_a_commit_message_is_found_without_the_value(self):
        token = fx.mixed(40)
        self.r.write("a.txt", "a\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-q", "-m", f"debug\n\nAuthorization: Bearer {token}")
        result = self.scan()
        self.assertEqual([(scan.AUTHORIZATION, "(commit message)")], self.classes(result))
        self.assertNotIn(token, self.dump(result))

    def test_an_evidence_only_path_is_scanned_like_any_other(self):
        # No path is exempt by being evidence: docs/evidence/** is where hand-written text lands.
        token = fx.mixed(40)
        self.r.write("docs/evidence/feature/pr-1.md", f"curl -H 'Authorization: Bearer {token}' https://x\n")
        self.r.commit("evidence")
        self.assertEqual([(scan.AUTHORIZATION, "docs/evidence/feature/pr-1.md")], self.classes(self.scan()))

    def test_a_root_commit_is_scanned_in_full(self):
        # `base` is unrelated to the feature branch: its root commit is part of base..head.
        self.r.git("switch", "-q", "--orphan", "orphan")
        for child in list(self.r.path.iterdir()):
            if child.name != ".git":
                child.unlink()
        self.r.write("capture.json", fx.attribute_document(fx.OTP_KEY, fx.random_b64()))
        leak = self.r.commit("first commit of an unrelated history")
        result = self.scan(base=self.base)
        self.assertEqual([(scan.FREEIPA_ATTRIBUTE, "capture.json")], self.classes(result))
        self.assertEqual(leak, result.findings[0].commit)
        self.assertEqual(1, result.commits)

    def test_content_added_inside_a_merge_is_found(self):
        self.r.git("switch", "-q", "main")
        self.r.write("m.txt", "main side\n")
        self.r.commit("main moves")
        self.r.git("switch", "-q", "feature")
        self.r.write("f.txt", "feature side\n")
        self.r.commit("feature moves")
        self.r.git("merge", "-q", "--no-ff", "--no-commit", "main")
        token = fx.mixed(40)
        self.r.write("merge-only.txt", f"Authorization: Bearer {token}\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-q", "-m", "Merge main")
        merge = self.r.out("rev-parse", "HEAD")
        result = self.scan()
        self.assertEqual([(scan.AUTHORIZATION, "merge-only.txt")], self.classes(result))
        self.assertEqual(merge, result.findings[0].commit)
        # A conflict resolved to a new line is also content only the merge has.
        self.r.git("switch", "-q", "-c", "conflict", self.base)
        self.r.write("README.md", "feature edit\n")
        self.r.commit("edit README on one side")
        self.r.git("switch", "-q", "-c", "other", self.base)
        self.r.write("README.md", "main edit\n")
        self.r.commit("edit README on the other")
        self.assertNotEqual(0, self.r.git("merge", "-q", "conflict", check=False).returncode)
        self.r.write("README.md", f"resolved\nAuthorization: Bearer {fx.mixed(40)}\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-q", "-m", "Merge conflict")
        resolved = self.scan(base=self.base)
        self.assertEqual([(scan.AUTHORIZATION, "README.md")], self.classes(resolved))

    def test_main_merged_into_the_branch_is_not_rescanned(self):
        # main carries a secret-shaped line of its own (already on the base of the PR); the branch merges
        # it in. Only the merge's own content counts: a first-parent diff would report main's line as added.
        self.r.git("switch", "-q", "main")
        self.r.write("on-main.txt", f"Authorization: Bearer {fx.mixed(40)}\n")
        main_tip = self.r.commit("main carries a synthetic header line")
        self.r.git("switch", "-q", "feature")
        self.r.write("f.txt", "feature work\n")
        self.r.commit("feature work")
        self.r.git("merge", "-q", "--no-ff", "-m", "Merge main", "main")
        result = self.scan(base=main_tip)
        self.assertClean(result)
        self.assertEqual(2, result.commits)
        # Control: the same main commit, scanned as part of the range, is found.
        self.assertEqual([(scan.AUTHORIZATION, "on-main.txt")], self.classes(self.scan(base=self.base)))

    def test_gitattributes_cannot_hide_content(self):
        # `-diff` makes `git diff` print "Binary files differ"; a textconv driver can print anything.
        token = fx.mixed(40)
        self.r.write(".gitattributes", "*.dat -diff\n*.conf diff=hide\n")
        self.r.git("config", "diff.hide.textconv", "true")
        self.r.commit("attributes")
        before = self.r.out("rev-parse", "HEAD")
        self.r.write("blob.dat", f"Authorization: Bearer {token}\n")
        self.r.write("hidden.conf", f"Authorization: Bearer {fx.mixed(40)}\n")
        self.r.commit("content the diff machinery would hide")
        self.assertIn("Binary files", self.r.out("show", "--format=", "HEAD", "--", "blob.dat"),
                      "premise: git itself hides the -diff file")
        result = self.scan(base=before)
        self.assertEqual([(scan.AUTHORIZATION, "blob.dat"), (scan.AUTHORIZATION, "hidden.conf")], self.classes(result))

    def test_odd_paths_are_attributed_exactly(self):
        for name in ("with space.txt", 'quo"te.txt', "tab\there.txt", "unié.txt", "back\\slash.txt"):
            with self.subTest(name=name):
                self.r.write(name, f"Authorization: Bearer {fx.mixed(40)}\n")
                self.r.commit("odd path")
        self.assertEqual(sorted(["with space.txt", 'quo"te.txt', "tab?here.txt", "unié.txt", "back\\slash.txt"]),
                         sorted(f.path for f in self.scan().findings))

    def test_a_changed_line_next_to_secret_shaped_content_that_was_already_there_passes(self):
        value = fx.random_b64()
        doc = fx.attribute_document(fx.NT_HASH, value).replace("User", "Alpha")
        self.r.write("data.json", doc)
        self.r.commit("the value, already on the base")
        base = self.r.out("rev-parse", "HEAD")
        self.r.write("data.json", doc.replace("Alpha", "Beta"))
        self.r.commit("edit another line")
        # Only the `sn` line was edited: the old value is not this change's to report.
        self.assertClean(self.scan(base=base))

    def test_binary_content_with_nul_bytes_does_not_break_the_walk(self):
        (self.r.path / "blob.bin").write_bytes(b"\x00\x01" + os.urandom(2048) + b"\n" + b"\x00" * 100)
        self.r.commit("binary")
        self.assertClean(self.scan())

    def test_an_empty_range_is_clean(self):
        result = scan.scan_range(self.r.path, self.base, self.base)
        self.assertClean(result)
        self.assertEqual(0, result.commits)

    def test_a_noisy_commit_without_triggers_is_clean(self):
        self.r.write("data.txt", "".join(f"{fx.mixed(40)} {i}\n" for i in range(500)))
        self.r.commit("lots of random-looking lines, no secret class")
        self.assertClean(self.scan())


class LongLines(RangeFixture):
    """A diff line longer than one window (scan.LINE_WINDOW) is read in windows. What lies past the first
    window must be seen even when that line is the only or the last added line of its hunk: the hunk's
    counters reach zero with the first window, the line goes on."""

    def filler(self, length: int) -> str:
        # Words and spaces: no trigger word and, unlike a run of `x`, not a bare base64 line, so a window
        # of it is silent. Only the secret (or its absence) decides what the scan reports.
        return ("lorem ipsum dolor " * (length // 18 + 1))[:length]

    def first_window(self, body: str, *, parents: int = 1) -> bytes:
        """The bytes of the first window of the diff line `+body` (prefix included)."""
        return ("+" * parents + body).encode()[:scan.LINE_WINDOW]

    def commit_body(self, body: str, name: str = "long.txt", *, newline: bool = True) -> str:
        self.r.write(name, body + ("\n" if newline else ""))
        return self.r.commit("a long line")

    # -- a header class past the first window ------------------------------------------------------

    def test_a_header_past_the_first_window_of_the_only_added_line_is_found(self):
        token = fx.mixed(40)
        words = self.filler(scan.LINE_WINDOW + 5000)
        body = words + f" Authorization: Bearer {token}"
        self.assertIsNone(scan._TRIGGER.search(self.first_window(body)), "premise: the first window is silent")
        self.assertGreater(len(body), scan.LINE_WINDOW, "premise: the line needs more than one window")
        leak = self.commit_body(body)
        result = self.scan()
        self.assertEqual([(scan.AUTHORIZATION, "long.txt")], self.classes(result))
        self.assertEqual(leak, result.findings[0].commit)
        self.assertEqual(1, result.findings[0].line)
        self.assertNotIn(token, self.dump(result))
        # Control: the same long line with a placeholder is clean.
        self.r.git("switch", "-q", "-c", "control", self.base)
        self.commit_body(words + " Authorization: Bearer <redacted>")
        self.assertClean(self.scan())

    def test_the_same_secret_is_found_wherever_the_long_line_sits_in_its_hunk(self):
        token = fx.mixed(40)
        body = self.filler(scan.LINE_WINDOW + 777) + f" Authorization: Bearer {token}"
        short = f"Cookie: sid={fx.mixed(40)}"
        for name, lines in {"only line": [body], "last of several": ["alpha", "beta", body],
                            "no newline at end of file": [body],
                            "followed by another file": [body]}.items():
            with self.subTest(name=name):
                self.setUp()
                text = "\n".join(lines) + ("" if name == "no newline at end of file" else "\n")
                self.r.write("long.txt", text)
                if name == "followed by another file":
                    self.r.write("zzz-after.txt", short + "\n")
                leak = self.r.commit("long line")
                result = self.scan()
                expected = [(scan.AUTHORIZATION, "long.txt")]
                if name == "followed by another file":
                    expected = sorted(expected + [(scan.COOKIE, "zzz-after.txt")])
                self.assertEqual(expected, self.classes(result))
                self.assertEqual({leak}, {f.commit for f in result.findings})
                self.assertEqual(len(lines), next(f.line for f in result.findings if f.path == "long.txt"))

    def test_lines_after_a_long_one_keep_their_numbers_and_a_second_hunk_is_still_parsed(self):
        cookie = f"Cookie: sid={fx.mixed(40)}"
        self.r.write("m.txt", "keep one\nold two\nkeep three\nold four\nkeep five\n")
        self.r.commit("a file with two spots to change")
        before = self.r.out("rev-parse", "HEAD")
        body = self.filler(scan.LINE_WINDOW + 100) + f" Authorization: Bearer {fx.mixed(40)}"
        self.r.write("m.txt", f"keep one\n{body}\nkeep three\n{cookie}\nkeep five\n")
        self.r.commit("two hunks, the first one ends with a long line")
        result = self.scan(base=before)
        self.assertEqual({(scan.AUTHORIZATION, 2), (scan.COOKIE, 4)}, {(f.cls, f.line) for f in result.findings})
        self.assertEqual([], result.errors)

    def test_the_tail_of_a_removed_long_line_is_not_this_commits(self):
        body = self.filler(scan.LINE_WINDOW + 500) + f" Authorization: Bearer {fx.mixed(40)}"
        leak = self.commit_body(body)
        self.assertEqual("FOUND", self.scan().status, "premise: the commit that adds it is found")
        self.r.write("long.txt", "short\n")
        self.r.commit("remove the long line")
        self.assertClean(self.scan(base=leak))

    # -- known values past and across the window boundary ------------------------------------------

    def straddling(self, value: str, inside_first: int) -> str:
        """A body whose first window ends `inside_first` bytes into `value`."""
        offset = scan.LINE_WINDOW - 1 - inside_first
        body = self.filler(offset) + value + self.filler(4000)
        line = ("+" + body).encode()
        self.assertNotIn(value.encode(), line[:scan.LINE_WINDOW], "premise: the first window lacks the whole value")
        self.assertNotIn(value.encode(), line[scan.LINE_WINDOW:], "premise: the second window lacks the whole value")
        self.assertIn(value.encode(), line)
        return body

    def test_a_known_value_past_the_first_window_is_found(self):
        value = fx.mixed(24)
        body = self.filler(scan.LINE_WINDOW + 3000) + f" {value} " + self.filler(100)
        self.assertNotIn(value.encode(), self.first_window(body))
        self.assertIsNone(scan._TRIGGER.search(self.first_window(body)), "premise: nothing but the value matters")
        leak = self.commit_body(body)
        result = self.scan(known=[value.encode()])
        self.assertEqual([(scan.KNOWN_VALUE, "long.txt")], self.classes(result))
        self.assertEqual(leak, result.findings[0].commit)
        self.assertNotIn(value, self.dump(result))
        # Controls: the same history without that value on the list, and a different value on it.
        self.assertClean(self.scan())
        self.assertClean(self.scan(known=[fx.mixed(24).encode()]))

    def test_a_known_value_split_across_two_windows_is_found(self):
        value = fx.mixed(24)
        for inside_first in (1, len(value) // 2, len(value) - 1):
            with self.subTest(inside_first=inside_first):
                self.setUp()
                self.commit_body(self.straddling(value, inside_first))
                result = self.scan(known=[value.encode()])
                self.assertEqual([(scan.KNOWN_VALUE, "long.txt")], self.classes(result))
                self.assertClean(self.scan())

    def test_a_known_value_longer_than_the_default_overlap_is_found_when_split(self):
        value = fx.mixed(3 * scan.WINDOW_OVERLAP)
        self.assertGreater(len(value), scan.WINDOW_OVERLAP + 1)
        self.commit_body(self.straddling(value, len(value) // 2))
        self.assertEqual([(scan.KNOWN_VALUE, "long.txt")], self.classes(self.scan(known=[value.encode()])))
        # Control: another value of that length, split the same way, is not reported.
        self.assertClean(self.scan(known=[fx.mixed(len(value)).encode()]))

    def test_a_value_that_is_too_long_to_window_is_refused(self):
        too_long = b"k" * (scan.MAX_KNOWN_LENGTH + 1)
        self.r.write("a.txt", "a\n")
        self.r.commit("a")
        result = self.scan(known=[too_long])
        self.assertEqual("ERROR", result.status)
        self.assertNotIn("k" * 20, self.dump(result))
        self.assertClean(self.scan(known=[b"k" * scan.MAX_KNOWN_LENGTH]))

    # -- the work stays bounded --------------------------------------------------------------------

    def test_trigger_text_of_a_file_too_large_to_read_back_is_judged_in_batches(self):
        # Small windows make the large-file path cheap: a 150 KiB line is several windows, and a file
        # past MAX_CONTEXT_BYTES is judged from its trigger windows instead of from the whole blob.
        seen: list[int] = []
        original = scan._Collector.window

        def watch(collector, body, number):
            original(collector, body, number)
            seen.append(collector.trigger_bytes)

        words = lambda n: ("lorem ipsum cookie dolor " * (n // 25 + 1))[:n]  # noqa: E731  (a trigger word in every window)
        lines = [words(70_000) + f" Authorization: Bearer {fx.mixed(40)}" + words(70_000)]
        lines += [words(150_000) for _ in range(6)]
        lines += [words(140_000) + f" Cookie: sid={fx.mixed(40)}"]
        self.r.write("big.txt", "\n".join(lines) + "\n")
        self.r.commit("a large file")
        limits = {"LINE_WINDOW": 64 << 10, "MAX_CONTEXT_BYTES": 256 << 10, "MAX_TRIGGER_BYTES": 400 << 10}
        with mock.patch.multiple(scan, **limits), mock.patch.object(scan._Collector, "window", watch):
            result = self.scan()
        self.assertEqual([], result.errors)
        self.assertEqual([(scan.AUTHORIZATION, "big.txt"), (scan.COOKIE, "big.txt")], self.classes(result))
        # The first secret was judged when a batch was dropped, the last one at the end of the file.
        self.assertLessEqual(max(seen), limits["MAX_TRIGGER_BYTES"] + limits["LINE_WINDOW"] + scan.WINDOW_OVERLAP)
        self.assertGreater(len(seen), 8, "premise: the file went through several windows")


class KnownValues(RangeFixture):
    def setUp(self):
        super().setUp()
        self.value = fx.mixed(18)

    def test_known_values_are_found_in_added_lines_messages_and_paths(self):
        known = [self.value.encode()]
        self.r.write("notes.txt", f"the password is {self.value}\n")
        a = self.r.commit("one")
        self.r.write("notes.txt", "scrubbed\n")
        self.r.commit("two")
        self.r.write("b.txt", "b\n")
        self.r.git("add", "-A")
        self.r.git("commit", "-q", "-m", f"note: {self.value}")
        self.r.write(f"{self.value}.txt", "c\n")
        path_commit = self.r.commit("three")
        result = self.scan(known=known)
        found = sorted((f.cls, f.path) for f in result.findings)
        self.assertEqual(3, len(found), found)
        self.assertTrue(all(cls == scan.KNOWN_VALUE for cls, _ in found), found)
        self.assertIn("(commit message)", [p for _, p in found])
        self.assertIn("notes.txt", [p for _, p in found])
        self.assertIn(a, [f.commit for f in result.findings], "the scrubbed value is still in the earlier commit")
        self.assertIn(path_commit, [f.commit for f in result.findings])
        self.assertEqual(1, result.known_values)
        self.assertNotIn(self.value, self.dump(result), "the path that holds the value is masked too")
        self.assertEqual("FOUND", result.status)

    def test_without_the_value_the_same_history_is_clean(self):
        self.r.write("notes.txt", f"the password is {self.value}\n")
        self.r.commit("one")
        self.assertClean(self.scan())
        self.assertClean(self.scan(known=[fx.mixed(18).encode()]))

    def test_a_known_value_is_never_exempted(self):
        exemptions = [scan.Exemption(scan.AUTHORIZATION, "**", "x" * 12)]
        self.r.write("notes.txt", f"{self.value}\n")
        self.r.commit("one")
        result = self.scan(known=[self.value.encode()], exemptions=exemptions)
        self.assertEqual("FOUND", result.status)


class SecretFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(os.path.realpath(self.tmp.name))
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.outside = self.root / "outside"
        self.outside.mkdir()

    def write(self, directory, content, name="values.txt"):
        path = directory / name
        path.write_bytes(content)
        return path

    def test_values_are_read_as_bytes_blank_lines_and_one_trailing_cr_dropped(self):
        a, b = fx.mixed(12), fx.mixed(15)
        path = self.write(self.outside, f"{a}\r\n\n\n{b}\n".encode() + b"\r\n")
        self.assertEqual([a.encode(), b.encode()], scan.load_secret_files([path], self.repo))
        self.assertEqual([], scan.load_secret_files([self.write(self.outside, b"\n\n", "empty.txt")], self.repo))

    def test_non_utf8_values_are_kept_as_bytes(self):
        value = b"\xff\xfe" + os.urandom(12)
        value = value.replace(b"\n", b"x")
        path = self.write(self.outside, value + b"\n")
        self.assertEqual([value], scan.load_secret_files([path], self.repo))

    def test_a_short_value_is_refused_by_line_number_never_by_value(self):
        short = fx.mixed(7)
        path = self.write(self.outside, f"{fx.mixed(12)}\n{short}\n".encode())
        with self.assertRaises(scan.SecretScanError) as caught:
            scan.load_secret_files([path], self.repo)
        message = str(caught.exception)
        self.assertIn("line 2", message)
        self.assertNotIn(short, message)

    def test_a_file_inside_the_repository_is_refused(self):
        inside = self.write(self.repo, f"{fx.mixed(12)}\n".encode())
        with self.assertRaises(scan.SecretScanError) as caught:
            scan.load_secret_files([inside], self.repo)
        self.assertIn("inside the repository", str(caught.exception))
        link = self.outside / "link.txt"
        link.symlink_to(inside)
        with self.assertRaises(scan.SecretScanError):
            scan.load_secret_files([link], self.repo)

    def test_only_a_regular_file_is_accepted(self):
        with self.assertRaises(scan.SecretScanError):
            scan.load_secret_files([self.outside], self.repo)
        with self.assertRaises(scan.SecretScanError):
            scan.load_secret_files([self.outside / "missing.txt"], self.repo)
        fifo = self.outside / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(scan.SecretScanError):
            scan.load_secret_files([fifo], self.repo)


class Exemptions(RangeFixture):
    def setUp(self):
        super().setUp()
        self.token = fx.mixed(40)

    def exemption_file(self, *entries):
        return json.dumps({"schema_version": 1, "allow": list(entries)})

    ENTRY = {"class": "authorization-header", "path_glob": "testdata/**",
             "reason": "synthetic header lines used by the redaction tests"}

    def with_base_exemptions(self, text):
        self.r.git("switch", "-q", "main")
        self.r.write(".github/secret-scan.json", text)
        base = self.r.commit("exemptions")
        self.r.git("switch", "-q", "-c", "work", "main")
        return base

    def test_exemptions_come_from_the_base_commit_and_match_class_and_path(self):
        base = self.with_base_exemptions(self.exemption_file(self.ENTRY))
        self.r.write("testdata/a.txt", f"Authorization: Bearer {self.token}\n")
        self.r.write("docs/b.txt", f"Authorization: Bearer {fx.mixed(40)}\n")
        self.r.commit("two files")
        result = self.scan(base=base)
        self.assertEqual([(scan.AUTHORIZATION, "docs/b.txt")], self.classes(result))
        self.assertEqual(["testdata/a.txt"], [f.path for f in result.exempted])
        self.assertTrue(result.exemptions_source.endswith(".github/secret-scan.json"), result.exemptions_source)
        # A different class in the same path is not exempt.
        self.r.write("testdata/c.json", fx.attribute_document(fx.NT_HASH, fx.random_b64()))
        self.r.commit("another class")
        self.assertIn((scan.FREEIPA_ATTRIBUTE, "testdata/c.json"), self.classes(self.scan(base=base)))

    def test_a_branch_cannot_exempt_itself(self):
        self.r.write(".github/secret-scan.json", self.exemption_file(self.ENTRY))
        self.r.write("testdata/a.txt", f"Authorization: Bearer {self.token}\n")
        self.r.commit("secret plus an exemption added by the same branch")
        result = self.scan()
        self.assertEqual("absent", result.exemptions_source)
        self.assertEqual([(scan.AUTHORIZATION, "testdata/a.txt")], self.classes(result))

    def test_malformed_exemptions_are_an_error_and_exempt_nothing(self):
        bad = {
            "not json": "{",
            "wrong version": json.dumps({"schema_version": 2, "allow": []}),
            "known-value": self.exemption_file({**self.ENTRY, "class": "known-value"}),
            "unknown class": self.exemption_file({**self.ENTRY, "class": "other"}),
            "no reason": self.exemption_file({**self.ENTRY, "reason": "x"}),
            "extra key": self.exemption_file({**self.ENTRY, "note": "y"}),
            "absolute glob": self.exemption_file({**self.ENTRY, "path_glob": "/etc/**"}),
            "everything": self.exemption_file({**self.ENTRY, "path_glob": "**"}),
        }
        for name, text in bad.items():
            with self.subTest(name=name):
                self.setUp()
                base = self.with_base_exemptions(text)
                self.r.write("testdata/a.txt", f"Authorization: Bearer {self.token}\n")
                self.r.commit("secret")
                result = self.scan(base=base)
                self.assertEqual("FOUND", result.status)
                self.assertTrue(result.errors, name)
                self.assertEqual([(scan.AUTHORIZATION, "testdata/a.txt")], self.classes(result))
                self.assertEqual([], result.exempted)

    def test_the_glob_dialect_matches_repo_evidence(self):
        evidence = load_module(SKILLS / "issue-to-pr" / "scripts" / "repo_evidence.py")
        paths = ["a.go", "docs/x.md", "docs/a/b/c.md", "internal/x/y_test.go", ".github/secret-scan.json", "a/b", "ab"]
        for pattern in ("**", "docs/**", "**/*.go", "*.go", "docs/*.md", "a?", "a/**/b", "internal/**/y_test.go", ".github/*"):
            for path in paths:
                self.assertEqual(bool(evidence.glob_regex(pattern).match(path)), bool(scan.glob_regex(pattern).match(path)),
                                 (pattern, path))


class FailClosed(RangeFixture):
    def test_a_missing_base_or_head_object_is_an_error_that_says_to_fetch(self):
        self.r.write("a.txt", "a\n")
        self.r.commit("a")
        for kwargs in ({"base": "f" * 40}, {"head": "e" * 40}):
            with self.subTest(**kwargs):
                result = self.scan(**kwargs)
                self.assertEqual("ERROR", result.status)
                self.assertIn("fetch", " ".join(result.errors))
                self.assertTrue(scan.refusal_messages(result))
                self.assertEqual("ERROR", scan.ScanResult(base="x", head="y", errors=["e"]).status)

    def test_a_revision_that_looks_like_an_option_is_refused(self):
        self.assertEqual("ERROR", self.scan(base="--output=/tmp/x").status)

    def test_a_missing_repository_is_an_error(self):
        result = scan.scan_range(self.r.path / "nope", "a" * 40, "b" * 40)
        self.assertEqual("ERROR", result.status)

    def test_findings_and_errors_both_refuse(self):
        self.r.write("a.txt", f"Authorization: Bearer {fx.mixed(40)}\n")
        self.r.commit("a")
        result = self.scan()
        self.assertEqual("FOUND", result.status)
        self.assertTrue(scan.refusal_messages(result))
        self.assertTrue(any("STOP" in m for m in scan.finding_messages(result)))
        self.assertIn(scan.GUIDE, " ".join(scan.finding_messages(result)))
        self.assertTrue(all("STOP" not in m for m in scan.error_messages(scan.ScanResult(base="b", head="h", errors=["x"]))))


class Cli(RangeFixture):
    def run_cli(self, *args, **kwargs):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        return subprocess.run([sys.executable, "-B", str(SCRIPT), *args], capture_output=True, text=True, env=env, **kwargs)

    def test_help_works(self):
        p = self.run_cli("--help")
        self.assertEqual(0, p.returncode)
        self.assertIn("--secret-file", p.stdout)
        self.assertIn(scan.GUIDE, p.stdout)

    def test_exit_status_and_json_for_clean_found_and_error(self):
        clean = self.run_cli("--repo", str(self.r.path), "--base", self.base, "--head", "HEAD")
        self.assertEqual(0, clean.returncode, clean.stderr)
        out = json.loads(clean.stdout)
        self.assertEqual({"schema": "pilot-secret-scan/v1", "status": "CLEAN", "commits_scanned": 0, "known_values": 0,
                          "exemptions_source": "absent", "findings": [], "errors": []},
                         {k: out[k] for k in ("schema", "status", "commits_scanned", "known_values", "exemptions_source",
                                              "findings", "errors")})
        token = fx.mixed(40)
        self.r.write("a.txt", f"Authorization: Bearer {token}\n")
        commit = self.r.commit("leak")
        found = self.run_cli("--repo", str(self.r.path), "--base", self.base, "--head", "HEAD", "--compact")
        self.assertEqual(1, found.returncode, found.stderr)
        data = json.loads(found.stdout)
        self.assertEqual("FOUND", data["status"])
        self.assertEqual([{"commit": commit, "path": "a.txt", "line": 1, "class": "authorization-header"}], data["findings"])
        self.assertEqual(1, data["commits_scanned"])
        self.assertEqual(1, len(found.stdout.strip().splitlines()), "--compact is one line")
        for channel in (found.stdout, found.stderr):
            self.assertNotIn(token, channel)
        broken = self.run_cli("--repo", str(self.r.path), "--base", "f" * 40, "--head", "HEAD")
        self.assertEqual(2, broken.returncode)
        self.assertEqual("ERROR", json.loads(broken.stdout)["status"])

    def test_secret_file_option_and_its_errors(self):
        value = fx.mixed(20)
        self.r.write("a.txt", f"x {value}\n")
        self.r.commit("leak")
        outside = Path(self.r.base) / "secrets.txt"
        outside.write_text(f"\n{value}\n")
        found = self.run_cli("--repo", str(self.r.path), "--base", self.base, "--head", "HEAD", "--secret-file", str(outside))
        self.assertEqual(1, found.returncode, found.stderr)
        self.assertEqual(1, json.loads(found.stdout)["known_values"])
        for channel in (found.stdout, found.stderr):
            self.assertNotIn(value, channel)
        inside = self.r.path / "secrets.txt"
        inside.write_text(f"{value}\n")
        refused = self.run_cli("--repo", str(self.r.path), "--base", self.base, "--head", "HEAD", "--secret-file", str(inside))
        self.assertEqual(2, refused.returncode)
        self.assertNotIn(value, refused.stdout + refused.stderr)
        short = Path(self.r.base) / "short.txt"
        short.write_text(f"{value}\n{fx.mixed(5)}\n")
        refused = self.run_cli("--repo", str(self.r.path), "--base", self.base, "--head", "HEAD", "--secret-file", str(short))
        self.assertEqual(2, refused.returncode)
        self.assertIn("line 2", refused.stdout)
        self.assertNotIn(value, refused.stdout + refused.stderr)

    def test_the_scanner_writes_no_bytecode_next_to_itself(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "secret_scan.py"
            copy.write_text(SCRIPT.read_text())
            env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
            p = subprocess.run([sys.executable, str(copy), "--help"], capture_output=True, text=True, env=env, cwd=tmp)
            self.assertEqual(0, p.returncode, p.stderr)
            self.assertEqual([], sorted(x.name for x in Path(tmp).rglob("__pycache__")))


class Consistency(unittest.TestCase):
    """The scanner records what internal/freeiparpc/fixture_secrets_test.go enforces for testdata."""

    GO = ROOT / "internal" / "freeiparpc" / "fixture_secrets_test.go"

    def setUp(self):
        if not (ROOT / "go.mod").is_file():
            self.skipTest("not a pilot checkout")
        self.go = self.GO.read_text()

    def test_attribute_list_matches_the_go_guard(self):
        found = re.search(r"var secretFixtureAttributes = \[\]string\{([^}]*)\}", self.go)
        self.assertIsNotNone(found, "the attribute list moved: update secret_scan.SECRET_ATTRIBUTES and this test")
        go_attrs = re.findall(r'"([^"]+)"', found.group(1))
        self.assertEqual(list(go_attrs), list(scan.SECRET_ATTRIBUTES))
        self.assertEqual(list(go_attrs), list(fx.ATTRIBUTES))

    def test_placeholder_matches_the_go_guard(self):
        found = re.search(r'const fixtureSecretPlaceholder = "([^"]+)"', self.go)
        self.assertIsNotNone(found, "the placeholder moved: update secret_scan.PLACEHOLDER and this test")
        self.assertEqual(found.group(1), scan.PLACEHOLDER)
        self.assertEqual(found.group(1), fx.PLACEHOLDER)

    def test_the_committed_exemptions_are_valid_and_each_is_still_needed(self):
        path = ROOT / ".github" / "secret-scan.json"
        exemptions = scan.parse_exemptions(path.read_bytes())
        tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True,
                                 env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")})
        if tracked.returncode:
            self.skipTest("not a git checkout")
        files = [x.decode() for x in tracked.stdout.split(b"\0") if x]
        for entry in exemptions:
            rx = scan.glob_regex(entry.path_glob)
            matching = [f for f in files if rx.match(f)]
            self.assertTrue(matching, f"{entry.path_glob} matches no tracked file: remove the stale entry")
            classes = {h.cls for f in matching for h in scan.scan_text(f, (ROOT / f).read_bytes())}
            self.assertIn(entry.cls, classes, f"{entry.path_glob} no longer matches {entry.cls}: remove the entry")

    def test_the_documented_class_names_are_the_exemption_classes(self):
        self.assertEqual(set(scan.CLASSES), {scan.FREEIPA_ATTRIBUTE, scan.PRIVATE_KEY, scan.AUTHORIZATION, scan.COOKIE,
                                             scan.IPA_SESSION, scan.KNOWN_VALUE})


class SelfScan(unittest.TestCase):
    """Rule prose must pass: no tracked skill file (the rule text, the scanner, the tests) is a finding."""

    def tracked_skill_files(self):
        p = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard",
                            "--", ".agents/skills"], capture_output=True, env={k: v for k, v in os.environ.items()
                                                                              if not k.startswith("GIT_")})
        if p.returncode == 0 and p.stdout:
            return [ROOT / x.decode() for x in p.stdout.split(b"\0") if x]
        return [x for x in SKILLS.rglob("*") if x.is_file() and "__pycache__" not in x.parts]

    def test_no_skill_file_is_a_finding(self):
        files = [f for f in self.tracked_skill_files() if f.is_file()]
        self.assertGreater(len(files), 50)
        self.assertIn(SKILLS / "_shared" / "committed-secrets.md", files)
        findings = [(h.cls, str(f.relative_to(ROOT)), h.line) for f in files for h in scan.scan_text(f.name, f.read_bytes())]
        self.assertEqual([], findings)


if __name__ == "__main__":
    unittest.main()
