"""Remote gate's target reuse policy: same machine rules as local issue-to-pr."""
import copy
import json
import unittest
from unittest import mock

from test_gate import Fake, sample, B, H
from test_target_validation import API, R, ART, RECORD, MANIFEST, REPO, repo_manifest, replay
import gh_runtime
from review_gate import evaluate

A = "d" * 40
APP = "playbooks/apply/x.yml"
DEP = "internal/shared/helper.go"
OTHER = "internal/unrelated/service.go"


def blob(n, mode="100644"):
    return (mode, str(n) * 40)


class TargetReuseRemoteTests(unittest.TestCase):
    def fixture(self):
        gh = Fake()
        manifest = json.loads(repo_manifest())
        manifest["required_evidence"][0]["kind"] = "target-run"
        gh.files[(MANIFEST, B)] = json.dumps(manifest).encode()
        gh.files[(ART, H)] = RECORD
        gh.compares[(R, H)] = {"ancestor": True, "merge_base": R, "files": [ART, OTHER]}
        gh.compares[(B, H)] = {"ancestor": True, "merge_base": B, "files": [ART, APP]}
        gh.compares[(R, B)] = {"ancestor": False, "merge_base": A, "files": [OTHER]}
        trees = {A: {DEP: blob(1)}, R: {APP: blob(2), DEP: blob(1)},
                 B: {DEP: blob(1), OTHER: blob(3)},
                 H: {APP: blob(2), DEP: blob(1), OTHER: blob(3), ART: blob(4)}}
        gh.tree_entries = lambda repo, revision: trees[revision]
        gh.branch_head = lambda repo, name: B
        e = sample()
        e["target_validation"] = {"decision": "required", "reason": "Native target chain passed; execution content and dependencies independently reviewed.",
                                  "artifact": ART, "tested_revision": R,
                                  "target_reuse": {"head_sha": H, "base_sha": B, "reviewer_confirmed": True,
                                      "execution_paths": [APP, DEP], "non_execution_changes": [],
                                      "dependency_review": "Reviewed complete target dependency closure; the unrelated service is not called by this target or its shared helpers."}}
        return gh, e, trees

    def test_remote_machine_record_uses_shared_closure_validator(self):
        gh, e, trees = self.fixture()
        record = {"schema": "pilot-evidence-record/v1", "outcome": "success",
                  "candidate": {"commit": R, "tree": "e" * 40, "source": "git"},
                  "closure": {"resolution_version": 6, "frozen": True, "files": [{"path": APP, "mode": "100644", "blob": trees[R][APP][1]}],
                              "patterns": ["playbooks/apply/*.yml"]}}
        # Reuse the explicitly synthetic proof builder; native execution lives
        # in Go integration tests, this fixture proves shared adapter parity.
        import importlib.util
        from pathlib import Path
        helper = Path(__file__).resolve().parents[2] / "issue-to-pr/tests/controller_fixture.py"
        spec = importlib.util.spec_from_file_location("controller_fixture", helper)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        fixture.add_controller(record)
        for path, raw in fixture.fixture_files().items():
            entry = fixture.descriptor(path, raw)
            trees[R][path] = trees[H][path] = ("100644", entry["blob"])
            gh.files[(path,R)] = raw
        gh.files[(ART, H)] = ("<!-- pilot-evidence-record v1 -->\n```json\n" + json.dumps(record) + "\n```\n").encode()
        gh.commit_tree = lambda repo, revision: "e" * 40
        del e["target_validation"]["target_reuse"]["execution_paths"]
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("MERGE", r["decision"], r["reasons"])
        # This synthetic typed controlled-scope record tests the gate only.
        # Local and remote must reject the same unsafe machine attestations,
        # including old resolver records that silently omitted file expressions.
        for change, reason in (
                (lambda r: r["closure"].pop("resolution_version"), "resolution version"),
                (lambda r: r["closure"].update(unresolved=[{"from": "environment", "ref": "ambient Ansible plugin discovery", "reason": "unfingerprinted controller paths"}]), "unresolved"),
                (lambda r: r["closure"].update(resolution_version=2), "resolution version"),
                (lambda r: r["closure"].update(resolution_version=3), "resolution version"),
                (lambda r: r["closure"].update(resolution_version=4), "resolution version"),
                (lambda r: r["closure"].update(resolution_version=5), "resolution version"),
                (lambda r: r["closure"].update(resolution_version=6), "resolution version"),
            (lambda r: r["closure"].update(resolution_version=7), "resolution version"),
            (lambda r: r["closure"].update(resolution_version=8), "resolution version"),
            (lambda r: r["closure"].update(resolution_version=9), "resolution version"),
            (lambda r: r["closure"].update(unresolved=[{"ref": "unproved Go build closure", "reason": "candidate assembly/system objects are unsupported"}]), "unresolved"),
            (lambda r: r["controller"].update(schema="pilot-controller/v2"), "current OCI proof"),
            (lambda r: r["verify"][0].pop("rows"), "row counts differ"),
            (lambda r: r["verify"][0].update(diagnostics_complete=False), "diagnostic export"),
            (lambda r: r["verify"][0]["rows"][0].update(probe_status="runner_error"), "verifier row identity/status"),
            (lambda r: r["controller"].update(schema="pilot-controller/v1"), "current OCI proof"),
            (lambda r: r["controller"]["build"].pop("sources_sha256"), "missing Go build/module fingerprints"),
            (lambda r: r["controller"]["build"].update(rebuilt_binary_sha256="0"*64), "reproducible source rebuild"),
                (lambda r: r.pop("controller"), "current OCI proof"),
                (lambda r: r["controller"].update(image_id="tag:latest"), "immutable image ID"),
                (lambda r: r["controller"]["steps"].update({"L5 verify":0}), "stage was not routed"),
                (lambda r: r["controller"]["build"].update(goamd64="v2"), "unsupported Go build context"),
                (lambda r: r["closure"].update(frozen=False), "frozen pre-run"),
                (lambda r: r["closure"].update(unresolved=[{"ref": "lookup/query expression"}]), "unresolved"),
                (lambda r: r["closure"].update(external=["/outside/input"]), "external"),
                (lambda r: r["closure"].update(unresolved=[{"ref": "unsupported task dispatch"}]), "unresolved"),
                (lambda r: r["closure"].update(unresolved=[{"ref": "unsupported task layout", "reason": "debug argument proof failed"}]), "unresolved"),
                (lambda r: r["closure"].update(unresolved=[{"ref": "unsupported task dispatch", "reason": "template execution is opaque to automatic reuse"}]), "unresolved"),
                (lambda r: r["closure"].update(unresolved=[{"ref": "unsupported task dispatch", "reason": "automatic reuse supports only literal copy and debug.msg actions"}]), "unresolved"),
                (lambda r: r.update(outcome="invalid-inputs"), "did not succeed")):
            bad = copy.deepcopy(record)
            change(bad)
            gh.files[(ART, H)] = ("<!-- pilot-evidence-record v1 -->\n```json\n" + json.dumps(bad) + "\n```\n").encode()
            self.assertIn(reason, self.reasons(gh, e))
        gh.files[(ART, H)] = ("<!-- pilot-evidence-record v1 -->\n```json\n" + json.dumps(record) + "\n```\n").encode()
        trees[H]["playbooks/apply/new.yml"] = blob(8)
        self.assertIn("search membership changed", self.reasons(gh, e))

    def test_remote_existing_assembly_header_import_refuses_old_resolution(self):
        # The fake GitHub graph represents a genuine existing-header base
        # import: unchanged candidate bytes become the advanced-base bytes at H.
        gh,e,trees=self.fixture()
        header="src/value.h"
        trees[A][header]=trees[R][header]=blob(5)
        trees[B][header]=trees[H][header]=blob(6)
        gh.compares[(R,H)]["files"].append(header)
        gh.compares[(R,B)]["files"].append(header)
        record={"schema":"pilot-evidence-record/v1","outcome":"success",
                "candidate":{"commit":R,"tree":"e"*40,"source":"git"},
                "closure":{"frozen":True,"files":[{"path":APP,"mode":"100644","blob":trees[R][APP][1]}],"patterns":["src/*.h"]}}
        import importlib.util
        from pathlib import Path
        spec=importlib.util.spec_from_file_location("controller_fixture",Path(__file__).resolve().parents[2]/"issue-to-pr/tests/controller_fixture.py")
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        fixture.add_controller(record)
        for path,raw in fixture.fixture_files().items():
            entry=fixture.descriptor(path,raw)
            trees[R][path]=trees[H][path]=("100644",entry["blob"])
            gh.files[(path,R)]=raw
        gh.commit_tree=lambda repo,revision:"e"*40
        del e["target_validation"]["target_reuse"]["execution_paths"]
        for version,unresolved,reason in ((9,[],"resolution version"),(10,[{"ref":"unproved Go build closure","reason":"candidate assembly/system objects are unsupported"}],"unresolved")):
            record["closure"].update(resolution_version=version,unresolved=unresolved)
            gh.files[(ART,H)]=("<!-- pilot-evidence-record v1 -->\n```json\n"+json.dumps(record)+"\n```\n").encode()
            self.assertIn(reason,self.reasons(gh,e))

        # Same-path ignored assembly activation is content-bound in resolver10.
        # This adapter-only fixture represents that producer's collected bytes.
        source="src/value.s"
        trees[A][source]=trees[R][source]=blob(7)
        trees[B][source]=trees[H][source]=blob(8)
        gh.compares[(R,H)]["files"].append(source)
        gh.compares[(R,B)]["files"].append(source)
        record["closure"].update(resolution_version=10,unresolved=[],patterns=["src/*"])
        record["closure"]["files"].append({"path":source,"mode":"100644","blob":trees[R][source][1]})
        gh.files[(ART,H)]=("<!-- pilot-evidence-record v1 -->\n```json\n"+json.dumps(record)+"\n```\n").encode()
        self.assertIn("execution input changed, missing or not a regular file: "+source,self.reasons(gh,e))

    def test_remote_gate_accepts_reviewed_main_import(self):
        gh, e, _ = self.fixture()
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("MERGE", r["decision"], r["reasons"])
        self.assertEqual("reviewed-base-integration", r["target_validation"]["delta_accepted"][0]["method"])

    def test_execution_dependency_mode_or_content_change_waits(self):
        for changed in (blob(9), blob(1, "100755"), None):
            gh, e, trees = self.fixture()
            if changed is None:
                del trees[H][DEP]
            else:
                trees[H][DEP] = changed
            r = evaluate(REPO, 42, e, client=gh)
            self.assertEqual("WAITING", r["decision"], r)
            self.assertIn("execution input changed", " ".join(r["reasons"]))

    def test_runtime_conflict_outside_scope_is_not_a_pure_import(self):
        gh, e, trees = self.fixture()
        trees[H][OTHER] = blob(8)
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("neither a pure base import", " ".join(r["reasons"]))

    def test_audited_docs_conflict_can_be_accepted(self):
        gh, e, trees = self.fixture()
        path = "docs/verification/x.md"
        trees[R][path], trees[H][path] = blob(5), blob(6)
        self.assertEqual("WAITING", evaluate(REPO, 42, e, client=gh)["decision"])
        e["target_validation"]["target_reuse"]["non_execution_changes"] = [
            {"path": path, "reason": "Changelog conflict resolution only; checklist commands and expected values are byte-identical."}]
        self.assertEqual("MERGE", evaluate(REPO, 42, e, client=gh)["decision"])

    def test_missing_stale_or_unconfirmed_attestation_waits(self):
        for kw, reason in (({"reviewer_confirmed": False}, "independent reviewer confirmation at current HEAD"),
                           ({"base_sha": A}, "target reuse base SHA does not match current base"),
                           ({"head_sha": R}, "independent reviewer confirmation at current HEAD")):
            with self.subTest(kw=kw):
                gh, e, _ = self.fixture()
                e["target_validation"]["target_reuse"].update(kw)
                self.assertIn(reason, self.reasons(gh, e))
        # Without an attestation the strict evidence-only delta applies: the imported main file is not.
        gh, e, _ = self.fixture()
        del e["target_validation"]["target_reuse"]
        self.assertIn("files outside evidence_only_paths changed: " + OTHER, self.reasons(gh, e))

    def test_stale_pr_base_metadata_does_not_prove_live_base(self):
        gh, e, _ = self.fixture()
        gh.branch_head = lambda repo, name: A
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("PR base metadata is stale", " ".join(r["reasons"]))

    def test_fresh_target_attestation_cannot_hide_stale_overall_review_base(self):
        gh, e, trees = self.fixture()
        current = "e" * 40
        trees[current] = trees[B].copy()
        gh.branch_head = lambda repo, name: current
        gh.compares[(current, H)] = {"ancestor": True, "merge_base": current, "files": [ART, APP]}
        gh.compares[(R, current)] = {"ancestor": False, "merge_base": A, "files": [OTHER]}
        e["target_validation"]["target_reuse"]["base_sha"] = current
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("independent review base must match live base", " ".join(r["reasons"]))

    def reasons(self, gh, e):
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"], r)
        return " ".join(r["reasons"])

    def test_symlinked_scoped_input_waits(self):
        gh, e, trees = self.fixture()
        target = "internal/shared/target.go"
        # DEP is an unchanged symlink at every revision; main changed the file it points at.
        for rev, n in ((A, 6), (R, 6), (B, 7), (H, 7)):
            trees[rev][target] = blob(n)
            if DEP in trees[rev]:
                trees[rev][DEP] = ("120000", "1" * 40)
        self.assertIn("execution input changed, missing or not a regular file: " + DEP, self.reasons(gh, e))

    def test_candidate_edit_replaced_by_base_version_waits(self):
        gh, e, trees = self.fixture()
        # The candidate edited an unscoped file, then the merge kept main's version: HEAD == base there.
        trees[A][OTHER], trees[R][OTHER] = blob(5), blob(7)
        self.assertEqual(trees[B][OTHER], trees[H][OTHER])
        self.assertIn("neither a pure base import nor an audited non-execution change: " + OTHER,
                      self.reasons(gh, e))

    def test_non_ancestor_candidate_waits(self):
        gh, e, _ = self.fixture()
        gh.compares[(R, H)] = {"ancestor": False, "merge_base": A, "files": [ART, OTHER]}
        self.assertIn("tested candidate is not an ancestor of HEAD", self.reasons(gh, e))

    def test_candidate_on_base_waits(self):
        # merge_base == R: the candidate is on main. merge_base == B: main never advanced past it.
        for merge_base in (R, B):
            with self.subTest(merge_base=merge_base[:7]):
                gh, e, _ = self.fixture()
                gh.compares[(R, B)] = {"ancestor": merge_base == R, "merge_base": merge_base, "files": [OTHER]}
                self.assertIn("target reuse requires a candidate branch and an advanced base", self.reasons(gh, e))

    def test_missing_live_base_name_waits(self):
        gh, e, _ = self.fixture()
        del gh.v["baseRefName"]
        self.assertIn("Live base branch name unavailable", self.reasons(gh, e))

    def test_untyped_base_manifest_cannot_be_weakened_from_pr(self):
        gh, e, _ = self.fixture()
        manifest = json.loads(gh.files[(MANIFEST, B)])
        del manifest["required_evidence"][0]["kind"]
        gh.files[(MANIFEST, B)] = json.dumps(manifest).encode()
        gh.files[(MANIFEST, H)] = repo_manifest()
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("requires kind: target-run", " ".join(r["reasons"]))

    def test_stale_independent_review_and_test_receipts_remain_rejected(self):
        gh, e, _ = self.fixture()
        stale = copy.deepcopy(e)
        stale["head_sha"] = R
        self.assertIn("Stale review evidence: reviewed HEAD/Base does not match GitHub", self.reasons(gh, stale))
        e["tests"][0]["sha"] = R
        self.assertIn("Test evidence is not bound to current PR HEAD: unit", self.reasons(gh, e))

    def test_missing_or_truncated_tree_waits(self):
        gh, e, _ = self.fixture()
        def fail(*args):
            raise gh_runtime.GitHubError("Complete Git tree unavailable (truncated)")
        gh.tree_entries = fail
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("truncated", " ".join(r["reasons"]))


class GitTreeAdapterTests(unittest.TestCase):
    def test_live_branch_head_is_resolved_and_malformed_answers_fail_closed(self):
        with mock.patch.object(gh_runtime, "gh_json", return_value={"commit": {"sha": B}}) as call:
            self.assertEqual(B, gh_runtime.branch_head(REPO, "release/main"))
            self.assertIn("release%2Fmain", call.call_args.args[0][-1])
        for data in ({}, {"commit": []}, {"commit": {"sha": "main"}}, []):
            with self.subTest(data=data), mock.patch.object(gh_runtime, "gh_json", return_value=data):
                with self.assertRaises(gh_runtime.GitHubError):
                    gh_runtime.branch_head(REPO, "main")
        for name in ("", None):
            with self.subTest(name=name), mock.patch.object(gh_runtime, "gh_json", return_value={"commit": {"sha": B}}):
                with self.assertRaisesRegex(gh_runtime.GitHubError, "branch name unavailable"):
                    gh_runtime.branch_head(REPO, name)

    def test_compare_needs_the_merge_base_commit_id(self):
        capture = API["compare"]["ahead_evidence_only"]
        run_gh, _ = replay(capture)
        with mock.patch.object(gh_runtime, "run_gh", run_gh):
            got = gh_runtime.compare(REPO, *capture["args"])
        self.assertRegex(got["merge_base"], r"[0-9a-f]{40}\Z")
        body = json.loads(capture["stdout"])
        body["merge_base_commit"]["sha"] = "main"
        run_gh, _ = replay(dict(capture, stdout=json.dumps(body)))
        with mock.patch.object(gh_runtime, "run_gh", run_gh):
            with self.assertRaisesRegex(gh_runtime.GitHubError, "Invalid compare response"):
                gh_runtime.compare(REPO, *capture["args"])

    def test_blob_modes_symlinks_and_submodules_are_preserved_without_following(self):
        rows = [{"path": p, "mode": mode, "type": typ, "sha": str(n)*40}
                for p, mode, typ, n in (("x", "100644", "blob", 1), ("exe", "100755", "blob", 2),
                                        ("link", "120000", "blob", 3), ("sub", "160000", "commit", 4))]
        data = {"truncated": False, "tree": rows}
        with mock.patch.object(gh_runtime, "gh_json", return_value=data) as call:
            got = gh_runtime.tree_entries(REPO, H)
            self.assertEqual(("120000", "3"*40), got["link"])
            self.assertEqual(("160000", "4"*40), got["sub"])
            self.assertIn(H+"?recursive=1", call.call_args.args[0][-1])

    def test_truncated_malformed_duplicate_and_unknown_mode_trees_fail_closed(self):
        row = {"path": "a", "mode": "100644", "type": "blob", "sha": "1"*40}
        cases = [{"truncated": True, "tree": []}, {"tree": []},
                 {"truncated": False, "tree": [row, row]},
                 {"truncated": False, "tree": [dict(row, mode="040000")]},
                 {"truncated": False, "tree": [dict(row, sha="bad")]},
                 {"truncated": False, "tree": [dict(row, type="commit")]},
                 {"truncated": False, "tree": [dict(row, mode="100664")]}]
        for data in cases:
            with self.subTest(data=data), mock.patch.object(gh_runtime, "gh_json", return_value=data):
                with self.assertRaises(gh_runtime.GitHubError):
                    gh_runtime.tree_entries(REPO, H)


if __name__ == "__main__":
    unittest.main()
